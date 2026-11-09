#![cfg(feature = "test")]
mod common;
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use database::{field_encryption, repositories::app_config_repository::app_config_encryption_id};
use serde_json::{json, Value};
use uuid::Uuid;

async fn stored(db: &database::Database, key: &str) -> String {
    db.pool()
        .get()
        .await
        .unwrap()
        .query_one("SELECT value FROM app_config WHERE key=$1", &[&key])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[serial_test::serial]
async fn config_values_are_encrypted_and_bound_to_the_key() {
    let (_, db) = create_test_server_and_db(Default::default()).await;
    enable_config_writes(&db);
    let repo = db.app_config_repository();
    let key = format!("vpc-test-{}", Uuid::new_v4());
    repo.set(&key, "test-api-key").await.unwrap();
    let ciphertext = stored(&db, &key).await;
    assert!(!ciphertext.contains("test-api-key"));
    assert!(field_encryption::is_envelope(
        &serde_json::from_str(&ciphertext).unwrap()
    ));
    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("test-api-key")
    );
    repo.set(&key, "refreshed-key").await.unwrap();
    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("refreshed-key")
    );
    let client = db.pool().get().await.unwrap();
    let sql_id: Uuid = client
        .query_one(
            "SELECT substr(encode(sha256(convert_to($1, 'UTF8')), 'hex'), 1, 32)::uuid",
            &[&key],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(sql_id, app_config_encryption_id(&key));
    let other = format!("other-{key}");
    client
        .execute(
            "INSERT INTO app_config (key,value) VALUES ($1,$2)",
            &[&other, &ciphertext],
        )
        .await
        .unwrap();
    assert!(
        repo.get(&other).await.is_err(),
        "ciphertext cannot be moved to another key"
    );
    repo.delete(&other).await.unwrap();
    repo.delete(&key).await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn reading_a_legacy_value_encrypts_it_in_place() {
    let (_, db) = create_test_server_and_db(Default::default()).await;
    enable_config_writes(&db);
    let key = format!("legacy-{}", Uuid::new_v4());
    db.pool()
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO app_config (key,value) VALUES ($1,'legacy-key')",
            &[&key],
        )
        .await
        .unwrap();
    assert_eq!(
        db.app_config_repository()
            .get(&key)
            .await
            .unwrap()
            .as_deref(),
        Some("legacy-key")
    );
    assert!(!stored(&db, &key).await.contains("legacy-key"));
    db.app_config_repository().delete(&key).await.unwrap();
}

async fn job(server: &axum_test::TestServer, token: &str, action: &str) {
    let response = server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({"mode":"execute", "scope":{"tables":["app_config"]},
            "batch_size": 10, "batch_delay_ms": 1, "actions":[action]}))
        .await;
    assert_eq!(response.status_code(), 202, "{}", response.text());
    let id = response.json::<Value>()["job_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..200 {
        let result = server
            .get(&format!("/v1/admin/database-encryption/jobs/{id}"))
            .add_header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await
            .json::<Value>();
        match result["status"].as_str() {
            Some("completed") => return,
            Some("queued" | "running") => (),
            _ => panic!("encryption job failed: {result}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("encryption job did not finish");
}

#[tokio::test]
#[serial_test::serial]
async fn registry_backfill_and_key_rotation_preserve_config_reads() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(true),
        ..Default::default()
    })
    .await;
    enable_config_writes(&db);
    let token = mock_login(&server, "db-encryption-admin@admin.org").await;
    let key = format!("backfill-{}", Uuid::new_v4());
    db.pool()
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO app_config (key,value) VALUES ($1,'backfill-key')",
            &[&key],
        )
        .await
        .unwrap();
    job(&server, &token, "encrypt").await;
    let old = stored(&db, &key).await;
    assert!(!old.contains("backfill-key"));
    assert_eq!(
        db.app_config_repository()
            .get(&key)
            .await
            .unwrap()
            .as_deref(),
        Some("backfill-key")
    );
    let config = db.pool().field_encryption().unwrap();
    let old_key = *config.ring().write_key();
    let old_id = config.ring().write_id().to_owned();
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            ring: field_encryption::KeyRing::new(
                "config-v2".into(),
                [0x51; 32],
                vec![(old_id, old_key)],
            )
            .unwrap(),
            ..config
        });
    assert_eq!(
        db.app_config_repository()
            .get(&key)
            .await
            .unwrap()
            .as_deref(),
        Some("backfill-key")
    );
    job(&server, &token, "rewrap").await;
    let rotated = stored(&db, &key).await;
    assert_eq!(
        serde_json::from_str::<Value>(&rotated).unwrap()["key_id"],
        "config-v2"
    );
    assert_eq!(
        db.app_config_repository()
            .get(&key)
            .await
            .unwrap()
            .as_deref(),
        Some("backfill-key")
    );
    db.app_config_repository().delete(&key).await.unwrap();
}

fn enable_config_writes(db: &database::Database) {
    let config = db.pool().field_encryption().unwrap();
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: true,
            app_config_write_enabled: true,
            ..config
        });
}

#[tokio::test]
#[serial_test::serial]
async fn separate_rollout_gate_preserves_plaintext_and_blocks_backfill() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(true),
        ..Default::default()
    })
    .await;
    let repo = db.app_config_repository();
    let key = format!("gate-{}", Uuid::new_v4());
    repo.set(&key, "legacy-reader-compatible").await.unwrap();
    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("legacy-reader-compatible")
    );
    assert_eq!(stored(&db, &key).await, "legacy-reader-compatible");
    let token = mock_login(&server, "db-encryption-admin@admin.org").await;
    let response = server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&json!({"mode":"execute","scope":{"tables":["app_config"]},"actions":["encrypt"]}))
        .await;
    assert_eq!(response.status_code(), 400);
    enable_config_writes(&db);
    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("legacy-reader-compatible")
    );
    assert_ne!(stored(&db, &key).await, "legacy-reader-compatible");
    // Turning off writes must not disable decryption of already-migrated rows.
    let config = db.pool().field_encryption().unwrap();
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            app_config_write_enabled: false,
            ..config
        });
    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("legacy-reader-compatible")
    );
    repo.delete(&key).await.unwrap();
}
