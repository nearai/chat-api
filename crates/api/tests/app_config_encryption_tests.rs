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
    let (_, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(true),
        ..Default::default()
    })
    .await;
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
    let (_, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(true),
        ..Default::default()
    })
    .await;
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
        .json(&json!({
            "mode": "execute",
            "scope": {"tables": ["app_config"]},
            "batch_size": 10,
            "batch_delay_ms": 1,
            "actions": [action],
        }))
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
    // This test rewraps every app_config row with a test-only key. It must
    // never use the shared database used by other integration tests.
    let config = config::Config::from_env().database;
    let control = database::Database::from_config(&config).await.unwrap();
    let database_name = format!("app_config_rotation_{}", Uuid::new_v4().simple());

    control
        .pool()
        .get()
        .await
        .unwrap()
        .batch_execute(&format!("CREATE DATABASE {database_name}"))
        .await
        .unwrap();
    let _cleanup = DatabaseCleanup {
        database_name: database_name.clone(),
        config,
    };

    let (server, db) = create_test_server_and_db(TestServerConfig {
        database_name: Some(database_name),
        database_encryption_write_enabled: Some(true),
        ..Default::default()
    })
    .await;
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

fn set_encryption_writes(db: &database::Database, enabled: bool) {
    let config = db.pool().field_encryption().unwrap();
    db.pool()
        .set_field_encryption(services::db_pool::FieldEncryptionConfig {
            write_enabled: enabled,
            ..config
        });
}

#[tokio::test]
#[serial_test::serial]
async fn global_write_gate_controls_config_writes_read_repair_and_backfill() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        database_encryption_write_enabled: Some(false),
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
        .json(&json!({
            "mode": "execute",
            "scope": {"tables": ["app_config"]},
            "actions": ["encrypt"],
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    assert!(response.text().contains("DB_ENCRYPTION_WRITE_ENABLED=true"));

    set_encryption_writes(&db, true);

    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("legacy-reader-compatible")
    );
    let ciphertext = stored(&db, &key).await;
    assert_ne!(ciphertext, "legacy-reader-compatible");

    // Turning off writes must not disable decryption of already-migrated rows.
    set_encryption_writes(&db, false);

    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("legacy-reader-compatible")
    );
    assert_eq!(stored(&db, &key).await, ciphertext);

    repo.set(&key, "writes-disabled").await.unwrap();

    assert_eq!(
        repo.get(&key).await.unwrap().as_deref(),
        Some("writes-disabled")
    );
    assert_eq!(stored(&db, &key).await, "writes-disabled");

    repo.delete(&key).await.unwrap();
}

struct DatabaseCleanup {
    database_name: String,
    config: config::DatabaseConfig,
}

impl Drop for DatabaseCleanup {
    fn drop(&mut self) {
        let database_name = self.database_name.clone();
        let config = self.config.clone();

        // A fresh runtime/connection avoids waiting on tasks owned by the test's
        // current-thread runtime while it is unwinding or dropping the fixture.
        let cleanup = std::thread::spawn(move || -> anyhow::Result<()> {
            tokio::runtime::Runtime::new()?.block_on(async move {
                let control = database::Database::from_config(&config).await?;
                control
                    .pool()
                    .get()
                    .await?
                    .batch_execute(&format!("DROP DATABASE {database_name} WITH (FORCE)"))
                    .await?;

                Ok(())
            })
        })
        .join();

        if !matches!(cleanup, Ok(Ok(()))) {
            if std::thread::panicking() {
                eprintln!("isolated app-config database cleanup failed during unwinding");
            } else {
                panic!("isolated app-config database cleanup failed");
            }
        }
    }
}
