mod common;

use axum_test::TestServer;
use common::{create_test_server_with_state, mock_login, TestServerConfig};
use database::{encryption, field_encryption, Database};
use http::{HeaderName, HeaderValue};
use serde_json::{json, Value};
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use uuid::Uuid;

fn scope() -> Value {
    json!({"fields": [
        {"table": "agent_instances", "column": "instance_token"},
        {"table": "user_passkey_credentials", "column": "auth_secret"},
        {"table": "user_passkey_credentials", "column": "backup_passphrase"}
    ]})
}

struct Fixture {
    server: TestServer,
    db: Database,
    state: api::AppState,
    auth: HeaderValue,
    user_id: UserId,
    instance_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let (server, db, state) = create_test_server_with_state(TestServerConfig {
            database_encryption_write_enabled: Some(true),
            database_encryption_agent_secrets_write_enabled: Some(false),
            ..Default::default()
        })
        .await;
        let user_id = UserId(Uuid::new_v4());
        db.pool()
            .get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO users(id,email) VALUES($1,$2)",
                &[&user_id, &format!("{user_id}@example.com")],
            )
            .await
            .unwrap();
        let instance = db
            .agent_repository()
            .create_instance(CreateInstanceParams {
                user_id,
                instance_id: Uuid::new_v4().to_string(),
                name: "credential-migration".into(),
                public_ssh_key: None,
                instance_url: None,
                instance_token: Some("instance-secret".into()),
                dashboard_url: None,
                agent_api_base_url: None,
                service_type: None,
            })
            .await
            .unwrap();
        db.agent_repository()
            .upsert_user_passkey_credentials(user_id, "auth-secret", "backup-secret")
            .await
            .unwrap();
        let token = mock_login(&server, "agent-encryption@admin.org").await;
        Self {
            server,
            db,
            state,
            auth: HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            user_id,
            instance_id: instance.id,
        }
    }

    fn enable_new_writes(&self) {
        let mut config = self.db.pool().field_encryption().unwrap();
        config.agent_secrets_write_enabled = true;
        self.db.pool().set_field_encryption(config);
    }

    async fn stored(&self) -> [String; 3] {
        let row = self
            .db
            .pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT ai.instance_token, pc.auth_secret, pc.backup_passphrase
             FROM agent_instances ai JOIN user_passkey_credentials pc ON pc.user_id=ai.user_id
             WHERE ai.id=$1",
                &[&self.instance_id],
            )
            .await
            .unwrap();
        [row.get(0), row.get(1), row.get(2)]
    }

    async fn job(&self, mode: &str) -> Value {
        let action = if mode == "verify" {
            "verify"
        } else {
            "encrypt"
        };
        let response = self
            .server
            .post("/v1/admin/database-encryption/jobs")
            .add_header(HeaderName::from_static("authorization"), self.auth.clone())
            .json(&json!({"mode": mode, "scope": scope(), "batch_size": 1, "actions": [action]}))
            .await;
        assert_eq!(response.status_code(), 202);
        let accepted: Value = response.json();
        let id = accepted["job_id"].as_str().unwrap();
        self.wait_for_job(id).await
    }

    async fn wait_for_job(&self, id: &str) -> Value {
        for _ in 0..200 {
            let response = self
                .server
                .get(&format!("/v1/admin/database-encryption/jobs/{id}"))
                .add_header(HeaderName::from_static("authorization"), self.auth.clone())
                .await;
            let job: Value = response.json();
            if job["status"] == "completed" || job["status"] == "failed" {
                return job;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("migration job did not finish");
    }

    async fn cleanup(&self) {
        let client = self.db.pool().get().await.unwrap();
        client
            .execute(
                "DELETE FROM user_passkey_credentials WHERE user_id=$1",
                &[&self.user_id],
            )
            .await
            .unwrap();
        client
            .execute("DELETE FROM users WHERE id=$1", &[&self.user_id])
            .await
            .unwrap();
    }
}

/// Restore the test process's old key even when an assertion fails.
struct AppKeyGuard(Option<std::ffi::OsString>);

impl AppKeyGuard {
    fn remove() -> Self {
        let guard = Self(std::env::var_os("ENCRYPTION_KEY"));
        std::env::remove_var("ENCRYPTION_KEY");
        guard
    }
}

impl Drop for AppKeyGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => std::env::set_var("ENCRYPTION_KEY", value),
            None => std::env::remove_var("ENCRYPTION_KEY"),
        }
    }
}

#[tokio::test]
#[serial]
async fn agent_credentials_roll_out_and_backfill_without_the_old_app_key() {
    let fixture = Fixture::new().await;
    let repository = fixture.db.agent_repository();
    let legacy = fixture.stored().await;
    for (ciphertext, plaintext) in
        legacy
            .iter()
            .zip(["instance-secret", "auth-secret", "backup-secret"])
    {
        assert_eq!(encryption::decrypt(ciphertext).unwrap(), plaintext);
    }

    // The global write gate alone must not change the three credential fields.
    let rejected = fixture
        .server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.auth.clone(),
        )
        .json(&json!({"mode":"execute", "scope":scope(), "actions":["encrypt"]}))
        .await;
    assert_eq!(rejected.status_code(), 400);
    let dry_run = fixture.job("dry_run").await;
    assert_eq!(dry_run["progress"]["pass"], true, "{dry_run}");
    assert!(dry_run["progress"]["legacy_encrypted"].as_i64().unwrap() >= 3);
    assert_eq!(fixture.stored().await, legacy);
    assert_eq!(fixture.job("verify").await["progress"]["pass"], false);

    fixture.enable_new_writes();
    // Exercise the admin route: it passes plaintext to the repository, not ciphertext.
    let updated = fixture
        .server
        .patch(&format!(
            "/v1/admin/agents/instances/{}",
            fixture.instance_id
        ))
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.auth.clone(),
        )
        .json(&json!({"instance_token":"updated-instance-secret"}))
        .await;
    assert_eq!(updated.status_code(), 200);
    assert_eq!(
        repository
            .get_instance(fixture.instance_id)
            .await
            .unwrap()
            .unwrap()
            .instance_token
            .as_deref(),
        Some("updated-instance-secret")
    );
    assert_eq!(
        repository
            .get_user_passkey_credentials(fixture.user_id)
            .await
            .unwrap(),
        Some(("auth-secret".into(), "backup-secret".into()))
    );

    // Historical plaintext is converted too; the other passkey field is still legacy ciphertext.
    fixture.db.pool().get().await.unwrap().execute(
        "UPDATE user_passkey_credentials SET backup_passphrase='historical:plaintext' WHERE user_id=$1",
        &[&fixture.user_id],
    ).await.unwrap();
    let migrated = fixture.job("execute").await;
    assert_eq!(migrated["status"], "completed", "{migrated}");
    assert_eq!(migrated["progress"]["pass"], true, "{migrated}");
    let config = fixture.db.pool().field_encryption().unwrap();
    let stored = fixture.stored().await;
    for (index, (table, column, id, expected)) in [
        (
            "agent_instances",
            "instance_token",
            fixture.instance_id,
            "updated-instance-secret",
        ),
        (
            "user_passkey_credentials",
            "auth_secret",
            fixture.user_id.0,
            "auth-secret",
        ),
        (
            "user_passkey_credentials",
            "backup_passphrase",
            fixture.user_id.0,
            "historical:plaintext",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            field_encryption::decrypt(
                &config.key,
                &config.key_id,
                table,
                column,
                id,
                &stored[index]
            )
            .unwrap(),
            expected
        );
    }
    let rerun = fixture.job("execute").await;
    assert_eq!(rerun["progress"]["encrypted"], 0, "{rerun}");
    assert_eq!(fixture.stored().await, stored);

    // Completed migration must not need the app key, for reads OR subsequent writes.
    let _old_key = AppKeyGuard::remove();
    assert_eq!(
        repository
            .get_instance(fixture.instance_id)
            .await
            .unwrap()
            .unwrap()
            .instance_token
            .as_deref(),
        Some("updated-instance-secret")
    );
    assert_eq!(
        repository
            .get_user_passkey_credentials(fixture.user_id)
            .await
            .unwrap(),
        Some(("auth-secret".into(), "historical:plaintext".into()))
    );
    repository
        .upsert_user_passkey_credentials(fixture.user_id, "new-auth", "new-backup")
        .await
        .unwrap();
    assert_eq!(
        repository
            .get_user_passkey_credentials(fixture.user_id)
            .await
            .unwrap(),
        Some(("new-auth".into(), "new-backup".into()))
    );
    let created = repository
        .create_instance(CreateInstanceParams {
            user_id: fixture.user_id,
            instance_id: Uuid::new_v4().to_string(),
            name: "new-root-instance".into(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: Some("new-instance-secret".into()),
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();
    assert_eq!(
        created.instance_token.as_deref(),
        Some("new-instance-secret")
    );
    let verified = fixture.job("verify").await;
    assert_eq!(verified["status"], "completed", "{verified}");
    assert_eq!(verified["progress"]["pass"], true, "{verified}");
    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn unreadable_credentials_fail_backfill_without_overwriting_data() {
    let fixture = Fixture::new().await;
    fixture.enable_new_writes();
    let wrong_key = rand::random::<[u8; 32]>();
    let wrong_key_ciphertext =
        encryption::encrypt_with_key(&wrong_key, "unreadable-token").unwrap();
    for invalid in [
        wrong_key_ciphertext,
        r#"{"__near_db_encrypted":1}"#.to_string(),
        "0123456789abcdef01234567:bad-ciphertext".to_string(),
    ] {
        fixture
            .db
            .pool()
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE agent_instances SET instance_token=$2 WHERE id=$1",
                &[&fixture.instance_id, &invalid],
            )
            .await
            .unwrap();
        let before = fixture.stored().await;
        assert!(fixture
            .db
            .agent_repository()
            .get_instance(fixture.instance_id)
            .await
            .is_err());
        let scan = fixture
            .server
            .post("/v1/admin/database-encryption/scan")
            .add_header(
                HeaderName::from_static("authorization"),
                fixture.auth.clone(),
            )
            .json(&json!({"scope": scope()}))
            .await;
        assert_eq!(scan.status_code(), 200);
        assert!(
            scan.json::<Value>()["totals"]["invalid_envelope"]
                .as_i64()
                .unwrap()
                >= 1
        );
        let dry_run = fixture.job("dry_run").await;
        assert_eq!(dry_run["progress"]["pass"], false, "{dry_run}");
        let failed = fixture.job("execute").await;
        assert_eq!(failed["status"], "failed", "{failed}");
        assert_eq!(failed["last_error_class"], "batch_failed");
        assert_eq!(fixture.stored().await, before);
        assert!(!failed.to_string().contains(&invalid));
        assert_eq!(fixture.job("verify").await["progress"]["pass"], false);
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn unreadable_tokens_do_not_hide_instance_lists_or_bypass_authentication() {
    let fixture = Fixture::new().await;
    let repository = fixture.db.agent_repository();
    let healthy = repository
        .create_instance(CreateInstanceParams {
            user_id: fixture.user_id,
            instance_id: Uuid::new_v4().to_string(),
            name: "healthy-instance".into(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: Some("healthy-token".into()),
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();

    let wrong_key = rand::random::<[u8; 32]>();
    let unreadable = encryption::encrypt_with_key(&wrong_key, "unreadable-token").unwrap();
    fixture
        .db
        .pool()
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE agent_instances SET instance_token=$2 WHERE id=$1",
            &[&fixture.instance_id, &unreadable],
        )
        .await
        .unwrap();

    // The write gate is still off: deploy-time reads must not break the lists.
    let (user_instances, count) = repository
        .list_user_instances(fixture.user_id, 100, 0)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let (admin_instances, _) = repository.list_all_instances(100, 0).await.unwrap();
    let (usage_instances, _, _) = repository
        .list_all_instances_with_usage(100, 0)
        .await
        .unwrap();
    for instances in [user_instances, admin_instances, usage_instances] {
        let broken = instances
            .iter()
            .find(|row| row.id == fixture.instance_id)
            .unwrap();
        assert_eq!(broken.name, "credential-migration");
        assert_eq!(broken.instance_token, None);
        let working = instances.iter().find(|row| row.id == healthy.id).unwrap();
        assert_eq!(working.instance_token.as_deref(), Some("healthy-token"));
    }
    assert!(repository.get_instance(fixture.instance_id).await.is_err());
    assert!(repository
        .get_instance_by_instance_id(&healthy.instance_id)
        .await
        .unwrap()
        .is_some());

    // Missing the old key never turns ciphertext into a usable credential.
    {
        let _old_key = AppKeyGuard::remove();
        assert!(repository.get_instance(healthy.id).await.is_err());
        assert!(repository
            .get_user_passkey_credentials(fixture.user_id)
            .await
            .is_err());
        let (instances, _) = repository
            .list_user_instances(fixture.user_id, 100, 0)
            .await
            .unwrap();
        assert!(instances
            .iter()
            .all(|instance| instance.instance_token.is_none()));
    }
    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn recovery_never_expands_a_previously_accepted_job_scope() {
    let fixture = Fixture::new().await;
    let before = fixture.stored().await;

    let response = fixture
        .server
        .post("/v1/admin/database-encryption/jobs")
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.auth.clone(),
        )
        .json(&json!({
            "mode": "dry_run",
            "scope": {"tables": ["agent_instances"]},
            "actions": ["encrypt"]
        }))
        .await;
    assert_eq!(response.status_code(), 202);
    let accepted: Value = response.json();
    let pinned_scope = json!({"tables": [], "fields": [
        {"table": "agent_instances", "column": "auth_session_token"},
        {"table": "agent_instances", "column": "dashboard_url"},
        {"table": "agent_instances", "column": "instance_token"},
        {"table": "agent_instances", "column": "instance_url"}
    ]});
    assert_eq!(accepted["scope"], pinned_scope);
    let completed = fixture
        .wait_for_job(accepted["job_id"].as_str().unwrap())
        .await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(completed["scope"], pinned_scope);

    // Old table scopes cannot silently add instance_token, with either gate value.
    // Old whole-database verify jobs also need a new, explicit snapshot.
    for (mode, scope, status, enabled) in [
        (
            "execute",
            json!({"tables": ["agent_instances"]}),
            "queued",
            false,
        ),
        (
            "execute",
            json!({"tables": ["agent_instances"]}),
            "running",
            true,
        ),
        ("verify", json!({}), "queued", true),
    ] {
        let mut config = fixture.db.pool().field_encryption().unwrap();
        config.agent_secrets_write_enabled = enabled;
        fixture.db.pool().set_field_encryption(config);
        let id = Uuid::new_v4();
        let cursor = json!({"field_index": 1, "after_id": fixture.instance_id});
        let actions = if mode == "verify" {
            json!(["verify"])
        } else {
            json!(["encrypt"])
        };
        fixture.db.pool().get().await.unwrap().execute(
            "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size,cursor)
             VALUES($1,$2,$3,$4,$5,1,$6)",
            &[&id, &mode, &status, &scope, &actions, &cursor],
        ).await.unwrap();
        api::database_encryption::recover_jobs(fixture.state.clone()).await;
        let failed = fixture.wait_for_job(&id.to_string()).await;
        assert_eq!(failed["status"], "failed", "{failed}");
        assert_eq!(failed["last_error_class"], "scope_requires_confirmation");
        assert_eq!(failed["cursor"], cursor);
        assert_eq!(fixture.stored().await, before);
    }

    // An old field-scoped job can still resume; it does not gain credentials.
    let id = Uuid::new_v4();
    let explicit_scope = json!({"fields": [
        {"table": "agent_instances", "column": "instance_url"}
    ]});
    fixture
        .db
        .pool()
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO database_encryption_jobs(id,mode,status,scope,actions,batch_size)
         VALUES($1,'execute','running',$2,'[\"encrypt\"]',1)",
            &[&id, &explicit_scope],
        )
        .await
        .unwrap();
    api::database_encryption::recover_jobs(fixture.state.clone()).await;
    let completed = fixture.wait_for_job(&id.to_string()).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(completed["progress"]["pass"], true);
    assert_eq!(fixture.stored().await, before);
    fixture.cleanup().await;
}
