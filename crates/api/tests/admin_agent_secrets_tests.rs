mod common;

use axum_test::{TestResponse, TestServer};
use common::{
    cleanup_user, cleanup_user_agent_instances, create_test_server_and_db, mock_login,
    TestServerConfig,
};
use database::{agent_secrets, Database};
use http::{HeaderName, HeaderValue};
use serde_json::{json, Value};
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "agent-secrets@admin.org";

struct Fixture {
    server: TestServer,
    db: Database,
    admin_auth: HeaderValue,
    owner_auth: HeaderValue,
    owner_email: String,
    owner_id: UserId,
    instance_id: Uuid,
}

impl Fixture {
    async fn new(field_encryption: bool) -> Self {
        let (server, db) = create_test_server_and_db(TestServerConfig {
            admin_emails: Some(vec![ADMIN_EMAIL.into()]),
            database_encryption_write_enabled: Some(field_encryption),
            database_encryption_agent_secrets_write_enabled: Some(field_encryption),
            ..Default::default()
        })
        .await;
        let owner_email = format!("agent-secrets-{}@example.com", Uuid::new_v4());
        let owner_token = mock_login(&server, &owner_email).await;
        let admin_token = mock_login(&server, ADMIN_EMAIL).await;
        let client = db.pool().get().await.unwrap();
        let owner_id = UserId(
            client
                .query_one("SELECT id FROM users WHERE email = $1", &[&owner_email])
                .await
                .unwrap()
                .get(0),
        );

        let instance = db
            .agent_repository()
            .create_instance(CreateInstanceParams {
                user_id: owner_id,
                instance_id: Uuid::new_v4().to_string(),
                name: "secrets-update".into(),
                public_ssh_key: Some("ssh-ed25519 test-public-key".into()),
                instance_url: Some("https://agent.example.com".into()),
                instance_token: Some("old-instance-token".into()),
                dashboard_url: Some("https://agent.example.com/dashboard".into()),
                agent_api_base_url: Some("https://manager.example.com".into()),
                service_type: Some("ironclaw".into()),
            })
            .await
            .unwrap();
        db.agent_repository()
            .upsert_user_passkey_credentials(owner_id, "auth-secret", "backup-secret")
            .await
            .unwrap();

        Self {
            server,
            db,
            admin_auth: HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
            owner_auth: HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
            owner_email,
            owner_id,
            instance_id: instance.id,
        }
    }

    fn path(&self) -> String {
        format!("/v1/admin/agents/instances/{}/secrets", self.instance_id)
    }

    async fn patch(&self, payload: Value) -> TestResponse {
        self.server
            .patch(&self.path())
            .add_header(
                HeaderName::from_static("authorization"),
                self.admin_auth.clone(),
            )
            .json(&payload)
            .await
    }

    async fn stored(&self) -> Value {
        self.db
            .pool()
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT to_jsonb(ai) FROM agent_instances ai WHERE id = $1",
                &[&self.instance_id],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn cleanup(&self) {
        cleanup_user_agent_instances(&self.db, &self.owner_email).await;
        cleanup_user(&self.db, &self.owner_email).await;
    }
}

#[tokio::test]
#[serial]
async fn admin_replaces_only_the_token_in_both_encryption_modes() {
    for field_encryption in [false, true] {
        let fixture = Fixture::new(field_encryption).await;
        let mut before = fixture.stored().await;
        let other = Fixture::new(field_encryption).await;
        let other_before = other.stored().await;

        let response = fixture
            .patch(json!({ "instance_token": "replacement-instance-token" }))
            .await;

        assert_eq!(response.status_code(), 204);
        assert!(response.text().is_empty());

        let mut after = fixture.stored().await;
        let encrypted = after["instance_token"].as_str().unwrap();
        assert_ne!(encrypted, "replacement-instance-token");
        assert_eq!(
            agent_secrets::is_field_envelope(encrypted),
            field_encryption
        );
        assert_eq!(
            agent_secrets::is_legacy_ciphertext(encrypted),
            !field_encryption
        );
        assert_eq!(
            fixture
                .db
                .agent_repository()
                .get_instance(fixture.instance_id)
                .await
                .unwrap()
                .unwrap()
                .instance_token
                .as_deref(),
            Some("replacement-instance-token")
        );
        assert_eq!(
            fixture
                .db
                .agent_repository()
                .get_user_passkey_credentials(fixture.owner_id)
                .await
                .unwrap(),
            Some(("auth-secret".into(), "backup-secret".into()))
        );

        for row in [&mut before, &mut after] {
            row.as_object_mut().unwrap().remove("instance_token");
            row.as_object_mut().unwrap().remove("updated_at");
        }
        assert_eq!(before, after, "All instance metadata must remain unchanged");
        assert_eq!(other.stored().await, other_before);

        fixture.cleanup().await;
        other.cleanup().await;
    }
}

#[tokio::test]
#[serial]
async fn instance_secrets_require_admin_authentication() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;
    let payload = json!({ "instance_token": "unauthorized-replacement" });

    let anonymous = fixture.server.patch(&fixture.path()).json(&payload).await;
    let owner = fixture
        .server
        .patch(&fixture.path())
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.owner_auth.clone(),
        )
        .json(&payload)
        .await;

    assert_eq!(anonymous.status_code(), 401);
    assert_eq!(owner.status_code(), 403);
    assert_eq!(fixture.stored().await, before);

    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn instance_secrets_reject_metadata_and_invalid_payloads_without_echoing_values() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;
    let marker = "sensitive-value-must-not-be-echoed";
    let mut payloads = vec![
        json!({}),
        json!({ "instance_token": null }),
        json!({ "instance_token": "" }),
        json!({ "instance_token": " \n\t" }),
        json!({ "instance_token": [marker] }),
        json!([marker]),
    ];
    for field in [
        "instance_url",
        "agent_api_base_url",
        "dashboard_url",
        "name",
        "user_id",
        "auth_secret",
        "backup_passphrase",
        marker,
    ] {
        payloads.push(json!({ "instance_token": marker, field: marker }));
    }

    for payload in payloads {
        let response = fixture.patch(payload).await;

        assert_eq!(response.status_code(), 400);
        assert!(!response.text().contains(marker));
        assert_eq!(fixture.stored().await, before);
    }

    let malformed = fixture
        .server
        .patch(&fixture.path())
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.admin_auth.clone(),
        )
        .add_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        )
        .text(format!("{{\"instance_token\":\"{marker}\""))
        .await;

    assert_eq!(malformed.status_code(), 400);
    assert!(!malformed.text().contains(marker));
    assert_eq!(fixture.stored().await, before);

    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn instance_secrets_reject_invalid_missing_and_deleted_instances() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;

    for (id, status) in [
        ("not-a-uuid".to_owned(), 400),
        (Uuid::new_v4().to_string(), 404),
    ] {
        let response = fixture
            .server
            .patch(&format!("/v1/admin/agents/instances/{id}/secrets"))
            .add_header(
                HeaderName::from_static("authorization"),
                fixture.admin_auth.clone(),
            )
            .json(&json!({ "instance_token": "replacement-token" }))
            .await;

        assert_eq!(response.status_code(), status);
        assert_eq!(fixture.stored().await, before);
    }

    fixture
        .db
        .pool()
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE agent_instances SET status = 'deleted' WHERE id = $1",
            &[&fixture.instance_id],
        )
        .await
        .unwrap();
    let deleted = fixture.stored().await;

    let response = fixture
        .patch(json!({ "instance_token": "replacement-token" }))
        .await;

    assert_eq!(response.status_code(), 404);
    assert_eq!(fixture.stored().await, deleted);

    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn instance_secrets_repair_an_unreadable_token_and_fail_closed_on_encryption_errors() {
    let fixture = Fixture::new(true).await;
    fixture
        .db
        .pool()
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE agent_instances SET instance_token = $1 WHERE id = $2",
            &[&"000000000000000000000000:broken", &fixture.instance_id],
        )
        .await
        .unwrap();
    assert!(fixture
        .db
        .agent_repository()
        .get_instance(fixture.instance_id)
        .await
        .is_err());

    let response = fixture
        .patch(json!({ "instance_token": "repaired-token" }))
        .await;

    assert_eq!(response.status_code(), 204);
    assert_eq!(
        fixture
            .db
            .agent_repository()
            .get_instance(fixture.instance_id)
            .await
            .unwrap()
            .unwrap()
            .instance_token
            .as_deref(),
        Some("repaired-token")
    );

    let before = fixture.stored().await;
    let mut config = fixture.db.pool().field_encryption().unwrap();
    config.write_enabled = false;
    fixture.db.pool().set_field_encryption(config);

    let response = fixture
        .patch(json!({ "instance_token": "must-not-be-stored" }))
        .await;

    assert_eq!(response.status_code(), 500);
    assert!(!response.text().contains("must-not-be-stored"));
    assert_eq!(fixture.stored().await, before);

    fixture.cleanup().await;
}

#[test]
fn openapi_exposes_only_the_secrets_patch_with_a_write_only_token() {
    use utoipa::OpenApi;

    let spec = serde_json::to_value(api::openapi::ApiDoc::openapi()).unwrap();
    let operation = &spec["paths"]["/v1/admin/agents/instances/{id}/secrets"]["patch"];
    let schema = &spec["components"]["schemas"]["UpdateInstanceSecretsRequest"];

    assert!(operation.is_object());
    assert!(operation["responses"]["204"]["content"].is_null());
    assert!(spec["paths"]["/v1/admin/agents/instances/{id}"]["patch"].is_null());
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["instance_token"]));
    assert_eq!(schema["properties"].as_object().unwrap().len(), 1);
    assert_eq!(schema["properties"]["instance_token"]["writeOnly"], true);
}
