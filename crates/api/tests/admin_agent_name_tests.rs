mod common;

use axum_test::{TestResponse, TestServer};
use common::{
    cleanup_user, cleanup_user_agent_instances, create_test_server_and_db, mock_login,
    TestServerConfig,
};
use database::Database;
use http::{HeaderName, HeaderValue};
use serde_json::{json, Value};
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "agent-name@admin.org";

struct Fixture {
    server: TestServer,
    db: Database,
    admin_auth: HeaderValue,
    owner_auth: HeaderValue,
    owner_email: String,
    instance_id: Uuid,
}

#[tokio::test]
#[serial]
async fn admin_corrects_only_the_stored_name_in_both_encryption_modes() {
    for field_encryption in [false, true] {
        let fixture = Fixture::new(field_encryption).await;
        let other = Fixture::new(field_encryption).await;
        let other_before = other.stored().await;
        let mut before = fixture.stored().await;

        let response = fixture.patch(json!({ "name": "corrected-agent" })).await;

        assert_eq!(response.status_code(), 204);
        assert!(response.text().is_empty());

        let mut after = fixture.stored().await;

        assert_eq!(after["name"], "corrected-agent");
        assert_ne!(before["updated_at"], after["updated_at"]);

        for row in [&mut before, &mut after] {
            row.as_object_mut().unwrap().remove("name");
            row.as_object_mut().unwrap().remove("updated_at");
        }

        assert_eq!(before, after);
        assert_eq!(other.stored().await, other_before);

        let listing = fixture
            .server
            .get("/v1/agents/instances")
            .add_header(
                HeaderName::from_static("authorization"),
                fixture.owner_auth.clone(),
            )
            .await;

        assert_eq!(listing.status_code(), 200);
        assert_eq!(
            listing.json::<Value>()["items"][0]["name"],
            "corrected-agent"
        );

        fixture.cleanup().await;
        other.cleanup().await;
    }
}

#[tokio::test]
#[serial]
async fn instance_name_requires_admin_authentication() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;
    let payload = json!({ "name": "corrected-agent" });

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
async fn instance_name_rejects_invalid_payloads_without_changing_the_row() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;
    let mut payloads = vec![
        json!({}),
        json!({ "name": null }),
        json!({ "name": 42 }),
        json!(["corrected-agent"]),
        json!({ "name": "corrected-agent", "status": "active" }),
        json!({ "name": "corrected-agent", "instance_id": "different-id" }),
    ];

    for name in [
        "",
        " ",
        " leading",
        "trailing ",
        "a/b",
        "a\\b",
        ".",
        "..",
        "a..b",
        "a\nname",
        "a\0name",
    ] {
        payloads.push(json!({ "name": name }));
    }
    payloads.push(json!({ "name": "a".repeat(256) }));

    for payload in payloads {
        let response = fixture.patch(payload).await;

        assert_eq!(response.status_code(), 400);
        assert!(!response.text().contains("corrected-agent"));
        assert_eq!(fixture.stored().await, before);
    }

    let malformed = fixture
        .server
        .patch(&fixture.path())
        .add_header(
            HeaderName::from_static("authorization"),
            fixture.admin_auth.clone(),
        )
        .content_type("application/json")
        .text("{\"name\":\"corrected-agent\"")
        .await;

    assert_eq!(malformed.status_code(), 400);
    assert!(!malformed.text().contains("corrected-agent"));
    assert_eq!(fixture.stored().await, before);

    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn instance_name_validates_ids_and_rejects_deleted_instances() {
    let fixture = Fixture::new(false).await;
    let before = fixture.stored().await;

    for (id, expected_status) in [
        ("invalid-id".to_owned(), 400),
        (Uuid::new_v4().to_string(), 404),
    ] {
        let response = fixture
            .server
            .patch(&format!("/v1/admin/agents/instances/{id}/name"))
            .add_header(
                HeaderName::from_static("authorization"),
                fixture.admin_auth.clone(),
            )
            .json(&json!({ "name": "corrected-agent" }))
            .await;

        assert_eq!(response.status_code(), expected_status);
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

    let response = fixture.patch(json!({ "name": "corrected-agent" })).await;

    assert_eq!(response.status_code(), 404);
    assert_eq!(fixture.stored().await, deleted);

    fixture.cleanup().await;
}

#[tokio::test]
#[serial]
async fn instance_name_accepts_the_character_limit_and_repeated_corrections() {
    let fixture = Fixture::new(false).await;
    let name = "名".repeat(255);

    for _ in 0..2 {
        let response = fixture.patch(json!({ "name": name })).await;

        assert_eq!(response.status_code(), 204);
        assert_eq!(fixture.stored().await["name"], name);
    }

    fixture.cleanup().await;
}

#[test]
fn openapi_documents_the_focused_name_update() {
    use utoipa::OpenApi;

    let spec = serde_json::to_value(api::openapi::ApiDoc::openapi()).unwrap();
    let operation = &spec["paths"]["/v1/admin/agents/instances/{id}/name"]["patch"];
    let schema = &spec["components"]["schemas"]["UpdateInstanceNameRequest"];

    assert!(operation.is_object());
    assert!(operation["responses"]["204"]["content"].is_null());
    assert!(spec["paths"]["/v1/admin/agents/instances/{id}"]["patch"].is_null());
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["name"]));
    assert_eq!(schema["properties"].as_object().unwrap().len(), 1);
    assert_eq!(schema["properties"]["name"]["maxLength"], 255);
}

impl Fixture {
    async fn new(field_encryption: bool) -> Self {
        Self::with_urls(
            field_encryption,
            Some("https://agent.example.com"),
            Some("https://agent.example.com/dashboard"),
        )
        .await
    }

    async fn with_urls(
        field_encryption: bool,
        instance_url: Option<&str>,
        dashboard_url: Option<&str>,
    ) -> Self {
        let (server, db) = create_test_server_and_db(TestServerConfig {
            admin_emails: Some(vec![ADMIN_EMAIL.into()]),
            database_encryption_write_enabled: Some(field_encryption),
            database_encryption_agent_secrets_write_enabled: Some(field_encryption),
            ..Default::default()
        })
        .await;
        let owner_email = format!("agent-name-{}@example.com", Uuid::new_v4());
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
                name: "original-name".into(),
                public_ssh_key: Some("ssh-ed25519 test-public-key".into()),
                instance_url: instance_url.map(str::to_owned),
                instance_token: Some("old-instance-token".into()),
                dashboard_url: dashboard_url.map(str::to_owned),
                agent_api_base_url: Some("https://manager.example.com".into()),
                service_type: Some("ironclaw".into()),
            })
            .await
            .unwrap();

        Self {
            server,
            db,
            admin_auth: HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
            owner_auth: HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
            owner_email,
            instance_id: instance.id,
        }
    }

    fn path(&self) -> String {
        format!("/v1/admin/agents/instances/{}/name", self.instance_id)
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
