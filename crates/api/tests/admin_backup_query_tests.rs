#![cfg(feature = "test")]
mod common;

use axum_test::TestServer;
use common::{create_test_server_with_state, mock_login, TestServerConfig};
use http::{header::AUTHORIZATION, StatusCode};
use serde_json::{json, Value};
use services::{
    agent::ports::{AgentRepository, CreateInstanceParams},
    user::ports::UserRepository,
};
use uuid::Uuid;
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Fixture {
    server: TestServer,
    manager: MockServer,
    admin: String,
    owner: String,
    instance_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let manager = MockServer::start().await;
        let admin_email = format!("backup-admin-{}@admin.org", Uuid::new_v4());
        let (server, db, _) = create_test_server_with_state(TestServerConfig {
            admin_emails: Some(vec![admin_email.clone()]),
            agent_managers: Some(vec![config::AgentManager {
                url: manager.uri(),
                token: "test-manager-token".into(),
            }]),
            ..Default::default()
        })
        .await;
        let owner_email = format!("backup-owner-{}@example.com", Uuid::new_v4());
        let owner = mock_login(&server, &owner_email).await;
        let admin = mock_login(&server, &admin_email).await;
        let user = db
            .user_repository()
            .get_user_by_email(&owner_email)
            .await
            .unwrap()
            .unwrap();
        let instance = db
            .agent_repository()
            .create_instance(CreateInstanceParams {
                user_id: user.id,
                instance_id: Uuid::new_v4().to_string(),
                name: "backup-query-instance".into(),
                public_ssh_key: None,
                instance_url: None,
                instance_token: None,
                dashboard_url: None,
                agent_api_base_url: Some(manager.uri()),
                service_type: None,
            })
            .await
            .unwrap();
        manager.reset().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session_token": "test-owner-session",
            })))
            .mount(&manager)
            .await;

        Self {
            server,
            manager,
            admin: format!("Bearer {admin}"),
            owner: format!("Bearer {owner}"),
            instance_id: instance.id,
        }
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "/v1/admin/agents/instances/{}/backups{suffix}",
            self.instance_id
        )
    }

    async fn metadata(&self, suffix: &str, status: u16, body: Value) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/instances/backup-query-instance/backups{suffix}"
            )))
            .and(bearer_token("test-owner-session"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.manager)
            .await;
    }
}

fn backup() -> Value {
    json!({
        "id": "BACKUP",
        "instance_name": "backup-query-instance",
        "status": "creating",
        "size_bytes": 0,
        "created_at": "2026-12-01T00:00:00Z",
    })
}

#[tokio::test]
async fn admin_queries_return_metadata_without_runtime_credentials_or_export_cutoff() {
    let f = Fixture::new().await;
    f.metadata("", 200, json!([backup()])).await;
    f.metadata("/BACKUP", 200, backup()).await;

    let list = f
        .server
        .get(&f.url(""))
        .add_header(AUTHORIZATION, &f.admin)
        .await;
    let detail = f
        .server
        .get(&f.url("/BACKUP"))
        .add_header(AUTHORIZATION, &f.admin)
        .await;

    list.assert_status_ok();
    detail.assert_status_ok();
    assert_eq!(list.json::<Value>()[0], detail.json::<Value>());
    assert_eq!(detail.json::<Value>()["status"], "creating");
    assert_eq!(f.manager.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn admin_queries_reject_nonadmins_and_invalid_or_missing_instances() {
    let f = Fixture::new().await;

    for suffix in ["", "/BACKUP"] {
        f.server
            .get(&f.url(suffix))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        f.server
            .get(&f.url(suffix))
            .add_header(AUTHORIZATION, &f.owner)
            .await
            .assert_status(StatusCode::FORBIDDEN);

        for (id, status) in [
            ("invalid".into(), StatusCode::BAD_REQUEST),
            (Uuid::new_v4().to_string(), StatusCode::NOT_FOUND),
        ] {
            f.server
                .get(&format!("/v1/admin/agents/instances/{id}/backups{suffix}"))
                .add_header(AUTHORIZATION, &f.admin)
                .await
                .assert_status(status);
        }
    }

    assert!(f.manager.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn admin_queries_distinguish_missing_backups_from_upstream_failure() {
    let f = Fixture::new().await;
    f.metadata("", 503, json!({})).await;
    f.metadata("/MISSING", 404, json!({})).await;

    f.server
        .get(&f.url(""))
        .add_header(AUTHORIZATION, &f.admin)
        .await
        .assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    f.server
        .get(&f.url("/MISSING"))
        .add_header(AUTHORIZATION, &f.admin)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}
