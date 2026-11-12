#![cfg(feature = "test")]
mod common;

use axum_test::TestServer;
use common::{create_test_server_with_state, mock_login, TestServerConfig};
use http::{header::AUTHORIZATION, StatusCode};
use serde_json::{json, Value};
use services::{
    agent::ports::{AgentInstance, AgentRepository, CreateInstanceParams},
    user::ports::UserRepository,
};
use uuid::Uuid;
use wiremock::matchers::{bearer_token, body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SESSION_TOKEN: &str = "crabshack-user-session";
const PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtestkeytestkeytestkeytestkeytestkey me@host";

struct Fixture {
    server: TestServer,
    manager: MockServer,
    instance: AgentInstance,
    owner_token: String,
    other_token: String,
}

impl Fixture {
    fn export_url(&self) -> String {
        format!("/v1/agents/instances/{}/backups/export", self.instance.id)
    }

    fn download_url(&self, backup_id: &str) -> String {
        format!(
            "/v1/agents/instances/{}/backups/{}/download",
            self.instance.id, backup_id
        )
    }

    fn manager_path(&self, suffix: &str) -> String {
        format!("/instances/{}/{}", self.instance.name, suffix)
    }

    async fn assert_manager_untouched(&self) {
        assert!(self.manager.received_requests().await.unwrap().is_empty());
    }
}

/// Owner with CrabShack passkey credentials and one instance on a mocked manager.
async fn fixture() -> Fixture {
    let manager = MockServer::start().await;
    let (server, db, _) = create_test_server_with_state(TestServerConfig {
        agent_managers: Some(vec![config::AgentManager {
            url: manager.uri(),
            token: "test-manager-token".into(),
        }]),
        ..Default::default()
    })
    .await;
    let email = format!("backup-owner-{}@example.com", Uuid::new_v4());
    let owner_token = mock_login(&server, &email).await;
    let other_email = format!("backup-other-{}@example.com", Uuid::new_v4());
    let other_token = mock_login(&server, &other_email).await;
    let owner = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .unwrap()
        .unwrap();
    let repo = db.agent_repository();
    repo.upsert_user_passkey_credentials(owner.id, "auth-secret", "backup-passphrase")
        .await
        .unwrap();
    let instance = repo
        .create_instance(CreateInstanceParams {
            user_id: owner.id,
            instance_id: Uuid::new_v4().to_string(),
            name: format!("backup-{}", Uuid::new_v4().simple()),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some(manager.uri()),
            service_type: None,
        })
        .await
        .unwrap();
    // Discard manager calls made while constructing the server and logging in.
    manager.reset().await;
    Fixture {
        server,
        manager,
        instance,
        owner_token,
        other_token,
    }
}

async fn mount_login(manager: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/login"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "session_token": SESSION_TOKEN })),
        )
        .mount(manager)
        .await;
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn backup_routes_reject_non_owner_before_manager_call() {
    let f = fixture().await;
    f.server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.other_token))
        .json(&json!({ "export_ssh_pubkey": PUBKEY }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    f.server
        .get(&f.download_url("01JBACKUP"))
        .add_header(AUTHORIZATION, bearer(&f.other_token))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn export_rejects_private_key_text() {
    let f = fixture().await;
    let response = f
        .server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .json(&json!({
            "export_ssh_pubkey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<Value>()["message"],
        "paste the public key (.pub)"
    );
    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn export_streams_manager_events_unchanged() {
    let f = fixture().await;
    mount_login(&f.manager).await;
    let sse = "event: backup_started\ndata: {\"backup_id\":\"01JBACKUP\"}\n\n\
               event: status\ndata: {\"step\":\"encrypting_uploading\"}\n\n\
               event: backup_complete\ndata: {\"backup_id\":\"01JBACKUP\",\"encrypted\":true}\n\n";
    Mock::given(method("POST"))
        .and(path(f.manager_path("backup")))
        .and(bearer_token(SESSION_TOKEN))
        .and(body_json(json!({ "export_ssh_pubkey": PUBKEY })))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
        .expect(1)
        .mount(&f.manager)
        .await;
    let response = f
        .server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .json(&json!({ "export_ssh_pubkey": format!("{PUBKEY}\n") }))
        .await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "text/event-stream");
    assert_eq!(response.text(), sse);
    f.manager.verify().await;
}

#[tokio::test]
async fn export_forwards_manager_400() {
    let f = fixture().await;
    mount_login(&f.manager).await;
    Mock::given(method("POST"))
        .and(path(f.manager_path("backup")))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({ "error": "unsupported key type" })),
        )
        .mount(&f.manager)
        .await;
    let response = f
        .server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .json(&json!({ "export_ssh_pubkey": PUBKEY }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["message"], "unsupported key type");
}

async fn mount_download(f: &Fixture, status: u16) {
    mount_login(&f.manager).await;
    Mock::given(method("GET"))
        .and(path(f.manager_path("backups/01JBACKUP/download")))
        .and(bearer_token(SESSION_TOKEN))
        .respond_with(
            ResponseTemplate::new(status).set_body_json(
                json!({ "url": "https://s3.test/presigned?sig=x", "expires_in": 3600 }),
            ),
        )
        .expect(1)
        .mount(&f.manager)
        .await;
}

#[tokio::test]
async fn download_returns_manager_link() {
    let f = fixture().await;
    mount_download(&f, 200).await;
    let response = f
        .server
        .get(&f.download_url("01JBACKUP"))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await;
    response.assert_status_ok();
    assert_eq!(
        response.json::<Value>(),
        json!({ "url": "https://s3.test/presigned?sig=x", "expires_in": 3600 })
    );
    f.manager.verify().await;
}

#[tokio::test]
async fn download_not_ready_is_409() {
    let f = fixture().await;
    mount_download(&f, 409).await;
    f.server
        .get(&f.download_url("01JBACKUP"))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn download_rejects_invalid_backup_id() {
    let f = fixture().await;
    for backup_id in ["bad-id", "bad.id", &"a".repeat(65)] {
        f.server
            .get(&f.download_url(backup_id))
            .add_header(AUTHORIZATION, bearer(&f.owner_token))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    f.assert_manager_untouched().await;
}
