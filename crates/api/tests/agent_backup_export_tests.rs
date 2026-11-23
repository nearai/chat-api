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
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SESSION_TOKEN: &str = "crabshack-user-session";

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
    fixture_with_cutoff(Some("2026-11-01T00:00:00Z")).await
}

async fn fixture_with_cutoff(cutoff: Option<&str>) -> Fixture {
    fixture_with_options(cutoff, false).await
}

async fn fixture_with_options(cutoff: Option<&str>, create_enabled: bool) -> Fixture {
    let manager = MockServer::start().await;
    let (server, db, _state) = create_test_server_with_state(TestServerConfig {
        backup_export_before: cutoff.map(str::to_owned),
        backup_export_create_enabled: create_enabled,
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

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn owner_export_creation_is_disabled_without_calling_manager() {
    let f = fixture().await;

    f.server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .json(&json!({}))
        .await
        .assert_status(StatusCode::GONE);

    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn all_backup_routes_require_owner() {
    let f = fixture().await;

    f.server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.other_token))
        .json(&json!({}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    for url in [
        format!("/v1/agents/instances/{}/backups", f.instance.id),
        f.download_url("BACKUP"),
    ] {
        f.server
            .get(&url)
            .add_header(AUTHORIZATION, bearer(&f.other_token))
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn list_and_download_apply_cutoff_and_hide_storage_metadata() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/auth/login"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "session_token": SESSION_TOKEN })),
        )
        .mount(&f.manager)
        .await;
    let old = json!({ "id": "OLD", "instance_name": f.instance.name,
        "created_at": "2026-10-31T23:59:59Z", "status": "ready", "size_bytes": 123,
        "s3_key": "private-metadata" });
    let exact = json!({ "id": "EXACT", "instance_name": f.instance.name,
        "created_at": "2026-11-01T00:00:00Z", "status": "ready", "size_bytes": 123 });
    for (suffix, data) in [
        ("backups", json!([old, exact])),
        ("backups/OLD", old),
        ("backups/EXACT", exact),
    ] {
        Mock::given(method("GET"))
            .and(path(f.manager_path(suffix)))
            .and(bearer_token(SESSION_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(data))
            .mount(&f.manager)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(f.manager_path("backups/OLD/download")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://storage.example/download", "expires_in": 3600
        })))
        .expect(1)
        .mount(&f.manager)
        .await;

    let list = f
        .server
        .get(&format!(
            "/v1/agents/instances/{}/backups?limit=1&offset=0",
            f.instance.id
        ))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await;
    list.assert_status_ok();
    let body = list.json::<Value>();
    assert_eq!(body["backups"].as_array().unwrap().len(), 1);
    assert_eq!(body["backups"][0]["id"], "OLD");
    assert!(body["backups"][0].get("s3_key").is_none());
    let requests = f.manager.received_requests().await.unwrap();
    let list_request = requests
        .iter()
        .find(|request| request.url.path().ends_with("/backups"))
        .unwrap();
    let params: std::collections::HashMap<_, _> = list_request.url.query_pairs().collect();
    assert_eq!(params.get("limit").map(|value| value.as_ref()), Some("1"));
    assert_eq!(params.get("offset").map(|value| value.as_ref()), Some("0"));
    assert_eq!(
        params.get("status").map(|value| value.as_ref()),
        Some("ready")
    );

    f.server
        .get(&f.download_url("OLD"))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await
        .assert_status_ok();
    f.server
        .get(&f.download_url("EXACT"))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    assert!(f
        .manager
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| !r.url.path().ends_with("/EXACT/download")));
}

#[tokio::test]
async fn download_rejects_invalid_backup_id_without_manager_call() {
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

#[tokio::test]
async fn unset_cutoff_disables_listing_and_downloads() {
    let f = fixture_with_cutoff(None).await;

    for url in [
        format!("/v1/agents/instances/{}/backups", f.instance.id),
        f.download_url("OLD"),
    ] {
        f.server
            .get(&url)
            .add_header(AUTHORIZATION, bearer(&f.owner_token))
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn backup_routes_require_authentication() {
    let f = fixture().await;

    f.server
        .get(&format!("/v1/agents/instances/{}/backups", f.instance.id))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    f.server
        .get(&f.download_url("OLD"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    f.server
        .post(&f.export_url())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    f.assert_manager_untouched().await;
}

#[tokio::test]
async fn enabled_fresh_export_streams_and_downloads_without_historical_cutoff() {
    let f = fixture_with_options(None, true).await;
    Mock::given(method("POST"))
        .and(path("/auth/login"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "session_token": SESSION_TOKEN })),
        )
        .mount(&f.manager)
        .await;
    let events = "event: backup_complete\ndata: {\"backup_id\":\"NEW\"}\n\n";
    Mock::given(method("POST"))
        .and(path(f.manager_path("backup")))
        .and(bearer_token(SESSION_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(events),
        )
        .expect(1)
        .mount(&f.manager)
        .await;
    Mock::given(method("GET"))
        .and(path(f.manager_path("backups/NEW")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "NEW", "instance_name": f.instance.name, "created_at": "2026-11-02T00:00:00Z",
            "size_bytes": 123, "status": "ready"
        })))
        .mount(&f.manager)
        .await;
    Mock::given(method("GET"))
        .and(path(f.manager_path("backups/NEW/download")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://storage.example/new", "expires_in": 3600
        })))
        .expect(1)
        .mount(&f.manager)
        .await;

    let response = f
        .server
        .post(&f.export_url())
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .json(&json!({}))
        .await;

    response.assert_status_ok();
    assert_eq!(response.text(), events);
    f.server
        .get(&f.download_url("NEW"))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await
        .assert_status_ok();
    f.server
        .get(&format!("/v1/agents/instances/{}/backups", f.instance.id))
        .add_header(AUTHORIZATION, bearer(&f.owner_token))
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn list_rejects_invalid_pagination_without_manager_calls() {
    let f = fixture().await;
    for query in [
        "limit=0",
        "limit=1001",
        "limit=-1",
        "offset=-1",
        "offset=9007199254740992",
    ] {
        f.server
            .get(&format!(
                "/v1/agents/instances/{}/backups?{query}",
                f.instance.id
            ))
            .add_header(AUTHORIZATION, bearer(&f.owner_token))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    f.assert_manager_untouched().await;
}
