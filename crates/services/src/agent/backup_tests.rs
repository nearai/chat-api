use super::*;
use crate::agent::ports::{AgentService, BackupListOptions, MockAgentRepository};
use crate::agent::service::AgentServiceImpl;
use crate::system_configs::ports::{PartialSystemConfigs, SystemConfigs, SystemConfigsService};
use async_trait::async_trait;
use config::AgentManager;
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const INSTANCE_NAME: &str = "backup-inst";
const MANAGER_TOKEN: &str = "manager-token";
const SESSION_TOKEN: &str = "user-session-token";

struct NoSystemConfigs;

#[async_trait]
impl SystemConfigsService for NoSystemConfigs {
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>> {
        Ok(None)
    }
    async fn upsert_configs(&self, configs: SystemConfigs) -> anyhow::Result<SystemConfigs> {
        Ok(configs)
    }
    async fn update_configs(&self, _: PartialSystemConfigs) -> anyhow::Result<SystemConfigs> {
        Ok(SystemConfigs::default())
    }
}

fn instance(owner: UserId, manager_url: &str) -> AgentInstance {
    AgentInstance {
        id: Uuid::new_v4(),
        user_id: owner,
        instance_id: format!("agent-{INSTANCE_NAME}"),
        name: INSTANCE_NAME.to_string(),
        public_ssh_key: None,
        instance_url: None,
        instance_token: None,
        dashboard_url: None,
        agent_api_base_url: Some(manager_url.to_string()),
        service_type: None,
        status: "active".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Service whose repository returns `inst` and passkey credentials for its owner.
fn service(server: &MockServer, inst: AgentInstance) -> AgentServiceImpl {
    let mut repo = MockAgentRepository::new();
    repo.expect_get_instance()
        .returning(move |_| Ok(Some(inst.clone())));
    repo.expect_get_user_passkey_credentials()
        .returning(|_| Ok(Some(("secret".to_string(), "passphrase".to_string()))));
    AgentServiceImpl::new(
        Arc::new(repo),
        vec![AgentManager {
            url: server.uri(),
            token: MANAGER_TOKEN.to_string(),
        }],
        "http://chat-api.test".to_string(),
        Arc::new(NoSystemConfigs),
        None,
    )
    .with_backup_export_before(Some("2026-11-01T00:00:00Z"))
    .unwrap()
}

async fn mount_login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "session_token": SESSION_TOKEN })),
        )
        .mount(server)
        .await;
}

fn row(id: &str, timestamp: &str, status: &str) -> Value {
    json!({
        "id": id,
        "instance_name": INSTANCE_NAME,
        "created_at": timestamp,
        "size_bytes": 123,
        "status": status,
        "s3_key": "not-public-metadata",
        "created_by": "not-public-metadata",
    })
}

async fn mount_metadata(server: &MockServer, suffix: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/instances/{INSTANCE_NAME}/{suffix}")))
        .and(bearer_token(SESSION_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_filters_by_instant_status_and_instance_and_sorts_newest_first() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    let mut foreign = row("FOREIGN", "2026-10-01T00:00:00Z", "ready");
    foreign["instance_name"] = json!("another-instance");
    mount_metadata(
        &server,
        "backups",
        json!([
            row("OLD", "2026-10-01T00:00:00Z", "ready"),
            row("EXACT", "2026-11-01T00:00:00Z", "ready"),
            row("OFFSET", "2026-11-01T08:00:00+08:00", "ready"),
            row("NEW", "2026-12-01T00:00:00Z", "ready"),
            row("FAILED", "2026-10-01T00:00:00Z", "failed"),
            row("CREATING", "2026-10-01T00:00:00Z", "creating"),
            row("LATEST", "2026-11-01T07:59:59.999+08:00", "ready"),
            row("bad/id", "2026-10-01T00:00:00Z", "ready"),
            foreign,
        ]),
    )
    .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());

    let result = service(&server, inst.clone())
        .list_backups(inst.id, owner, BackupListOptions::default())
        .await
        .unwrap();

    assert_eq!(
        result
            .backups
            .iter()
            .map(|b| b.id.as_str())
            .collect::<Vec<_>>(),
        ["LATEST", "OLD"]
    );
    let json = serde_json::to_value(result).unwrap();
    assert_eq!(json["export_before"], "2026-11-01T00:00:00Z");
    assert!(json["backups"][0].get("s3_key").is_none());
    assert!(json["backups"][0].get("created_by").is_none());
}

#[tokio::test]
async fn download_rechecks_cutoff_and_instance_before_requesting_link() {
    for (timestamp, status, instance_name, id, expected) in [
        (
            "2026-11-01T00:00:00Z",
            "ready",
            INSTANCE_NAME,
            "BACKUP",
            "not_found",
        ),
        (
            "2026-11-02T00:00:00Z",
            "ready",
            INSTANCE_NAME,
            "BACKUP",
            "not_found",
        ),
        (
            "2026-10-31T23:59:59Z",
            "creating",
            INSTANCE_NAME,
            "BACKUP",
            "not_ready",
        ),
        (
            "2026-10-31T23:59:59Z",
            "failed",
            INSTANCE_NAME,
            "BACKUP",
            "not_ready",
        ),
        (
            "2026-10-31T23:59:59Z",
            "ready",
            "other",
            "BACKUP",
            "not_found",
        ),
        (
            "2026-10-31T23:59:59Z",
            "ready",
            INSTANCE_NAME,
            "OTHER",
            "not_found",
        ),
    ] {
        let server = MockServer::start().await;
        mount_login(&server).await;
        let mut metadata = row(id, timestamp, status);
        metadata["instance_name"] = json!(instance_name);
        mount_metadata(&server, "backups/BACKUP", metadata).await;
        let owner = UserId(Uuid::new_v4());
        let inst = instance(owner, &server.uri());

        let result = service(&server, inst.clone())
            .get_backup_download(inst.id, owner, "BACKUP")
            .await;

        match expected {
            "not_ready" => assert!(matches!(result, Err(AgentBackupError::BackupNotReady))),
            _ => assert!(matches!(result, Err(AgentBackupError::BackupNotFound))),
        }
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !r.url.path().ends_with("/download")));
    }
}

#[tokio::test]
async fn download_refresh_reads_metadata_each_time() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    mount_metadata(
        &server,
        "backups/BACKUP",
        row("BACKUP", "2026-10-31T23:59:59Z", "ready"),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/instances/{INSTANCE_NAME}/backups/BACKUP/download"
        )))
        .and(bearer_token(SESSION_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://storage.example/download", "expires_in": 3600
        })))
        .expect(2)
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let service = service(&server, inst.clone());

    for _ in 0..2 {
        let link = service
            .get_backup_download(inst.id, owner, "BACKUP")
            .await
            .unwrap();
        assert_eq!(link.expires_in, 3600);
        assert!(!format!("{link:?}").contains("storage.example"));
    }

    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with("/backups/BACKUP"))
            .count(),
        2
    );
}

#[tokio::test]
async fn missing_cutoff_and_non_owner_make_no_manager_calls() {
    let server = MockServer::start().await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let service = service(&server, inst.clone())
        .with_backup_export_before(None)
        .unwrap();

    assert!(matches!(
        service
            .list_backups(inst.id, owner, BackupListOptions::default())
            .await,
        Err(AgentBackupError::ExportUnavailable)
    ));
    assert!(matches!(
        service.get_backup_download(inst.id, owner, "BACKUP").await,
        Err(AgentBackupError::ExportUnavailable)
    ));
    let other = UserId(Uuid::new_v4());
    assert!(matches!(
        service
            .list_backups(inst.id, other, BackupListOptions::default())
            .await,
        Err(AgentBackupError::AccessDenied)
    ));
    assert!(matches!(
        service.get_backup_download(inst.id, other, "BACKUP").await,
        Err(AgentBackupError::AccessDenied)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_cutoffs_fail_initialization() {
    let server = MockServer::start().await;
    let inst = instance(UserId(Uuid::new_v4()), &server.uri());

    for cutoff in ["", "not-a-date", "2026-11-01T00:00:00"] {
        assert!(service(&server, inst.clone())
            .with_backup_export_before(Some(cutoff))
            .is_err());
    }
    assert!(service(&server, inst)
        .with_backup_export_before(Some("2026-11-01T08:00:00+08:00"))
        .is_ok());
}

#[tokio::test]
async fn invalid_metadata_fails_closed() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    mount_metadata(
        &server,
        "backups",
        json!([row("BACKUP", "not-a-date", "ready")]),
    )
    .await;
    mount_metadata(
        &server,
        "backups/BACKUP",
        row("BACKUP", "not-a-date", "ready"),
    )
    .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let service = service(&server, inst.clone());

    assert!(service
        .list_backups(inst.id, owner, BackupListOptions::default())
        .await
        .is_err());
    assert!(service
        .get_backup_download(inst.id, owner, "BACKUP")
        .await
        .is_err());
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| !r.url.path().ends_with("/download")));
}

#[test]
fn backup_id_must_be_short_alphanumeric() {
    assert!(is_valid_backup_id("BACKUP123"));
    for bad in [
        "",
        "../x",
        "a-b",
        "a b",
        "a%2F",
        &"a".repeat(MAX_BACKUP_ID_LEN + 1),
    ] {
        assert!(!is_valid_backup_id(bad));
    }
}

#[tokio::test]
async fn empty_history_is_a_successful_empty_list() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    mount_metadata(&server, "backups", json!([])).await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());

    let result = service(&server, inst.clone())
        .list_backups(inst.id, owner, BackupListOptions::default())
        .await
        .unwrap();

    assert!(result.backups.is_empty());
}

#[tokio::test]
async fn list_forwards_eligibility_filters_and_pagination_to_manager() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    Mock::given(method("GET"))
        .and(path(format!("/instances/{INSTANCE_NAME}/backups")))
        .and(wiremock::matchers::query_param(
            "created_at_lt",
            "2026-11-01T00:00:00.000Z",
        ))
        .and(wiremock::matchers::query_param("status", "ready"))
        .and(wiremock::matchers::query_param("limit", "1"))
        .and(wiremock::matchers::query_param("offset", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([row(
            "SIXTH",
            "2026-10-20T00:00:00Z",
            "ready"
        )])))
        .expect(1)
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());

    let page = service(&server, inst.clone())
        .list_backups(
            inst.id,
            owner,
            BackupListOptions {
                limit: 1,
                offset: 5,
            },
        )
        .await
        .unwrap();

    assert_eq!(page.backups.len(), 1);
    assert_eq!(page.backups[0].id, "SIXTH");
}

#[tokio::test]
async fn invalid_pagination_never_calls_manager() {
    for options in [
        BackupListOptions {
            limit: 0,
            offset: 0,
        },
        BackupListOptions {
            limit: 1001,
            offset: 0,
        },
        BackupListOptions {
            limit: 1,
            offset: 9_007_199_254_740_992,
        },
    ] {
        let server = MockServer::start().await;
        let owner = UserId(Uuid::new_v4());
        let inst = instance(owner, &server.uri());

        let result = service(&server, inst.clone())
            .list_backups(inst.id, owner, options)
            .await;

        assert!(matches!(result, Err(AgentBackupError::InvalidRequest(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn enabled_fresh_exports_allow_new_downloads_without_a_cutoff() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    mount_metadata(
        &server,
        "backups/NEW",
        row("NEW", "2026-11-02T00:00:00Z", "ready"),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/instances/{INSTANCE_NAME}/backups/NEW/download"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://storage.example/new", "expires_in": 3600
        })))
        .expect(2)
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());

    for cutoff in [None, Some("2026-11-01T00:00:00Z")] {
        let service = service(&server, inst.clone())
            .with_backup_export_create_enabled(true)
            .with_backup_export_before(cutoff)
            .unwrap();

        let link = service
            .get_backup_download(inst.id, owner, "NEW")
            .await
            .unwrap();

        assert_eq!(link.url, "https://storage.example/new");
    }
}

#[tokio::test]
async fn fresh_export_downloads_still_check_status_instance_and_owner() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let service = service(&server, inst.clone()).with_backup_export_create_enabled(true);
    let result = service
        .get_backup_download(inst.id, UserId(Uuid::new_v4()), "NEW")
        .await;
    assert!(matches!(result, Err(AgentBackupError::AccessDenied)));
    assert!(server.received_requests().await.unwrap().is_empty());

    for (name, status) in [(INSTANCE_NAME, "creating"), ("other-instance", "ready")] {
        let mut metadata = row("NEW", "2026-11-02T00:00:00Z", status);
        metadata["instance_name"] = json!(name);
        let guard = Mock::given(method("GET"))
            .and(path(format!("/instances/{INSTANCE_NAME}/backups/NEW")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount_as_scoped(&server)
            .await;

        assert!(service
            .get_backup_download(inst.id, owner, "NEW")
            .await
            .is_err());
        drop(guard);
    }

    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| !request.url.path().ends_with("/download")));
}
