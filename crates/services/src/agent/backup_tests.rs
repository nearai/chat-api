use super::*;
use crate::agent::ports::{AgentService, MockAgentRepository};
use crate::agent::service::AgentServiceImpl;
use crate::system_configs::ports::{PartialSystemConfigs, SystemConfigs, SystemConfigsService};
use async_trait::async_trait;
use chrono::Utc;
use config::AgentManager;
use std::sync::Arc;
use wiremock::matchers::{bearer_token, body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const INSTANCE_NAME: &str = "backup-inst";
const MANAGER_TOKEN: &str = "manager-token";
const SESSION_TOKEN: &str = "user-session-token";
const PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtestkeytestkeytestkeytestkeytestkeytest me@host";

#[tokio::test]
async fn client_disconnect_closes_idle_upstream_body() {
    let (upstream_tx, upstream_rx) = tokio::sync::mpsc::channel::<anyhow::Result<bytes::Bytes>>(1);
    let body = reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(upstream_rx));
    let response = reqwest::Response::from(http::Response::new(body));
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(forward_stream(response, tx, Uuid::new_v4()));
    // The upstream stays open without producing even a keepalive.
    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), upstream_tx.closed())
        .await
        .expect("disconnect must drop the idle upstream body");
    task.await.unwrap();
}

#[tokio::test]
async fn upstream_body_failure_is_forwarded_after_partial_frame() {
    let partial = bytes::Bytes::from_static(b"event: status\ndata: {\"step\":\"arch");
    let body = reqwest::Body::wrap_stream(futures::stream::iter(vec![
        Ok(partial.clone()),
        Err(std::io::Error::other("upstream disconnected")),
    ]));
    let response = reqwest::Response::from(http::Response::new(body));
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    forward_stream(response, tx, Uuid::new_v4()).await;
    assert_eq!(rx.recv().await.unwrap().unwrap(), partial);
    assert!(rx.recv().await.unwrap().is_err());
    assert!(rx.recv().await.is_none());
}

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

async fn collect(mut rx: tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>) -> String {
    let mut out = Vec::new();
    while let Some(chunk) = rx.recv().await {
        out.extend_from_slice(&chunk.expect("stream chunk"));
    }
    String::from_utf8(out).expect("utf8 stream")
}

#[test]
fn export_key_blank_or_missing_is_omitted() {
    assert_eq!(validate_export_ssh_pubkey(None), Ok(None));
    assert_eq!(validate_export_ssh_pubkey(Some("  \n ")), Ok(None));
}

#[test]
fn export_key_is_trimmed() {
    let padded = format!("  {PUBKEY}\n");
    assert_eq!(
        validate_export_ssh_pubkey(Some(&padded)),
        Ok(Some(PUBKEY.to_string()))
    );
}

#[test]
fn export_key_rejects_private_key_text() {
    let private =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----";
    assert_eq!(
        validate_export_ssh_pubkey(Some(private)),
        Err("paste the public key (.pub)")
    );
}

#[test]
fn export_key_rejects_oversized_and_multi_line_input() {
    let long = format!("ssh-rsa {}", "A".repeat(MAX_EXPORT_SSH_PUBKEY_BYTES));
    assert_eq!(
        validate_export_ssh_pubkey(Some(&long)),
        Err("SSH public key is too long")
    );
    let two_keys = format!("{PUBKEY}\n{PUBKEY}");
    assert_eq!(
        validate_export_ssh_pubkey(Some(&two_keys)),
        Err("SSH public key must be a single line")
    );
}

#[test]
fn backup_id_must_be_short_alphanumeric() {
    assert!(is_valid_backup_id("01JCX5Z8M3Q9V7K2N4P6R8T0WY"));
    assert!(is_valid_backup_id(&"a".repeat(MAX_BACKUP_ID_LEN)));
    for bad in [
        "",
        "../x",
        "a-b",
        "a b",
        "a%2F",
        &"a".repeat(MAX_BACKUP_ID_LEN + 1),
    ] {
        assert!(!is_valid_backup_id(bad), "accepted {bad:?}");
    }
}

#[tokio::test]
async fn export_streams_manager_events_unchanged_with_user_session() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    let sse = "event: backup_started\ndata: {\"backup_id\":\"01J\"}\n\n\
               event: backup_complete\ndata: {\"backup_id\":\"01J\",\"size_bytes\":7}\n\n";
    Mock::given(method("POST"))
        .and(path(format!("/instances/{INSTANCE_NAME}/backup")))
        .and(bearer_token(SESSION_TOKEN))
        .and(body_json(
            serde_json::json!({ "export_ssh_pubkey": PUBKEY }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
        .expect(1)
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let rx = service(&server, inst.clone())
        .export_backup_stream(inst.id, owner, Some(PUBKEY.to_string()))
        .await
        .expect("stream starts");
    assert_eq!(collect(rx).await, sse);
}

#[tokio::test]
async fn export_without_key_sends_empty_body() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/instances/{INSTANCE_NAME}/backup")))
        .and(body_json(serde_json::json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_raw("data: {}\n\n", "text/event-stream"))
        .expect(1)
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let rx = service(&server, inst.clone())
        .export_backup_stream(inst.id, owner, None)
        .await
        .expect("stream starts");
    assert_eq!(collect(rx).await, "data: {}\n\n");
}

#[tokio::test]
async fn export_forwards_manager_rejection_message() {
    let server = MockServer::start().await;
    mount_login(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/instances/{INSTANCE_NAME}/backup")))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "unsupported key type" })),
        )
        .mount(&server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    let err = service(&server, inst.clone())
        .export_backup_stream(inst.id, owner, Some(PUBKEY.to_string()))
        .await
        .expect_err("manager rejects");
    assert!(matches!(err, AgentBackupError::InvalidRequest(m) if m == "unsupported key type"));
}

#[tokio::test]
async fn export_by_non_owner_never_reaches_manager() {
    let server = MockServer::start().await;
    let inst = instance(UserId(Uuid::new_v4()), &server.uri());
    let err = service(&server, inst.clone())
        .export_backup_stream(inst.id, UserId(Uuid::new_v4()), None)
        .await
        .expect_err("not the owner");
    assert!(matches!(err, AgentBackupError::AccessDenied));
    assert!(server.received_requests().await.unwrap().is_empty());
}

async fn download(server: &MockServer, status: u16) -> Result<BackupDownload, AgentBackupError> {
    mount_login(server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/instances/{INSTANCE_NAME}/backups/01JBACKUP/download"
        )))
        .and(bearer_token(SESSION_TOKEN))
        .respond_with(ResponseTemplate::new(status).set_body_json(
            serde_json::json!({ "url": "https://s3.test/presigned", "expires_in": 3600 }),
        ))
        .expect(1)
        .mount(server)
        .await;
    let owner = UserId(Uuid::new_v4());
    let inst = instance(owner, &server.uri());
    service(server, inst.clone())
        .get_backup_download(inst.id, owner, "01JBACKUP")
        .await
}

#[tokio::test]
async fn download_returns_presigned_link() {
    let server = MockServer::start().await;
    let link = download(&server, 200).await.expect("download link");
    assert_eq!(link.url, "https://s3.test/presigned");
    assert_eq!(link.expires_in, 3600);
    assert!(!format!("{link:?}").contains("s3.test"));
}

#[tokio::test]
async fn download_maps_not_ready_and_unknown() {
    let server = MockServer::start().await;
    assert!(matches!(
        download(&server, 409).await,
        Err(AgentBackupError::BackupNotReady)
    ));
    let server = MockServer::start().await;
    assert!(matches!(
        download(&server, 404).await,
        Err(AgentBackupError::BackupNotFound)
    ));
}
