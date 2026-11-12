use super::ports::{AgentBackupError, AgentInstance, AgentRepository, BackupDownload};
use crate::logging::error_type;
use crate::UserId;
use anyhow::anyhow;
use futures::stream::StreamExt;
use reqwest::StatusCode;
use std::time::Duration;
use uuid::Uuid;

/// Upper bound for a whole backup export stream; CrabShack backups take several minutes.
pub const BACKUP_EXPORT_TIMEOUT: Duration = Duration::from_secs(20 * 60);
pub const MAX_EXPORT_SSH_PUBKEY_BYTES: usize = 16 * 1024;
pub const MAX_BACKUP_ID_LEN: usize = 64;
const MAX_MANAGER_ERROR_CHARS: usize = 512;
const DEFAULT_MANAGER_ERROR: &str = "Invalid backup request";

/// Normalizes the optional export key: blank means none. Returns the user-facing error message.
pub fn validate_export_ssh_pubkey(key: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(key) = key.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    if key.contains("PRIVATE KEY") {
        return Err("paste the public key (.pub)");
    }
    if key.len() > MAX_EXPORT_SSH_PUBKEY_BYTES {
        return Err("SSH public key is too long");
    }
    if key.contains(['\n', '\r']) {
        return Err("SSH public key must be a single line");
    }
    Ok(Some(key.to_string()))
}

/// Backup ids are CrabShack ULIDs; anything else never reaches the manager URL.
pub fn is_valid_backup_id(backup_id: &str) -> bool {
    !backup_id.is_empty()
        && backup_id.len() <= MAX_BACKUP_ID_LEN
        && backup_id.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub(super) async fn load_owned_instance(
    repository: &dyn AgentRepository,
    instance_id: Uuid,
    user_id: UserId,
) -> Result<AgentInstance, AgentBackupError> {
    let instance = repository
        .get_instance(instance_id)
        .await?
        .ok_or(AgentBackupError::InstanceNotFound)?;
    if instance.user_id != user_id {
        return Err(AgentBackupError::AccessDenied);
    }
    Ok(instance)
}

/// Target of a manager call for one instance.
pub(super) struct ManagerTarget<'a> {
    pub base_url: &'a str,
    pub bearer_token: &'a str,
    pub instance_name: &'a str,
    pub instance_id: Uuid,
}

impl ManagerTarget<'_> {
    fn instance_url(&self, suffix: &str) -> String {
        let name = urlencoding::encode(self.instance_name);
        format!("{}/instances/{}/{}", self.base_url, name, suffix)
    }
}

/// POSTs the backup request and, once the manager accepts it, forwards the SSE body chunks.
pub(super) async fn start_backup_export(
    http_client: &reqwest::Client,
    target: ManagerTarget<'_>,
    export_ssh_pubkey: Option<String>,
) -> Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>, AgentBackupError> {
    let body = match export_ssh_pubkey {
        Some(key) => serde_json::json!({ "export_ssh_pubkey": key }),
        None => serde_json::json!({}),
    };
    let instance_id = target.instance_id;
    let response = http_client
        .post(target.instance_url("backup"))
        .bearer_auth(target.bearer_token)
        .json(&body)
        .timeout(BACKUP_EXPORT_TIMEOUT)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to call Agent API backup: {}", e.without_url()))?;

    let status = response.status();
    if status == StatusCode::BAD_REQUEST {
        tracing::warn!(%instance_id, "Agent API rejected backup request");
        return Err(AgentBackupError::InvalidRequest(
            manager_error_message(response).await,
        ));
    }
    if !status.is_success() {
        tracing::error!(%instance_id, %status, "Agent API backup failed");
        return Err(anyhow!("Agent API backup failed with status {}", status).into());
    }

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(forward_stream(response, tx, instance_id));
    Ok(rx)
}

async fn forward_stream(
    response: reqwest::Response,
    tx: tokio::sync::mpsc::Sender<anyhow::Result<bytes::Bytes>>,
    instance_id: Uuid,
) {
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if tx.send(Ok(bytes)).await.is_err() {
                    tracing::info!(%instance_id, "Backup export client disconnected");
                    return;
                }
            }
            Err(e) => {
                tracing::error!(%instance_id, error = error_type(&e), "Backup export stream error");
                let _ = tx.send(Err(anyhow!("Backup stream error"))).await;
                return;
            }
        }
    }
    tracing::info!(%instance_id, "Backup export stream ended");
}

async fn manager_error_message(response: reqwest::Response) -> String {
    let body = response.json::<serde_json::Value>().await.ok();
    body.as_ref()
        .and_then(|b| b.get("error"))
        .and_then(|e| e.as_str())
        .filter(|e| !e.is_empty())
        .map(|e| e.chars().take(MAX_MANAGER_ERROR_CHARS).collect())
        .unwrap_or_else(|| DEFAULT_MANAGER_ERROR.to_string())
}

pub(super) async fn fetch_backup_download(
    http_client: &reqwest::Client,
    target: ManagerTarget<'_>,
    backup_id: &str,
) -> Result<BackupDownload, AgentBackupError> {
    let suffix = format!("backups/{}/download", urlencoding::encode(backup_id));
    let instance_id = target.instance_id;
    let response = http_client
        .get(target.instance_url(&suffix))
        .bearer_auth(target.bearer_token)
        .send()
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to call Agent API backup download: {}",
                e.without_url()
            )
        })?;

    match response.status() {
        status if status.is_success() => {}
        StatusCode::NOT_FOUND => return Err(AgentBackupError::BackupNotFound),
        StatusCode::CONFLICT => return Err(AgentBackupError::BackupNotReady),
        status => {
            tracing::error!(%instance_id, %status, "Agent API backup download failed");
            return Err(anyhow!("Agent API backup download failed with status {}", status).into());
        }
    }
    response.json::<BackupDownload>().await.map_err(|e| {
        anyhow!(
            "Invalid Agent API backup download response: {}",
            e.without_url()
        )
        .into()
    })
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
