use super::ports::{
    AgentBackupError, AgentInstance, AgentRepository, BackupDownload, BackupList, BackupSummary,
};
use crate::UserId;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize};
use uuid::Uuid;

pub const MAX_BACKUP_ID_LEN: usize = 64;

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

#[derive(Deserialize)]
struct ManagerBackup {
    id: String,
    instance_name: String,
    created_at: DateTime<Utc>,
    size_bytes: u64,
    status: String,
}

async fn fetch_metadata<T: DeserializeOwned>(
    client: &reqwest::Client,
    target: &ManagerTarget<'_>,
    suffix: &str,
) -> Result<T, AgentBackupError> {
    let response = client
        .get(target.instance_url(suffix))
        .bearer_auth(target.bearer_token)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to fetch backup metadata: {}", e.without_url()))?;

    if response.status() == StatusCode::NOT_FOUND {
        return Err(AgentBackupError::BackupNotFound);
    }
    if !response.status().is_success() {
        return Err(anyhow!(
            "Backup metadata request failed with status {}",
            response.status()
        )
        .into());
    }

    response
        .json()
        .await
        .map_err(|_| anyhow!("Invalid backup metadata response").into())
}

pub(super) async fn fetch_backup_list(
    client: &reqwest::Client,
    target: ManagerTarget<'_>,
    cutoff: DateTime<Utc>,
) -> Result<BackupList, AgentBackupError> {
    let rows: Vec<ManagerBackup> = fetch_metadata(client, &target, "backups").await?;
    let mut backups: Vec<BackupSummary> = rows
        .into_iter()
        .filter(|row| {
            row.instance_name == target.instance_name
                && row.status == "ready"
                && row.created_at < cutoff
                && is_valid_backup_id(&row.id)
        })
        .map(|row| BackupSummary {
            id: row.id,
            created_at: row.created_at,
            size_bytes: row.size_bytes,
            status: row.status,
        })
        .collect();
    backups.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });

    Ok(BackupList {
        export_before: cutoff,
        backups,
    })
}

pub(super) async fn fetch_backup_download(
    http_client: &reqwest::Client,
    target: ManagerTarget<'_>,
    backup_id: &str,
    cutoff: DateTime<Utc>,
) -> Result<BackupDownload, AgentBackupError> {
    // Re-read metadata on every request, including signed-link refreshes.
    let metadata: ManagerBackup = fetch_metadata(
        http_client,
        &target,
        &format!("backups/{}", urlencoding::encode(backup_id)),
    )
    .await?;
    if metadata.id != backup_id || metadata.instance_name != target.instance_name {
        return Err(AgentBackupError::BackupNotFound);
    }
    if metadata.created_at >= cutoff {
        return Err(AgentBackupError::BackupNotFound);
    }
    if metadata.status != "ready" {
        return Err(AgentBackupError::BackupNotReady);
    }

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
