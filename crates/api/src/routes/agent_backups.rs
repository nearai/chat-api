use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::{Extension, Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use services::agent::backup::is_valid_backup_id;
use services::agent::ports::{AgentBackupError, BackupList};
use services::logging::error_type;
use services::UserId;
use uuid::Uuid;

/// Presigned download link for a finished backup.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct BackupDownloadResponse {
    pub url: String,
    /// Seconds until `url` expires
    pub expires_in: u64,
}

async fn ensure_instance_owner(
    app_state: &AppState,
    instance_id: &str,
    user_id: UserId,
) -> Result<Uuid, ApiError> {
    let instance_uuid = Uuid::parse_str(instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;
    let instance = app_state
        .agent_repository
        .get_instance(instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!(instance_id = %instance_uuid, error = error_type(&e), "Failed to fetch instance");
            ApiError::internal_server_error("Failed to fetch instance")
        })?
        .ok_or_else(|| ApiError::not_found("Instance not found"))?;
    if instance.user_id != user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }
    Ok(instance_uuid)
}

fn backup_api_error(err: AgentBackupError, instance_id: Uuid, failure: &str) -> ApiError {
    match err {
        AgentBackupError::InstanceNotFound => ApiError::not_found("Instance not found"),
        AgentBackupError::AccessDenied => {
            ApiError::forbidden("This instance does not belong to you")
        }
        AgentBackupError::ExportUnavailable => {
            ApiError::service_unavailable("Historical backup downloads are not configured")
        }
        AgentBackupError::BackupNotFound => ApiError::not_found("Backup not found"),
        AgentBackupError::BackupNotReady => ApiError::conflict("Backup is not ready yet"),
        AgentBackupError::Internal(e) => {
            tracing::error!(%instance_id, error = error_type(&e), "{}", failure);
            ApiError::internal_server_error(failure)
        }
    }
}

/// New backup creation is retired; owners can download eligible historical backups.
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/backups/export",
    tag = "Agents",
    params(("id" = String, Path, description = "Instance ID")),
    responses((status = 410, description = "New backup exports are no longer available")),
    security(("session_token" = []))
)]
pub async fn export_backup(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<(), ApiError> {
    ensure_instance_owner(&app_state, &instance_id, user.user_id).await?;
    Err(ApiError::new(
        axum::http::StatusCode::GONE,
        "backup_creation_retired",
        "New backup exports are no longer available. Choose an existing backup.",
    ))
}

/// List ready historical backups created strictly before the configured cutoff.
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/backups",
    tag = "Agents",
    params(("id" = String, Path, description = "Instance ID")),
    responses(
        (status = 200, description = "Eligible historical backups, newest first", body = BackupList),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not your instance"),
        (status = 404, description = "Instance not found"),
        (status = 503, description = "Historical downloads are not configured")
    ),
    security(("session_token" = []))
)]
pub async fn list_backups(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Json<BackupList>, ApiError> {
    let instance_uuid = ensure_instance_owner(&app_state, &instance_id, user.user_id).await?;
    app_state
        .agent_service
        .list_backups(instance_uuid, user.user_id)
        .await
        .map(Json)
        .map_err(|e| backup_api_error(e, instance_uuid, "Failed to list backups"))
}

/// Get a presigned download link for a finished backup of the caller's instance
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/backups/{backup_id}/download",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID"),
        ("backup_id" = String, Path, description = "Backup ID from the eligible backup list")
    ),
    responses(
        (status = 200, description = "Presigned download link", body = BackupDownloadResponse),
        (status = 400, description = "Invalid instance or backup ID", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance or eligible backup not found", body = crate::error::ApiErrorResponse),
        (status = 409, description = "Backup is not ready yet", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Historical downloads are not configured"),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn get_backup_download(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((instance_id, backup_id)): Path<(String, String)>,
) -> Result<Json<BackupDownloadResponse>, ApiError> {
    let instance_uuid = ensure_instance_owner(&app_state, &instance_id, user.user_id).await?;
    if !is_valid_backup_id(&backup_id) {
        return Err(ApiError::bad_request("Invalid backup ID format"));
    }

    let download = app_state
        .agent_service
        .get_backup_download(instance_uuid, user.user_id, &backup_id)
        .await
        .map_err(|e| backup_api_error(e, instance_uuid, "Failed to get backup download"))?;
    tracing::info!(instance_id = %instance_uuid, user_id = %user.user_id, "Backup download link issued");
    Ok(Json(BackupDownloadResponse {
        url: download.url,
        expires_in: download.expires_in,
    }))
}
