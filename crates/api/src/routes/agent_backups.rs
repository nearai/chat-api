use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use services::agent::backup::{is_valid_backup_id, validate_export_ssh_pubkey};
use services::agent::ports::{AgentBackupError, BackupList, BackupListOptions};
use services::logging::error_type;
use services::UserId;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

/// Request body for exporting a backup of the caller's instance.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct ExportBackupRequest {
    /// One SSH public key line (ssh-ed25519 or ssh-rsa) that can also decrypt the backup
    #[serde(default)]
    pub export_ssh_pubkey: Option<String>,
}

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
        AgentBackupError::CreationDisabled => ApiError::new(
            StatusCode::GONE,
            "backup_creation_disabled",
            "New backup exports are disabled. Choose an existing backup.",
        ),
        AgentBackupError::InvalidRequest(message) => ApiError::bad_request(message),
        AgentBackupError::BackupNotFound => ApiError::not_found("Backup not found"),
        AgentBackupError::BackupNotReady => ApiError::conflict("Backup is not ready yet"),
        AgentBackupError::Internal(e) => {
            tracing::error!(%instance_id, error = error_type(&e), "{}", failure);
            ApiError::internal_server_error(failure)
        }
    }
}

/// Export an encrypted backup of the caller's agent instance
///
/// Requires AGENT_BACKUP_EXPORT_CREATE_ENABLED=true.
/// Streams the agent manager's SSE events unchanged: `backup_started`, `status`,
/// `backup_complete` or `error`. A backup can take several minutes.
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/backups/export",
    tag = "Agents",
    params(("id" = String, Path, description = "Instance ID")),
    request_body = ExportBackupRequest,
    responses(
        (status = 200, description = "SSE stream of backup progress", content_type = "text/event-stream"),
        (status = 400, description = "Invalid instance ID or SSH public key", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 410, description = "New backup exports are disabled"),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn export_backup(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
    Json(request): Json<ExportBackupRequest>,
) -> Result<Response, ApiError> {
    let instance_uuid = ensure_instance_owner(&app_state, &instance_id, user.user_id).await?;
    let export_ssh_pubkey = validate_export_ssh_pubkey(request.export_ssh_pubkey.as_deref())
        .map_err(ApiError::bad_request)?;
    tracing::info!(instance_id = %instance_uuid, user_id = %user.user_id, "Backup export requested");

    let rx = app_state
        .agent_service
        .export_backup_stream(instance_uuid, user.user_id, export_ssh_pubkey)
        .await
        .map_err(|e| backup_api_error(e, instance_uuid, "Failed to start backup"))?;

    // Propagate body errors: appending an SSE event could complete a truncated JSON frame.
    let stream = ReceiverStream::new(rx);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .header("x-accel-buffering", "no")
        .body(axum::body::Body::from_stream(stream))
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

/// List ready historical backups created strictly before the configured cutoff.
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/backups",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID"),
        ("limit" = Option<u32>, Query, description = "Page size, 1–1000; default 100"),
        ("offset" = Option<u64>, Query, description = "Rows to skip after filtering; default 0")
    ),
    responses(
        (status = 200, description = "Eligible historical backups, newest first", body = BackupList),
        (status = 400, description = "Invalid pagination"),
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
    Query(options): Query<BackupListOptions>,
) -> Result<Json<BackupList>, ApiError> {
    let instance_uuid = ensure_instance_owner(&app_state, &instance_id, user.user_id).await?;
    app_state
        .agent_service
        .list_backups(instance_uuid, user.user_id, options)
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
