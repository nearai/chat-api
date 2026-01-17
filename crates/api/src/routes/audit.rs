use crate::{error::ApiError, middleware::TenantContext, state::AppState};
use axum::{
    extract::{Extension, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::{
    audit::ports::{AuditLog, AuditLogQuery, AuditStatus, ExportFormat},
    OrganizationId, UserId, WorkspaceId,
};

// --- Request/Response types ---

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuditLogResponse {
    pub id: i64,
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_id: Option<UserId>,
    pub actor_type: String,
    pub actor_ip: Option<String>,
    pub actor_user_agent: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub changes: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: String,
}

impl From<AuditLog> for AuditLogResponse {
    fn from(log: AuditLog) -> Self {
        Self {
            id: log.id,
            organization_id: log.organization_id,
            workspace_id: log.workspace_id,
            actor_id: log.actor_id,
            actor_type: log.actor_type.as_str().to_string(),
            actor_ip: log.actor_ip.map(|ip| ip.to_string()),
            actor_user_agent: log.actor_user_agent,
            action: log.action,
            resource_type: log.resource_type,
            resource_id: log.resource_id,
            changes: log.changes,
            metadata: log.metadata,
            status: log.status.as_str().to_string(),
            error_message: log.error_message,
            created_at: log.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuditLogListResponse {
    pub logs: Vec<AuditLogResponse>,
    pub limit: i64,
    pub offset: i64,
    pub total: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AuditLogQueryParams {
    /// Filter by workspace ID
    pub workspace_id: Option<WorkspaceId>,
    /// Filter by actor (user) ID
    pub actor_id: Option<UserId>,
    /// Filter by action (e.g., "create", "update", "delete")
    pub action: Option<String>,
    /// Filter by resource type (e.g., "conversation", "workspace")
    pub resource_type: Option<String>,
    /// Filter by resource ID
    pub resource_id: Option<String>,
    /// Filter by status (success, failure, pending)
    pub status: Option<String>,
    /// Start of date range (ISO 8601 format)
    pub from_date: Option<String>,
    /// End of date range (ISO 8601 format)
    pub to_date: Option<String>,
    /// Maximum number of items (default: 50, max: 200)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

impl AuditLogQueryParams {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.limit <= 0 {
            return Err(ApiError::bad_request("Limit must be positive"));
        }
        if self.limit > 200 {
            return Err(ApiError::bad_request("Limit cannot exceed 200"));
        }
        if self.offset < 0 {
            return Err(ApiError::bad_request("Offset cannot be negative"));
        }
        Ok(())
    }

    pub fn parse_from_date(&self) -> Result<Option<DateTime<Utc>>, ApiError> {
        if let Some(ref date_str) = self.from_date {
            date_str
                .parse::<DateTime<Utc>>()
                .map(Some)
                .map_err(|_| ApiError::bad_request("Invalid from_date format. Use ISO 8601."))
        } else {
            Ok(None)
        }
    }

    pub fn parse_to_date(&self) -> Result<Option<DateTime<Utc>>, ApiError> {
        if let Some(ref date_str) = self.to_date {
            date_str
                .parse::<DateTime<Utc>>()
                .map(Some)
                .map_err(|_| ApiError::bad_request("Invalid to_date format. Use ISO 8601."))
        } else {
            Ok(None)
        }
    }

    pub fn parse_status(&self) -> Option<AuditStatus> {
        self.status.as_deref().and_then(AuditStatus::from_str)
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ExportQueryParams {
    /// Filter by workspace ID
    pub workspace_id: Option<WorkspaceId>,
    /// Filter by actor (user) ID
    pub actor_id: Option<UserId>,
    /// Filter by action
    pub action: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Start of date range (ISO 8601 format)
    pub from_date: Option<String>,
    /// End of date range (ISO 8601 format)
    pub to_date: Option<String>,
    /// Export format: "json" or "csv" (default: json)
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".to_string()
}

impl ExportQueryParams {
    pub fn parse_from_date(&self) -> Result<Option<DateTime<Utc>>, ApiError> {
        if let Some(ref date_str) = self.from_date {
            date_str
                .parse::<DateTime<Utc>>()
                .map(Some)
                .map_err(|_| ApiError::bad_request("Invalid from_date format. Use ISO 8601."))
        } else {
            Ok(None)
        }
    }

    pub fn parse_to_date(&self) -> Result<Option<DateTime<Utc>>, ApiError> {
        if let Some(ref date_str) = self.to_date {
            date_str
                .parse::<DateTime<Utc>>()
                .map(Some)
                .map_err(|_| ApiError::bad_request("Invalid to_date format. Use ISO 8601."))
        } else {
            Ok(None)
        }
    }

    pub fn parse_format(&self) -> Result<ExportFormat, ApiError> {
        match self.format.as_str() {
            "json" => Ok(ExportFormat::Json),
            "csv" => Ok(ExportFormat::Csv),
            other => Err(ApiError::bad_request(&format!(
                "Invalid export format: '{}'. Must be 'json' or 'csv'",
                other
            ))),
        }
    }
}

// --- Handlers ---

/// Query audit logs
#[utoipa::path(
    get,
    path = "/v1/admin/audit-logs",
    tag = "Audit",
    params(
        ("workspace_id" = Option<WorkspaceId>, Query, description = "Filter by workspace ID"),
        ("actor_id" = Option<UserId>, Query, description = "Filter by actor ID"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("resource_type" = Option<String>, Query, description = "Filter by resource type"),
        ("resource_id" = Option<String>, Query, description = "Filter by resource ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("from_date" = Option<String>, Query, description = "Start of date range (ISO 8601)"),
        ("to_date" = Option<String>, Query, description = "End of date range (ISO 8601)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of items (default: 50, max: 200)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of audit logs", body = AuditLogListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn query_audit_logs(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Query(params): Query<AuditLogQueryParams>,
) -> Result<Json<AuditLogListResponse>, ApiError> {
    tracing::info!(
        "Querying audit logs: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"audit:read".to_string()) {
        return Err(ApiError::forbidden("Missing permission to view audit logs"));
    }

    params.validate()?;
    let from_date = params.parse_from_date()?;
    let to_date = params.parse_to_date()?;
    let status = params.parse_status();

    let query = AuditLogQuery {
        organization_id: tenant.organization_id,
        workspace_id: params.workspace_id,
        actor_id: params.actor_id,
        action: params.action,
        resource_type: params.resource_type,
        resource_id: params.resource_id,
        status,
        from_date,
        to_date,
        limit: params.limit,
        offset: params.offset,
    };

    let (logs, total) = app_state
        .audit_service
        .query(query)
        .await
        .map_err(|e| {
            tracing::error!("Failed to query audit logs: {}", e);
            ApiError::internal_server_error("Failed to query audit logs")
        })?;

    Ok(Json(AuditLogListResponse {
        logs: logs.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Export audit logs as JSON or CSV
#[utoipa::path(
    get,
    path = "/v1/admin/audit-logs/export",
    tag = "Audit",
    params(
        ("workspace_id" = Option<WorkspaceId>, Query, description = "Filter by workspace ID"),
        ("actor_id" = Option<UserId>, Query, description = "Filter by actor ID"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("resource_type" = Option<String>, Query, description = "Filter by resource type"),
        ("from_date" = Option<String>, Query, description = "Start of date range (ISO 8601)"),
        ("to_date" = Option<String>, Query, description = "End of date range (ISO 8601)"),
        ("format" = Option<String>, Query, description = "Export format: json or csv (default: json)")
    ),
    responses(
        (status = 200, description = "Exported audit logs file", content_type = "application/octet-stream"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    security(("session_token" = []))
)]
pub async fn export_audit_logs(
    State(app_state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Query(params): Query<ExportQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        "Exporting audit logs: organization_id={}, user_id={}",
        tenant.organization_id,
        tenant.user_id
    );

    // Check permission
    if !tenant.permissions.contains(&"audit:export".to_string()) {
        return Err(ApiError::forbidden("Missing permission to export audit logs"));
    }

    let from_date = params.parse_from_date()?;
    let to_date = params.parse_to_date()?;
    let format = params.parse_format()?;

    let query = AuditLogQuery {
        organization_id: tenant.organization_id,
        workspace_id: params.workspace_id,
        actor_id: params.actor_id,
        action: params.action,
        resource_type: params.resource_type,
        resource_id: None,
        status: None,
        from_date,
        to_date,
        limit: 10000, // Max export limit
        offset: 0,
    };

    let data = app_state
        .audit_service
        .export(query, format)
        .await
        .map_err(|e| {
            tracing::error!("Failed to export audit logs: {}", e);
            ApiError::internal_server_error("Failed to export audit logs")
        })?;

    let (content_type, extension) = match format {
        ExportFormat::Json => ("application/json", "json"),
        ExportFormat::Csv => ("text/csv", "csv"),
    };

    let filename = format!(
        "audit-logs-{}.{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        extension
    );

    let content_disposition = format!("attachment; filename=\"{}\"", filename);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_DISPOSITION, content_disposition),
        ],
        data,
    ))
}

/// Create audit routes router
pub fn create_audit_router() -> Router<AppState> {
    Router::new()
        .route("/", get(query_audit_logs))
        .route("/export", get(export_audit_logs))
}
