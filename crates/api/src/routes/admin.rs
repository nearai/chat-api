use crate::{consts::LIST_USERS_LIMIT_MAX, error::ApiError, models::*, state::AppState};
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

/// Pagination query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Maximum number of items to return (default: 20, max: LIMIT_MAX)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl PaginationQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.limit < 1 {
            return Err(ApiError::bad_request(
                "limit is less than minimum value of 1",
            ));
        }

        if self.limit > LIST_USERS_LIMIT_MAX {
            return Err(ApiError::bad_request(format!(
                "limit exceeds maximum value of {}",
                LIST_USERS_LIMIT_MAX
            )));
        }

        if self.offset < 0 {
            return Err(ApiError::bad_request("offset cannot be negative"));
        }

        Ok(())
    }
}

fn default_limit() -> i64 {
    20
}

fn default_offset() -> i64 {
    0
}

/// List users
///
/// Returns a paginated list of users. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "Admin",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of items to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)")
    ),
    responses(
        (status = 200, description = "User list retrieved", body = UserListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_users(
    State(app_state): State<AppState>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<UserListResponse>, ApiError> {
    tracing::info!(
        "Listing users with limit={}, offset={}",
        params.limit,
        params.offset
    );

    params.validate()?;

    let (users, total) = app_state
        .user_service
        .list_users(params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct SystemPromptRequest {
    pub system_prompt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct SystemPromptResponse {
    pub system_prompt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CloudApiSettingsResponse {
    settings: CloudApiSettings,
}

#[derive(Debug, Deserialize, Serialize)]
struct CloudApiSettings {
    system_prompt: Option<String>,
}

#[derive(Debug, Serialize)]
struct CloudApiPatchRequest {
    system_prompt: Option<String>,
}

/// Get system prompt for the organization
///
/// Fetches the system prompt from Cloud API. Requires admin authentication.
/// Uses the VPC session token to authenticate with Cloud API.
#[utoipa::path(
    get,
    path = "/v1/admin/system_prompt",
    tag = "Admin",
    responses(
        (status = 200, description = "System prompt retrieved", body = SystemPromptResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_system_prompt(
    State(app_state): State<AppState>,
) -> Result<Json<SystemPromptResponse>, ApiError> {
    if app_state.cloud_api_base_url.is_empty() {
        tracing::error!("Cloud API base URL not configured");
        return Err(ApiError::internal_server_error("Cloud API not configured"));
    }

    let credentials = app_state
        .vpc_credentials_service
        .get_credentials()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get VPC credentials: {}", e);
            ApiError::internal_server_error("Failed to authenticate with VPC")
        })?
        .ok_or_else(|| {
            tracing::error!("VPC not configured");
            ApiError::internal_server_error("VPC authentication not configured")
        })?;

    let url = format!(
        "{}/organizations/{}/settings",
        app_state.cloud_api_base_url.trim_end_matches('/'),
        credentials.organization_id
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(
            "Authorization",
            format!("Bearer {}", credentials.access_token),
        )
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to call Cloud API: {}", e);
            ApiError::bad_gateway("Failed to connect to Cloud API")
        })?;

    if !response.status().is_success() {
        let status = response.status();
        tracing::error!("Cloud API error: status {}", status);
        return Err(ApiError::internal_server_error(format!(
            "Cloud API returned error: {}",
            status
        )));
    }

    let settings: CloudApiSettingsResponse = response.json().await.map_err(|e| {
        tracing::error!("Failed to parse Cloud API response: {}", e);
        ApiError::internal_server_error("Failed to parse Cloud API response")
    })?;

    Ok(Json(SystemPromptResponse {
        system_prompt: settings.settings.system_prompt,
    }))
}

/// Set system prompt for the organization
///
/// Updates the system prompt in Cloud API. Requires admin authentication.
/// Uses the VPC session token to authenticate with Cloud API.
#[utoipa::path(
    post,
    path = "/v1/admin/system_prompt",
    tag = "Admin",
    request_body = SystemPromptRequest,
    responses(
        (status = 200, description = "System prompt updated", body = SystemPromptResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn set_system_prompt(
    State(app_state): State<AppState>,
    Json(request): Json<SystemPromptRequest>,
) -> Result<Json<SystemPromptResponse>, ApiError> {
    if app_state.cloud_api_base_url.is_empty() {
        tracing::error!("Cloud API base URL not configured");
        return Err(ApiError::internal_server_error("Cloud API not configured"));
    }

    let credentials = app_state
        .vpc_credentials_service
        .get_credentials()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get VPC credentials: {}", e);
            ApiError::internal_server_error("Failed to authenticate with VPC")
        })?
        .ok_or_else(|| {
            tracing::error!("VPC not configured");
            ApiError::internal_server_error("VPC authentication not configured")
        })?;

    let url = format!(
        "{}/organizations/{}/settings",
        app_state.cloud_api_base_url.trim_end_matches('/'),
        credentials.organization_id
    );

    let patch_request = CloudApiPatchRequest {
        system_prompt: request.system_prompt,
    };

    let client = reqwest::Client::new();
    let response = client
        .patch(&url)
        .header(
            "Authorization",
            format!("Bearer {}", credentials.access_token),
        )
        .header("Content-Type", "application/json")
        .json(&patch_request)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to call Cloud API: {}", e);
            ApiError::bad_gateway("Failed to connect to Cloud API")
        })?;

    if !response.status().is_success() {
        let status = response.status();
        tracing::error!("Cloud API error: status {}", status);
        return Err(ApiError::internal_server_error(format!(
            "Cloud API returned error: {}",
            status
        )));
    }

    let settings: CloudApiSettingsResponse = response.json().await.map_err(|e| {
        tracing::error!("Failed to parse Cloud API response: {}", e);
        ApiError::internal_server_error("Failed to parse Cloud API response")
    })?;

    Ok(Json(SystemPromptResponse {
        system_prompt: settings.settings.system_prompt,
    }))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new().route("/users", get(list_users)).route(
        "/system_prompt",
        get(get_system_prompt).post(set_system_prompt),
    )
}
