use crate::{consts::LIST_USERS_LIMIT_MAX, error::ApiError, models::*, state::AppState};
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityLogEntry, AnalyticsSummary, TopActiveUsersResponse};
use services::UserId;

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

/// Query parameters for analytics endpoint
#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    /// Start of the time period (ISO 8601 timestamp)
    pub start: DateTime<Utc>,
    /// End of the time period (ISO 8601 timestamp)
    pub end: DateTime<Utc>,
}

/// Get analytics summary
///
/// Returns user metrics, activity metrics, and breakdown by auth method for a time period.
/// Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/analytics",
    tag = "Admin",
    params(
        ("start" = DateTime<Utc>, Query, description = "Start of time period (ISO 8601)"),
        ("end" = DateTime<Utc>, Query, description = "End of time period (ISO 8601)")
    ),
    responses(
        (status = 200, description = "Analytics retrieved", body = AnalyticsSummary),
        (status = 400, description = "Bad request - invalid date range", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_analytics(
    State(app_state): State<AppState>,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsSummary>, ApiError> {
    tracing::info!(
        "Getting analytics for period {} to {}",
        params.start,
        params.end
    );

    // Validate date range
    if params.start >= params.end {
        return Err(ApiError::bad_request("start date must be before end date"));
    }

    let analytics = app_state
        .analytics_service
        .get_analytics_summary(params.start, params.end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get analytics: {}", e);
            ApiError::internal_server_error("Failed to retrieve analytics")
        })?;

    Ok(Json(analytics))
}

/// Response for user activity endpoint
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserActivityResponse {
    pub user_id: UserId,
    pub activities: Vec<ActivityLogEntry>,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for top users endpoint
#[derive(Debug, Deserialize)]
pub struct TopUsersQuery {
    /// Start of the time period (ISO 8601 timestamp)
    pub start: DateTime<Utc>,
    /// End of the time period (ISO 8601 timestamp)
    pub end: DateTime<Utc>,
    /// Maximum number of users to return (default: 10)
    #[serde(default = "default_top_users_limit")]
    pub limit: i64,
}

fn default_top_users_limit() -> i64 {
    10
}

/// Get activity history for a specific user
///
/// Returns paginated activity log for a user. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/users/{user_id}/activity",
    tag = "Admin",
    params(
        ("user_id" = UserId, Path, description = "User ID"),
        ("limit" = Option<i64>, Query, description = "Maximum number of activities to return (default: 50)"),
        ("offset" = Option<i64>, Query, description = "Number of activities to skip (default: 0)")
    ),
    responses(
        (status = 200, description = "User activity retrieved", body = UserActivityResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_user_activity(
    State(app_state): State<AppState>,
    Path(user_id): Path<UserId>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<UserActivityResponse>, ApiError> {
    tracing::info!(
        "Getting activity for user {} with limit={}, offset={}",
        user_id,
        params.limit,
        params.offset
    );

    let activities = app_state
        .analytics_service
        .get_user_activity(user_id, Some(params.limit), Some(params.offset))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user activity: {}", e);
            ApiError::internal_server_error("Failed to retrieve user activity")
        })?;

    Ok(Json(UserActivityResponse {
        user_id,
        activities,
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Get top active users
///
/// Returns the most active users in a time period. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/analytics/top-users",
    tag = "Admin",
    params(
        ("start" = DateTime<Utc>, Query, description = "Start of time period (ISO 8601)"),
        ("end" = DateTime<Utc>, Query, description = "End of time period (ISO 8601)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of users to return (default: 10)")
    ),
    responses(
        (status = 200, description = "Top users retrieved", body = TopActiveUsersResponse),
        (status = 400, description = "Bad request - invalid date range", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_top_users(
    State(app_state): State<AppState>,
    Query(params): Query<TopUsersQuery>,
) -> Result<Json<TopActiveUsersResponse>, ApiError> {
    tracing::info!(
        "Getting top {} users for period {} to {}",
        params.limit,
        params.start,
        params.end
    );

    // Validate date range
    if params.start >= params.end {
        return Err(ApiError::bad_request("start date must be before end date"));
    }

    // Validate limit
    if params.limit < 1 || params.limit > 100 {
        return Err(ApiError::bad_request("limit must be between 1 and 100"));
    }

    let users = app_state
        .analytics_service
        .get_top_active_users(params.start, params.end, params.limit)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top users: {}", e);
            ApiError::internal_server_error("Failed to retrieve top users")
        })?;

    Ok(Json(TopActiveUsersResponse {
        period_start: params.start,
        period_end: params.end,
        users,
    }))
}

/// Get model settings for a specific model
///
/// Returns the current model settings. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/model_settings/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    responses(
        (status = 200, description = "Model settings retrieved", body = ModelSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_model_settings(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<ModelSettingsResponse>, ApiError> {
    tracing::info!("Getting model settings for model_id={}", model_id);

    let content = app_state
        .model_settings_service
        .get_settings(&model_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get model settings: {}", e);
            ApiError::internal_server_error("Failed to get model settings")
        })?;

    Ok(Json(ModelSettingsResponse {
        content: content.into(),
    }))
}

/// Fully update global model settings
///
/// Overwrites the settings for a specific model. Requires admin authentication.
#[utoipa::path(
    post,
    path = "/v1/admin/model_settings/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    request_body = UpdateModelSettingsRequest,
    responses(
        (status = 200, description = "Model settings updated", body = ModelSettingsResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_model_settings(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
    Json(request): Json<UpdateModelSettingsRequest>,
) -> Result<Json<ModelSettingsResponse>, ApiError> {
    tracing::info!(
        "Fully updating model settings for model_id={}: {:?}",
        model_id,
        request
    );

    let content = services::settings::ports::ModelSettingsContent {
        public: request.public,
    };

    let content = app_state
        .model_settings_service
        .update_settings(&model_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update model settings: {}", e);
            ApiError::internal_server_error("Failed to update model settings")
        })?;

    Ok(Json(ModelSettingsResponse {
        content: content.into(),
    }))
}

/// Partially update global model settings
///
/// Partially updates the settings for a specific model. Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/model_settings/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    request_body = UpdateModelSettingsPartiallyRequest,
    responses(
        (status = 200, description = "Model settings updated", body = ModelSettingsResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_model_settings_partially(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
    Json(request): Json<UpdateModelSettingsPartiallyRequest>,
) -> Result<Json<ModelSettingsResponse>, ApiError> {
    tracing::info!(
        "Partially updating model settings for model_id={}: {:?}",
        model_id,
        request
    );

    let content = services::settings::ports::PartialModelSettingsContent {
        public: request.public,
    };

    let content = app_state
        .model_settings_service
        .update_settings_partially(&model_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update model settings: {}", e);
            ApiError::internal_server_error("Failed to update model settings")
        })?;

    Ok(Json(ModelSettingsResponse {
        content: content.into(),
    }))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users))
        .route("/users/{user_id}/activity", get(get_user_activity))
        .route(
            "/system_prompt",
            get(get_system_prompt).post(set_system_prompt),
        )
        .route(
            "/model_settings/{model_id}",
            get(get_model_settings)
                .post(update_model_settings)
                .patch(update_model_settings_partially),
        )
        .route("/analytics", get(get_analytics))
        .route("/analytics/top-users", get(get_top_users))
}
