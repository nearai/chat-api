use crate::{consts::LIST_USERS_LIMIT_MAX, error::ApiError, models::*, state::AppState};
use axum::routing::post;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityLogEntry, AnalyticsSummary, TopActiveUsersResponse};
use services::model::ports::UpsertModelParams;
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

/// List all models with pagination
///
/// Returns a paginated list of all models. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/models",
    tag = "Admin",
    params(
        ("limit" = i64, Query, description = "Maximum number of items to return"),
        ("offset" = i64, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of models", body = ModelListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_models(
    State(app_state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<ModelListResponse>, ApiError> {
    pagination.validate()?;

    tracing::info!(
        "Listing models with limit={} and offset={}",
        pagination.limit,
        pagination.offset
    );

    let (models, total) = app_state
        .model_service
        .list_models(pagination.limit, pagination.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list models: {}", e);
            ApiError::internal_server_error("Failed to list models")
        })?;

    Ok(Json(ModelListResponse {
        models: models.into_iter().map(Into::into).collect(),
        limit: pagination.limit,
        offset: pagination.offset,
        total,
    }))
}

/// Batch create or update models
///
/// Creates new models or updates existing ones in batch. The request body should be a JSON object
/// where keys are model IDs and values are partial settings to update.
///
/// Example:
/// ```json
/// {
///   "gpt-4": { "public": true, "system_prompt": "..." },
///   "gpt-3.5": { "public": false }
/// }
/// ```
///
/// All provided model IDs must already exist; missing IDs return 400.
/// Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/models",
    tag = "Admin",
    request_body = BatchUpsertModelsRequest,
    responses(
        (status = 200, description = "Models created or updated", body = Vec<ModelResponse>),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn batch_upsert_models(
    State(app_state): State<AppState>,
    Json(request): Json<BatchUpsertModelsRequest>,
) -> Result<Json<Vec<ModelResponse>>, ApiError> {
    if request.models.is_empty() {
        return Err(ApiError::bad_request("At least one model must be provided"));
    }

    tracing::info!("Batch upserting {} models", request.models.len());

    let mut results = Vec::new();

    for (model_id, partial_settings) in request.models {
        if model_id.trim().is_empty() {
            return Err(ApiError::bad_request("model_id cannot be empty"));
        }

        #[cfg(not(feature = "test"))]
        {
            ensure_model_exists(&app_state, &model_id).await?;
        }

        // Validate system prompt length if provided
        if let Some(ref system_prompt) = partial_settings.system_prompt {
            if system_prompt.len() > crate::consts::SYSTEM_PROMPT_MAX_LEN {
                return Err(ApiError::bad_request(format!(
                    "System prompt for model '{}' exceeds maximum length of {} bytes",
                    model_id,
                    crate::consts::SYSTEM_PROMPT_MAX_LEN
                )));
            }
        }

        let settings =
            services::model::ports::ModelSettings::default().into_updated(partial_settings.into());

        let params = UpsertModelParams {
            model_id: model_id.clone(),
            settings,
        };

        let model = app_state
            .model_service
            .upsert_model(params)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update model {}: {}", model_id, e);
                ApiError::internal_server_error(format!("Failed to update model {}", model_id))
            })?;

        // Invalidate cache immediately after each successful DB write
        // NOTE: This only invalidates cache on the current instance. In multi-instance deployments,
        // other instances may serve stale data for up to MODEL_SETTINGS_CACHE_TTL_SECS.
        {
            let mut cache = app_state.model_settings_cache.write().await;
            cache.remove(&model_id);
        }

        results.push(model.clone());
    }

    Ok(Json(results.into_iter().map(Into::into).collect()))
}

/// Delete a model
///
/// Deletes a specific model and its settings. Requires admin authentication.
#[utoipa::path(
    delete,
    path = "/v1/admin/models/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    responses(
        (status = 204, description = "Model deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Model not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn delete_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if model_id.trim().is_empty() {
        return Err(ApiError::bad_request("model_id cannot be empty"));
    }

    tracing::info!("Deleting model for model_id={}", model_id);

    let deleted = app_state
        .model_service
        .delete_model(&model_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete model: {}", e);
            ApiError::internal_server_error("Failed to delete model")
        })?;

    if !deleted {
        return Err(ApiError::not_found("Model not found"));
    }

    // Invalidate cache AFTER successful DB delete
    {
        let mut cache = app_state.model_settings_cache.write().await;
        cache.remove(&model_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke VPC credentials
///
/// Deletes the stored `vpc_api_key` from database and clears the in-memory VPC cache so the
/// next proxied request will request a new API key from the VPC.
#[utoipa::path(
    post,
    path = "/v1/admin/vpc/revoke",
    tag = "Admin",
    responses(
        (status = 204, description = "VPC credentials revoked"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn revoke_vpc_credentials(
    State(app_state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    tracing::info!("Admin revoked VPC credentials");

    app_state
        .vpc_credentials_service
        .revoke_credentials()
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke VPC credentials: {}", e);
            ApiError::internal_server_error("Failed to revoke VPC credentials")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Create or update system configs
///
/// Creates new system configs or updates existing ones. All fields in the request are optional.
/// If the configs don't exist, missing fields will use default values.
/// If the configs exist, only provided fields will be updated.
/// Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/configs",
    tag = "Admin",
    request_body = UpdateSystemConfigsRequest,
    responses(
        (status = 200, description = "System configs created or updated", body = SystemConfigsResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn upsert_system_configs(
    State(app_state): State<AppState>,
    Json(request): Json<UpdateSystemConfigsRequest>,
) -> Result<Json<SystemConfigsResponse>, ApiError> {
    tracing::info!("Upserting system configs");

    #[cfg(not(feature = "test"))]
    {
        if let Some(ref model_id) = request.default_model {
            ensure_model_exists(&app_state, model_id).await?;
        }
    }

    let partial: services::system_configs::ports::PartialSystemConfigs = request.into();

    // Check if configs exist
    let existing_configs = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!("Failed to check if system configs exist: {}", e);
            ApiError::internal_server_error("Failed to check if system configs exist")
        })?;

    let updated = if existing_configs.is_some() {
        // Configs exist: partial update
        app_state
            .system_configs_service
            .update_configs(partial)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to update system configs");
                ApiError::internal_server_error("Failed to update system configs")
            })?
    } else {
        // Configs don't exist: create with defaults + provided partial configs
        use services::system_configs::ports::SystemConfigs;
        let default_configs = SystemConfigs::default();
        let full_configs = default_configs.into_updated(partial);

        app_state
            .system_configs_service
            .upsert_configs(full_configs)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to create system configs");
                ApiError::internal_server_error("Failed to create system configs")
            })?
    };

    Ok(Json(updated.into()))
}

#[cfg(not(feature = "test"))]
async fn ensure_model_exists(app_state: &AppState, model_id: &str) -> Result<(), ApiError> {
    let exists = app_state
        .model_service
        .get_model(model_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get model '{}': {}", model_id, e);
            ApiError::internal_server_error("Failed to get model")
        })?;

    if exists.is_none() {
        return Err(ApiError::bad_request(format!(
            "Model '{}' does not exist",
            model_id
        )));
    }

    Ok(())
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users))
        .route("/users/{user_id}/activity", get(get_user_activity))
        .route("/models", get(list_models).patch(batch_upsert_models))
        .route("/models/{model_id}", delete(delete_model))
        .route("/vpc/revoke", post(revoke_vpc_credentials))
        .route("/configs", patch(upsert_system_configs))
        .route("/analytics", get(get_analytics))
        .route("/analytics/top-users", get(get_top_users))
}
