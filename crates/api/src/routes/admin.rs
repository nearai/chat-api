use crate::{consts::LIST_USERS_LIMIT_MAX, error::ApiError, models::*, state::AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityLogEntry, AnalyticsSummary, TopActiveUsersResponse};
use services::model::ports::{UpdateModelParams, UpsertModelParams};
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

/// Get model settings for a specific model
///
/// Returns the current model (including settings). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/models/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    responses(
        (status = 200, description = "Model settings retrieved", body = Option<ModelResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<Option<ModelResponse>>, ApiError> {
    tracing::info!("Getting model for model_id={}", model_id);

    let model = app_state
        .model_service
        .get_model(&model_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get model: {}", e);
            ApiError::internal_server_error("Failed to get model")
        })?;

    Ok(Json(model.map(Into::into)))
}

/// Fully create or update a model
///
/// Overwrites the settings for a specific model. Requires admin authentication.
#[utoipa::path(
    post,
    path = "/v1/admin/models/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    request_body = UpsertModelsRequest,
    responses(
        (status = 200, description = "Model updated", body = ModelResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn upsert_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
    Json(request): Json<UpsertModelsRequest>,
) -> Result<Json<ModelResponse>, ApiError> {
    tracing::info!(
        "Fully upserting model for model_id={}: {:?}",
        model_id,
        request
    );

    let params = UpsertModelParams {
        model_id,
        settings: request.settings.into(),
    };

    let model = app_state
        .model_service
        .upsert_model(params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to upsert model: {}", e);
            ApiError::internal_server_error("Failed to upsert model")
        })?;

    // Update in-memory cache for /v1/responses immediately
    {
        let mut cache = app_state.model_system_prompt_cache.write().await;
        cache.insert(
            model.model_id.clone(),
            crate::state::ModelSystemPromptCacheEntry {
                last_checked_at: Utc::now(),
                exists: true,
                public: model.settings.public,
                system_prompt: model.settings.system_prompt.clone(),
            },
        );
    }

    Ok(Json(model.into()))
}

/// Partially update a model
///
/// Partially updates the settings for a specific model. Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/models/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    request_body = UpdateModelRequest,
    responses(
        (status = 200, description = "Model settings updated", body = ModelResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Model not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
    Json(request): Json<UpdateModelRequest>,
) -> Result<Json<ModelResponse>, ApiError> {
    tracing::info!(
        "Partially updating model for model_id={}: {:?}",
        model_id,
        request
    );

    let settings = request.settings.map(Into::into);

    let params = UpdateModelParams {
        model_id: model_id.clone(),
        settings,
    };

    let model = app_state
        .model_service
        .update_model(params)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update model: {}", e);
            if e.to_string().contains("Model not found") {
                return ApiError::not_found("Model not found");
            }
            ApiError::internal_server_error("Failed to update model")
        })?;

    // Update in-memory cache for /v1/responses immediately
    {
        let mut cache = app_state.model_system_prompt_cache.write().await;
        cache.insert(
            model.model_id.clone(),
            crate::state::ModelSystemPromptCacheEntry {
                last_checked_at: Utc::now(),
                exists: true,
                public: model.settings.public,
                system_prompt: model.settings.system_prompt.clone(),
            },
        );
    }

    Ok(Json(model.into()))
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

    // Remove from in-memory cache
    {
        let mut cache = app_state.model_system_prompt_cache.write().await;
        cache.remove(&model_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get global configuration
#[utoipa::path(
    get,
    path = "/v1/admin/globals/config",
    tag = "Admin",
    responses(
        (status = 200, description = "Global config retrieved", body = Option<GlobalConfigResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_global_config(
    State(app_state): State<AppState>,
) -> Result<Json<Option<GlobalConfigResponse>>, ApiError> {
    tracing::info!("Getting global config");

    let config = app_state
        .global_config_service
        .get_config()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get global config");
            ApiError::internal_server_error("Failed to get global config")
        })?;

    Ok(Json(config.map(Into::into)))
}

/// Fully create or replace global configuration
#[utoipa::path(
    post,
    path = "/v1/admin/globals/config",
    tag = "Admin",
    request_body = UpsertGlobalConfigRequest,
    responses(
        (status = 200, description = "Global config upserted", body = GlobalConfigResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn upsert_global_config(
    State(app_state): State<AppState>,
    Json(request): Json<UpsertGlobalConfigRequest>,
) -> Result<Json<GlobalConfigResponse>, ApiError> {
    tracing::info!("Upserting global config: {:?}", request);

    let config: services::global_config::ports::GlobalConfig = request.into();

    let updated = app_state
        .global_config_service
        .upsert_config(config)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to upsert global config");
            ApiError::internal_server_error("Failed to upsert global config")
        })?;

    Ok(Json(updated.into()))
}

/// Partially update global configuration
#[utoipa::path(
    patch,
    path = "/v1/admin/globals/config",
    tag = "Admin",
    request_body = UpdateGlobalConfigRequest,
    responses(
        (status = 200, description = "Global config updated", body = GlobalConfigResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_global_config(
    State(app_state): State<AppState>,
    Json(request): Json<UpdateGlobalConfigRequest>,
) -> Result<Json<GlobalConfigResponse>, ApiError> {
    tracing::info!("Partially updating global config: {:?}", request);

    let partial: services::global_config::ports::PartialGlobalConfig = request.into();

    let updated = app_state
        .global_config_service
        .update_config(partial)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to update global config");
            ApiError::internal_server_error("Failed to update global config")
        })?;

    Ok(Json(updated.into()))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users))
        .route("/users/{user_id}/activity", get(get_user_activity))
        .route(
            "/models/{model_id}",
            get(get_model)
                .post(upsert_model)
                .patch(update_model)
                .delete(delete_model),
        )
        .route(
            "/globals/config",
            get(get_global_config)
                .post(upsert_global_config)
                .patch(update_global_config),
        )
        .route("/analytics", get(get_analytics))
        .route("/analytics/top-users", get(get_top_users))
}
