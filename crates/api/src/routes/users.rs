use crate::{
    error::{ApiError, ApiErrorResponse},
    middleware::AuthenticatedUser,
    models::*,
    state::AppState,
};
use axum::{
    extract::{Extension, Query, State},
    http::{header::CACHE_CONTROL, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::user::ports::UserStatusError;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserStatusResponse {
    pub status: &'static str,
}

/// Get current user's access status.
///
/// Checks the current user's linked NEAR account against AML status when needed.
#[utoipa::path(
    get,
    path = "/v1/users/status",
    tag = "Users",
    responses(
        (status = 200, description = "Current user status is OK", body = UserStatusResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Current user is blocked", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_user_status(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserStatusResponse>, ApiError> {
    app_state
        .user_service
        .check_user_status(user.user_id)
        .await
        .map_err(|e| match e {
            UserStatusError::AmlHighRiskBlocked { .. } => ApiError::forbidden("Account error"),
            UserStatusError::Internal(err) => {
                tracing::error!(
                    user_id = %user.user_id,
                    error = ?err,
                    "Failed to check user status"
                );
                ApiError::internal_server_error("Failed to check user status")
            }
        })?;

    Ok(Json(UserStatusResponse { status: "ok" }))
}

/// Get current user
///
/// Returns the profile of the currently authenticated user, including their linked OAuth accounts.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "Users",
    responses(
        (status = 200, description = "Current user profile", body = UserProfileResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_current_user(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserProfileResponse>, ApiError> {
    tracing::info!("Getting user profile for user: {}", user.user_id);

    let profile = app_state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user profile: {}", e);
            ApiError::user_profile_error()
        })?;

    Ok(Json(profile.into()))
}

/// Delete current user account
///
/// This self-service endpoint is retired for the Stage I migration window.
/// Existing deletion jobs keep their worker path and can complete normally, but this endpoint
/// never creates a new deletion record or task.
#[utoipa::path(
    delete,
    path = "/v1/users/me",
    tag = "Users",
    responses(
        (status = 410, description = "Self-service account deletion is retired; response includes Cache-Control: no-store", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn delete_current_user(Extension(user): Extension<AuthenticatedUser>) -> Response {
    tracing::warn!(
        user_id = %user.user_id,
        "Self-service account deletion is retired"
    );

    (
        StatusCode::GONE,
        [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(ApiErrorResponse {
            code: "gone".to_string(),
            message: "Self-service account deletion is no longer available.".to_string(),
            details: None,
        }),
    )
        .into_response()
}

/// Query parameters for usage time range.
#[derive(Debug, Deserialize)]
pub struct UsageTimeRangeQuery {
    /// Start of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub start: Option<DateTime<Utc>>,
    /// End of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub end: Option<DateTime<Utc>>,
}

/// Get current user's usage (all-time or within time range).
///
/// Returns the authenticated user's own usage. No admin required.
/// Without start/end, returns all-time usage.
#[utoipa::path(
    get,
    path = "/v1/users/me/usage",
    tag = "Users",
    params(
        ("start" = Option<DateTime<Utc>>, Query, description = "Start of time period (ISO 8601); use with end; interval [start, end)"),
        ("end" = Option<DateTime<Utc>>, Query, description = "End of time period (ISO 8601); use with start; interval [start, end)")
    ),
    responses(
        (status = 200, description = "Current user usage", body = UserUsageResponse),
        (status = 400, description = "Bad request - start and end must be used together, start must be before end", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No usage recorded", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_my_usage(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<UsageTimeRangeQuery>,
) -> Result<Json<UserUsageResponse>, ApiError> {
    let (start, end) = (params.start, params.end);
    if let (Some(s), Some(e)) = (start, end) {
        if s >= e {
            return Err(ApiError::bad_request("start must be before end"));
        }
    } else if start.is_some() || end.is_some() {
        return Err(ApiError::bad_request("start and end must be used together"));
    }

    let summary = app_state
        .user_usage_service
        .get_usage_by_user_id(user.user_id, start, end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get usage for user_id={}: {}", user.user_id, e);
            ApiError::internal_server_error("Failed to retrieve usage")
        })?;

    let summary = summary.ok_or_else(|| {
        tracing::info!("No usage found for user_id={}", user.user_id);
        ApiError::not_found("No usage recorded")
    })?;

    Ok(Json(UserUsageResponse {
        user_id: summary.user_id,
        token_sum: summary.token_sum,
        image_num: summary.image_num,
        cost_nano_usd: summary.cost_nano_usd,
    }))
}

/// Get user settings
///
/// Retrieves the settings for the currently authenticated user.
#[utoipa::path(
    get,
    path = "/v1/users/me/settings",
    tag = "Users",
    responses(
        (status = 200, description = "User settings retrieved", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_user_settings(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Getting user settings for user: {}", user.user_id);

    let content = app_state
        .user_settings_service
        .get_settings(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user settings: {}", e);
            ApiError::internal_server_error("Failed to get user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Update user settings
///
/// Fully updates the settings for the currently authenticated user.
#[utoipa::path(
    post,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UpdateUserSettingsRequest,
    responses(
        (status = 200, description = "User settings updated", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_user_settings(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UpdateUserSettingsRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Fully updating user settings for user: {}", user.user_id);

    request.validate()?;

    let content = services::user::ports::UserSettingsContent {
        notification: request.notification,
        system_prompt: request.system_prompt,
        web_search: request.web_search,
        appearance: request.appearance.into(),
    };

    let content = app_state
        .user_settings_service
        .update_settings(user.user_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user settings: {}", e);
            ApiError::internal_server_error("Failed to update user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Update user settings
///
/// Partially updates the settings for the currently authenticated user.
#[utoipa::path(
    patch,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UpdateUserSettingsPartiallyRequest,
    responses(
        (status = 200, description = "User settings updated", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_user_settings_partially(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UpdateUserSettingsPartiallyRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!(
        "Partially updating user settings for user: {}",
        user.user_id
    );

    request.validate()?;

    let content = services::user::ports::PartialUserSettingsContent {
        notification: request.notification,
        system_prompt: request.system_prompt,
        web_search: request.web_search,
        appearance: request.appearance.map(Into::into),
    };

    let content = app_state
        .user_settings_service
        .update_settings_partially(user.user_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user settings: {}", e);
            ApiError::internal_server_error("Failed to update user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Create user router with all routes (requires authentication)
pub fn create_user_router() -> Router<AppState> {
    Router::new()
        .route("/status", get(get_user_status))
        .route("/me", get(get_current_user).delete(delete_current_user))
        // Keep DELETE's Stage I cutoff explicit for the trailing-slash form
        // too, rather than allowing it to fall through to the SPA fallback.
        .route("/me/", axum::routing::delete(delete_current_user))
        .route("/me/usage", get(get_my_usage))
        .route("/me/settings", get(get_user_settings))
        .route("/me/settings", post(update_user_settings))
        .route("/me/settings", patch(update_user_settings_partially))
}

#[cfg(test)]
mod tests {
    use super::*;
    use services::{SessionId, UserId};

    #[tokio::test]
    async fn retired_account_deletion_response_is_gone_and_not_cacheable() {
        let response = delete_current_user(Extension(AuthenticatedUser {
            user_id: UserId::new(),
            session_id: SessionId::new(),
        }))
        .await;

        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
}
