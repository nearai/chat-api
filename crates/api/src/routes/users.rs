use crate::{error::ApiError, middleware::AuthenticatedUser, models::*, state::AppState};
use axum::{
    extract::{Extension, State},
    routing::{get, patch, post},
    Json, Router,
};
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

/// Get current user's usage (all-time token sum and cost in nano-USD).
///
/// Returns the authenticated user's own usage. No admin required.
#[utoipa::path(
    get,
    path = "/v1/users/me/usage",
    tag = "Users",
    responses(
        (status = 200, description = "Current user usage", body = UserUsageResponse),
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
) -> Result<Json<UserUsageResponse>, ApiError> {
    let summary = app_state
        .user_usage_service
        .get_usage_by_user_id(user.user_id)
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
        .route("/me", get(get_current_user))
        .route("/me/usage", get(get_my_usage))
        .route("/me/settings", get(get_user_settings))
        .route("/me/settings", post(update_user_settings))
        .route("/me/settings", patch(update_user_settings_partially))
}
