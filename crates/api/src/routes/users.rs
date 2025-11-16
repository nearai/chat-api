use axum::{
    extract::{Extension, State},
    routing::{get, patch, post},
    Json, Router,
};

use crate::{error::ApiError, middleware::AuthenticatedUser, models::*, state::AppState};

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

/// Create user settings
///
/// Creates or updates user settings for the currently authenticated user.
#[utoipa::path(
    post,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UserSettingsRequest,
    responses(
        (status = 200, description = "User settings created/updated", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn create_user_settings(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UserSettingsRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Creating user settings for user: {}", user.user_id);

    let content = serde_json::json!({
        "notification": request.notification,
        "system_prompt": request.system_prompt,
    });

    let settings = app_state
        .user_settings_service
        .upsert_settings(user.user_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create user settings: {}", e);
            ApiError::internal_server_error("Failed to create user settings")
        })?;

    Ok(Json(settings.into()))
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
        (status = 404, description = "User settings not found", body = crate::error::ApiErrorResponse),
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

    let settings = app_state
        .user_settings_service
        .get_settings(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user settings: {}", e);
            if e.to_string().contains("not found") {
                ApiError::not_found("User settings not found")
            } else {
                ApiError::internal_server_error("Failed to get user settings")
            }
        })?;

    Ok(Json(settings.into()))
}

/// Update user settings
///
/// Partially updates the settings for the currently authenticated user.
#[utoipa::path(
    patch,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UserSettingsUpdateRequest,
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
    Json(request): Json<UserSettingsUpdateRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Updating user settings for user: {}", user.user_id);

    let mut content = serde_json::Map::new();
    if let Some(notification) = request.notification {
        content.insert(
            "notification".to_string(),
            serde_json::Value::Bool(notification),
        );
    }
    if let Some(system_prompt) = request.system_prompt {
        content.insert(
            "system_prompt".to_string(),
            serde_json::Value::String(system_prompt),
        );
    }

    let settings = app_state
        .user_settings_service
        .update_settings(user.user_id, serde_json::Value::Object(content))
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user settings: {}", e);
            ApiError::internal_server_error("Failed to update user settings")
        })?;

    Ok(Json(settings.into()))
}

/// Create user router with all routes
pub fn create_user_router() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_current_user))
        .route("/me/settings", post(create_user_settings))
        .route("/me/settings", get(get_user_settings))
        .route("/me/settings", patch(update_user_settings))
}
