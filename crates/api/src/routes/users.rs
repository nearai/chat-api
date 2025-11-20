use crate::{
    consts::PAGE_SIZE_MAX, error::ApiError, middleware::AuthenticatedUser, models::*,
    state::AppState,
};
use axum::routing::post;
use axum::{
    extract::{Extension, Query, State},
    routing::{get, patch},
    Json, Router,
};
use serde::Deserialize;

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

/// Pagination query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Page number (1-based, default: 1)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page (default: 20, max: PAGE_SIZE_MAX)
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    20
}

/// List users
///
/// Returns a paginated list of users. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/users",
    tag = "Users",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-based, default: 1)"),
        ("page_size" = Option<u32>, Query, description = "Number of items per page (default: 20, max: 100)")
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
        "Listing users with page={}, page_size={}",
        params.page,
        params.page_size
    );

    if params.page == 0 {
        return Err(ApiError::bad_request(
            "page is less than minimum value of 1",
        ));
    }

    if params.page_size > PAGE_SIZE_MAX {
        return Err(ApiError::bad_request(format!(
            "page_size exceeds maximum value of {}",
            PAGE_SIZE_MAX
        )));
    }

    let (users, total) = app_state
        .user_service
        .list_users(params.page, params.page_size)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    let total_pages = ((total as f64) / (params.page_size as f64)).ceil() as u32;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(Into::into).collect(),
        page: params.page,
        page_size: params.page_size,
        total,
        total_pages,
    }))
}

/// Create user router with all routes (requires authentication)
pub fn create_user_router() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_current_user))
        .route("/me/settings", get(get_user_settings))
        .route("/me/settings", post(update_user_settings))
        .route("/me/settings", patch(update_user_settings_partially))
}

/// Create admin user router (requires admin authentication)
pub fn create_admin_user_router() -> Router<AppState> {
    Router::new().route("/", get(list_users))
}
