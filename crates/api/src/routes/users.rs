use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

use crate::{middleware::AuthenticatedUser, models::*, state::AppState};

/// Get current user
///
/// Returns the profile of the currently authenticated user, including their linked OAuth accounts.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "Users",
    responses(
        (status = 200, description = "Current user profile", body = UserProfileResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_current_user(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserProfileResponse>, Response> {
    tracing::info!("Getting user profile for user: {}", user.user_id);
    match app_state.user_service.get_user_profile(user.user_id).await {
        Ok(profile) => Ok(Json(profile.into())),
        Err(e) => {
            tracing::error!("Failed to get user profile: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to retrieve user profile".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Create user router with all routes
pub fn create_user_router() -> Router<AppState> {
    Router::new().route("/me", get(get_current_user))
}
