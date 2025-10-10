use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use services::SessionId;

use crate::{models::*, state::AppState};

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

/// Query parameters for OAuth initiation
#[derive(Debug, Deserialize)]
pub struct OAuthInitQuery {
    pub redirect_uri: Option<String>,
}

/// Handler for initiating Google OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/google",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional redirect URI after authentication")
    ),
    responses(
        (status = 302, description = "Redirect to Google OAuth"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn google_login(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthInitQuery>,
) -> Result<Redirect, Response> {
    let redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    match app_state
        .oauth_service
        .get_authorization_url(services::auth::ports::OAuthProvider::Google, redirect_uri)
        .await
    {
        Ok(auth_url) => Ok(Redirect::temporary(&auth_url)),
        Err(e) => {
            tracing::error!("Failed to generate Google authorization URL: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to initiate OAuth flow".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Handler for unified OAuth callback (works for all providers)
#[utoipa::path(
    get,
    path = "/v1/auth/callback",
    tag = "Auth",
    params(
        ("code" = String, Query, description = "Authorization code from OAuth provider"),
        ("state" = String, Query, description = "State parameter for CSRF protection")
    ),
    responses(
        (status = 200, description = "Successfully authenticated", body = AuthResponse),
        (status = 401, description = "Authentication failed", body = ErrorResponse)
    )
)]
pub async fn oauth_callback(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Json<AuthResponse>, Response> {
    // The provider is determined from the state stored in the database
    match app_state
        .oauth_service
        .handle_callback_unified(params.code, params.state)
        .await
    {
        Ok(session) => {
            let token = session.token.ok_or_else(|| {
                tracing::error!("Session token not returned from service");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to create session".to_string(),
                    }),
                )
                    .into_response()
            })?;

            Ok(Json(AuthResponse {
                token,
                expires_at: session.expires_at.to_rfc3339(),
            }))
        }
        Err(e) => {
            tracing::error!("OAuth callback failed: {}", e);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Handler for initiating Github OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/github",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional redirect URI after authentication")
    ),
    responses(
        (status = 302, description = "Redirect to Github OAuth"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn github_login(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthInitQuery>,
) -> Result<Redirect, Response> {
    let redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    match app_state
        .oauth_service
        .get_authorization_url(services::auth::ports::OAuthProvider::Github, redirect_uri)
        .await
    {
        Ok(auth_url) => Ok(Redirect::temporary(&auth_url)),
        Err(e) => {
            tracing::error!("Failed to generate Github authorization URL: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to initiate OAuth flow".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Handler for logout
#[utoipa::path(
    get,
    path = "/v1/auth/logout",
    tag = "Auth",
    params(
        ("session_id" = uuid::Uuid, Query, description = "Session ID to revoke")
    ),
    responses(
        (status = 204, description = "Successfully logged out"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn logout(
    State(app_state): State<AppState>,
    Query(session_id): Query<SessionId>,
) -> Result<StatusCode, Response> {
    match app_state.oauth_service.revoke_session(session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!("Failed to revoke session: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to logout".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Create OAuth router with all routes
pub fn create_oauth_router() -> Router<AppState> {
    Router::new()
        // OAuth initiation routes
        .route("/google", get(google_login))
        .route("/github", get(github_login))
        // Unified callback route for all providers
        .route("/callback", get(oauth_callback))
        // Logout route
        .route("/logout", get(logout))
}
