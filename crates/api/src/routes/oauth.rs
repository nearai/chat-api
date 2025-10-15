use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
    Router,
};
use serde::Deserialize;
use services::SessionId;

use crate::{error::ApiError, state::AppState};

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
    pub frontend_callback: Option<String>,
}

/// Handler for initiating Google OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/google",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional OAuth redirect URI (usually your API callback)"),
        ("frontend_callback" = Option<String>, Query, description = "Frontend URL to redirect to after authentication")
    ),
    responses(
        (status = 302, description = "Redirect to Google OAuth"),
        (status = 502, description = "OAuth provider error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn google_login(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthInitQuery>,
) -> Result<Redirect, ApiError> {
    let redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Google,
            redirect_uri,
            params.frontend_callback,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate Google authorization URL: {}", e);
            ApiError::oauth_provider_error("Google")
        })?;

    Ok(Redirect::temporary(&auth_url))
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
        (status = 302, description = "Redirect to frontend with token"),
        (status = 401, description = "Authentication failed", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn oauth_callback(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Redirect, ApiError> {
    // The provider is determined from the state stored in the database
    // Returns (session, frontend_callback_url)
    let (session, frontend_callback) = app_state
        .oauth_service
        .handle_callback_unified(params.code, params.state)
        .await
        .map_err(|e| {
            tracing::error!("OAuth callback failed: {}", e);
            ApiError::oauth_failed()
        })?;

    let token = session.token.ok_or_else(|| {
        tracing::error!("Session token not returned from service");
        ApiError::internal_server_error("Failed to create session")
    })?;

    // Use frontend_callback from OAuth state, or fall back to FRONTEND_URL env var
    let frontend_url = frontend_callback.unwrap_or_else(|| {
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    });

    tracing::info!("Redirecting to frontend: {}", frontend_url);

    let callback_url = format!(
        "{}/auth/callback?token={}&expires_at={}",
        frontend_url,
        urlencoding::encode(&token),
        urlencoding::encode(&session.expires_at.to_rfc3339())
    );

    Ok(Redirect::temporary(&callback_url))
}

/// Handler for initiating Github OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/github",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional OAuth redirect URI (usually your API callback)"),
        ("frontend_callback" = Option<String>, Query, description = "Frontend URL to redirect to after authentication")
    ),
    responses(
        (status = 302, description = "Redirect to Github OAuth"),
        (status = 502, description = "OAuth provider error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn github_login(
    State(app_state): State<AppState>,
    Query(params): Query<OAuthInitQuery>,
) -> Result<Redirect, ApiError> {
    let redirect_uri = params
        .redirect_uri
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Github,
            redirect_uri,
            params.frontend_callback,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate Github authorization URL: {}", e);
            ApiError::oauth_provider_error("Github")
        })?;

    Ok(Redirect::temporary(&auth_url))
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
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn logout(
    State(app_state): State<AppState>,
    Query(session_id): Query<SessionId>,
) -> Result<StatusCode, ApiError> {
    app_state
        .oauth_service
        .revoke_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke session: {}", e);
            ApiError::logout_failed()
        })?;

    Ok(StatusCode::NO_CONTENT)
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
