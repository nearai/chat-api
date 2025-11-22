use crate::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
    Router,
};
use serde::Deserialize;
use services::SessionId;

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

/// Request body for mock login (test only)
#[cfg(feature = "test")]
#[derive(Debug, Deserialize)]
pub struct MockLoginRequest {
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
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
    tracing::info!(
        "Google OAuth login initiated - redirect_uri: {:?}, frontend_callback: {:?}",
        params.redirect_uri,
        params.frontend_callback
    );

    let redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    tracing::debug!("Using OAuth redirect_uri: {}", redirect_uri);

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Google,
            redirect_uri.clone(),
            params.frontend_callback.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate Google authorization URL: {}", e);
            ApiError::oauth_provider_error("Google")
        })?;

    tracing::info!("Google OAuth URL generated successfully, redirecting to Google");
    tracing::debug!("Google OAuth URL: {}", auth_url);

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
    tracing::info!(
        "OAuth callback received - code length: {}, state: {}",
        params.code.len(),
        params.state
    );

    // The provider is determined from the state stored in the database
    // Returns (session, frontend_callback_url, is_new_user)
    let (session, frontend_callback, is_new_user) = app_state
        .oauth_service
        .handle_callback_unified(params.code.clone(), params.state.clone())
        .await
        .map_err(|e| {
            tracing::error!("OAuth callback failed for state {}: {}", params.state, e);
            ApiError::oauth_failed()
        })?;

    tracing::info!(
        "OAuth callback processed successfully - session_id: {}, user_id: {}",
        session.session_id,
        session.user_id
    );

    let token = session.token.ok_or_else(|| {
        tracing::error!(
            "Session token not returned from service for session_id: {}",
            session.session_id
        );
        ApiError::internal_server_error("Failed to create session")
    })?;

    tracing::debug!("Session token generated, length: {}", token.len());

    // Use frontend_callback from OAuth state, or fall back to FRONTEND_URL env var
    let frontend_url = frontend_callback.clone().unwrap_or_else(|| {
        let fallback =
            std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        tracing::debug!(
            "No frontend_callback in OAuth state, using fallback: {}",
            fallback
        );
        fallback
    });

    tracing::info!("Redirecting to frontend: {}", frontend_url);

    let mut callback_url = format!(
        "{}/auth/callback?token={}&expires_at={}",
        frontend_url,
        urlencoding::encode(&token),
        urlencoding::encode(&session.expires_at.to_rfc3339())
    );
    if is_new_user {
        callback_url.push_str("&is_new_user=true");
    }

    tracing::debug!("Final callback URL: {}", callback_url);

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
    tracing::info!(
        "Github OAuth login initiated - redirect_uri: {:?}, frontend_callback: {:?}",
        params.redirect_uri,
        params.frontend_callback
    );

    let redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));

    tracing::debug!("Using OAuth redirect_uri: {}", redirect_uri);

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Github,
            redirect_uri.clone(),
            params.frontend_callback.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate Github authorization URL: {}", e);
            ApiError::oauth_provider_error("Github")
        })?;

    tracing::info!("Github OAuth URL generated successfully, redirecting to Github");
    tracing::debug!("Github OAuth URL: {}", auth_url);

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
    tracing::info!("Logout requested for session_id: {}", session_id);

    app_state
        .oauth_service
        .revoke_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke session {}: {}", session_id, e);
            ApiError::logout_failed()
        })?;

    tracing::info!("Session {} successfully revoked", session_id);

    Ok(StatusCode::NO_CONTENT)
}

/// Mock login handler for testing (test only)
///
/// This endpoint allows creating a user and getting a session token directly,
/// bypassing the OAuth flow. Only available in test builds.
#[cfg(feature = "test")]
pub async fn mock_login(
    State(app_state): State<AppState>,
    axum::Json(request): axum::Json<MockLoginRequest>,
) -> Result<axum::Json<crate::models::AuthResponse>, ApiError> {
    tracing::info!("Mock login requested for email: {}", request.email);

    // Check if user already exists
    let user = match app_state
        .user_repository
        .get_user_by_email(&request.email)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check existing user: {}", e);
            ApiError::internal_server_error("Failed to check user")
        })? {
        Some(existing_user) => {
            tracing::info!("User already exists: user_id={}", existing_user.id);
            existing_user
        }
        None => {
            // Create new user
            tracing::info!("Creating new user with email: {}", request.email);
            app_state
                .user_repository
                .create_user(
                    request.email.clone(),
                    request.name.clone(),
                    request.avatar_url.clone(),
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create user: {}", e);
                    ApiError::internal_server_error("Failed to create user")
                })?
        }
    };

    // Create session
    let session = app_state
        .session_repository
        .create_session(user.id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            ApiError::internal_server_error("Failed to create session")
        })?;

    let token = session.token.ok_or_else(|| {
        tracing::error!("Session token not returned for user_id: {}", user.id);
        ApiError::internal_server_error("Failed to create session")
    })?;

    tracing::info!(
        "Mock login successful - user_id={}, session_id={}",
        user.id,
        session.session_id
    );

    Ok(axum::Json(crate::models::AuthResponse {
        token,
        expires_at: session.expires_at.to_rfc3339(),
    }))
}

/// Create OAuth router with all routes
pub fn create_oauth_router() -> Router<AppState> {
    let router = Router::new()
        // OAuth initiation routes
        .route("/google", get(google_login))
        .route("/github", get(github_login))
        // Unified callback route for all providers
        .route("/callback", get(oauth_callback))
        // Logout route
        .route("/logout", get(logout));

    // Add mock login route only in test builds
    #[cfg(feature = "test")]
    let router = router.route("/mock-login", axum::routing::post(mock_login));

    router
}
