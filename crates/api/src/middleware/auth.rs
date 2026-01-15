use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use services::{SessionId, UserId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::error::ApiError;

/// Authenticated user information inserted into request extensions by the auth middleware.
/// Extract in route handlers using `Extension<AuthenticatedUser>`
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub session_id: SessionId,
}

/// State for authentication middleware
#[derive(Clone)]
pub struct AuthState {
    pub session_repository: Arc<dyn services::auth::ports::SessionRepository>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub admin_domains: Arc<Vec<String>>,
}

/// Hash a session token for lookup
fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extract and validate token from Authorization header
fn extract_token_from_request(request: &Request) -> Result<String, ApiError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    let auth_value = auth_header.ok_or_else(|| {
        tracing::warn!("No authorization header found");
        ApiError::missing_auth_header()
    })?;

    let token = auth_value.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::warn!(
            "Authorization header does not start with 'Bearer ', header: {}",
            auth_value
        );
        ApiError::invalid_auth_header()
    })?;

    // Validate token format (should start with sess_ and be the right length)
    if !token.starts_with("sess_") {
        tracing::warn!("Invalid session token format: token does not start with 'sess_'");
        return Err(ApiError::invalid_token());
    }

    if token.len() != 37 {
        tracing::warn!(
            "Invalid session token format: expected length 37, got {}",
            token.len()
        );
        return Err(ApiError::invalid_token());
    }

    Ok(token.to_string())
}

/// Authenticate a token string (without needing Request object)
async fn authenticate_token_string(
    token: String,
    auth_state: &AuthState,
) -> Result<AuthenticatedUser, ApiError> {
    tracing::debug!(
        "Authenticating token, length: {}, prefix: {}...",
        token.len(),
        &token.chars().take(8).collect::<String>()
    );

    // Hash the token and look it up
    let token_hash = hash_session_token(&token);
    tracing::debug!(
        "Token hashed, hash prefix: {}...",
        &token_hash.chars().take(16).collect::<String>()
    );

    authenticate_session_by_token(auth_state, token_hash).await
}

/// Authenticate a session by token hash
async fn authenticate_session_by_token(
    state: &AuthState,
    token_hash: String,
) -> Result<AuthenticatedUser, ApiError> {
    tracing::debug!(
        "Authenticating session by token hash: {}...",
        &token_hash.chars().take(16).collect::<String>()
    );

    // Look up the session by token hash
    let session = state
        .session_repository
        .get_session_by_token_hash(token_hash.clone())
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get session from repository for token_hash {}...: {}",
                &token_hash.chars().take(16).collect::<String>(),
                e
            );
            ApiError::internal_server_error("Failed to authenticate session")
        })?
        .ok_or_else(|| {
            tracing::warn!(
                "Session not found for token_hash: {}...",
                &token_hash.chars().take(16).collect::<String>()
            );
            ApiError::session_not_found()
        })?;

    tracing::debug!(
        "Session found: session_id={}, user_id={}, created_at={}, expires_at={}",
        session.session_id,
        session.user_id,
        session.created_at,
        session.expires_at
    );

    // Check if session is expired
    let now = Utc::now();
    if session.expires_at < now {
        let time_expired = now.signed_duration_since(session.expires_at);
        tracing::warn!(
            "Session expired: session_id={}, expired {} seconds ago",
            session.session_id,
            time_expired.num_seconds()
        );
        return Err(ApiError::session_expired());
    }

    let time_until_expiry = session.expires_at.signed_duration_since(now);
    tracing::debug!(
        "Session valid for {} more seconds",
        time_until_expiry.num_seconds()
    );

    tracing::info!(
        "Successfully authenticated session: user_id={}, session_id={}",
        session.user_id,
        session.session_id
    );

    Ok(AuthenticatedUser {
        user_id: session.user_id,
        session_id: session.session_id,
    })
}

/// Extracts the domain portion from an email address.
///
/// # Arguments
/// * `email` - The email address to parse
///
/// # Returns
/// The lowercase domain if the email contains an '@' symbol, None otherwise
///
/// # Examples
/// * `user@example.com` -> `Some("example.com")`
/// * `invalid-email` -> `None`
fn extract_email_domain(email: &str) -> Option<String> {
    email
        .split_once('@')
        .map(|(_, domain)| domain.to_lowercase())
}

/// Check if email domain is in the allowed admin domains list
fn is_admin_domain(email: &str, admin_domains: &[String]) -> bool {
    if admin_domains.is_empty() {
        tracing::warn!("Admin domains list is empty, denying access");
        return false;
    }

    if let Some(domain) = extract_email_domain(email) {
        admin_domains.contains(&domain)
    } else {
        tracing::warn!("Failed to extract domain from email: {}", email);
        false
    }
}

/// Authentication middleware that validates session tokens
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    tracing::info!("Auth middleware invoked for {} {}", method, path);

    let token = extract_token_from_request(&request).map_err(|e| e.into_response())?;
    let user = authenticate_token_string(token, &state)
        .await
        .map_err(|e| e.into_response())?;

    tracing::info!(
        "Authentication successful for user_id={}, session_id={} on {} {}",
        user.user_id,
        user.session_id,
        method,
        path
    );
    // Add authenticated user to request extensions
    request.extensions_mut().insert(user);
    let response = next.run(request).await;
    tracing::debug!("Request completed with status: {}", response.status());
    Ok(response)
}

/// Optional authentication middleware - doesn't fail if no token provided
/// Use this for routes that can work with or without authentication (e.g., public shares)
/// Inserts Option<AuthenticatedUser> into request extensions
pub async fn optional_auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    tracing::debug!("Optional auth middleware invoked for {} {}", method, path);

    let user: Option<AuthenticatedUser> = match extract_token_from_request(&request) {
        Ok(token) => match authenticate_token_string(token, &state).await {
            Ok(user) => {
                tracing::info!(
                    "Optional auth: authenticated user_id={} on {} {}",
                    user.user_id,
                    method,
                    path
                );
                Some(user)
            }
            Err(e) => {
                tracing::debug!(
                    "Optional auth: token validation failed on {} {}: {:?}",
                    method,
                    path,
                    e
                );
                None
            }
        },
        Err(_) => {
            tracing::debug!(
                "Optional auth: no token provided on {} {}",
                method,
                path
            );
            None
        }
    };

    // Add optional user to request extensions
    request.extensions_mut().insert(user);
    let response = next.run(request).await;
    Ok(response)
}

/// Admin authentication middleware that validates session tokens and checks admin domain
/// This middleware first authenticates the user, then checks if their email domain
/// is in the allowed admin domains list.
pub async fn admin_auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    tracing::info!("Admin auth middleware invoked for {} {}", method, path);

    let token = extract_token_from_request(&request).map_err(|e| e.into_response())?;
    let authenticated_user = authenticate_token_string(token, &state)
        .await
        .map_err(|err| {
            tracing::error!("Authentication failed in admin middleware: {:?}", err);
            err.into_response()
        })?;

    tracing::info!(
        "User authenticated, checking admin access for user_id={}",
        authenticated_user.user_id
    );

    // Get user profile to check email domain
    let user_profile = state
        .user_service
        .get_user_profile(authenticated_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user profile for admin check: {}", e);
            ApiError::internal_server_error("Failed to verify admin access").into_response()
        })?;

    let user_email = &user_profile.user.email;
    tracing::debug!("Checking admin access for email: {}", user_email);

    if !is_admin_domain(user_email, &state.admin_domains) {
        tracing::warn!(
            "Admin access denied for user_id={}, email={}, domain not in allowed list: {:?}",
            authenticated_user.user_id,
            user_email,
            &state.admin_domains
        );
        return Err(ApiError::forbidden("Admin access required").into_response());
    }

    tracing::info!(
        "Admin access granted for user_id={}, email={}",
        authenticated_user.user_id,
        user_email
    );

    // Add authenticated user to request extensions
    request.extensions_mut().insert(authenticated_user);
    let response = next.run(request).await;
    Ok(response)
}
