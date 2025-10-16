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
}

/// Hash a session token for lookup
fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Authentication middleware that validates session tokens
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();
    let method = request.method().clone();
    
    tracing::info!(
        "Auth middleware invoked for {} {}",
        method,
        path
    );

    // Try to extract authentication from Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    tracing::debug!("Auth middleware: processing request with auth_header present: {}", auth_header.is_some());
    
    if let Some(auth_value) = auth_header {
        tracing::debug!("Authorization header value prefix: {}...", &auth_value.chars().take(10).collect::<String>());
    }

    let auth_result = if let Some(auth_value) = auth_header {
        if let Some(token) = auth_value.strip_prefix("Bearer ") {
            tracing::debug!("Extracted Bearer token, length: {}, prefix: {}...", token.len(), &token.chars().take(8).collect::<String>());

            // Validate token format (should start with sess_ and be the right length)
            if !token.starts_with("sess_") {
                tracing::warn!("Invalid session token format: token does not start with 'sess_'");
                return Err(ApiError::invalid_token().into_response());
            }
            
            if token.len() != 37 {
                tracing::warn!("Invalid session token format: expected length 37, got {}", token.len());
                return Err(ApiError::invalid_token().into_response());
            }

            tracing::debug!("Token format validation passed, proceeding to authenticate");
            
            // Hash the token and look it up
            let token_hash = hash_session_token(token);
            tracing::debug!("Token hashed, hash prefix: {}...", &token_hash.chars().take(16).collect::<String>());
            
            authenticate_session_by_token(&state, token_hash).await
        } else {
            tracing::warn!("Authorization header does not start with 'Bearer ', header: {}", auth_value);
            Err(ApiError::invalid_auth_header())
        }
    } else {
        tracing::warn!("No authorization header found for {} {}", method, path);
        Err(ApiError::missing_auth_header())
    };

    match auth_result {
        Ok(user) => {
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
        Err(err) => {
            tracing::error!("Authentication failed for {} {}: {:?}", method, path, err);
            Err(err.into_response())
        }
    }
}

/// Authenticate a session by token hash
async fn authenticate_session_by_token(
    state: &AuthState,
    token_hash: String,
) -> Result<AuthenticatedUser, ApiError> {
    tracing::debug!("Authenticating session by token hash: {}...", &token_hash.chars().take(16).collect::<String>());
    
    // Look up the session by token hash
    let session = state
        .session_repository
        .get_session_by_token_hash(token_hash.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to get session from repository for token_hash {}...: {}", &token_hash.chars().take(16).collect::<String>(), e);
            ApiError::internal_server_error("Failed to authenticate session")
        })?
        .ok_or_else(|| {
            tracing::warn!("Session not found for token_hash: {}...", &token_hash.chars().take(16).collect::<String>());
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
