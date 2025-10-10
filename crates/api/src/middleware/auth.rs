use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use services::{SessionId, UserId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Authenticated user information
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
) -> Result<Response, StatusCode> {
    // Try to extract authentication from Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    tracing::debug!("Auth middleware: {:?}", auth_header);

    let auth_result = if let Some(auth_value) = auth_header {
        if let Some(token) = auth_value.strip_prefix("Bearer ") {
            tracing::debug!("Extracted Bearer token");

            // Validate token format (should start with sess_ and be the right length)
            if !token.starts_with("sess_") || token.len() != 37 {
                tracing::warn!("Invalid session token format");
                return Err(StatusCode::UNAUTHORIZED);
            }

            // Hash the token and look it up
            let token_hash = hash_session_token(token);
            authenticate_session_by_token(&state, token_hash).await
        } else {
            tracing::warn!("Authorization header does not start with 'Bearer '");
            Err(StatusCode::UNAUTHORIZED)
        }
    } else {
        tracing::warn!("No authorization header found");
        Err(StatusCode::UNAUTHORIZED)
    };

    match auth_result {
        Ok(user) => {
            // Add authenticated user to request extensions
            request.extensions_mut().insert(user);
            Ok(next.run(request).await)
        }
        Err(status) => Err(status),
    }
}

/// Authenticate a session by token hash
async fn authenticate_session_by_token(
    state: &AuthState,
    token_hash: String,
) -> Result<AuthenticatedUser, StatusCode> {
    // Look up the session by token hash
    let session = state
        .session_repository
        .get_session_by_token_hash(token_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get session: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("Session not found");
            StatusCode::UNAUTHORIZED
        })?;

    // Check if session is expired
    if session.expires_at < Utc::now() {
        tracing::warn!("Session expired: {}", session.session_id);
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(AuthenticatedUser {
        user_id: session.user_id,
        session_id: session.session_id,
    })
}
