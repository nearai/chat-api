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

/// Agent API key authentication info inserted into request extensions
/// Extract in route handlers using `Extension<AuthenticatedApiKey>`
#[derive(Debug, Clone)]
pub struct AuthenticatedApiKey {
    pub api_key_info: services::agent::ports::AgentApiKey,
    pub instance: services::agent::ports::AgentInstance,
}

/// Unified authentication type for endpoints that accept both session tokens and API keys
/// Used to conditionally apply subscription gating based on auth method
#[derive(Debug, Clone)]
pub enum ChatCompletionsAuth {
    /// Session token authenticated user - no subscription gating required
    User(AuthenticatedUser),
    /// API key authenticated user - subject to subscription gating and token limits
    ApiKey(Box<AuthenticatedApiKey>),
}

impl ChatCompletionsAuth {
    /// Returns true if this is API key authentication (requires subscription validation)
    pub fn is_api_key(&self) -> bool {
        matches!(self, Self::ApiKey(_))
    }

    /// Returns true if this is session token authentication (no subscription validation)
    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }
}

/// State for agent API key authentication middleware
#[derive(Clone)]
pub struct AgentAuthState {
    pub agent_service: Arc<dyn services::agent::AgentService>,
    pub agent_repository: Arc<dyn services::agent::ports::AgentRepository>,
}

/// Combined state for chat completions authentication (supports both session tokens and API keys)
#[derive(Clone)]
pub struct ChatCompletionsAuthState {
    pub auth_state: AuthState,
    pub agent_auth_state: AgentAuthState,
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
            tracing::debug!("Optional auth: no token provided on {} {}", method, path);
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

/// Extract and validate Agent API key from Authorization header
fn extract_agent_api_key_from_request(request: &Request) -> Result<String, ApiError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    let auth_value = auth_header.ok_or_else(|| {
        tracing::warn!("No authorization header found for Agent API key");
        ApiError::missing_auth_header()
    })?;

    let token = auth_value.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::warn!(
            "Authorization header does not start with 'Bearer ', header: {}",
            auth_value
        );
        ApiError::invalid_auth_header()
    })?;

    // Validate API key format (should start with ag_ and be 35 chars)
    if !token.starts_with("ag_") {
        tracing::warn!("Invalid agent API key format: does not start with 'ag_'");
        return Err(ApiError::invalid_token());
    }

    if token.len() != 35 {
        tracing::warn!(
            "Invalid agent API key format: expected length 35, got {}",
            token.len()
        );
        return Err(ApiError::invalid_token());
    }

    Ok(token.to_string())
}

/// Hash an API key for lookup
fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Agent API key authentication middleware
pub async fn agent_api_key_middleware(
    State(state): State<AgentAuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    tracing::info!(
        "Agent API key auth middleware invoked for {} {}",
        method,
        path
    );

    let api_key = extract_agent_api_key_from_request(&request).map_err(|e| e.into_response())?;

    // Hash the API key for lookup
    let key_hash = hash_api_key(&api_key);
    tracing::debug!(
        "Agent API key hashed, hash prefix: {}...",
        &key_hash.chars().take(16).collect::<String>()
    );

    // Get instance and API key info from repository
    let (instance, api_key_info) = state
        .agent_repository
        .get_instance_by_api_key_hash(&key_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get API key from repository: {}", e);
            ApiError::internal_server_error("Failed to authenticate API key").into_response()
        })?
        .ok_or_else(|| {
            tracing::warn!("Agent API key not found or inactive");
            ApiError::invalid_token().into_response()
        })?;

    // Check if key is expired
    if let Some(expires_at) = api_key_info.expires_at {
        let now = Utc::now();
        if expires_at < now {
            tracing::warn!(
                "Agent API key expired: api_key_id={}, expired_at={}",
                api_key_info.id,
                expires_at
            );
            return Err(ApiError::invalid_token().into_response());
        }
    }

    // Validate instance has required connection info
    if instance.instance_url.is_none() || instance.instance_token.is_none() {
        tracing::warn!(
            "Agent instance missing connection info: instance_id={}",
            instance.id
        );
        return Err(
            ApiError::internal_server_error("Instance not properly configured").into_response(),
        );
    }

    // Update last_used_at timestamp
    if let Err(e) = state
        .agent_repository
        .update_api_key_last_used(api_key_info.id)
        .await
    {
        tracing::error!(
            "Failed to update API key last_used_at: api_key_id={}, error={}",
            api_key_info.id,
            e
        );
        // Continue despite this error
    }

    tracing::info!(
        "Agent API key authenticated: user_id={}, instance_id={}, api_key_id={}",
        api_key_info.user_id,
        instance.id,
        api_key_info.id
    );

    // Create authenticated API key info
    let authenticated_api_key = AuthenticatedApiKey {
        api_key_info: api_key_info.clone(),
        instance,
    };

    // Also insert AuthenticatedUser for rate limiting to work.
    // Derive a deterministic session ID from the API key ID so that
    // requests authenticated with the same API key share a stable logical session identifier.
    let mut hasher = Sha256::new();
    hasher.update(api_key_info.id.as_bytes());
    let hash = hasher.finalize();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&hash[..16]);
    let authenticated_user = AuthenticatedUser {
        user_id: api_key_info.user_id,
        session_id: SessionId(uuid::Uuid::from_bytes(uuid_bytes)),
    };

    request.extensions_mut().insert(authenticated_api_key);
    request.extensions_mut().insert(authenticated_user);

    let response = next.run(request).await;
    tracing::debug!(
        "Agent API key request completed with status: {}",
        response.status()
    );
    Ok(response)
}

/// Unified middleware for chat/completions endpoint that accepts both session tokens and API keys.
/// Tries API key first, falls back to session token.
pub async fn chat_completions_auth_middleware(
    State(combined_state): State<ChatCompletionsAuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Try API key authentication first
    let api_key_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    if let Some(api_key_str) = api_key_header {
        // Try to authenticate as API key
        match authenticate_api_key(&combined_state.agent_auth_state, &api_key_str).await {
            Ok((api_key_info, instance)) => {
                let authenticated_api_key = AuthenticatedApiKey {
                    api_key_info: api_key_info.clone(),
                    instance,
                };

                // Create deterministic session ID from API key for rate limiting
                let mut hasher = Sha256::new();
                hasher.update(api_key_info.id.as_bytes());
                let hash = hasher.finalize();
                let mut uuid_bytes = [0u8; 16];
                uuid_bytes.copy_from_slice(&hash[..16]);
                let authenticated_user = AuthenticatedUser {
                    user_id: api_key_info.user_id,
                    session_id: SessionId(uuid::Uuid::from_bytes(uuid_bytes)),
                };

                let auth = ChatCompletionsAuth::ApiKey(Box::new(authenticated_api_key));
                request.extensions_mut().insert(auth);
                request.extensions_mut().insert(authenticated_user);
                return Ok(next.run(request).await);
            }
            Err(_) => {
                // API key auth failed, fall through to session token auth
            }
        }
    }

    // Fall back to session token authentication
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(crate::error::ApiErrorResponse {
                    code: "unauthorized".to_string(),
                    message: "Missing or invalid Authorization header".to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?;

    let token_hash = hash_session_token(&token);
    let session = combined_state
        .auth_state
        .session_repository
        .get_session_by_token_hash(token_hash)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(crate::error::ApiErrorResponse {
                    code: "internal_error".to_string(),
                    message: "Failed to verify session".to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(crate::error::ApiErrorResponse {
                    code: "unauthorized".to_string(),
                    message: "Invalid or expired session token".to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?;

    // Check if session is expired
    if session.expires_at < Utc::now() {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(crate::error::ApiErrorResponse {
                code: "unauthorized".to_string(),
                message: "Session token expired".to_string(),
                details: None,
            }),
        )
            .into_response());
    }

    let authenticated_user = AuthenticatedUser {
        user_id: session.user_id,
        session_id: session.session_id,
    };
    let auth = ChatCompletionsAuth::User(authenticated_user.clone());
    request.extensions_mut().insert(auth);
    // Also insert AuthenticatedUser for rate limiting middleware
    request.extensions_mut().insert(authenticated_user);

    Ok(next.run(request).await)
}

/// Helper function to authenticate API key (extracted from agent_api_key_middleware logic)
async fn authenticate_api_key(
    state: &AgentAuthState,
    api_key_str: &str,
) -> Result<
    (
        services::agent::ports::AgentApiKey,
        services::agent::ports::AgentInstance,
    ),
    String,
> {
    // Hash the API key
    let mut hasher = Sha256::new();
    hasher.update(api_key_str.as_bytes());
    let api_key_hash = format!("{:x}", hasher.finalize());

    // Look up API key
    let api_key_info = state
        .agent_repository
        .get_api_key_by_hash(&api_key_hash)
        .await
        .map_err(|_| "Database error".to_string())?
        .ok_or_else(|| "Invalid API key".to_string())?;

    // Get the bound instance
    let instance_id = api_key_info
        .instance_id
        .ok_or_else(|| "API key not bound to instance".to_string())?;
    let instance = state
        .agent_repository
        .get_instance(instance_id)
        .await
        .map_err(|_| "Database error".to_string())?
        .ok_or_else(|| "Instance not found".to_string())?;

    Ok((api_key_info, instance))
}
