use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::extract::Query;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use near_api::signer::NEP413Payload;
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityType, AuthMethod, RecordActivityRequest};
use services::auth::ports::OAuthProvider;
use services::auth::{near::SignedMessage, AssertionCredential, PasskeyAssertionOptions};
use services::metrics::consts::{
    METRIC_USER_LOGIN, METRIC_USER_SIGNUP, TAG_AUTH_METHOD, TAG_IS_NEW_USER,
};
use services::SessionId;
use utoipa::ToSchema;

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

/// Request body for logout
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LogoutRequest {
    /// Session ID to revoke
    pub session_id: SessionId,
}

/// Request body for mock login (test only)
#[cfg(feature = "test")]
#[derive(Debug, Deserialize)]
pub struct MockLoginRequest {
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    /// Optional OAuth provider to link as a mocked linked account (google/github/near)
    pub oauth_provider: Option<String>,
}

/// Request body for NEAR authentication (NEP-413)
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct NearAuthRequest {
    /// The signed message from the wallet
    pub signed_message: NearSignedMessageJson,
    /// The payload that was signed
    pub payload: NearPayloadJson,
}

/// Signed message from wallet (NEP-413 SignedMessage)
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NearSignedMessageJson {
    /// NEAR account ID (e.g., "alice.near")
    pub account_id: String,
    /// Public key used to sign (e.g., "ed25519:...")
    pub public_key: String,
    /// Base64-encoded signature
    pub signature: String,
    /// Optional state for browser wallets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Payload that was signed (NEP-413 Payload)
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NearPayloadJson {
    /// The message that was signed
    pub message: String,
    /// The nonce (as array of 32 bytes)
    pub nonce: Vec<u8>,
    /// The recipient (your app identifier)
    pub recipient: String,
    /// Optional callback URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

impl TryFrom<NearSignedMessageJson> for SignedMessage {
    type Error = anyhow::Error;

    fn try_from(msg: NearSignedMessageJson) -> Result<Self, Self::Error> {
        use base64::prelude::*;
        use near_api::types::Signature;

        let public_key: near_api::PublicKey = msg.public_key.parse()?;

        // Parse base64 signature and create Signature based on key type
        let sig_bytes = BASE64_STANDARD.decode(&msg.signature)?;
        let signature = Signature::from_parts(public_key.key_type(), &sig_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;

        Ok(SignedMessage {
            account_id: msg.account_id.parse()?,
            public_key,
            signature,
            state: msg.state,
        })
    }
}

impl TryFrom<NearPayloadJson> for NEP413Payload {
    type Error = anyhow::Error;

    fn try_from(payload: NearPayloadJson) -> Result<Self, Self::Error> {
        let nonce: [u8; 32] = payload.nonce.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("Invalid nonce length: expected 32, got {}", v.len())
        })?;
        Ok(NEP413Payload {
            message: payload.message,
            nonce,
            recipient: payload.recipient,
            callback_url: payload.callback_url,
        })
    }
}

/// Response for NEAR authentication
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NearAuthResponse {
    /// Session token
    pub token: String,
    /// Session ID
    pub session_id: String,
    /// Token expiration time (RFC3339)
    pub expires_at: String,
    /// Whether this is a new user
    pub is_new_user: bool,
}

/// Response containing the WebAuthn options used to prompt a passkey assertion on the client
#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyOptionsResponse {
    #[serde(flatten)]
    pub options: PasskeyAssertionOptions,
    pub user_verification: String,
}

impl From<PasskeyAssertionOptions> for PasskeyOptionsResponse {
    fn from(options: PasskeyAssertionOptions) -> Self {
        Self {
            options,
            user_verification: "preferred".to_string(),
        }
    }
}

/// WebAuthn credential response payload coming from the browser
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyAssertionRequest {
    pub id: String,
    #[serde(rename = "raw_id")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: PasskeyAssertionResponsePayload,
}

/// Nested WebAuthn assertion response body
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyAssertionResponsePayload {
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
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
    // Returns (session, frontend_callback_url, is_new_user, provider)
    let (session, frontend_callback, is_new_user, provider) = app_state
        .oauth_service
        .handle_callback_unified(params.code.clone(), params.state.clone())
        .await
        .map_err(|e| {
            tracing::error!("OAuth callback failed for state {}: {}", params.state, e);
            ApiError::oauth_failed()
        })?;

    tracing::info!(
        "OAuth callback processed successfully - session_id: {}, user_id: {}, provider: {:?}",
        session.session_id,
        session.user_id,
        provider
    );

    // Record metrics and analytics
    let auth_method = match provider {
        OAuthProvider::Google => AuthMethod::Google,
        OAuthProvider::Github => AuthMethod::Github,
        OAuthProvider::Near => AuthMethod::Near,
    };
    let auth_method_str = auth_method.as_str();

    // Record metrics
    let metric_name = if is_new_user {
        METRIC_USER_SIGNUP
    } else {
        METRIC_USER_LOGIN
    };
    let tags = [
        format!("{}:{}", TAG_AUTH_METHOD, auth_method_str),
        format!("{}:{}", TAG_IS_NEW_USER, is_new_user),
    ];
    let tags_str: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
    app_state
        .metrics_service
        .record_count(metric_name, 1, &tags_str);

    // Record analytics in database
    let activity_type = if is_new_user {
        ActivityType::Signup
    } else {
        ActivityType::Login
    };
    if let Err(e) = app_state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: session.user_id,
            activity_type,
            auth_method: Some(auth_method),
            metadata: None,
        })
        .await
    {
        tracing::warn!("Failed to record analytics for OAuth callback: {}", e);
    }

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
        "{}/auth/callback?token={}&session_id={}&expires_at={}",
        frontend_url,
        urlencoding::encode(&token),
        urlencoding::encode(&session.session_id.to_string()),
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
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    request_body = LogoutRequest,
    responses(
        (status = 204, description = "Successfully logged out"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - session does not belong to authenticated user", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Session not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn logout(
    State(app_state): State<AppState>,
    Extension(authenticated_user): Extension<AuthenticatedUser>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, ApiError> {
    let session_id = request.session_id;
    tracing::info!(
        "Logout requested for session_id: {} by user_id: {}",
        session_id,
        authenticated_user.user_id
    );

    // Verify that the session belongs to the authenticated user
    let session = app_state
        .session_repository
        .get_session_by_id(session_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get session {}: {}", session_id, e);
            ApiError::logout_failed()
        })?;

    let session = session.ok_or_else(|| {
        tracing::warn!("Session {} not found", session_id);
        ApiError::session_id_not_found()
    })?;

    // Verify that the session belongs to the authenticated user
    if session.user_id != authenticated_user.user_id {
        tracing::warn!(
            "User {} attempted to logout session {} which belongs to user {}",
            authenticated_user.user_id,
            session_id,
            session.user_id
        );
        return Err(ApiError::forbidden("You can only logout your own sessions"));
    }

    app_state
        .oauth_service
        .revoke_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke session {}: {}", session_id, e);
            ApiError::logout_failed()
        })?;

    tracing::info!(
        "Session {} successfully revoked by user_id: {}",
        session_id,
        authenticated_user.user_id
    );

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

    // Optionally link a mocked OAuth account for this user (for tests)
    if let Some(provider_str) = request.oauth_provider.as_deref() {
        use services::user::ports::OAuthProvider;

        let provider = match provider_str.to_lowercase().as_str() {
            "google" => Some(OAuthProvider::Google),
            "github" => Some(OAuthProvider::Github),
            "near" => Some(OAuthProvider::Near),
            other => {
                tracing::warn!(
                    "Unknown oauth_provider '{}' in mock login for user_id={}; skipping link",
                    other,
                    user.id
                );
                None
            }
        };

        if let Some(provider) = provider {
            // Derive provider_user_id from email.
            // For NEAR we expect email like `alice.near@near` and use `alice.near` as provider_user_id.
            let provider_user_id = match provider {
                OAuthProvider::Near => {
                    if let Some((account_id, domain)) = request.email.split_once('@') {
                        if domain == "near" {
                            account_id.to_string()
                        } else {
                            request.email.clone()
                        }
                    } else {
                        request.email.clone()
                    }
                }
                _ => request.email.clone(),
            };

            if let Err(e) = app_state
                .user_repository
                .link_oauth_account(user.id, provider, provider_user_id)
                .await
            {
                tracing::warn!(
                    "Failed to link mock OAuth account for user_id={} provider={:?}: {}",
                    user.id,
                    provider,
                    e
                );
            } else {
                tracing::info!(
                    "Linked mock OAuth account for user_id={} provider={:?}",
                    user.id,
                    provider
                );
            }
        }
    }

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

/// Handler for NEAR wallet authentication
#[utoipa::path(
    post,
    path = "/v1/auth/near",
    tag = "Auth",
    request_body = NearAuthRequest,
    responses(
        (status = 200, description = "Successfully authenticated", body = NearAuthResponse),
        (status = 401, description = "Invalid signature or expired", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn near_auth(
    State(app_state): State<AppState>,
    Json(request): Json<NearAuthRequest>,
) -> Result<Json<NearAuthResponse>, ApiError> {
    tracing::info!(
        "NEAR authentication request for account: {}",
        request.signed_message.account_id
    );

    // Convert to near-api types
    let signed_message: SignedMessage = request
        .signed_message
        .try_into()
        .map_err(|e| ApiError::bad_request(format!("{}", e)))?;

    let payload: NEP413Payload = request
        .payload
        .try_into()
        .map_err(|e| ApiError::bad_request(format!("{}", e)))?;

    let (session, is_new_user) = app_state
        .oauth_service
        .authenticate_near(signed_message, payload)
        .await
        .map_err(|e| {
            tracing::error!("NEAR authentication failed: {}", e);
            ApiError::unauthorized(e.to_string())
        })?;

    // Record metrics and analytics
    let auth_method = AuthMethod::Near;
    let auth_method_str = auth_method.as_str();

    // Record metrics
    let metric_name = if is_new_user {
        METRIC_USER_SIGNUP
    } else {
        METRIC_USER_LOGIN
    };
    let tags = [
        format!("{}:{}", TAG_AUTH_METHOD, auth_method_str),
        format!("{}:{}", TAG_IS_NEW_USER, is_new_user),
    ];
    let tags_str: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
    app_state
        .metrics_service
        .record_count(metric_name, 1, &tags_str);

    // Record analytics in database
    let activity_type = if is_new_user {
        ActivityType::Signup
    } else {
        ActivityType::Login
    };
    if let Err(e) = app_state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: session.user_id,
            activity_type,
            auth_method: Some(auth_method),
            metadata: None,
        })
        .await
    {
        tracing::warn!("Failed to record analytics for NEAR auth: {}", e);
    }

    let token = session.token.ok_or_else(|| {
        tracing::error!(
            "Session token not returned from service for session_id: {}",
            session.session_id
        );
        ApiError::internal_server_error("Failed to create session")
    })?;

    tracing::info!(
        "NEAR authentication successful - session_id: {}, user_id: {}, is_new_user: {}",
        session.session_id,
        session.user_id,
        is_new_user
    );

    Ok(Json(NearAuthResponse {
        token,
        session_id: session.session_id.to_string(),
        expires_at: session.expires_at.to_rfc3339(),
        is_new_user,
    }))
}

/// Retrieve WebAuthn assertion options for passkey authentication
#[utoipa::path(
    get,
    path = "/v1/auth/passkey/options",
    tag = "Auth",
    responses(
        (status = 200, description = "Generated passkey assertion options", body = PasskeyOptionsResponse),
        (status = 500, description = "Failed to generate options", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn passkey_options(
    State(app_state): State<AppState>,
) -> Result<Json<PasskeyOptionsResponse>, ApiError> {
    tracing::debug!("Generating passkey assertion options");
    let options = app_state
        .passkey_service
        .generate_assertion_options(None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create passkey assertion challenge: {}", e);
            ApiError::internal_server_error("Failed to create passkey challenge")
        })?;

    Ok(Json(PasskeyOptionsResponse::from(options)))
}

/// Verify a WebAuthn assertion response and create a session
#[utoipa::path(
    post,
    path = "/v1/auth/passkey/verify",
    tag = "Auth",
    request_body = PasskeyAssertionRequest,
    responses(
        (status = 200, description = "Successfully authenticated with passkey", body = NearAuthResponse),
        (status = 401, description = "Invalid challenge response", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn passkey_verify(
    State(app_state): State<AppState>,
    Json(request): Json<PasskeyAssertionRequest>,
) -> Result<Json<NearAuthResponse>, ApiError> {
    tracing::info!("Passkey verification attempt for credential {}", request.id);

    if request.credential_type != "public-key" {
        return Err(ApiError::bad_request("Unsupported credential type"));
    }

    let authenticator_data =
        decode_passkey_field(&request.response.authenticator_data, "authenticator_data")?;
    let client_data_json =
        decode_passkey_field(&request.response.client_data_json, "client_data_json")?;
    let signature = decode_passkey_field(&request.response.signature, "signature")?;

    let credential = AssertionCredential {
        credential_id: request.id.clone(),
        authenticator_data,
        client_data_json,
        signature,
    };

    let passkey = app_state
        .passkey_service
        .verify_assertion(credential)
        .await
        .map_err(|e| {
            tracing::warn!("Passkey verification failed for {}: {}", request.id, e);
            ApiError::unauthorized("Invalid passkey challenge response")
        })?;

    let session = app_state
        .session_repository
        .create_session(passkey.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to create session for passkey user {}: {}",
                passkey.user_id,
                e
            );
            ApiError::internal_server_error("Failed to create session")
        })?;

    let token = session.token.ok_or_else(|| {
        tracing::error!(
            "Passkey session token missing for session_id={}",
            session.session_id
        );
        ApiError::internal_server_error("Failed to create session")
    })?;

    let is_new_user = passkey.last_used_at.is_none();
    let auth_method = AuthMethod::Passkey;
    let metric_name = if is_new_user {
        METRIC_USER_SIGNUP
    } else {
        METRIC_USER_LOGIN
    };
    let tags = [
        format!("{}:{}", TAG_AUTH_METHOD, auth_method.as_str()),
        format!("{}:{}", TAG_IS_NEW_USER, is_new_user),
    ];
    let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
    app_state
        .metrics_service
        .record_count(metric_name, 1, &tag_refs);

    let activity_type = if is_new_user {
        ActivityType::Signup
    } else {
        ActivityType::Login
    };
    if let Err(e) = app_state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: passkey.user_id,
            activity_type,
            auth_method: Some(auth_method),
            metadata: None,
        })
        .await
    {
        tracing::warn!("Failed to record passkey analytics event: {}", e);
    }

    tracing::info!(
        "Passkey authentication successful - user_id={}, session_id={}, is_new_user={}",
        passkey.user_id,
        session.session_id,
        is_new_user
    );

    Ok(Json(NearAuthResponse {
        token,
        session_id: session.session_id.to_string(),
        expires_at: session.expires_at.to_rfc3339(),
        is_new_user,
    }))
}

/// Create OAuth router with all routes (excluding logout, which requires auth)
pub fn create_oauth_router() -> Router<AppState> {
    let router = Router::new()
        // OAuth initiation routes
        .route("/google", get(google_login))
        .route("/github", get(github_login))
        // NEAR wallet authentication
        .route("/near", post(near_auth))
        // Passkey authentication
        .route("/passkey/options", get(passkey_options))
        .route("/passkey/verify", post(passkey_verify))
        // Unified callback route for all providers
        .route("/callback", get(oauth_callback));

    // Add mock login route only in test builds
    #[cfg(feature = "test")]
    let router = router.route("/mock-login", axum::routing::post(mock_login));

    router
}

fn decode_passkey_field(value: &str, field_name: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request(format!("Invalid passkey {field_name} payload")))
}
