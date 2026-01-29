//! OAuth 2.0 Authorization Server Routes
//!
//! Implements RFC 6749 authorization code grant flow endpoints:
//! - GET /v1/oauth/authorize - Authorization endpoint
//! - POST /v1/oauth/token - Token endpoint
//! - GET /v1/oauth/consent/{id} - Get pending authorization for consent UI
//! - POST /v1/oauth/consent/{id} - Approve or deny consent

use axum::{
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    error::{OAuthError, OAuthErrorResponse},
    middleware::AuthenticatedUser,
    state::AppState,
};
use services::auth::AuthorizeResult;

// =============================================================================
// Authorization Endpoint (GET /v1/oauth/authorize)
// =============================================================================

/// Query parameters for the authorization endpoint.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuthorizeQuery {
    /// Must be "code" for authorization code flow
    pub response_type: String,
    /// The client identifier
    pub client_id: String,
    /// URI to redirect to after authorization
    pub redirect_uri: String,
    /// Space-separated list of requested scopes
    #[serde(default)]
    pub scope: String,
    /// Opaque value for CSRF protection
    pub state: Option<String>,
    /// PKCE code challenge (required for public clients)
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (must be S256 if provided)
    pub code_challenge_method: Option<String>,
}

/// Authorization endpoint.
///
/// Initiates the authorization code flow. If the user has already granted
/// consent for the requested scopes, redirects directly with an authorization code.
/// Otherwise, returns a response indicating consent is needed.
#[utoipa::path(
    get,
    path = "/v1/oauth/authorize",
    tag = "OAuth",
    params(AuthorizeQuery),
    responses(
        (status = 302, description = "Redirect to client with code or consent page"),
        (status = 400, description = "Invalid request", body = OAuthErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
    // Validate response_type
    if params.response_type != "code" {
        return error_redirect(
            &params.redirect_uri,
            "unsupported_response_type",
            "Only 'code' response_type is supported",
            params.state.as_deref(),
        );
    }

    // Call the service
    let result = state
        .oauth_server_service
        .authorize(
            user.user_id,
            &params.client_id,
            &params.redirect_uri,
            &params.scope,
            params.state.as_deref(),
            params.code_challenge.as_deref(),
            params.code_challenge_method.as_deref(),
        )
        .await;

    match result {
        Ok(AuthorizeResult::Success { code, state: s }) => {
            // Redirect back to client with authorization code
            let mut redirect_url = params.redirect_uri.clone();
            redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
            redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
            if let Some(state_value) = s {
                redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state_value)));
            }
            Redirect::to(&redirect_url).into_response()
        }
        Ok(AuthorizeResult::NeedsConsent {
            pending_id,
            client_name: _,
            scopes: _,
        }) => {
            // Redirect to consent page
            let consent_url = format!("/oauth/consent.html?pending_id={}", pending_id);
            Redirect::to(&consent_url).into_response()
        }
        Err(e) => {
            // For client errors (invalid redirect_uri, invalid client), return JSON error
            // For other errors, redirect with error
            let error_code = e.error_code();
            if error_code == "invalid_client" || error_code == "invalid_request" {
                OAuthError::from(e).into_response()
            } else {
                error_redirect(
                    &params.redirect_uri,
                    error_code,
                    &e.to_string(),
                    params.state.as_deref(),
                )
            }
        }
    }
}

/// Response when consent is needed.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizeNeedsConsentResponse {
    /// Always true for this response type
    pub needs_consent: bool,
    /// ID of the pending authorization to approve/deny
    pub pending_id: Uuid,
    /// Name of the client application
    pub client_name: String,
    /// Scopes being requested
    pub scopes: Vec<String>,
}

/// Build an error redirect URL per RFC 6749.
fn error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut url = redirect_uri.to_string();
    url.push_str(if url.contains('?') { "&" } else { "?" });
    url.push_str(&format!(
        "error={}&error_description={}",
        urlencoding::encode(error),
        urlencoding::encode(description)
    ));
    if let Some(s) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&url).into_response()
}

// =============================================================================
// Consent Endpoints
// =============================================================================

/// Get pending authorization details for consent UI.
#[utoipa::path(
    get,
    path = "/v1/oauth/consent/{id}",
    tag = "OAuth",
    params(
        ("id" = Uuid, Path, description = "Pending authorization ID")
    ),
    responses(
        (status = 200, description = "Pending authorization details", body = ConsentInfoResponse),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_consent(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentInfoResponse>, OAuthError> {
    let info = state
        .oauth_server_service
        .get_pending_authorization(id, user.user_id)
        .await
        .map_err(OAuthError::from)?
        .ok_or_else(|| OAuthError::invalid_request("Pending authorization not found"))?;

    // Get user email
    let user_data = state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|_| OAuthError::server_error("Failed to get user data"))?;

    Ok(Json(ConsentInfoResponse {
        client_name: info.client_name,
        client_id: info.client_id,
        scopes: info.scopes,
        redirect_uri: info.redirect_uri,
        user_email: user_data.user.email,
    }))
}

/// Response with consent information.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentInfoResponse {
    pub client_name: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub user_email: String,
}

/// Request body for consent decision.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConsentDecisionRequest {
    /// Whether the user approved the authorization
    pub approved: bool,
    /// Scopes the user approved (must be subset of requested scopes)
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Response after consent decision.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentDecisionResponse {
    /// Redirect URL with code or error
    pub redirect_url: String,
}

/// Submit consent decision.
#[utoipa::path(
    post,
    path = "/v1/oauth/consent/{id}",
    tag = "OAuth",
    params(
        ("id" = Uuid, Path, description = "Pending authorization ID")
    ),
    request_body = ConsentDecisionRequest,
    responses(
        (status = 200, description = "Consent processed", body = ConsentDecisionResponse),
        (status = 400, description = "Invalid request", body = OAuthErrorResponse),
    )
)]
pub async fn post_consent(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
    Json(body): Json<ConsentDecisionRequest>,
) -> Result<Json<ConsentDecisionResponse>, OAuthError> {
    if !body.approved {
        // User denied - get pending auth info for redirect before deleting
        let info = state
            .oauth_server_service
            .get_pending_authorization(id, user.user_id)
            .await
            .map_err(OAuthError::from)?;

        // Delete the pending authorization
        state
            .oauth_server_service
            .deny_consent(id)
            .await
            .map_err(OAuthError::from)?;

        // Build error redirect
        let redirect_url = if let Some(pending_info) = info {
            format!(
                "{}{}error=access_denied&error_description={}",
                pending_info.redirect_uri,
                if pending_info.redirect_uri.contains('?') { "&" } else { "?" },
                urlencoding::encode("User denied the authorization request")
            )
        } else {
            // No redirect info available - return generic error
            return Err(OAuthError::access_denied("User denied the authorization request"));
        };

        return Ok(Json(ConsentDecisionResponse { redirect_url }));
    }

    // Get redirect_uri before approving (since approve_consent consumes the pending auth)
    let pending_info = state
        .oauth_server_service
        .get_pending_authorization(id, user.user_id)
        .await
        .map_err(OAuthError::from)?
        .ok_or_else(|| OAuthError::invalid_request("Pending authorization not found"))?;

    let redirect_uri = pending_info.redirect_uri;

    // User approved - process consent
    let result = state
        .oauth_server_service
        .approve_consent(user.user_id, id, body.scopes)
        .await
        .map_err(OAuthError::from)?;

    match result {
        AuthorizeResult::Success { code, state: s } => {
            // Build full redirect URL with code
            let mut redirect_url = redirect_uri;
            redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
            redirect_url.push_str(&format!("code={}", urlencoding::encode(&code)));
            if let Some(st) = s {
                redirect_url.push_str(&format!("&state={}", urlencoding::encode(&st)));
            }

            Ok(Json(ConsentDecisionResponse { redirect_url }))
        }
        AuthorizeResult::NeedsConsent { .. } => {
            // This shouldn't happen after approving
            Err(OAuthError::server_error("Unexpected state after consent"))
        }
    }
}

// =============================================================================
// Token Endpoint (POST /v1/oauth/token)
// =============================================================================

/// Form parameters for the token endpoint.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct TokenRequest {
    /// Grant type: "authorization_code" or "refresh_token"
    pub grant_type: String,
    /// Authorization code (for authorization_code grant)
    pub code: Option<String>,
    /// Redirect URI (for authorization_code grant, must match authorize request)
    pub redirect_uri: Option<String>,
    /// PKCE code verifier (for authorization_code grant)
    pub code_verifier: Option<String>,
    /// Refresh token (for refresh_token grant)
    pub refresh_token: Option<String>,
    /// Client ID (alternative to Basic auth)
    pub client_id: Option<String>,
    /// Client secret (alternative to Basic auth)
    pub client_secret: Option<String>,
}

/// Token response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponseBody {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// Token endpoint.
///
/// Exchanges an authorization code for tokens, or refreshes an access token.
#[utoipa::path(
    post,
    path = "/v1/oauth/token",
    tag = "OAuth",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Token response", body = TokenResponseBody),
        (status = 400, description = "Invalid request", body = OAuthErrorResponse),
        (status = 401, description = "Invalid client", body = OAuthErrorResponse),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(params): Form<TokenRequest>,
) -> Result<Json<TokenResponseBody>, OAuthError> {
    // Extract client credentials from either Basic auth header or form params
    let (client_id, client_secret) = extract_client_credentials(&headers, &params)?;

    let result = match params.grant_type.as_str() {
        "authorization_code" => {
            let code = params
                .code
                .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
            let redirect_uri = params
                .redirect_uri
                .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;

            state
                .oauth_server_service
                .token_authorization_code(
                    &client_id,
                    client_secret.as_deref(),
                    &code,
                    &redirect_uri,
                    params.code_verifier.as_deref(),
                )
                .await
                .map_err(OAuthError::from)?
        }
        "refresh_token" => {
            let refresh_token = params
                .refresh_token
                .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;

            state
                .oauth_server_service
                .token_refresh(&client_id, client_secret.as_deref(), &refresh_token)
                .await
                .map_err(OAuthError::from)?
        }
        _ => {
            return Err(OAuthError::unsupported_grant_type(format!(
                "Unsupported grant_type: {}",
                params.grant_type
            )));
        }
    };

    Ok(Json(TokenResponseBody {
        access_token: result.access_token,
        token_type: result.token_type,
        expires_in: result.expires_in,
        refresh_token: result.refresh_token,
        scope: result.scope,
    }))
}

/// Extract client credentials from Authorization header (Basic) or form parameters.
fn extract_client_credentials(
    headers: &axum::http::HeaderMap,
    params: &TokenRequest,
) -> Result<(String, Option<String>), OAuthError> {
    // Try Basic auth header first
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OAuthError::invalid_client("Invalid Authorization header"))?;

        if let Some(basic_creds) = auth_str.strip_prefix("Basic ") {
            let decoded = STANDARD
                .decode(basic_creds)
                .map_err(|_| OAuthError::invalid_client("Invalid Basic auth encoding"))?;

            let decoded_str = String::from_utf8(decoded)
                .map_err(|_| OAuthError::invalid_client("Invalid Basic auth encoding"))?;

            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(OAuthError::invalid_client("Invalid Basic auth format"));
            }

            return Ok((
                urlencoding::decode(parts[0])
                    .map_err(|_| OAuthError::invalid_client("Invalid client_id encoding"))?
                    .into_owned(),
                if parts[1].is_empty() {
                    None
                } else {
                    Some(
                        urlencoding::decode(parts[1])
                            .map_err(|_| OAuthError::invalid_client("Invalid client_secret encoding"))?
                            .into_owned(),
                    )
                },
            ));
        }
    }

    // Fall back to form parameters
    let client_id = params
        .client_id
        .clone()
        .ok_or_else(|| OAuthError::invalid_client("client_id is required"))?;

    Ok((client_id, params.client_secret.clone()))
}

// =============================================================================
// Router
// =============================================================================

/// Create the OAuth server router.
///
/// Note: The authorize and consent endpoints require authentication (session cookie).
/// The token endpoint does not require user authentication (uses client credentials).
pub fn create_oauth_server_router() -> Router<AppState> {
    Router::new()
        // Token endpoint - no user auth required, uses client credentials
        .route("/token", post(token))
}

/// Create routes that require user authentication.
pub fn create_oauth_server_auth_router() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/consent/{id}", get(get_consent).post(post_consent))
}
