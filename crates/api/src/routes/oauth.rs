use crate::{
    error::ApiError, middleware::AuthenticatedUser, state::AppState, validation::validate_email,
};
use axum::extract::Query;
use axum::{
    extract::{ConnectInfo, Extension, FromRequestParts, State},
    http::{header::LOCATION, request::Parts, HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use near_api::signer::NEP413Payload;
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityType, AuthMethod, RecordActivityRequest};
use services::auth::near::SignedMessage;
use services::auth::ports::{OAuthProvider, RequestEmailCodeError, VerifyEmailCodeError};
use services::metrics::consts::{
    METRIC_USER_LOGIN, METRIC_USER_SIGNUP, TAG_AUTH_METHOD, TAG_IS_NEW_USER,
};
use services::SessionId;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use url::{Host, Url};
use utoipa::ToSchema;

const FRONTEND_CALLBACK_ALLOWED_ORIGINS_ENV: &str = "FRONTEND_CALLBACK_ALLOWED_ORIGINS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrontendCallbackValidationError {
    Malformed,
    UnsupportedScheme,
    MissingHost,
    CredentialsNotAllowed,
    QueryOrFragmentNotAllowed,
    Insecure,
    UntrustedOrigin,
}

impl std::fmt::Display for FrontendCallbackValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Malformed => "malformed URL",
            Self::UnsupportedScheme => "unsupported URL scheme",
            Self::MissingHost => "missing URL host",
            Self::CredentialsNotAllowed => "credentials are not allowed in callback URLs",
            Self::QueryOrFragmentNotAllowed => {
                "query strings and fragments are not allowed in callback URLs"
            }
            Self::Insecure => "callback URL must use HTTPS",
            Self::UntrustedOrigin => "callback URL origin is not allowlisted",
        };
        f.write_str(message)
    }
}

pub struct OptionalConnectInfo<T>(Option<T>);

impl<S, T> FromRequestParts<S> for OptionalConnectInfo<T>
where
    S: Send + Sync,
    T: Clone + Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<T>>()
                .map(|ConnectInfo(addr)| addr.clone()),
        ))
    }
}

/// Helper to add a Set-Cookie header to a HeaderMap when available
fn try_add_gateway_cookie(headers: &mut HeaderMap, cookie: Option<String>, context: &str) {
    if let Some(cookie) = cookie {
        if let Ok(cookie_value) = cookie.parse() {
            headers.insert(axum::http::header::SET_COOKIE, cookie_value);
        } else {
            tracing::warn!(
                "Failed to parse Set-Cookie header value in {}: set_cookie_len={}",
                context,
                cookie.len()
            );
        }
    } else {
        tracing::debug!(
            "No Set-Cookie header returned from gateway session setup in {}",
            context
        );
    }
}

pub fn frontend_callback_allowed_origins() -> Option<Vec<String>> {
    frontend_callback_allowed_origins_from(
        std::env::var(FRONTEND_CALLBACK_ALLOWED_ORIGINS_ENV)
            .ok()
            .as_deref(),
    )
}

fn frontend_callback_allowed_origins_from(configured_origins: Option<&str>) -> Option<Vec<String>> {
    let raw_origins = configured_origins?;
    let mut origins = Vec::new();
    let mut seen = HashSet::new();

    for origin in raw_origins
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match validate_frontend_origin(origin) {
            Ok(url) => insert_origin(&mut origins, &mut seen, &url),
            Err(err) => tracing::warn!(
                "Ignoring invalid {FRONTEND_CALLBACK_ALLOWED_ORIGINS_ENV} entry '{origin}': {err}"
            ),
        }
    }

    Some(origins)
}

fn validate_frontend_callback_url(
    raw_url: &str,
    allowed_origins: Option<&[String]>,
) -> Result<String, FrontendCallbackValidationError> {
    if let Some(origins) = allowed_origins {
        if origins.is_empty() {
            return Err(FrontendCallbackValidationError::UntrustedOrigin);
        }
    }

    validate_frontend_url(raw_url, allowed_origins.unwrap_or(&[]))
        .map(|url| trim_trailing_slash(url.as_str()))
}

fn build_oauth_frontend_redirect(
    frontend_base_url: &str,
    token: &str,
    session_id: &str,
    expires_at: &str,
    is_new_user: bool,
) -> Result<String, url::ParseError> {
    let mut url = Url::parse(frontend_base_url)?;
    let base_path = url.path().trim_end_matches('/');
    let callback_path = if base_path.is_empty() {
        "/auth/callback".to_string()
    } else {
        format!("{base_path}/auth/callback")
    };

    url.set_path(&callback_path);
    url.query_pairs_mut()
        .clear()
        .append_pair("token", token)
        .append_pair("session_id", session_id)
        .append_pair("expires_at", expires_at);

    if is_new_user {
        url.query_pairs_mut().append_pair("is_new_user", "true");
    }

    Ok(url.to_string())
}

fn validate_frontend_origin(raw_url: &str) -> Result<Url, FrontendCallbackValidationError> {
    let url = validate_frontend_url(raw_url, &[])?;
    if !url.path().is_empty() && url.path() != "/" {
        return Err(FrontendCallbackValidationError::Malformed);
    }
    Ok(url)
}

fn validate_frontend_url(
    raw_url: &str,
    allowed_origins: &[String],
) -> Result<Url, FrontendCallbackValidationError> {
    let url = Url::parse(raw_url.trim()).map_err(|_| FrontendCallbackValidationError::Malformed)?;

    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(FrontendCallbackValidationError::UnsupportedScheme),
    }

    if url.host().is_none() {
        return Err(FrontendCallbackValidationError::MissingHost);
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(FrontendCallbackValidationError::CredentialsNotAllowed);
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err(FrontendCallbackValidationError::QueryOrFragmentNotAllowed);
    }

    if url.scheme() != "https" && !is_loopback_http_url(&url) {
        return Err(FrontendCallbackValidationError::Insecure);
    }

    if !allowed_origins.is_empty()
        && !allowed_origins
            .iter()
            .any(|origin| origin == &url_origin(&url))
    {
        return Err(FrontendCallbackValidationError::UntrustedOrigin);
    }

    Ok(url)
}

fn is_loopback_http_url(url: &Url) -> bool {
    if url.scheme() != "http" {
        return false;
    }

    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

fn insert_origin(origins: &mut Vec<String>, seen: &mut HashSet<String>, url: &Url) {
    let origin = url_origin(url);
    if seen.insert(origin.clone()) {
        origins.push(origin);
    }
}

fn url_origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn trim_trailing_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

/// Request body for email OTP code request
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct EmailRequestCodeRequest {
    pub email: String,
    pub turnstile_token: String,
}

/// Request body for email OTP verification
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct EmailVerifyCodeRequest {
    pub email: String,
    pub code: String,
}

fn normalize_email_input(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy)]
enum ClientIpSource {
    XForwardedFor,
    XRealIp,
    Forwarded,
    PeerAddress,
    LoopbackFallback,
}

impl ClientIpSource {
    fn as_str(self) -> &'static str {
        match self {
            ClientIpSource::XForwardedFor => "x_forwarded_for",
            ClientIpSource::XRealIp => "x_real_ip",
            ClientIpSource::Forwarded => "forwarded",
            ClientIpSource::PeerAddress => "peer_address",
            ClientIpSource::LoopbackFallback => "loopback_fallback",
        }
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn parse_ip_candidate(candidate: &str) -> Option<IpAddr> {
    let trimmed = candidate.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(socket_addr) = trimmed.parse::<std::net::SocketAddr>() {
        return Some(socket_addr.ip());
    }

    if let Some(bracketed) = trimmed.strip_prefix('[') {
        if let Some((host, _rest)) = bracketed.split_once(']') {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

fn select_proxy_chain_ip(ips: &[IpAddr], trusted_proxy_count: usize) -> Option<IpAddr> {
    if ips.is_empty() {
        return None;
    }

    // ONLINE VALIDATION REQUIRED:
    // This assumes our ingress/proxy chain appends trusted hops to X-Forwarded-For / Forwarded.
    // The client IP is selected by walking left from the trusted proxy suffix. This should be
    // verified against production ingress behavior and adjusted if the deployed proxy topology
    // differs from the configured trusted_proxy_count.
    let index = ips.len().saturating_sub(trusted_proxy_count + 1);
    ips.get(index).copied()
}

fn extract_x_forwarded_for_ip(headers: &HeaderMap, trusted_proxy_count: usize) -> Option<IpAddr> {
    let ips: Vec<IpAddr> = header_value(headers, "x-forwarded-for")?
        .split(',')
        .filter_map(parse_ip_candidate)
        .collect();
    select_proxy_chain_ip(&ips, trusted_proxy_count)
}

fn extract_forwarded_ip(headers: &HeaderMap, trusted_proxy_count: usize) -> Option<IpAddr> {
    let mut ips = Vec::new();

    for entry in header_value(headers, "forwarded")?.split(',') {
        for part in entry.split(';') {
            let part = part.trim();
            if let Some(for_value) = part.strip_prefix("for=") {
                if let Some(ip) = parse_ip_candidate(for_value) {
                    ips.push(ip);
                }
            }
        }
    }

    select_proxy_chain_ip(&ips, trusted_proxy_count)
}

fn extract_client_ip(
    headers: &HeaderMap,
    trusted_proxy_count: usize,
    peer_addr: Option<SocketAddr>,
) -> String {
    let x_forwarded_for = header_value(headers, "x-forwarded-for");
    let x_real_ip = header_value(headers, "x-real-ip");
    let forwarded = header_value(headers, "forwarded");

    let forwarded_ip = if trusted_proxy_count > 0 {
        extract_x_forwarded_for_ip(headers, trusted_proxy_count)
            .map(|ip| (ip, ClientIpSource::XForwardedFor))
            .or_else(|| {
                x_real_ip
                    .and_then(parse_ip_candidate)
                    .map(|ip| (ip, ClientIpSource::XRealIp))
            })
            .or_else(|| {
                extract_forwarded_ip(headers, trusted_proxy_count)
                    .map(|ip| (ip, ClientIpSource::Forwarded))
            })
    } else {
        None
    };

    let (resolved_ip, source) = forwarded_ip
        .or_else(|| peer_addr.map(|addr| (addr.ip(), ClientIpSource::PeerAddress)))
        .unwrap_or((
            IpAddr::from([127, 0, 0, 1]),
            ClientIpSource::LoopbackFallback,
        ));

    tracing::info!(
        resolved_client_ip = %resolved_ip,
        client_ip_source = source.as_str(),
        trusted_proxy_count,
        peer_addr = %peer_addr.map(|addr| addr.to_string()).unwrap_or_default(),
        x_forwarded_for = x_forwarded_for.unwrap_or(""),
        x_real_ip = x_real_ip.unwrap_or(""),
        forwarded = forwarded.unwrap_or(""),
        "Resolved client IP for email auth request"
    );

    resolved_ip.to_string()
}

fn email_verify_error_to_api_error(error: VerifyEmailCodeError) -> ApiError {
    match error {
        VerifyEmailCodeError::Disabled => {
            ApiError::service_unavailable("Email authentication is disabled")
        }
        VerifyEmailCodeError::Misconfigured => {
            ApiError::service_unavailable("Email authentication is not fully configured")
        }
        VerifyEmailCodeError::InvalidOrExpired => {
            ApiError::unauthorized("Invalid or expired verification code")
        }
        VerifyEmailCodeError::RateLimited => {
            ApiError::too_many_requests("Too many verification attempts. Please try again later")
        }
        VerifyEmailCodeError::Internal(err) => {
            tracing::error!("Email verification failed: {}", err);
            ApiError::internal_server_error("Failed to verify email code")
        }
    }
}

fn request_email_code_error_to_api_error(error: RequestEmailCodeError) -> ApiError {
    match error {
        RequestEmailCodeError::Disabled => {
            ApiError::service_unavailable("Email authentication is disabled")
        }
        RequestEmailCodeError::Misconfigured => {
            ApiError::service_unavailable("Email authentication is not fully configured")
        }
        RequestEmailCodeError::HumanVerificationFailed => {
            ApiError::unprocessable_entity("Human verification failed")
        }
        RequestEmailCodeError::RateLimited => ApiError::too_many_requests(
            "Too many verification code requests. Please try again later",
        ),
        RequestEmailCodeError::Internal(err) => {
            tracing::error!("Email code request failed: {}", err);
            ApiError::internal_server_error("Failed to request verification code")
        }
    }
}

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
    pub frontend_callback: String,
}

fn validate_oauth_frontend_callback(
    frontend_callback: &str,
    app_state: &AppState,
) -> Result<String, ApiError> {
    validate_frontend_callback_url(
        frontend_callback,
        app_state
            .frontend_callback_allowed_origins
            .as_deref()
            .map(|origins| origins.as_slice()),
    )
    .map_err(|err| {
        tracing::warn!("Rejected OAuth frontend_callback: {}", err);
        ApiError::bad_request("Invalid frontend_callback")
    })
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

/// Handler for requesting an email verification code
#[utoipa::path(
    post,
    path = "/v1/auth/email/request-code",
    tag = "Auth",
    request_body = EmailRequestCodeRequest,
    responses(
        (status = 204, description = "Verification code requested"),
        (status = 400, description = "Invalid email format", body = crate::error::ApiErrorResponse),
        (status = 422, description = "Human verification failed", body = crate::error::ApiErrorResponse),
        (status = 429, description = "Too many verification code requests", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Email authentication unavailable", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn request_email_code(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    OptionalConnectInfo(peer_addr): OptionalConnectInfo<SocketAddr>,
    Json(request): Json<EmailRequestCodeRequest>,
) -> Result<StatusCode, ApiError> {
    let email = normalize_email_input(&request.email);
    validate_email(&email).map_err(ApiError::bad_request)?;
    let turnstile_token = request.turnstile_token.trim();
    if turnstile_token.is_empty() {
        return Err(ApiError::bad_request("turnstile_token is required"));
    }

    app_state
        .email_auth_service
        .request_code(
            email,
            extract_client_ip(
                &headers,
                app_state.email_auth_trusted_proxy_count,
                peer_addr,
            ),
            turnstile_token.to_string(),
        )
        .await
        .map_err(request_email_code_error_to_api_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Handler for verifying an email verification code
#[utoipa::path(
    post,
    path = "/v1/auth/email/verify-code",
    tag = "Auth",
    request_body = EmailVerifyCodeRequest,
    responses(
        (status = 200, description = "Successfully authenticated", body = crate::models::EmailAuthResponse),
        (status = 400, description = "Invalid request format", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Invalid or expired verification code", body = crate::error::ApiErrorResponse),
        (status = 429, description = "Too many verification attempts", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Email authentication unavailable", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn verify_email_code(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    OptionalConnectInfo(peer_addr): OptionalConnectInfo<SocketAddr>,
    Json(request): Json<EmailVerifyCodeRequest>,
) -> Result<(HeaderMap, Json<crate::models::EmailAuthResponse>), ApiError> {
    let email = normalize_email_input(&request.email);
    validate_email(&email).map_err(ApiError::bad_request)?;

    if request.code.len() != 6 || !request.code.chars().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::bad_request(
            "Verification code must be a 6-digit number",
        ));
    }

    let result = app_state
        .email_auth_service
        .verify_code(
            email,
            request.code,
            extract_client_ip(
                &headers,
                app_state.email_auth_trusted_proxy_count,
                peer_addr,
            ),
        )
        .await
        .map_err(email_verify_error_to_api_error)?;

    let auth_method = AuthMethod::Email;
    let metric_name = if result.is_new_user {
        METRIC_USER_SIGNUP
    } else {
        METRIC_USER_LOGIN
    };
    let tags = [
        format!("{}:{}", TAG_AUTH_METHOD, auth_method.as_str()),
        format!("{}:{}", TAG_IS_NEW_USER, result.is_new_user),
    ];
    let tags_str: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
    app_state
        .metrics_service
        .record_count(metric_name, 1, &tags_str);

    let activity_type = if result.is_new_user {
        ActivityType::Signup
    } else {
        ActivityType::Login
    };
    if let Err(err) = app_state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: result.session.user_id,
            activity_type,
            auth_method: Some(auth_method),
            metadata: None,
        })
        .await
    {
        tracing::warn!("Failed to record analytics for email auth: {}", err);
    }

    let token = result
        .session
        .token
        .ok_or_else(|| ApiError::internal_server_error("Failed to create session"))?;

    let gateway_cookie = app_state
        .agent_service
        .setup_gateway_session_for_user(result.session.user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to set up gateway session for user in verify_email_code: user_id={}, error={}",
                result.session.user_id,
                e
            );
            None
        });

    let mut response_headers = HeaderMap::new();
    try_add_gateway_cookie(&mut response_headers, gateway_cookie, "verify_email_code");

    Ok((
        response_headers,
        Json(crate::models::EmailAuthResponse {
            token,
            session_id: result.session.session_id.to_string(),
            expires_at: result.session.expires_at.to_rfc3339(),
            is_new_user: result.is_new_user,
        }),
    ))
}

/// Handler for initiating Google OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/google",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional OAuth redirect URI (usually your API callback)"),
        ("frontend_callback" = String, Query, description = "Required frontend URL to redirect to after authentication")
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
        "Google OAuth login initiated - redirect_uri: {:?}, frontend_callback_provided=true",
        params.redirect_uri,
    );

    let redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));
    let frontend_callback =
        validate_oauth_frontend_callback(&params.frontend_callback, &app_state)?;

    tracing::debug!("Using OAuth redirect_uri: {}", redirect_uri);

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Google,
            redirect_uri.clone(),
            Some(frontend_callback),
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
) -> Result<(StatusCode, HeaderMap), ApiError> {
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

    // For non-TEE mode: set up gateway session (authenticate with compose-api)
    // This allows users with existing non-TEE instances to access them immediately upon login
    let gateway_cookie = app_state
        .agent_service
        .setup_gateway_session_for_user(session.user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to set up gateway session for user in oauth_callback: user_id={}, error={}",
                session.user_id,
                e
            );
            None
        });

    let mut headers = HeaderMap::new();
    try_add_gateway_cookie(&mut headers, gateway_cookie, "oauth_callback");

    // Use the validated frontend_callback from OAuth state as the only redirect destination.
    let frontend_url = match frontend_callback.as_deref() {
        Some(callback) => {
            match validate_frontend_callback_url(
                callback,
                app_state
                    .frontend_callback_allowed_origins
                    .as_deref()
                    .map(|origins| origins.as_slice()),
            ) {
                Ok(validated) => validated,
                Err(err) => {
                    tracing::warn!("Stored OAuth frontend_callback is invalid: {}", err);
                    return Err(ApiError::bad_request("Invalid frontend_callback"));
                }
            }
        }
        None => {
            tracing::warn!("OAuth state is missing frontend_callback");
            return Err(ApiError::bad_request("frontend_callback is required"));
        }
    };

    tracing::info!("Redirecting to validated OAuth frontend callback");

    let callback_url = build_oauth_frontend_redirect(
        &frontend_url,
        &token,
        &session.session_id.to_string(),
        &session.expires_at.to_rfc3339(),
        is_new_user,
    )
    .map_err(|err| {
        tracing::error!("Failed to build OAuth frontend callback URL: {}", err);
        ApiError::internal_server_error("Invalid callback URL")
    })?;

    tracing::debug!("OAuth frontend callback URL built successfully");
    headers.insert(
        LOCATION,
        callback_url.parse().map_err(|_| {
            tracing::error!("Failed to parse callback URL as header value");
            ApiError::internal_server_error("Invalid callback URL")
        })?,
    );

    Ok((StatusCode::FOUND, headers))
}

/// Handler for initiating Github OAuth flow
#[utoipa::path(
    get,
    path = "/v1/auth/github",
    tag = "Auth",
    params(
        ("redirect_uri" = Option<String>, Query, description = "Optional OAuth redirect URI (usually your API callback)"),
        ("frontend_callback" = String, Query, description = "Required frontend URL to redirect to after authentication")
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
        "Github OAuth login initiated - redirect_uri: {:?}, frontend_callback_provided=true",
        params.redirect_uri,
    );

    let redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| format!("{}/v1/auth/callback", app_state.redirect_uri));
    let frontend_callback =
        validate_oauth_frontend_callback(&params.frontend_callback, &app_state)?;

    tracing::debug!("Using OAuth redirect_uri: {}", redirect_uri);

    let auth_url = app_state
        .oauth_service
        .get_authorization_url(
            services::auth::ports::OAuthProvider::Github,
            redirect_uri.clone(),
            Some(frontend_callback),
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
) -> Result<(HeaderMap, axum::Json<crate::models::AuthResponse>), ApiError> {
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
            match app_state
                .user_repository
                .create_user(
                    request.email.clone(),
                    request.name.clone(),
                    request.avatar_url.clone(),
                )
                .await
            {
                Ok(user) => user,
                Err(_) => {
                    // This can happen if tests run in parallel: two requests race between
                    // "get_user_by_email(None)" and "create_user", leading to a unique constraint
                    // violation for the email. In that case, treat it as success by re-fetching.
                    app_state
                        .user_repository
                        .get_user_by_email(&request.email)
                        .await
                        .map_err(|_| {
                            ApiError::internal_server_error(
                                "Failed to re-fetch user after create_user failure",
                            )
                        })?
                        .ok_or_else(|| ApiError::internal_server_error("Failed to create user"))?
                }
            }
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

    // For non-TEE mode: set up gateway session (authenticate with compose-api)
    // This allows users with existing non-TEE instances to access them immediately upon login
    let gateway_cookie = app_state
        .agent_service
        .setup_gateway_session_for_user(user.id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to set up gateway session for user in mock_login: user_id={}, error={}",
                user.id,
                e
            );
            None
        });

    let mut response_headers = HeaderMap::new();
    try_add_gateway_cookie(&mut response_headers, gateway_cookie, "mock_login");

    Ok((
        response_headers,
        axum::Json(crate::models::AuthResponse {
            token,
            expires_at: session.expires_at.to_rfc3339(),
        }),
    ))
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
) -> Result<(HeaderMap, Json<NearAuthResponse>), ApiError> {
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

    // For non-TEE mode: set up gateway session (authenticate with compose-api)
    // This allows users with existing non-TEE instances to access them immediately upon login
    let gateway_cookie = app_state
        .agent_service
        .setup_gateway_session_for_user(session.user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to set up gateway session for user in near_auth: user_id={}, error={}",
                session.user_id,
                e
            );
            None
        });

    let mut response_headers = HeaderMap::new();
    try_add_gateway_cookie(&mut response_headers, gateway_cookie, "near_auth");

    Ok((
        response_headers,
        Json(NearAuthResponse {
            token,
            session_id: session.session_id.to_string(),
            expires_at: session.expires_at.to_rfc3339(),
            is_new_user,
        }),
    ))
}

/// Create OAuth router with all routes (excluding logout, which requires auth)
pub fn create_oauth_router() -> Router<AppState> {
    let router = Router::new()
        // OAuth initiation routes
        .route("/google", get(google_login))
        .route("/github", get(github_login))
        .route("/email/request-code", post(request_email_code))
        .route("/email/verify-code", post(verify_email_code))
        // NEAR wallet authentication
        .route("/near", post(near_auth))
        // Unified callback route for all providers
        .route("/callback", get(oauth_callback));

    // Add mock login route only in test builds
    #[cfg(feature = "test")]
    let router = router.route("/mock-login", axum::routing::post(mock_login));

    router
}

#[cfg(test)]
mod tests {
    use super::{
        build_oauth_frontend_redirect, extract_client_ip, frontend_callback_allowed_origins_from,
        select_proxy_chain_ip, validate_frontend_callback_url, FrontendCallbackValidationError,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, SocketAddr};

    fn allowlist() -> Vec<String> {
        vec![
            "https://app.near.ai".to_string(),
            "http://localhost:3000".to_string(),
        ]
    }

    #[test]
    fn validates_https_callback_on_allowlisted_origin() {
        let callback =
            validate_frontend_callback_url("https://app.near.ai/app/", Some(&allowlist())).unwrap();
        assert_eq!(callback, "https://app.near.ai/app");
    }

    #[test]
    fn rejects_untrusted_callback_origin() {
        let err = validate_frontend_callback_url("https://evil.example/auth", Some(&allowlist()))
            .unwrap_err();
        assert_eq!(err, FrontendCallbackValidationError::UntrustedOrigin);
    }

    #[test]
    fn allows_any_origin_when_allowlist_is_unset() {
        let callback = validate_frontend_callback_url("https://staging.example.dev", None).unwrap();
        assert_eq!(callback, "https://staging.example.dev");
    }

    #[test]
    fn rejects_callbacks_when_allowlist_is_explicitly_empty() {
        let err = validate_frontend_callback_url("https://app.near.ai", Some(&[])).unwrap_err();
        assert_eq!(err, FrontendCallbackValidationError::UntrustedOrigin);
    }

    #[test]
    fn rejects_insecure_remote_callback_even_when_allowlisted() {
        let allowed = vec!["http://app.near.ai".to_string()];
        let err = validate_frontend_callback_url("http://app.near.ai", Some(&allowed)).unwrap_err();
        assert_eq!(err, FrontendCallbackValidationError::Insecure);
    }

    #[test]
    fn allows_localhost_http_for_local_development() {
        let callback =
            validate_frontend_callback_url("http://localhost:3000", Some(&allowlist())).unwrap();
        assert_eq!(callback, "http://localhost:3000");
    }

    #[test]
    fn rejects_ambiguous_callback_urls() {
        assert_eq!(
            validate_frontend_callback_url("javascript:alert(1)", Some(&allowlist())).unwrap_err(),
            FrontendCallbackValidationError::UnsupportedScheme
        );
        assert_eq!(
            validate_frontend_callback_url("https://user@app.near.ai", Some(&allowlist()))
                .unwrap_err(),
            FrontendCallbackValidationError::CredentialsNotAllowed
        );
        assert_eq!(
            validate_frontend_callback_url(
                "https://app.near.ai?next=https://evil.example",
                Some(&allowlist())
            )
            .unwrap_err(),
            FrontendCallbackValidationError::QueryOrFragmentNotAllowed
        );
        assert_eq!(
            validate_frontend_callback_url("https://app.near.ai#token", Some(&allowlist()))
                .unwrap_err(),
            FrontendCallbackValidationError::QueryOrFragmentNotAllowed
        );
    }

    #[test]
    fn builds_oauth_redirect_under_validated_frontend_base() {
        let redirect = build_oauth_frontend_redirect(
            "https://app.near.ai/app",
            "tok en",
            "session-1",
            "2026-05-27T00:00:00Z",
            true,
        )
        .unwrap();

        assert_eq!(
            redirect,
            "https://app.near.ai/app/auth/callback?token=tok+en&session_id=session-1&expires_at=2026-05-27T00%3A00%3A00Z&is_new_user=true"
        );
    }

    #[test]
    fn derives_allowed_origins_from_env_list() {
        let origins = frontend_callback_allowed_origins_from(Some(
            "https://admin.near.ai,ftp://bad.example,http://localhost:3000",
        ));

        assert_eq!(
            origins,
            Some(vec![
                "https://admin.near.ai".to_string(),
                "http://localhost:3000".to_string()
            ])
        );
    }

    #[test]
    fn unset_env_origin_list_disables_origin_restrictions() {
        assert_eq!(frontend_callback_allowed_origins_from(None), None);
    }

    #[test]
    fn select_proxy_chain_ip_uses_ip_before_trusted_suffix() {
        let cases = [
            (
                vec![
                    "198.51.100.10".parse::<IpAddr>().unwrap(),
                    "203.0.113.20".parse::<IpAddr>().unwrap(),
                ],
                1,
                Some("198.51.100.10".parse::<IpAddr>().unwrap()),
            ),
            (
                vec![
                    "198.51.100.10".parse::<IpAddr>().unwrap(),
                    "203.0.113.20".parse::<IpAddr>().unwrap(),
                    "203.0.113.21".parse::<IpAddr>().unwrap(),
                ],
                2,
                Some("198.51.100.10".parse::<IpAddr>().unwrap()),
            ),
            (
                vec![
                    "198.51.100.10".parse::<IpAddr>().unwrap(),
                    "203.0.113.20".parse::<IpAddr>().unwrap(),
                ],
                5,
                Some("198.51.100.10".parse::<IpAddr>().unwrap()),
            ),
            (Vec::new(), 1, None),
        ];

        for (ips, trusted_proxy_count, expected) in cases {
            assert_eq!(select_proxy_chain_ip(&ips, trusted_proxy_count), expected);
        }
    }

    #[test]
    fn extract_client_ip_uses_peer_address_when_no_proxies_are_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.10, 203.0.113.20"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.11"));
        let peer_addr = "203.0.113.99:443".parse::<SocketAddr>().unwrap();

        assert_eq!(
            extract_client_ip(&headers, 0, Some(peer_addr)),
            "203.0.113.99"
        );
    }

    #[test]
    fn extract_client_ip_logs_and_falls_back_to_loopback_without_peer_address() {
        let headers = HeaderMap::new();

        assert_eq!(extract_client_ip(&headers, 0, None), "127.0.0.1");
    }
}
