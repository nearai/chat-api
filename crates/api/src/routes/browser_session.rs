//! Browser-only session transport. Origin checks are authorization checks here,
//! not merely CORS response headers. Native clients must use a separate contract.
use crate::{error::ApiError, state::AppState};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    Json,
};
use database::repositories::browser_session_repository::{
    BrowserCredentials, BrowserSessionRepository,
};
use serde::{Deserialize, Serialize};
use services::auth::ports::UserSession;

pub struct BrowserContext {
    client: String,
    origin: String,
}

fn origin_allowed(origin: &str, configured: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    let secure = url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")));
    secure
        && url.origin().ascii_serialization() == origin
        && configured
            .split(',')
            .map(str::trim)
            .any(|entry| entry == origin)
}

pub fn login_context(headers: &HeaderMap) -> Result<Option<BrowserContext>, ApiError> {
    let Some(client) = headers.get("x-session-client") else {
        return Ok(None);
    };
    let client = client
        .to_str()
        .map_err(|_| ApiError::bad_request("Invalid session client"))?;
    let env = match client {
        "user" => "BROWSER_SESSION_USER_ORIGINS",
        "admin" => "BROWSER_SESSION_ADMIN_ORIGINS",
        _ => return Err(ApiError::bad_request("Invalid session client")),
    };
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::forbidden("Browser session requires an Origin"))?;
    if !origin_allowed(origin, &std::env::var(env).unwrap_or_default()) {
        return Err(ApiError::forbidden("Untrusted browser session origin"));
    }

    Ok(Some(BrowserContext {
        client: client.into(),
        origin: origin.into(),
    }))
}

fn required_context(headers: &HeaderMap) -> Result<BrowserContext, ApiError> {
    login_context(headers)?.ok_or_else(|| ApiError::forbidden("Browser session client required"))
}

fn cookie_name(context: &BrowserContext) -> &'static str {
    if context.client == "admin" {
        "__Host-nearai_admin_refresh"
    } else {
        "__Host-nearai_user_refresh"
    }
}

fn refresh_cookie(headers: &HeaderMap, context: &BrowserContext) -> Option<String> {
    let prefix = format!("{}=", cookie_name(context));
    let values: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|part| part.trim().strip_prefix(&prefix))
        .collect();
    // Reject ambiguous duplicate cookies and bound all untrusted input.
    if values.len() != 1
        || values[0].len() != 64
        || !values[0].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(values[0].to_owned())
}

fn set_cookie(context: &BrowserContext, secret: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        cookie_name(context),
        secret,
        max_age.max(0),
    ))
    .expect("generated refresh cookie contains only safe characters")
}

fn internal(error: anyhow::Error) -> ApiError {
    tracing::error!(error = %error, "Browser session operation failed");
    ApiError::internal_server_error("Browser session unavailable")
}

pub async fn establish(
    state: &AppState,
    context: Option<&BrowserContext>,
    session: &mut UserSession,
) -> Result<Option<HeaderValue>, ApiError> {
    let Some(context) = context else {
        return Ok(None);
    };

    let result = establish_for_context(state, context, session).await;
    if result.is_err() {
        // No login credential is returned on setup failure. Revoke both the
        // original bearer and any browser family committed before an error.
        session.token = None;

        if let Err(error) = state
            .session_repository
            .delete_session(session.session_id)
            .await
        {
            tracing::error!(
                session_id = %session.session_id,
                error = %error,
                "Failed to revoke session after browser setup failure"
            );
        }
    }

    result
}

async fn establish_for_context(
    state: &AppState,
    context: &BrowserContext,
    session: &mut UserSession,
) -> Result<Option<HeaderValue>, ApiError> {
    if context.client == "admin" {
        let profile = state
            .user_service
            .get_user_profile(session.user_id)
            .await
            .map_err(internal)?;
        if !crate::middleware::auth::is_admin_domain(&profile.user.email, &state.admin_domains)
            || !crate::middleware::auth::is_admin_email(&profile.user.email, &state.admin_emails)
        {
            return Err(ApiError::forbidden("Admin access required"));
        }
    }
    let issued = BrowserSessionRepository(state.db_pool.clone())
        .establish(session, &context.client, &context.origin)
        .await
        .map_err(internal)?;
    session.token = Some(issued.token);
    session.expires_at = issued.expires_at;

    Ok(Some(set_cookie(
        context,
        &issued.refresh_token,
        issued
            .absolute_expires_at
            .signed_duration_since(chrono::Utc::now())
            .num_seconds(),
    )))
}

pub fn append_cookie(headers: &mut HeaderMap, cookie: Option<HeaderValue>) {
    if let Some(cookie) = cookie {
        headers.append(header::SET_COOKIE, cookie);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RefreshRequest {
    /// Set only in response to recent user interaction, never background polling.
    #[serde(default)]
    active: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AccessResponse {
    token: String,
    session_id: String,
    expires_at: String,
}

#[utoipa::path(
    post,
    path = "/v1/auth/session/refresh",
    tag = "Auth",
    request_body = RefreshRequest,
    params(
        ("X-Session-Client" = String, Header, description = "user or admin; bound to an exact configured Origin"),
        ("Origin" = String, Header, description = "Exact trusted browser origin")
    ),
    responses(
        (status = 200, description = "Rotated HttpOnly refresh cookie and short-lived access credential", body = AccessResponse),
        (status = 401, description = "Missing, expired, or replayed refresh credential"),
        (status = 403, description = "Untrusted origin or client")
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<(HeaderMap, Json<AccessResponse>), ApiError> {
    let context = required_context(&headers)?;
    let secret = refresh_cookie(&headers, &context).ok_or_else(ApiError::invalid_token)?;
    let issued: BrowserCredentials = BrowserSessionRepository(state.db_pool.clone())
        .refresh(&secret, &context.client, &context.origin, request.active)
        .await
        .map_err(internal)?
        .ok_or_else(ApiError::session_expired)?;
    let mut response_headers = HeaderMap::new();
    append_cookie(
        &mut response_headers,
        Some(set_cookie(
            &context,
            &issued.refresh_token,
            issued
                .absolute_expires_at
                .signed_duration_since(chrono::Utc::now())
                .num_seconds(),
        )),
    );

    Ok((
        response_headers,
        Json(AccessResponse {
            token: issued.token,
            session_id: issued.session_id.to_string(),
            expires_at: issued.expires_at.to_rfc3339(),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/auth/session/logout",
    tag = "Auth",
    params(
        ("X-Session-Client" = String, Header, description = "user or admin"),
        ("Origin" = String, Header, description = "Exact trusted browser origin")
    ),
    responses(
        (status = 204, description = "Session family revoked and refresh cookie cleared"),
        (status = 403, description = "Untrusted origin or client")
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let context = required_context(&headers)?;
    if let Some(secret) = refresh_cookie(&headers, &context) {
        BrowserSessionRepository(state.db_pool.clone())
            .logout(&secret, &context.client, &context.origin)
            .await
            .map_err(internal)?;
    }
    let mut response_headers = HeaderMap::new();
    append_cookie(&mut response_headers, Some(set_cookie(&context, "", 0)));

    Ok((response_headers, StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_exact_and_fail_closed() {
        let allowed = "https://admin.near.ai,http://localhost:3000";

        assert!(origin_allowed("https://admin.near.ai", allowed));
        assert!(origin_allowed("http://localhost:3000", allowed));
        for origin in [
            "null",
            "https://evil.near.ai",
            "https://admin.near.ai.evil.test",
            "https://admin.near.ai/",
            "http://admin.near.ai",
        ] {
            assert!(!origin_allowed(origin, allowed));
        }
        assert!(!origin_allowed("https://admin.near.ai", "*.near.ai"));
    }

    #[test]
    fn cookies_are_host_only_and_duplicates_are_rejected() {
        let context = BrowserContext {
            client: "admin".into(),
            origin: "https://admin.near.ai".into(),
        };
        let secret = "a".repeat(64);
        let cookie = set_cookie(&context, &secret, 100);
        let cookie = cookie.to_str().unwrap();

        assert!(cookie.starts_with("__Host-nearai_admin_refresh="));
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
        assert!(!cookie.contains("Domain="));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={secret}", cookie_name(&context))
                .parse()
                .unwrap(),
        );
        assert_eq!(refresh_cookie(&headers, &context), Some(secret.clone()));

        headers.append(
            header::COOKIE,
            format!("{}={secret}", cookie_name(&context))
                .parse()
                .unwrap(),
        );
        assert!(refresh_cookie(&headers, &context).is_none());
    }
}
