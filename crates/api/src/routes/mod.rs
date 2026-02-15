pub mod admin;
pub mod agents;
pub mod api;
pub mod attestation;
pub mod configs;
pub mod oauth;
pub mod subscriptions;
pub mod users;

use axum::{middleware::from_fn_with_state, routing::get, Json, Router};
use http::header::{HeaderName, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::HeaderValue;
use http::Method;
use serde::Serialize;
use tower_http::cors::{AllowOrigin, CorsLayer};
use utoipa::ToSchema;

use crate::{
    middleware::{AuthState, MetricsState},
    state::AppState,
    static_files,
};

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Service status
    pub status: &'static str,
    /// API version
    pub version: &'static str,
}

/// Health check endpoint
///
/// Returns the health status of the API service. This endpoint is typically used by
/// load balancers, monitoring systems, and orchestration tools to verify service availability.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

fn is_origin_allowed(origin_str: &str, cors_config: &config::CorsConfig) -> bool {
    if cors_config.exact_matches.iter().any(|o| o == origin_str) {
        return true;
    }

    if let Some(remainder) = origin_str.strip_prefix("http://localhost") {
        if remainder.is_empty() || remainder.starts_with(':') {
            return true;
        }
    }

    if let Some(remainder) = origin_str.strip_prefix("http://127.0.0.1") {
        if remainder.is_empty() || remainder.starts_with(':') {
            return true;
        }
    }

    if origin_str.starts_with("https://")
        && cors_config
            .wildcard_suffixes
            .iter()
            .any(|suffix| origin_str.ends_with(suffix))
    {
        return true;
    }

    false
}

/// Create the main API router with CORS configuration
pub fn create_router_with_cors(app_state: AppState, cors_config: config::CorsConfig) -> Router {
    // Create auth state for middleware
    let auth_state = AuthState {
        session_repository: app_state.session_repository.clone(),
        user_service: app_state.user_service.clone(),
        admin_domains: app_state.admin_domains.clone(),
    };

    // Create metrics state for middleware
    let metrics_state = MetricsState {
        metrics_service: app_state.metrics_service.clone(),
    };

    // OAuth routes (public, no auth required)
    let auth_routes = oauth::create_oauth_router();

    // Logout route (requires authentication)
    let logout_route = Router::new()
        .route("/logout", axum::routing::post(oauth::logout))
        .layer(from_fn_with_state(
            auth_state.clone(),
            crate::middleware::auth_middleware,
        ));

    // Attestation routes (public, no auth required)
    let attestation_routes = attestation::create_attestation_router();

    // Admin routes (requires admin authentication) - includes agent admin endpoints
    let admin_routes = admin::create_admin_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::admin_auth_middleware,
    ));

    // User routes (requires authentication)
    let user_routes = users::create_user_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::auth_middleware,
    ));

    // Agent routes (requires authentication)
    let agent_routes = agents::create_agent_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::auth_middleware,
    ));

    // Get rate limit state from app state
    let rate_limit_state = app_state.rate_limit_state.clone();

    // Configs routes (requires user authentication, not admin)
    let configs_routes = configs::create_configs_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::auth_middleware,
    ));

    // Subscription routes (requires user authentication)
    let subscription_routes = subscriptions::create_subscriptions_router().layer(
        from_fn_with_state(auth_state.clone(), crate::middleware::auth_middleware),
    );

    // Public subscription routes (webhook, no auth required)
    let public_subscription_routes = subscriptions::create_public_subscriptions_router();

    // Conversation read routes with optional authentication
    // These routes work for both authenticated users and unauthenticated users
    // (for accessing publicly shared conversations)
    let optional_auth_routes = api::create_optional_auth_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::optional_auth_middleware,
    ));

    let dual_auth_state = crate::middleware::DualAuthState {
        auth_state: auth_state.clone(),
        agent_auth_state: crate::middleware::AgentAuthState {
            agent_service: app_state.agent_service.clone(),
            agent_repository: app_state.agent_repository.clone(),
        },
    };

    // API routes: llm proxy (dual auth + rate limit), models proxy (dual auth), session routes
    let api_routes = api::create_api_router(rate_limit_state, dual_auth_state, auth_state);

    // Build the base router
    // Note: optional_auth_routes must come BEFORE api_routes since they share paths
    // but have different HTTP methods (optional auth for GET, required auth for POST/DELETE)
    let router = Router::new()
        .route("/health", get(health_check))
        .merge(configs_routes) // Configs route (requires user auth)
        .merge(subscription_routes) // Subscription routes (requires user auth)
        .merge(public_subscription_routes) // Public subscription webhook route (no auth)
        .nest("/v1/auth", auth_routes)
        .nest("/v1/auth", logout_route) // Logout route with auth middleware
        .nest("/v1/users", user_routes)
        .nest("/v1/agents", agent_routes) // Agent routes (requires user auth)
        .nest("/v1/admin", admin_routes)
        .merge(optional_auth_routes) // Conversation read routes (optional auth)
        .merge(api_routes) // API routes: llm proxy, models proxy, conversations, share groups, files
        .merge(attestation_routes) // Merge attestation routes (already have /v1 prefix)
        .with_state(app_state)
        // Add static file serving as fallback (must be last)
        .fallback(static_files::static_handler);

    let cors_config_clone = cors_config.clone();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _request_parts: &http::request::Parts| {
                let origin_str = match origin.to_str() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                is_origin_allowed(origin_str, &cors_config_clone)
            },
        ))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            // Allow ngrok-skip-browser-warning header for development with ngrok tunnels
            // When using ngrok for local development/testing, this header prevents the
            // ngrok browser warning page from appearing on the first request
            // This is safe for production as unknown headers are simply ignored
            HeaderName::from_static("ngrok-skip-browser-warning"),
        ])
        .allow_credentials(true);

    // Add HTTP metrics middleware to track request counts and latencies
    router.layer(cors).layer(from_fn_with_state(
        metrics_state,
        crate::middleware::http_metrics_middleware,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cors_config() -> config::CorsConfig {
        config::CorsConfig {
            exact_matches: vec![
                "https://example.com".to_string(),
                "http://test.com".to_string(),
            ],
            wildcard_suffixes: vec![".near.ai".to_string(), "-example.com".to_string()],
        }
    }

    #[test]
    fn test_exact_match_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://example.com", &config));
        assert!(is_origin_allowed("http://test.com", &config));
    }

    #[test]
    fn test_exact_match_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("https://evil.com", &config));
        assert!(!is_origin_allowed("http://example.com", &config));
    }

    #[test]
    fn test_localhost_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("http://localhost:3000", &config));
        assert!(is_origin_allowed("http://localhost:8080", &config));
        assert!(is_origin_allowed("http://localhost", &config));
    }

    #[test]
    fn test_localhost_subdomain_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://localhost.evil.com", &config));
        assert!(!is_origin_allowed(
            "http://localhost.evil.com:3000",
            &config
        ));
    }

    #[test]
    fn test_127_0_0_1_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("http://127.0.0.1:3000", &config));
        assert!(is_origin_allowed("http://127.0.0.1:8080", &config));
        assert!(is_origin_allowed("http://127.0.0.1", &config));
    }

    #[test]
    fn test_127_0_0_1_subdomain_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://127.0.0.1.evil.com", &config));
    }

    #[test]
    fn test_https_wildcard_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://app.near.ai", &config));
        assert!(is_origin_allowed("https://chat.near.ai", &config));
        assert!(is_origin_allowed("https://preview-example.com", &config));
    }

    #[test]
    fn test_https_wildcard_denied() {
        let config = test_cors_config();
        assert!(!is_origin_allowed("http://app.near.ai", &config));
        assert!(!is_origin_allowed("https://fakenear.ai", &config));
        assert!(!is_origin_allowed("https://near.ai.evil.com", &config));
    }

    #[test]
    fn test_wildcard_suffix_protection() {
        let config = config::CorsConfig {
            exact_matches: vec![],
            wildcard_suffixes: vec![".near.ai".to_string()],
        };
        assert!(is_origin_allowed("https://app.near.ai", &config));
        assert!(!is_origin_allowed("https://fakenear.ai", &config));
    }

    #[test]
    fn test_wildcard_with_hyphen_allowed() {
        let config = test_cors_config();
        assert!(is_origin_allowed("https://preview-example.com", &config));
        assert!(is_origin_allowed("https://staging-example.com", &config));
    }
}
