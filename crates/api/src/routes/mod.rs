pub mod admin;
pub mod api;
pub mod attestation;
pub mod oauth;
pub mod users;

use axum::{middleware::from_fn_with_state, routing::get, Json, Router};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use utoipa::ToSchema;

use crate::{middleware::AuthState, state::AppState, static_files};

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

/// Create the main API router with all routes
pub fn create_router(app_state: AppState) -> Router {
    create_router_with_cors(app_state, vec![])
}

/// Create the main API router with CORS configuration
pub fn create_router_with_cors(app_state: AppState, allowed_origins: Vec<String>) -> Router {
    // Create auth state for middleware
    let auth_state = AuthState {
        session_repository: app_state.session_repository.clone(),
        user_service: app_state.user_service.clone(),
        admin_domains: app_state.admin_domains.clone(),
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

    // Admin routes (requires admin authentication)
    let admin_routes = admin::create_admin_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::admin_auth_middleware,
    ));

    // User routes (requires authentication)
    let user_routes = users::create_user_router().layer(from_fn_with_state(
        auth_state.clone(),
        crate::middleware::auth_middleware,
    ));

    // API proxy routes (requires authentication)
    let api_routes = api::create_api_router().layer(from_fn_with_state(
        auth_state,
        crate::middleware::auth_middleware,
    ));

    // Build the base router
    let router = Router::new()
        .route("/health", get(health_check))
        .nest("/v1/auth", auth_routes)
        .nest("/v1/auth", logout_route) // Logout route with auth middleware
        .nest("/v1/users", user_routes)
        .nest("/v1/admin", admin_routes)
        .merge(api_routes) // Merge instead of nest since api routes already have /v1 prefix
        .merge(attestation_routes) // Merge attestation routes (already have /v1 prefix)
        .with_state(app_state)
        // Add static file serving as fallback (must be last)
        .fallback(static_files::static_handler);

    tracing::info!("CORS enabled for origins: {:?}", allowed_origins);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    router.layer(cors)
}
