pub mod api;
pub mod attestation;
pub mod oauth;
pub mod users;

use axum::{middleware::from_fn_with_state, Router};
use tower_http::cors::{Any, CorsLayer};

use crate::{middleware::AuthState, state::AppState};

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

    // Attestation routes (public, no auth required)
    let attestation_routes = attestation::create_attestation_router();

    // Admin user routes (requires admin authentication)
    let admin_user_routes = users::create_admin_user_router().layer(from_fn_with_state(
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
    // Note: admin_user_routes must be registered before user_routes to ensure /v1/users matches first
    let router = Router::new()
        .nest("/v1/auth", auth_routes)
        .nest("/v1/users", admin_user_routes) // Admin routes (requires admin auth) - matches /v1/users
        .nest("/v1/users", user_routes) // Protected routes (requires auth) - matches /v1/users/me, etc.
        .merge(api_routes) // Merge instead of nest since api routes already have /v1 prefix
        .merge(attestation_routes) // Merge attestation routes (already have /v1 prefix)
        .with_state(app_state);

    tracing::info!("CORS enabled for origins: {:?}", allowed_origins);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    router.layer(cors)
}
