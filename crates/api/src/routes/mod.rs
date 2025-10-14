pub mod api;
pub mod attestation;
pub mod oauth;
pub mod users;

use axum::{middleware::from_fn_with_state, Router};

use crate::{middleware::AuthState, state::AppState};

/// Create the main API router with all routes
pub fn create_router(app_state: AppState) -> Router {
    // Create auth state for middleware
    let auth_state = AuthState {
        session_repository: app_state.session_repository.clone(),
    };

    // OAuth routes (public, no auth required)
    let auth_routes = oauth::create_oauth_router();

    // Attestation routes (public, no auth required)
    let attestation_routes = attestation::create_attestation_router();

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

    // Combine all routes
    Router::new()
        .nest("/v1/auth", auth_routes)
        .nest("/v1/users", user_routes)
        .merge(api_routes) // Merge instead of nest since api routes already have /v1 prefix
        .merge(attestation_routes) // Merge attestation routes (already have /v1 prefix)
        .with_state(app_state)
}
