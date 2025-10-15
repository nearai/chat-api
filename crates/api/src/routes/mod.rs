pub mod api;
pub mod attestation;
pub mod oauth;
pub mod users;

use axum::{middleware::from_fn_with_state, Router};
use tower_http::cors::CorsLayer;

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

    // Build the base router
    let router = Router::new()
        .nest("/v1/auth", auth_routes)
        .nest("/v1/users", user_routes)
        .merge(api_routes) // Merge instead of nest since api routes already have /v1 prefix
        .merge(attestation_routes) // Merge attestation routes (already have /v1 prefix)
        .with_state(app_state);

    // Add CORS layer if origins are specified
    if !allowed_origins.is_empty() {
        tracing::info!("CORS enabled for origins: {:?}", allowed_origins);

        let cors = CorsLayer::new()
            .allow_origin(
                allowed_origins
                    .iter()
                    .filter_map(|origin| origin.parse().ok())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::ACCEPT,
            ])
            .allow_credentials(true);

        router.layer(cors)
    } else {
        tracing::warn!("CORS not configured - frontend requests may be blocked");
        router
    }
}
