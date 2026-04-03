pub mod cloud_api;
pub mod common;
pub mod consts;
pub mod error;
pub mod middleware;
pub mod model_pricing;
pub mod models;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod static_files;
pub mod tasks;
pub mod usage_parsing;
pub mod validation;
pub mod web_search_pricing;

pub use error::{ApiError, ApiErrorResponse};
pub use middleware::{auth_middleware, AuthState, AuthenticatedUser};
pub use models::*;
pub use openapi::ApiDoc;
pub use routes::create_router_with_cors;
pub use state::AppState;

use config::LoggingConfig;
use tracing_subscriber::EnvFilter;

pub fn init_tracing_from_config(logging_config: &LoggingConfig) {
    let mut filter = logging_config.level.clone();
    for (module, level) in &logging_config.modules {
        filter.push_str(&format!(",{module}={level}"));
    }

    let env_filter = EnvFilter::try_new(&filter).unwrap_or_else(|err| {
        eprintln!(
            "Invalid log filter '{}': {}. Falling back to 'info'.",
            filter, err
        );
        EnvFilter::new("info")
    });

    match logging_config.format.as_str() {
        "compact" => {
            tracing_subscriber::fmt()
                .compact()
                .with_env_filter(env_filter)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .init();
        }
        "pretty" => {
            tracing_subscriber::fmt()
                .pretty()
                .with_env_filter(env_filter)
                .init();
        }
        _ => {
            // Default to JSON for "json" or any unknown format
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_current_span(false)
                .with_span_list(false)
                .init();
        }
    }
}
