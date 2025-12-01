#![allow(clippy::uninlined_format_args)]

pub mod common;
pub mod consts;
pub mod error;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod static_files;

pub use error::{ApiError, ApiErrorResponse};
pub use middleware::{auth_middleware, AuthState, AuthenticatedUser};
pub use models::*;
pub use openapi::ApiDoc;
pub use routes::{create_router, create_router_with_cors};
pub use state::AppState;
