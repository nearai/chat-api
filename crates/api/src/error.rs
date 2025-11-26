use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Structured error response returned to API consumers
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct ApiErrorResponse {
    /// Error code for programmatic handling
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Optional additional details about the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Convenient wrapper type for API errors that combines status code with error response
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub response: ApiErrorResponse,
}

impl ApiError {
    /// Create a new API error
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            response: ApiErrorResponse {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }

    /// Add optional details to the error
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.response.details = Some(details.into());
        self
    }

    // Common error constructors for user/auth endpoints

    /// 400 Bad Request
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 401 Unauthorized
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    /// 403 Forbidden
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 404 Not Found
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// 409 Conflict
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// 422 Unprocessable Entity
    pub fn unprocessable_entity(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unprocessable_entity",
            message,
        )
    }

    /// 500 Internal Server Error
    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_server_error",
            message,
        )
    }

    /// 502 Bad Gateway
    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "bad_gateway", message)
    }

    /// 503 Service Unavailable
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            message,
        )
    }

    // Auth-specific errors with more context

    /// Invalid or malformed session token
    pub fn invalid_token() -> Self {
        Self::unauthorized("Invalid or malformed session token")
            .with_details("Session token must start with 'sess_' and be 37 characters long")
    }

    /// Session id not found
    pub fn session_id_not_found() -> Self {
        Self::not_found("Session id not found")
            .with_details("The provided session id does not match any active session.")
    }

    /// Session token not found
    pub fn session_not_found() -> Self {
        Self::unauthorized("Session not found").with_details(
            "The provided session token does not match any active session. Please log in again.",
        )
    }

    /// Session expired
    pub fn session_expired() -> Self {
        Self::unauthorized("Session has expired")
            .with_details("Your session has expired. Please log in again to continue.")
    }

    /// Missing authorization header
    pub fn missing_auth_header() -> Self {
        Self::unauthorized("Missing authorization header")
            .with_details("Request must include an Authorization header with a Bearer token")
    }

    /// Invalid authorization header format
    pub fn invalid_auth_header() -> Self {
        Self::unauthorized("Invalid authorization header format")
            .with_details("Authorization header must be in the format: 'Bearer <token>'")
    }

    /// OAuth authentication failed
    pub fn oauth_failed() -> Self {
        Self::unauthorized("OAuth authentication failed")
            .with_details("Failed to authenticate with the OAuth provider. Please try again.")
    }

    /// OAuth provider error
    pub fn oauth_provider_error(provider: &str) -> Self {
        Self::bad_gateway(format!(
            "Failed to communicate with {provider} OAuth provider"
        ))
    }

    /// Failed to create or retrieve user profile
    pub fn user_profile_error() -> Self {
        Self::internal_server_error("Failed to retrieve user profile")
            .with_details("An error occurred while fetching your profile information")
    }

    /// Failed to logout
    pub fn logout_failed() -> Self {
        Self::internal_server_error("Failed to logout")
            .with_details("An error occurred while revoking your session")
    }
}

/// Implement IntoResponse so ApiError can be returned directly from handlers
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.response)).into_response()
    }
}

/// Convert from anyhow::Error for convenience in services
impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("Internal error: {:#}", err);
        Self::internal_server_error("An internal error occurred")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_error() {
        let err = ApiError::bad_request("Invalid input");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.response.code, "bad_request");
        assert_eq!(err.response.message, "Invalid input");
        assert!(err.response.details.is_none());
    }

    #[test]
    fn test_error_with_details() {
        let err = ApiError::unauthorized("Access denied").with_details("Token expired");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.response.details, Some("Token expired".to_string()));
    }

    #[test]
    fn test_auth_specific_errors() {
        let err = ApiError::invalid_token();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.response.details.is_some());
    }
}
