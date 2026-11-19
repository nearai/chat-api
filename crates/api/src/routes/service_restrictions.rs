use crate::error::ApiError;
use axum::http::StatusCode;

pub fn require_new_subscriptions_allowed() -> Result<(), ApiError> {
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "service_subscriptions_closed",
        "New subscriptions are closed. Existing subscriptions remain available.",
    ))
}

pub fn signups_closed_error() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "service_signups_closed",
        "New account registrations are closed. Existing users can still sign in.",
    )
}
