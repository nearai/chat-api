use crate::error::ApiError;
use axum::http::StatusCode;

pub fn require_new_subscriptions_allowed() -> Result<(), ApiError> {
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "agent_hosting_subscriptions_closed",
        "New Agent Hosting subscriptions are closed. Existing subscriptions remain available.",
    ))
}

pub fn signups_closed_error() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "agent_hosting_signups_closed",
        "Agent Hosting is closed to new signups. Existing users can still sign in.",
    )
}
