use crate::error::ApiError;
use axum::http::StatusCode;

pub fn require_new_activity_allowed() -> Result<(), ApiError> {
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "agent_hosting_closed",
        "Agent Hosting no longer accepts new deployments, subscriptions or credit purchases.",
    ))
}

pub fn signups_closed_error() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "agent_hosting_signups_closed",
        "Agent Hosting is closed to new signups. Existing users can still sign in.",
    )
}
