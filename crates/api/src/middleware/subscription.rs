//! Subscription validation middleware for LLM proxy endpoints.
//!
//! Ensures the authenticated user has sufficient token quota (active subscription
//! and within monthly limits) before allowing access to chat completions, images, and responses.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde::Serialize;
use std::sync::Arc;

use crate::middleware::AuthenticatedUser;
use services::subscription::ports::{SubscriptionError, SubscriptionService};

/// Error response shape for subscription-related failures (matches proxy API format)
#[derive(Serialize)]
struct SubscriptionErrorResponse {
    error: String,
}

/// Error message when subscription is required but user has none
const SUBSCRIPTION_REQUIRED_ERROR_MESSAGE: &str =
    "Active subscription required. Please subscribe to continue.";

/// Error message when monthly credit limit is exceeded
const MONTHLY_CREDIT_LIMIT_EXCEEDED_MESSAGE: &str =
    "Monthly credit limit exceeded. Upgrade your plan or purchase more credits.";

/// State for subscription validation middleware
#[derive(Clone)]
pub struct SubscriptionState {
    pub subscription_service: Arc<dyn SubscriptionService>,
}

/// Middleware that validates the authenticated user has an active subscription
/// and sufficient token quota for proxy/chat access.
///
/// Must run after auth middleware (so `AuthenticatedUser` is in request extensions).
/// Applies to both session users and agent API key users (owner's subscription).
/// Returns 403 when no active subscription, 402 when monthly token limit exceeded.
pub async fn subscription_middleware(
    State(state): State<SubscriptionState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let user = request
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .ok_or_else(|| {
            tracing::error!("Subscription middleware: AuthenticatedUser missing from extensions");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubscriptionErrorResponse {
                    error: "Authentication error".to_string(),
                }),
            )
                .into_response()
        })?;

    match state
        .subscription_service
        .require_subscription_for_proxy(user.user_id)
        .await
    {
        Ok(()) => Ok(next.run(request).await),
        Err(SubscriptionError::NoActiveSubscription) => {
            tracing::info!(
                "Blocked proxy access for user_id={}: no active subscription",
                user.user_id
            );
            Err((
                StatusCode::FORBIDDEN,
                Json(SubscriptionErrorResponse {
                    error: SUBSCRIPTION_REQUIRED_ERROR_MESSAGE.to_string(),
                }),
            )
                .into_response())
        }
        Err(SubscriptionError::MonthlyCreditLimitExceeded { used, limit }) => {
            tracing::info!(
                "Blocked proxy access for user_id={}: monthly credit limit exceeded (used {} of {})",
                user.user_id,
                used,
                limit
            );
            Err((
                StatusCode::PAYMENT_REQUIRED,
                Json(SubscriptionErrorResponse {
                    error: format!(
                        "{} You have used {} of {} credits this period.",
                        MONTHLY_CREDIT_LIMIT_EXCEEDED_MESSAGE, used, limit
                    ),
                }),
            )
                .into_response())
        }
        Err(SubscriptionError::MonthlyTokenLimitExceeded { used, limit }) => {
            tracing::info!(
                "Blocked proxy access for user_id={}: monthly token limit exceeded (used {} of {})",
                user.user_id,
                used,
                limit
            );
            Err((
                StatusCode::PAYMENT_REQUIRED,
                Json(SubscriptionErrorResponse {
                    error: format!(
                        "{} You have used {} of {} tokens this period.",
                        MONTHLY_CREDIT_LIMIT_EXCEEDED_MESSAGE, used, limit
                    ),
                }),
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!(
                "Failed to check subscription status for user_id={}: {}",
                user.user_id,
                e
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubscriptionErrorResponse {
                    error: "Failed to verify subscription status".to_string(),
                }),
            )
                .into_response())
        }
    }
}
