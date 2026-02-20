use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    extract::State,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use services::subscription::ports::{CreditsSummary, SubscriptionError};
use url::Url;
use utoipa::ToSchema;

/// Request to create a credit purchase checkout session
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateCreditCheckoutRequest {
    /// Number of credits to purchase
    pub credits: u64,
    /// URL to redirect after successful checkout
    pub success_url: String,
    /// URL to redirect after cancelled checkout
    pub cancel_url: String,
}

/// Response containing checkout URL for credit purchase
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateCreditCheckoutResponse {
    /// Stripe checkout URL for completing purchase
    pub checkout_url: String,
}

fn validate_redirect_url(url_str: &str, field_name: &str) -> Result<(), ApiError> {
    let url = Url::parse(url_str).map_err(|_| {
        ApiError::bad_request(format!("Invalid {}: must be a valid URL", field_name))
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host_ok = url
                .host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1")
                .unwrap_or(false);
            if host_ok {
                Ok(())
            } else {
                Err(ApiError::bad_request(format!(
                    "Invalid {}: URL must use https for non-localhost",
                    field_name
                )))
            }
        }
        _ => Err(ApiError::bad_request(format!(
            "Invalid {}: URL scheme must be https or http (localhost only)",
            field_name
        ))),
    }
}

/// GET /v1/credits - Get user's credits summary
#[utoipa::path(
    get,
    path = "/v1/credits",
    tag = "Credits",
    responses(
        (status = 200, description = "Credits summary", body = CreditsSummary),
        (status = 401, description = "Unauthorized"),
        (status = 503, description = "Credits not configured")
    ),
    security(("session_token" = []))
)]
pub async fn get_credits(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<CreditsSummary>, ApiError> {
    let summary = app_state
        .subscription_service
        .get_credits(user.user_id)
        .await
        .map_err(|e| match e {
            SubscriptionError::CreditsNotConfigured => {
                ApiError::service_unavailable("Credit purchase is not configured")
            }
            SubscriptionError::NoMonthlyCreditsConfigured(plan) => ApiError::service_unavailable(
                format!("Plan '{}' has no monthly credits configured", plan),
            ),
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error getting credits");
                ApiError::internal_server_error("Failed to get credits")
            }
            _ => ApiError::internal_server_error("Failed to get credits"),
        })?;
    Ok(Json(summary))
}

/// POST /v1/credits - Create checkout session for credit purchase
#[utoipa::path(
    post,
    path = "/v1/credits",
    tag = "Credits",
    request_body = CreateCreditCheckoutRequest,
    responses(
        (status = 200, description = "Checkout URL", body = CreateCreditCheckoutResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 503, description = "Credits not configured")
    ),
    security(("session_token" = []))
)]
pub async fn create_credit_checkout(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateCreditCheckoutRequest>,
) -> Result<Json<CreateCreditCheckoutResponse>, ApiError> {
    validate_redirect_url(&req.success_url, "success_url")?;
    validate_redirect_url(&req.cancel_url, "cancel_url")?;

    let checkout_url = app_state
        .subscription_service
        .create_credit_purchase_checkout(user.user_id, req.credits, req.success_url, req.cancel_url)
        .await
        .map_err(|e| match e {
            SubscriptionError::CreditsNotConfigured => {
                ApiError::service_unavailable("Credit purchase is not configured")
            }
            SubscriptionError::InvalidCredits(msg) => ApiError::bad_request(msg),
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error creating checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error creating checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
            _ => ApiError::internal_server_error("Failed to create checkout"),
        })?;

    Ok(Json(CreateCreditCheckoutResponse { checkout_url }))
}

/// Create credits router with authenticated routes
pub fn create_credits_router() -> Router<AppState> {
    Router::new()
        .route("/v1/credits", get(get_credits))
        .route("/v1/credits", post(create_credit_checkout))
}
