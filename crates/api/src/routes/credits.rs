use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState, validation};
use axum::{
    extract::State,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use services::subscription::ports::{
    CreateCreditPurchaseOutcome, CreditsSummary, SubscriptionError,
};
use utoipa::ToSchema;

/// Request to create a credit purchase checkout session
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateCreditCheckoutRequest {
    /// Number of credits to purchase
    pub credits: u64,
    /// Optional payment provider override (`stripe` or `house-of-stake`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// URL to redirect after successful checkout
    pub success_url: String,
    /// URL to redirect after cancelled checkout
    pub cancel_url: String,
}

/// Response containing either a Stripe Checkout redirect or House-of-Stake payment intent.
pub type CreateCreditCheckoutResponse = CreateCreditPurchaseOutcome;

/// Request to confirm a House-of-Stake credit purchase after wallet signing.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConfirmCreditPurchaseRequest {
    /// staking-contract purchase id returned by `pay`
    pub purchase_id: String,
    /// Credit quantity the user intended to purchase
    pub expected_credits: u64,
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
        (status = 200, description = "Stripe checkout redirect or House-of-Stake payment intent", body = CreateCreditCheckoutResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "House-of-Stake credit purchase requires a linked NEAR wallet"),
        (status = 503, description = "Credits or selected payment provider is not configured")
    ),
    security(("session_token" = []))
)]
pub async fn create_credit_checkout(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateCreditCheckoutRequest>,
) -> Result<Json<CreateCreditCheckoutResponse>, ApiError> {
    validation::validate_redirect_url(&req.success_url, "success_url")
        .map_err(ApiError::bad_request)?;
    validation::validate_redirect_url(&req.cancel_url, "cancel_url")
        .map_err(ApiError::bad_request)?;

    let outcome = app_state
        .subscription_service
        .create_credit_purchase_checkout(
            user.user_id,
            req.credits,
            req.provider,
            req.success_url,
            req.cancel_url,
        )
        .await
        .map_err(|e| match e {
            SubscriptionError::CreditsNotConfigured => {
                ApiError::service_unavailable("Credit purchase is not configured")
            }
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Selected payment provider is not configured")
            }
            SubscriptionError::InvalidProvider(msg) => ApiError::bad_request(msg),
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::HouseOfStakeRequiresNearWallet => {
                ApiError::forbidden("Credit purchase requires signing in with a NEAR wallet")
            }
            SubscriptionError::InvalidCredits(msg) => ApiError::bad_request(msg),
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error creating credit checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error creating checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
            _ => ApiError::internal_server_error("Failed to create checkout"),
        })?;

    Ok(Json(outcome))
}

/// POST /v1/credits/confirm - Confirm a House-of-Stake purchase and grant credits
#[utoipa::path(
    post,
    path = "/v1/credits/confirm",
    tag = "Credits",
    request_body = ConfirmCreditPurchaseRequest,
    responses(
        (status = 200, description = "Credits summary after confirmed purchase", body = CreditsSummary),
        (status = 400, description = "Invalid or stale purchase"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Credit purchase requires a linked NEAR wallet"),
        (status = 503, description = "Credits or House-of-Stake billing not configured, or NEAR RPC unavailable")
    ),
    security(("session_token" = []))
)]
pub async fn confirm_credit_purchase(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<ConfirmCreditPurchaseRequest>,
) -> Result<Json<CreditsSummary>, ApiError> {
    if req.purchase_id.trim().is_empty() {
        return Err(ApiError::bad_request("purchase_id is required"));
    }

    let summary = app_state
        .subscription_service
        .confirm_credit_purchase(user.user_id, req.purchase_id, req.expected_credits)
        .await
        .map_err(|e| match e {
            SubscriptionError::CreditsNotConfigured => {
                ApiError::service_unavailable("Credit purchase is not configured")
            }
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::HouseOfStakeRequiresNearWallet => {
                ApiError::forbidden("Credit purchase requires signing in with a NEAR wallet")
            }
            SubscriptionError::InvalidCredits(msg) => ApiError::bad_request(msg),
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error confirming credit purchase");
                ApiError::service_unavailable(
                    "Failed to reach NEAR RPC to verify House-of-Stake purchase",
                )
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error confirming credit purchase");
                ApiError::internal_server_error("Failed to confirm credit purchase")
            }
            _ => ApiError::internal_server_error("Failed to confirm credit purchase"),
        })?;

    Ok(Json(summary))
}

/// Create credits router with authenticated routes
pub fn create_credits_router() -> Router<AppState> {
    Router::new()
        .route("/v1/credits", get(get_credits))
        .route("/v1/credits", post(create_credit_checkout))
        .route("/v1/credits/confirm", post(confirm_credit_purchase))
}
