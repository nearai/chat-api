use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState};
use axum::{
    body::Bytes,
    extract::Query,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use services::subscription::ports::{SubscriptionError, SubscriptionPlan, SubscriptionWithPlan};
use utoipa::ToSchema;

/// Request to create a new subscription
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateSubscriptionRequest {
    /// Payment provider (e.g., "stripe"). Defaults to "stripe" if not specified.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Plan name (e.g., "basic", "pro")
    pub plan: String,
    /// URL to redirect after successful checkout
    pub success_url: String,
    /// URL to redirect after cancelled checkout
    pub cancel_url: String,
}

fn default_provider() -> String {
    "stripe".to_string()
}

/// Response containing checkout URL
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateSubscriptionResponse {
    /// Stripe checkout URL for completing subscription
    pub checkout_url: String,
}

/// Response for subscription cancellation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CancelSubscriptionResponse {
    /// Success message
    pub message: String,
}

/// Response containing user's subscriptions
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ListSubscriptionsResponse {
    /// List of subscriptions
    pub subscriptions: Vec<SubscriptionWithPlan>,
}

/// Query parameters for listing subscriptions
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSubscriptionsParams {
    /// Include inactive (expired/canceled) subscriptions
    #[serde(default = "default_false")]
    pub include_inactive: bool,
}

fn default_false() -> bool {
    false
}

/// Response containing available subscription plans
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ListPlansResponse {
    /// List of available subscription plans
    pub plans: Vec<SubscriptionPlan>,
}

/// Create a subscription checkout session
#[utoipa::path(
    post,
    path = "/v1/subscriptions",
    tag = "Subscriptions",
    request_body = CreateSubscriptionRequest,
    responses(
        (status = 200, description = "Checkout session created successfully", body = CreateSubscriptionResponse),
        (status = 400, description = "Invalid plan or bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 409, description = "Active subscription already exists", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Stripe not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn create_subscription(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateSubscriptionRequest>,
) -> Result<Json<CreateSubscriptionResponse>, ApiError> {
    tracing::info!(
        "Creating subscription for user_id={}, provider={}, plan={}",
        user.user_id,
        req.provider,
        req.plan
    );

    let checkout_url = app_state
        .subscription_service
        .create_subscription(
            user.user_id,
            req.provider,
            req.plan,
            req.success_url,
            req.cancel_url,
        )
        .await
        .map_err(|e| match e {
            SubscriptionError::ActiveSubscriptionExists => {
                ApiError::conflict("User already has an active subscription")
            }
            SubscriptionError::InvalidPlan(plan) => {
                ApiError::bad_request(format!("Invalid plan: {}", plan))
            }
            SubscriptionError::InvalidProvider(provider) => {
                ApiError::bad_request(format!("Invalid provider: {}", provider))
            }
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error creating subscription");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error creating subscription");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::InternalError(msg) => {
                tracing::error!(error = ?msg, "Internal error creating subscription");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::NoActiveSubscription => {
                tracing::error!("Unexpected NoActiveSubscription in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::WebhookVerificationFailed(msg) => {
                tracing::error!(error = ?msg, "Unexpected webhook error in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
        })?;

    Ok(Json(CreateSubscriptionResponse { checkout_url }))
}

/// Cancel user's active subscription
#[utoipa::path(
    post,
    path = "/v1/subscriptions/cancel",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Subscription canceled successfully", body = CancelSubscriptionResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No active subscription found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn cancel_subscription(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<CancelSubscriptionResponse>, ApiError> {
    tracing::info!("Canceling subscription for user_id={}", user.user_id);

    app_state
        .subscription_service
        .cancel_subscription(user.user_id)
        .await
        .map_err(|e| match e {
            SubscriptionError::NoActiveSubscription => {
                ApiError::not_found("No active subscription found")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error canceling subscription");
                ApiError::internal_server_error("Failed to cancel subscription")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error canceling subscription");
                ApiError::internal_server_error("Failed to cancel subscription")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to cancel subscription");
                ApiError::internal_server_error("Failed to cancel subscription")
            }
        })?;

    Ok(Json(CancelSubscriptionResponse {
        message: "Subscription will be canceled at period end".to_string(),
    }))
}

/// Get available subscription plans
#[utoipa::path(
    get,
    path = "/v1/subscriptions/plans",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Plans retrieved successfully", body = ListPlansResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Stripe not configured", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn list_plans(
    State(app_state): State<AppState>,
) -> Result<Json<ListPlansResponse>, ApiError> {
    tracing::debug!("Listing available subscription plans");

    let plans = app_state
        .subscription_service
        .get_available_plans()
        .await
        .map_err(|e| match e {
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to list plans");
                ApiError::internal_server_error("Failed to list plans")
            }
        })?;

    Ok(Json(ListPlansResponse { plans }))
}

/// Get user's subscriptions
#[utoipa::path(
    get,
    path = "/v1/subscriptions",
    tag = "Subscriptions",
    params(
        ListSubscriptionsParams
    ),
    responses(
        (status = 200, description = "Subscriptions retrieved successfully", body = ListSubscriptionsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Stripe not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_subscriptions(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<ListSubscriptionsParams>,
) -> Result<Json<ListSubscriptionsResponse>, ApiError> {
    tracing::debug!(
        "Listing subscriptions for user_id={}, include_inactive={}",
        user.user_id,
        params.include_inactive
    );

    let subscriptions = app_state
        .subscription_service
        .get_user_subscriptions(user.user_id, !params.include_inactive)
        .await
        .map_err(|e| match e {
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error listing subscriptions");
                ApiError::internal_server_error("Failed to list subscriptions")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to list subscriptions");
                ApiError::internal_server_error("Failed to list subscriptions")
            }
        })?;

    Ok(Json(ListSubscriptionsResponse { subscriptions }))
}

/// Handle Stripe webhook events (public endpoint - no auth required)
pub async fn handle_stripe_webhook(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::info!("Received Stripe webhook");

    // Get Stripe signature from headers
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Missing Stripe-Signature header"))?;

    // Process webhook
    app_state
        .subscription_service
        .handle_webhook(&body, signature)
        .await
        .map_err(|e| match e {
            SubscriptionError::WebhookVerificationFailed(msg) => {
                tracing::warn!(error = ?msg, "Webhook verification failed");
                ApiError::bad_request("Invalid webhook signature")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error processing webhook");
                ApiError::internal_server_error("Failed to process webhook")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to process webhook");
                ApiError::internal_server_error("Failed to process webhook")
            }
        })?;

    Ok(Json(serde_json::json!({ "received": true })))
}

/// Create subscription router with authenticated routes
pub fn create_subscriptions_router() -> Router<AppState> {
    Router::new()
        .route("/v1/subscriptions", post(create_subscription))
        .route("/v1/subscriptions", get(list_subscriptions))
        .route("/v1/subscriptions/cancel", post(cancel_subscription))
}

/// Create public subscription router (for webhooks and plans - no auth)
pub fn create_public_subscriptions_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/subscription/stripe/webhook",
            post(handle_stripe_webhook),
        )
        .route("/v1/subscriptions/plans", get(list_plans))
}
