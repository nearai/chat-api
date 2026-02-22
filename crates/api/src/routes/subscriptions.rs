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
use url::Url;
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

/// Validates that a URL is valid and secure for Stripe checkout/portal redirects.
/// Requires https for production. Allows http only for localhost/127.0.0.1 (development).
fn validate_redirect_url(url_str: &str, field_name: &str) -> Result<(), ApiError> {
    let url = Url::parse(url_str).map_err(|_| {
        ApiError::bad_request(format!(
            "Invalid {}: must be a valid URL (e.g., https://example.com/success)",
            field_name
        ))
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            // Allow http only for local development (localhost, 127.0.0.1)
            let host_ok = url
                .host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1")
                .unwrap_or(false);
            if host_ok {
                Ok(())
            } else {
                Err(ApiError::bad_request(format!(
                    "Invalid {}: URL must use https for non-localhost addresses (http is only allowed for localhost/127.0.0.1 during development)",
                    field_name
                )))
            }
        }
        _ => Err(ApiError::bad_request(format!(
            "Invalid {}: URL scheme must be https (or http for localhost/127.0.0.1 only)",
            field_name
        ))),
    }
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

/// Response for subscription resume
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResumeSubscriptionResponse {
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

/// Min tokens per purchase (500k)
const TOKEN_PURCHASE_MIN_AMOUNT: u64 = 500_000;
/// Max tokens per purchase (10B)
const TOKEN_PURCHASE_MAX_AMOUNT: u64 = 10_000_000_000;

/// Response containing available subscription plans
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ListPlansResponse {
    /// List of available subscription plans
    pub plans: Vec<SubscriptionPlan>,
}

/// Request to create a token purchase checkout
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateTokenPurchaseRequest {
    /// Number of tokens to purchase (price computed from fixed price_per_million)
    pub amount: u64,
    /// URL to redirect after successful checkout
    pub success_url: String,
    /// URL to redirect after cancelled checkout
    pub cancel_url: String,
}

/// Response containing token purchase checkout URL
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateTokenPurchaseResponse {
    /// Stripe checkout URL for completing token purchase
    pub checkout_url: String,
}

/// Response containing purchased token balance
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PurchasedTokenBalanceResponse {
    /// Current purchased token balance (spendable)
    pub balance: i64,
}

/// Response containing token purchase info (for UI display)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokensPurchaseInfoResponse {
    /// Suggested default amount (from config; user can specify any amount in range)
    pub amount: u64,
    /// Price per 1M tokens in USD (e.g. 1.70)
    pub price_per_million: f64,
    /// Minimum tokens allowed per purchase
    pub min_amount: u64,
    /// Maximum tokens allowed per purchase
    pub max_amount: u64,
}

/// Request to create a customer portal session
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreatePortalSessionRequest {
    /// URL to redirect after leaving the portal
    pub return_url: String,
}

/// Response containing portal URL
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreatePortalSessionResponse {
    /// Stripe customer portal URL
    pub url: String,
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

    validate_redirect_url(&req.success_url, "success_url")?;
    validate_redirect_url(&req.cancel_url, "cancel_url")?;

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
            SubscriptionError::NoStripeCustomer => {
                tracing::error!("Unexpected NoStripeCustomer in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::WebhookVerificationFailed(msg) => {
                tracing::error!(error = ?msg, "Unexpected webhook error in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::SubscriptionNotScheduledForCancellation => {
                tracing::error!("Unexpected SubscriptionNotScheduledForCancellation in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::MonthlyTokenLimitExceeded { .. } => {
                tracing::error!("Unexpected MonthlyTokenLimitExceeded in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::TokenPurchaseNotConfigured => {
                tracing::error!("Unexpected TokenPurchaseNotConfigured in create");
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

/// Resume a subscription that was scheduled to cancel at period end
#[utoipa::path(
    post,
    path = "/v1/subscriptions/resume",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Subscription resumed successfully", body = ResumeSubscriptionResponse),
        (status = 400, description = "Subscription is not scheduled for cancellation", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No active subscription found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn resume_subscription(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<ResumeSubscriptionResponse>, ApiError> {
    tracing::info!("Resuming subscription for user_id={}", user.user_id);

    app_state
        .subscription_service
        .resume_subscription(user.user_id)
        .await
        .map_err(|e| match e {
            SubscriptionError::NoActiveSubscription => {
                ApiError::not_found("No active subscription found")
            }
            SubscriptionError::SubscriptionNotScheduledForCancellation => {
                ApiError::bad_request("Subscription is not scheduled for cancellation")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error resuming subscription");
                ApiError::internal_server_error("Failed to resume subscription")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error resuming subscription");
                ApiError::internal_server_error("Failed to resume subscription")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to resume subscription");
                ApiError::internal_server_error("Failed to resume subscription")
            }
        })?;

    Ok(Json(ResumeSubscriptionResponse {
        message: "Subscription resumed successfully".to_string(),
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

/// Create a customer portal session
#[utoipa::path(
    post,
    path = "/v1/subscriptions/portal",
    tag = "Subscriptions",
    request_body = CreatePortalSessionRequest,
    responses(
        (status = 200, description = "Portal session created successfully", body = CreatePortalSessionResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No Stripe customer found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Stripe not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn create_portal_session(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreatePortalSessionRequest>,
) -> Result<Json<CreatePortalSessionResponse>, ApiError> {
    tracing::info!("Creating portal session for user_id={}", user.user_id);

    validate_redirect_url(&req.return_url, "return_url")?;

    let url = app_state
        .subscription_service
        .create_customer_portal_session(user.user_id, req.return_url)
        .await
        .map_err(|e| match e {
            SubscriptionError::NoStripeCustomer => {
                ApiError::not_found("No Stripe customer found for this user")
            }
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable("Stripe is not configured")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to create portal session");
                ApiError::internal_server_error("Failed to create portal session")
            }
        })?;

    Ok(Json(CreatePortalSessionResponse { url }))
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
        .handle_stripe_webhook(&body, signature)
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

/// Create token purchase checkout session
#[utoipa::path(
    post,
    path = "/v1/subscriptions/tokens/purchase",
    tag = "Subscriptions",
    request_body = CreateTokenPurchaseRequest,
    responses(
        (status = 200, description = "Checkout session created successfully", body = CreateTokenPurchaseResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Token purchase not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn create_token_purchase(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateTokenPurchaseRequest>,
) -> Result<Json<CreateTokenPurchaseResponse>, ApiError> {
    tracing::info!(
        "Creating token purchase checkout for user_id={}",
        user.user_id
    );

    if req.amount < TOKEN_PURCHASE_MIN_AMOUNT || req.amount > TOKEN_PURCHASE_MAX_AMOUNT {
        return Err(ApiError::bad_request(format!(
            "amount must be between {} and {} tokens",
            TOKEN_PURCHASE_MIN_AMOUNT, TOKEN_PURCHASE_MAX_AMOUNT
        )));
    }
    validate_redirect_url(&req.success_url, "success_url")?;
    validate_redirect_url(&req.cancel_url, "cancel_url")?;

    let checkout_url = app_state
        .subscription_service
        .create_token_purchase_checkout(
            user.user_id,
            req.amount,
            req.success_url,
            req.cancel_url,
        )
        .await
        .map_err(|e| match e {
            SubscriptionError::TokenPurchaseNotConfigured => {
                ApiError::service_unavailable("Token purchase is not configured")
            }
            SubscriptionError::NoStripeCustomer => {
                ApiError::not_found("No Stripe customer found for this user")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error creating token purchase checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to create token purchase checkout");
                ApiError::internal_server_error("Failed to create checkout")
            }
        })?;

    Ok(Json(CreateTokenPurchaseResponse { checkout_url }))
}

/// Get purchased token balance
#[utoipa::path(
    get,
    path = "/v1/subscriptions/tokens/balance",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Balance retrieved successfully", body = PurchasedTokenBalanceResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_purchased_token_balance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<PurchasedTokenBalanceResponse>, ApiError> {
    let balance = app_state
        .subscription_service
        .get_purchased_token_balance(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get purchased token balance");
            ApiError::internal_server_error("Failed to get balance")
        })?;

    Ok(Json(PurchasedTokenBalanceResponse { balance }))
}

/// Get token purchase info (amount, price) for UI display
#[utoipa::path(
    get,
    path = "/v1/subscriptions/tokens/purchase-info",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Purchase info retrieved successfully", body = TokensPurchaseInfoResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Token purchase not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_tokens_purchase_info(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
) -> Result<Json<TokensPurchaseInfoResponse>, ApiError> {
    let info = app_state
        .subscription_service
        .get_tokens_purchase_info()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get tokens purchase info");
            ApiError::internal_server_error("Failed to get purchase info")
        })?;

    let info = info.ok_or_else(|| ApiError::not_found("Token purchase is not configured"))?;

    Ok(Json(TokensPurchaseInfoResponse {
        amount: info.amount,
        price_per_million: info.price_per_million,
        min_amount: TOKEN_PURCHASE_MIN_AMOUNT,
        max_amount: TOKEN_PURCHASE_MAX_AMOUNT,
    }))
}

/// Create subscription router with authenticated routes
pub fn create_subscriptions_router() -> Router<AppState> {
    Router::new()
        .route("/v1/subscriptions", post(create_subscription))
        .route("/v1/subscriptions", get(list_subscriptions))
        .route("/v1/subscriptions/cancel", post(cancel_subscription))
        .route("/v1/subscriptions/resume", post(resume_subscription))
        .route("/v1/subscriptions/portal", post(create_portal_session))
        .route(
            "/v1/subscriptions/tokens/purchase",
            post(create_token_purchase),
        )
        .route(
            "/v1/subscriptions/tokens/balance",
            get(get_purchased_token_balance),
        )
        .route(
            "/v1/subscriptions/tokens/purchase-info",
            get(get_tokens_purchase_info),
        )
}

/// Create public subscription router (for webhooks and plans - no auth)
pub fn create_public_subscriptions_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/subscriptions/stripe/webhook",
            post(handle_stripe_webhook),
        )
        .route("/v1/subscriptions/plans", get(list_plans))
}
