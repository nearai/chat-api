use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState, validation};
use axum::{
    body::Bytes,
    extract::Query,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use services::subscription::ports::{
    CancelSubscriptionOutcome, ChangePlanOutcome, CreateSubscriptionOutcome,
    ResumeSubscriptionOutcome, SubscriptionError, SubscriptionPlan, SubscriptionWithPlan,
};
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
    /// Optional test clock ID to bind customer to (requires STRIPE_TEST_CLOCK_ENABLED)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_clock_id: Option<String>,
}

fn default_provider() -> String {
    "stripe".to_string()
}

/// Subscription checkout: Stripe redirect URL or HoS catalog `price_id` for client-side locking.
pub type CreateSubscriptionResponse = CreateSubscriptionOutcome;

/// Response for subscription cancellation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CancelSubscriptionResponse {
    pub message: String,
}

/// Response for subscription resume
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResumeSubscriptionResponse {
    pub message: String,
}

/// Request to change subscription plan
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChangePlanRequest {
    /// Target plan name (e.g., "starter", "basic")
    pub plan: String,
}

/// Response for plan change
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChangePlanResponse {
    /// Success message
    pub message: String,
    /// Change result type
    pub result: ChangePlanOutcome,
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

/// Response from POST /v1/subscriptions/near/sync
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NearStakingSyncResponse {
    pub synced: bool,
}

/// Query `provider`: omit or `stripe` for Stripe-backed plans; `house-of-stake` for staking-contract SKUs.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListPlansParams {
    #[serde(default)]
    pub provider: Option<String>,
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
        (status = 200, description = "Stripe: flat `{ \"checkout_url\": \"...\" }`. HoS: `{ \"kind\": \"house_of_stake\", \"price_id\": \"...\" }`.", body = CreateSubscriptionResponse),
        (status = 400, description = "Invalid plan or bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "House-of-Stake requires a linked NEAR wallet", body = crate::error::ApiErrorResponse),
        (status = 409, description = "Active subscription already exists", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Billing not configured (Stripe or House-of-Stake)", body = crate::error::ApiErrorResponse)
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

    validation::validate_redirect_url(&req.success_url, "success_url")
        .map_err(ApiError::bad_request)?;
    validation::validate_redirect_url(&req.cancel_url, "cancel_url")
        .map_err(ApiError::bad_request)?;

    // Validate test clock usage
    if req.test_clock_id.is_some() && !app_state.stripe_test_clock_enabled {
        return Err(ApiError::bad_request("Test clock feature is not enabled"));
    }

    // Snapshot for error mapping (provider is moved into the service call).
    let provider_lc = req.provider.to_lowercase();

    let outcome = app_state
        .subscription_service
        .create_subscription(
            user.user_id,
            req.provider,
            req.plan,
            req.success_url,
            req.cancel_url,
            req.test_clock_id,
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
                let msg = if provider_lc == "house-of-stake" {
                    "House-of-Stake subscription billing is not configured"
                } else {
                    "Stripe is not configured"
                };
                ApiError::service_unavailable(msg)
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
            SubscriptionError::CreditsNotConfigured => {
                ApiError::service_unavailable("Credit purchase is not configured")
            }
            SubscriptionError::InvalidCredits(msg) => ApiError::bad_request(msg),
            SubscriptionError::InstanceLimitExceeded { current, max } => {
                ApiError::bad_request(format!(
                    "Cannot subscribe: current instance count ({}) exceeds plan limit ({})",
                    current, max
                ))
            }
            SubscriptionError::TestClockNotAllowedForExistingCustomer => ApiError::bad_request(
                "Cannot associate test clock with existing Stripe customer".to_string(),
            ),
            SubscriptionError::ModelNotAllowedInPlan { model, plan } => {
                tracing::error!(
                    model = ?model,
                    plan = ?plan,
                    "Unexpected ModelNotAllowedInPlan in create_subscription"
                );
                ApiError::internal_server_error("Failed to create subscription")
            }
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::HouseOfStakeRequiresNearWallet => ApiError::forbidden(
                "House-of-Stake subscription requires signing in with a NEAR wallet",
            ),
            unexpected => {
                tracing::error!(error = ?unexpected, "Unexpected subscription error in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
        })?;

    Ok(Json(outcome))
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
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "House-of-Stake not configured or NEAR RPC error", body = crate::error::ApiErrorResponse)
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

    let outcome = app_state
        .subscription_service
        .cancel_subscription(user.user_id)
        .await
        .map_err(|e| match e {
            SubscriptionError::NoActiveSubscription => {
                ApiError::not_found("No active subscription found")
            }
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error canceling subscription");
                ApiError::service_unavailable("Failed to reach NEAR RPC for subscription sync")
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

    let message = match outcome {
        CancelSubscriptionOutcome::Completed => {
            "Subscription will be canceled at period end".to_string()
        }
        CancelSubscriptionOutcome::NearStakingCancel => {
            "Complete cancellation in your NEAR wallet".to_string()
        }
    };

    Ok(Json(CancelSubscriptionResponse { message }))
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
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "House-of-Stake not configured or NEAR RPC error", body = crate::error::ApiErrorResponse)
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

    let outcome = app_state
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
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error resuming subscription");
                ApiError::service_unavailable("Failed to reach NEAR RPC for subscription sync")
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

    let message = match outcome {
        ResumeSubscriptionOutcome::Completed => "Subscription resumed successfully".to_string(),
        ResumeSubscriptionOutcome::NearStakingResume => {
            "Complete resume in your NEAR wallet".to_string()
        }
    };

    Ok(Json(ResumeSubscriptionResponse { message }))
}

/// Change the user's subscription plan
#[utoipa::path(
    post,
    path = "/v1/subscriptions/change",
    tag = "Subscriptions",
    request_body = ChangePlanRequest,
    responses(
        (status = 200, description = "Plan changed successfully", body = ChangePlanResponse),
        (status = 400, description = "Invalid plan, instance limit exceeded, or subscription is scheduled for cancellation", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No active subscription found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "House-of-Stake not configured, NEAR RPC error, or Stripe not configured", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn change_plan(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<ChangePlanRequest>,
) -> Result<Json<ChangePlanResponse>, ApiError> {
    tracing::info!(
        "Changing plan for user_id={} to plan={}",
        user.user_id,
        req.plan
    );

    let outcome = app_state
        .subscription_service
        .change_plan(user.user_id, req.plan.clone())
        .await
        .map_err(|e| match e {
            SubscriptionError::InstanceLimitExceeded { current, max } => {
                ApiError::bad_request(format!(
                    "Cannot switch to this plan: you have {} agent instances but this plan allows only {}. Delete excess instances to switch plans.",
                    current, max
                ))
            }
            SubscriptionError::InvalidPlan(plan) => {
                ApiError::bad_request(format!("Invalid plan: {}", plan))
            }
            SubscriptionError::NoActiveSubscription => {
                ApiError::not_found("No active subscription found")
            }
            SubscriptionError::SubscriptionScheduledForCancellation => {
                ApiError::bad_request("Subscription is scheduled for cancellation; resume it before changing plans")
            }
            SubscriptionError::NotConfigured => {
                ApiError::service_unavailable(
                    "Subscription billing is not configured for this operation",
                )
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error changing plan");
                ApiError::internal_server_error("Failed to change plan")
            }
            SubscriptionError::StripeError(msg) => {
                tracing::error!(error = ?msg, "Stripe error changing plan");
                ApiError::internal_server_error("Failed to change plan")
            }
            SubscriptionError::NoPendingDowngrade => {
                ApiError::bad_request("No pending downgrade to cancel")
            }
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
            }
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error changing plan");
                ApiError::service_unavailable("Failed to reach NEAR RPC for staking catalog")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to change plan");
                ApiError::internal_server_error("Failed to change plan")
            }
        })?;

    Ok(Json(ChangePlanResponse {
        message: match &outcome {
            ChangePlanOutcome::ChangedImmediately => "Plan changed successfully".to_string(),
            ChangePlanOutcome::ScheduledForPeriodEnd => {
                "Downgrade scheduled and will be checked near period end".to_string()
            }
            ChangePlanOutcome::NoOp => "User is already on the target plan".to_string(),
            ChangePlanOutcome::DowngradeCancelled => "Pending downgrade cancelled".to_string(),
            ChangePlanOutcome::NearStakingUpgrade { .. }
            | ChangePlanOutcome::NearStakingScheduleDowngrade { .. } => {
                "Complete plan change in your NEAR wallet".to_string()
            }
        },
        result: outcome,
    }))
}

/// Get available subscription plans
#[utoipa::path(
    get,
    path = "/v1/subscriptions/plans",
    tag = "Subscriptions",
    params(ListPlansParams),
    responses(
        (status = 200, description = "Plans retrieved successfully", body = ListPlansResponse),
        (status = 400, description = "Invalid provider filter", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "Billing provider not configured", body = crate::error::ApiErrorResponse)
    )
)]
pub async fn list_plans(
    State(app_state): State<AppState>,
    Query(params): Query<ListPlansParams>,
) -> Result<Json<ListPlansResponse>, ApiError> {
    tracing::debug!(
        "Listing available subscription plans provider={:?}",
        params.provider
    );

    let provider_filter = params
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let plans = app_state
        .subscription_service
        .get_available_plans(provider_filter)
        .await
        .map_err(|e| match e {
            SubscriptionError::NotConfigured => ApiError::service_unavailable(
                "Subscription plans are not configured for the requested provider",
            ),
            SubscriptionError::InvalidProvider(msg) => ApiError::bad_request(msg),
            SubscriptionError::HouseOfStakeNotConfigured => {
                ApiError::service_unavailable("House-of-Stake billing is not configured")
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
        (status = 503, description = "No billing provider configured or NEAR RPC sync failed", body = crate::error::ApiErrorResponse)
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
            SubscriptionError::NotConfigured => ApiError::service_unavailable(
                "Subscription plans are not configured for any billing provider",
            ),
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error listing subscriptions");
                ApiError::service_unavailable("Failed to sync subscription from NEAR RPC")
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

    validation::validate_redirect_url(&req.return_url, "return_url")
        .map_err(ApiError::bad_request)?;

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

/// POST /v1/subscriptions/near/sync — refresh local `house-of-stake` row from chain (authenticated).
#[utoipa::path(
    post,
    path = "/v1/subscriptions/near/sync",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Local subscription row refreshed from chain", body = NearStakingSyncResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse),
        (status = 503, description = "NEAR RPC unavailable", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn sync_near_staking_subscription(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<NearStakingSyncResponse>, ApiError> {
    app_state
        .subscription_service
        .sync_near_staking_subscription(user.user_id)
        .await
        .map_err(|e| match e {
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC sync failed");
                ApiError::service_unavailable("Failed to sync subscription from NEAR RPC")
            }
            SubscriptionError::DatabaseError(msg) => {
                tracing::error!(error = ?msg, "Database error syncing NEAR subscription");
                ApiError::internal_server_error("Failed to sync subscription")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to sync NEAR subscription");
                ApiError::internal_server_error("Failed to sync subscription")
            }
        })?;

    Ok(Json(NearStakingSyncResponse { synced: true }))
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

/// Create subscription router with authenticated routes
pub fn create_subscriptions_router() -> Router<AppState> {
    Router::new()
        .route("/v1/subscriptions", post(create_subscription))
        .route("/v1/subscriptions", get(list_subscriptions))
        .route("/v1/subscriptions/cancel", post(cancel_subscription))
        .route("/v1/subscriptions/resume", post(resume_subscription))
        .route("/v1/subscriptions/change", post(change_plan))
        .route("/v1/subscriptions/portal", post(create_portal_session))
        .route(
            "/v1/subscriptions/near/sync",
            post(sync_near_staking_subscription),
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
