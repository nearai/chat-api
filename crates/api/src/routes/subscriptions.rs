use crate::{error::ApiError, middleware::AuthenticatedUser, state::AppState, validation};
use axum::{
    body::Bytes,
    extract::Query,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::aml::{AmlCheckResult, AmlRiskLevel};
use services::subscription::ports::{
    CancelSubscriptionOutcome, ChangePlanOutcome, CreateSubscriptionOutcome,
    NearStakingStorageIntent, NearStakingSyncSummary, ResumeSubscriptionOutcome, SubscriptionError,
    SubscriptionPlan, SubscriptionWithPlan,
};
use utoipa::ToSchema;

pub(crate) fn aml_blocked_error(_account_id: String) -> ApiError {
    ApiError::forbidden("Invalid NEAR account")
}

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
#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum CreateSubscriptionResponse {
    StripeCheckout {
        checkout_url: String,
    },
    HouseOfStake {
        kind: String,
        contract_id: String,
        price_id: String,
        network_id: String,
        attached_deposit_yocto: String,
        storage: Box<NearStakingStorageIntent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aml: Option<PublicAmlCheckResult>,
    },
}

impl CreateSubscriptionResponse {
    fn from_outcome(outcome: CreateSubscriptionOutcome) -> Self {
        match outcome {
            CreateSubscriptionOutcome::StripeCheckout { checkout_url } => {
                Self::StripeCheckout { checkout_url }
            }
            CreateSubscriptionOutcome::NearStakeLock {
                contract_id,
                price_id,
                network_id,
                attached_deposit_yocto,
                storage,
                aml,
            } => Self::HouseOfStake {
                kind: "house_of_stake".to_string(),
                contract_id,
                price_id,
                network_id,
                attached_deposit_yocto,
                storage,
                aml: public_aml_result(*aml),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicAmlCheckResult {
    pub risk_level: AmlRiskLevel,
    pub checked_at: DateTime<Utc>,
}

impl From<&AmlCheckResult> for PublicAmlCheckResult {
    fn from(result: &AmlCheckResult) -> Self {
        Self {
            risk_level: result.risk_level,
            checked_at: result.checked_at,
        }
    }
}

pub(crate) fn public_aml_result(result: AmlCheckResult) -> Option<PublicAmlCheckResult> {
    Some(PublicAmlCheckResult::from(&result))
}

fn public_change_plan_result(outcome: ChangePlanOutcome) -> serde_json::Value {
    match outcome {
        ChangePlanOutcome::ChangedImmediately => serde_json::json!("changed_immediately"),
        ChangePlanOutcome::ScheduledForPeriodEnd => serde_json::json!("scheduled_for_period_end"),
        ChangePlanOutcome::NoOp => serde_json::json!("no_op"),
        ChangePlanOutcome::DowngradeCancelled => serde_json::json!("downgrade_cancelled"),
        ChangePlanOutcome::NearStakingChangePlan {
            contract_id,
            network_id,
            subscription_id,
            target_price_id,
            target_amount,
            required_deposit_yocto,
            timing,
            aml,
        } => {
            let mut value = serde_json::json!({
                "kind": "near_staking_change_plan",
                "contract_id": contract_id,
                "network_id": network_id,
                "subscription_id": subscription_id,
                "target_price_id": target_price_id,
                "target_amount": target_amount,
                "required_deposit_yocto": required_deposit_yocto,
                "timing": timing,
            });
            if let Some(public_aml) = public_aml_result(*aml) {
                value["aml"] = serde_json::to_value(public_aml)
                    .expect("PublicAmlCheckResult serializes to JSON");
            }
            value
        }
    }
}

/// Response for subscription cancellation
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CancelSubscriptionResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_deposit_yocto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aml: Option<PublicAmlCheckResult>,
}

/// Response for subscription resume
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResumeSubscriptionResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_deposit_yocto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aml: Option<PublicAmlCheckResult>,
}

/// Request to change subscription plan
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChangePlanRequest {
    /// Target plan name (e.g., "starter", "basic")
    pub plan: String,
    /// Target HoS stake amount in yoctoNEAR. Required for House-of-Stake subscriptions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_amount: Option<String>,
}

/// Response for plan change
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChangePlanResponse {
    /// Success message
    pub message: String,
    /// Change result type
    pub result: serde_json::Value,
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
        (status = 200, description = "Stripe: flat `{ \"checkout_url\": \"...\" }`. HoS: `{ \"kind\": \"house_of_stake\", \"contract_id\": \"...\", \"price_id\": \"...\", \"network_id\": \"...\" }`.", body = CreateSubscriptionResponse),
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
            SubscriptionError::AmlHighRiskBlocked { account_id } => aml_blocked_error(account_id),
            unexpected => {
                tracing::error!(error = ?unexpected, "Unexpected subscription error in create");
                ApiError::internal_server_error("Failed to create subscription")
            }
        })?;

    Ok(Json(CreateSubscriptionResponse::from_outcome(outcome)))
}

/// Cancel user's active subscription
#[utoipa::path(
    post,
    path = "/v1/subscriptions/cancel",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Stripe: subscription set to cancel at period end. House-of-stake: wallet instructions only — local `cancel_at_period_end` updates after chain sync (`POST /v1/subscriptions/near/sync` or reconcile on other subscription calls).", body = CancelSubscriptionResponse),
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
            SubscriptionError::AmlHighRiskBlocked { account_id } => aml_blocked_error(account_id),
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

    let response = match outcome {
        CancelSubscriptionOutcome::Completed => CancelSubscriptionResponse {
            message: "Subscription will be canceled at period end".to_string(),
            kind: None,
            contract_id: None,
            subscription_id: None,
            network_id: None,
            required_deposit_yocto: None,
            aml: None,
        },
        CancelSubscriptionOutcome::NearStakingCancel {
            contract_id,
            subscription_id,
            network_id,
            required_deposit_yocto,
            aml,
        } => CancelSubscriptionResponse {
            message: "Complete cancellation in your NEAR wallet".to_string(),
            kind: Some("near_staking_cancel".to_string()),
            contract_id: Some(contract_id),
            subscription_id: Some(subscription_id),
            network_id: Some(network_id),
            required_deposit_yocto: Some(required_deposit_yocto),
            aml: public_aml_result(*aml),
        },
    };

    Ok(Json(response))
}

/// Resume a subscription that was scheduled to cancel at period end
#[utoipa::path(
    post,
    path = "/v1/subscriptions/resume",
    tag = "Subscriptions",
    responses(
        (status = 200, description = "Stripe: cancellation at period end cleared. House-of-stake: wallet instructions only — local DB updates after chain sync (`POST /v1/subscriptions/near/sync` or reconcile on other subscription calls).", body = ResumeSubscriptionResponse),
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
            SubscriptionError::AmlHighRiskBlocked { account_id } => aml_blocked_error(account_id),
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

    let response = match outcome {
        ResumeSubscriptionOutcome::Completed => ResumeSubscriptionResponse {
            message: "Subscription resumed successfully".to_string(),
            kind: None,
            contract_id: None,
            subscription_id: None,
            network_id: None,
            required_deposit_yocto: None,
            aml: None,
        },
        ResumeSubscriptionOutcome::NearStakingResume {
            contract_id,
            subscription_id,
            network_id,
            required_deposit_yocto,
            aml,
        } => ResumeSubscriptionResponse {
            message: "Complete resume in your NEAR wallet".to_string(),
            kind: Some("near_staking_resume".to_string()),
            contract_id: Some(contract_id),
            subscription_id: Some(subscription_id),
            network_id: Some(network_id),
            required_deposit_yocto: Some(required_deposit_yocto),
            aml: public_aml_result(*aml),
        },
    };

    Ok(Json(response))
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
        (status = 403, description = "House-of-Stake plan changes require a linked NEAR wallet", body = crate::error::ApiErrorResponse),
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
        .change_plan(user.user_id, req.plan.clone(), req.target_amount.clone())
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
            SubscriptionError::InvalidTargetAmount(msg) => ApiError::bad_request(msg),
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
            SubscriptionError::HouseOfStakeRequiresNearWallet => {
                ApiError::forbidden("House-of-Stake plan changes require NEAR wallet authentication")
            }
            SubscriptionError::AmlHighRiskBlocked { account_id } => aml_blocked_error(account_id),
            SubscriptionError::NearRpcError(msg) => {
                tracing::error!(error = ?msg, "NEAR RPC error changing plan");
                ApiError::service_unavailable("Failed to reach NEAR RPC for staking catalog")
            }
            _ => {
                tracing::error!(error = ?e, "Failed to change plan");
                ApiError::internal_server_error("Failed to change plan")
            }
        })?;

    let message = match &outcome {
        ChangePlanOutcome::ChangedImmediately => "Plan changed successfully".to_string(),
        ChangePlanOutcome::ScheduledForPeriodEnd => {
            "Downgrade scheduled and will be checked near period end".to_string()
        }
        ChangePlanOutcome::NoOp => "User is already on the target plan".to_string(),
        ChangePlanOutcome::DowngradeCancelled => "Pending downgrade cancelled".to_string(),
        ChangePlanOutcome::NearStakingChangePlan { timing, .. } => {
            if timing == "cancel_pending_downgrade" {
                "Complete pending downgrade cancellation in your NEAR wallet".to_string()
            } else {
                "Complete plan change in your NEAR wallet".to_string()
            }
        }
    };
    let result = public_change_plan_result(outcome);

    Ok(Json(ChangePlanResponse { message, result }))
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
        (status = 200, description = "Reconcile finished; see `skipped`, `deleted_house_of_stake_rows`, `canceled_house_of_stake_rows`, `upserted_house_of_stake_row`, and optional `skipped_reason` in the body.", body = NearStakingSyncSummary),
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
) -> Result<Json<NearStakingSyncSummary>, ApiError> {
    let summary = app_state
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

    Ok(Json(summary))
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

#[cfg(test)]
mod tests {
    use super::*;
    use services::aml::AmlRiskLevel;

    fn storage_intent() -> Box<NearStakingStorageIntent> {
        Box::new(NearStakingStorageIntent {
            method_name: "storage_deposit".to_string(),
            account_id: "staking.testnet".to_string(),
            required_deposit_yocto: "0".to_string(),
            balance_total_yocto: "0".to_string(),
            balance_available_yocto: "0".to_string(),
            bounds_min_yocto: "0".to_string(),
            bounds_max_yocto: None,
            args: serde_json::json!({}),
        })
    }

    fn aml_result(risk_level: AmlRiskLevel) -> AmlCheckResult {
        AmlCheckResult {
            provider: "lukka".to_string(),
            account_id: "alice.testnet".to_string(),
            address_type: "NEAR".to_string(),
            risk_level,
            score: Some(42),
            report_id: Some("provider-report-id".to_string()),
            checked_at: Utc::now(),
            reason: Some("provider_reason".to_string()),
        }
    }

    #[test]
    fn public_subscription_response_omits_raw_aml_fields() {
        let response =
            CreateSubscriptionResponse::from_outcome(CreateSubscriptionOutcome::NearStakeLock {
                contract_id: "staking.testnet".to_string(),
                price_id: "price_hos_basic".to_string(),
                network_id: "testnet".to_string(),
                attached_deposit_yocto: "1".to_string(),
                storage: storage_intent(),
                aml: Box::new(aml_result(AmlRiskLevel::Low)),
            });

        let value = serde_json::to_value(response).expect("serialize response");
        assert!(value.pointer("/aml/checked_at").is_some());
        assert_eq!(
            value.pointer("/aml/risk_level").and_then(|x| x.as_str()),
            Some("LOW")
        );
        assert!(value.pointer("/aml/score").is_none());
        assert!(value.pointer("/aml/report_id").is_none());
        assert!(value.pointer("/aml/reason").is_none());
        assert!(value.pointer("/aml/account_id").is_none());
        assert!(value.pointer("/aml/provider").is_none());
        assert!(value.pointer("/aml/address_type").is_none());
    }

    #[test]
    fn public_aml_result_returns_public_safe_high_risk_metadata() {
        let mut result = aml_result(AmlRiskLevel::Low);
        result.score = Some(75);
        let public = public_aml_result(result).expect("public aml result");
        assert_eq!(public.risk_level, AmlRiskLevel::Low);
    }
}
