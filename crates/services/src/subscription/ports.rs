use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::system_configs::ports::PlanLimitConfig;
use crate::UserId;

pub const DEFAULT_MONTHLY_TOKEN_LIMIT: u64 = 1_000_000;

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DowngradeIntentStatus {
    Pending,
    Applied,
    Missed,
    Unsatisfied,
}

impl DowngradeIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Missed => "missed",
            Self::Unsatisfied => "unsatisfied",
        }
    }
}

impl std::str::FromStr for DowngradeIntentStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            "missed" => Ok(Self::Missed),
            "unsatisfied" => Ok(Self::Unsatisfied),
            _ => Err(format!("invalid downgrade intent status: {value}")),
        }
    }
}

/// Database model for subscription records (generic, supports multiple providers e.g. Stripe)
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub subscription_id: String,
    pub user_id: UserId,
    pub provider: String,
    pub customer_id: String,
    pub price_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Target price_id for a deferred downgrade intent.
    pub pending_downgrade_target_price_id: Option<String>,
    /// Snapshot of current price_id when the downgrade intent was created.
    pub pending_downgrade_from_price_id: Option<String>,
    /// Snapshot of current_period_end when the downgrade intent was created.
    pub pending_downgrade_expected_period_end: Option<DateTime<Utc>>,
    /// Last downgrade intent status.
    pub pending_downgrade_status: Option<DowngradeIntentStatus>,
    /// Timestamp when the downgrade intent was last changed.
    pub pending_downgrade_updated_at: Option<DateTime<Utc>>,
}

/// Admin repair payload for replacing one existing subscription row.
#[derive(Debug, Clone)]
pub struct SubscriptionReplacement {
    pub user_id: UserId,
    pub provider: String,
    pub customer_id: String,
    pub price_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub pending_downgrade_target_price_id: Option<String>,
    pub pending_downgrade_from_price_id: Option<String>,
    pub pending_downgrade_expected_period_end: Option<DateTime<Utc>>,
    pub pending_downgrade_status: Option<DowngradeIntentStatus>,
    pub pending_downgrade_updated_at: Option<DateTime<Utc>>,
}

/// API response model with plan name resolved from `price_id` (HoS clients use `price_id` + `provider` for wallet flows).
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionWithPlan {
    pub subscription_id: String,
    pub user_id: String,
    pub provider: String,
    pub price_id: String,
    pub plan: String, // Resolved from price_id
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Target plan name for a pending downgrade (resolved from price_id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_downgrade_plan: Option<String>,
    /// Status of the pending downgrade intent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_downgrade_status: Option<DowngradeIntentStatus>,
    /// Expected period end when the downgrade will be checked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_downgrade_period_end: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingPeriod {
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
}

/// Result of a plan-change request.
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangePlanOutcome {
    /// Stripe subscription was updated immediately.
    ChangedImmediately,
    /// A downgrade intent was recorded and will be checked near period end.
    ScheduledForPeriodEnd,
    /// Requested plan is already active.
    NoOp,
    /// A pending downgrade was cancelled (same plan requested with active pending downgrade).
    DowngradeCancelled,
    /// HoS: call `upgrade_subscription` in the wallet with this `new_price_id` (contract + network from app config).
    NearStakingUpgrade { new_price_id: String },
    /// HoS: call `schedule_downgrade_subscription` with this `target_price_id`.
    NearStakingScheduleDowngrade { target_price_id: String },
}

/// Stripe path updates `cancel_at_period_end` in the DB. HoS returns a wallet intent only: local
/// `cancel_at_period_end` and related fields change after the chain transaction lands and the user
/// calls `POST /v1/subscriptions/near/sync` (or a mutation that reconciles from RPC).
#[derive(Debug, Clone)]
pub enum CancelSubscriptionOutcome {
    Completed,
    NearStakingCancel,
}

/// Stripe path updates the DB. HoS returns a wallet intent only; local rows refresh after chain
/// settlement and `POST /v1/subscriptions/near/sync` (or reconcile-on-mutation).
#[derive(Debug, Clone)]
pub enum ResumeSubscriptionOutcome {
    Completed,
    NearStakingResume,
}

/// Summary from `POST /v1/subscriptions/near/sync` / internal HoS reconcile.
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearStakingSyncSummary {
    /// True when reconcile exited early (no HoS contract configured, user has no linked NEAR account, or no HoS anchor price in catalog). No RPC or DB mutation was attempted.
    pub skipped: bool,
    /// Local `house-of-stake` rows removed after chain reported no subscription for the probed price.
    pub deleted_house_of_stake_rows: u32,
    /// True when a local row was upserted from chain JSON.
    pub upserted_house_of_stake_row: bool,
}

/// Stripe customer mapping data
#[derive(Debug, Clone)]
pub struct StripeCustomer {
    pub user_id: UserId,
    pub customer_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Payment webhook event data
#[derive(Debug, Clone)]
pub struct PaymentWebhook {
    pub id: uuid::Uuid,
    pub provider: String,
    pub event_id: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Result of storing a webhook event, with idempotency flag
#[derive(Debug, Clone)]
pub struct StoreWebhookResult {
    pub webhook: PaymentWebhook,
    /// True if the webhook was newly inserted; false if it already existed (duplicate/retry)
    pub is_new: bool,
}

/// Error types for subscription operations
#[derive(Debug)]
pub enum SubscriptionError {
    /// User already has an active subscription
    ActiveSubscriptionExists,
    /// Invalid plan name provided
    InvalidPlan(String),
    /// Invalid or unsupported payment provider
    InvalidProvider(String),
    /// Stripe is not configured
    NotConfigured,
    /// No active subscription found for user
    NoActiveSubscription,
    /// Credit limit exceeded (used >= limit)
    CreditLimitExceeded { used: i64, limit: u64 },
    /// Cannot switch to plan: current instance count exceeds target plan's limit
    InstanceLimitExceeded { current: u64, max: u64 },
    /// Subscription is not scheduled for cancellation (cannot resume)
    SubscriptionNotScheduledForCancellation,
    /// Subscription is scheduled for cancellation; resume it before changing plans
    SubscriptionScheduledForCancellation,
    /// User has no Stripe customer record
    NoStripeCustomer,
    /// Stripe API error
    StripeError(String),
    /// Database error
    DatabaseError(String),
    /// Webhook verification failed
    WebhookVerificationFailed(String),
    /// Model not allowed in user's subscription plan
    ModelNotAllowedInPlan { model: String, plan: String },
    /// Internal error
    InternalError(String),
    /// Credit purchase not configured (missing provider config / price id)
    CreditsNotConfigured,
    /// Invalid credits amount for purchase
    InvalidCredits(String),
    /// Cannot associate test clock with existing Stripe customer
    TestClockNotAllowedForExistingCustomer,
    /// No pending downgrade to cancel (same plan requested but no pending downgrade exists)
    NoPendingDowngrade,
    /// No subscription row found for the requested subscription_id.
    SubscriptionNotFound,
    /// House-of-Stake contract id is not configured
    HouseOfStakeNotConfigured,
    /// House-of-Stake requires the user to authenticate with a NEAR wallet
    HouseOfStakeRequiresNearWallet,
    /// NEAR JSON-RPC view call failed
    NearRpcError(String),
}

impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveSubscriptionExists => {
                write!(f, "User already has an active subscription")
            }
            Self::InvalidPlan(plan) => write!(f, "Invalid plan: {}", plan),
            Self::InvalidProvider(provider) => write!(f, "Invalid provider: {}", provider),
            Self::NotConfigured => write!(f, "Stripe is not configured"),
            Self::NoActiveSubscription => write!(f, "No active subscription found"),
            Self::CreditLimitExceeded { used, limit } => {
                write!(
                    f,
                    "Credit limit exceeded: used {} of {} plan credits",
                    used, limit
                )
            }
            Self::InstanceLimitExceeded { current, max } => {
                write!(
                    f,
                    "Cannot switch to this plan: you have {} agent instances but this plan allows only {}",
                    current, max
                )
            }
            Self::SubscriptionNotScheduledForCancellation => {
                write!(f, "Subscription is not scheduled for cancellation")
            }
            Self::SubscriptionScheduledForCancellation => {
                write!(
                    f,
                    "Subscription is scheduled for cancellation; resume it before changing plans"
                )
            }
            Self::NoStripeCustomer => write!(f, "User has no Stripe customer record"),
            Self::StripeError(msg) => write!(f, "Stripe error: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::WebhookVerificationFailed(msg) => {
                write!(f, "Webhook verification failed: {}", msg)
            }
            Self::ModelNotAllowedInPlan { model, plan } => {
                write!(
                    f,
                    "Model '{}' is not available in your plan '{}'",
                    model, plan
                )
            }
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
            Self::CreditsNotConfigured => write!(f, "Credit purchase is not configured"),
            Self::InvalidCredits(msg) => write!(f, "Invalid credits: {}", msg),
            Self::TestClockNotAllowedForExistingCustomer => {
                write!(
                    f,
                    "Cannot associate test clock with existing Stripe customer"
                )
            }
            Self::NoPendingDowngrade => {
                write!(f, "No pending downgrade to cancel")
            }
            Self::SubscriptionNotFound => {
                write!(f, "Subscription not found")
            }
            Self::HouseOfStakeNotConfigured => {
                write!(f, "House-of-Stake billing is not configured")
            }
            Self::HouseOfStakeRequiresNearWallet => {
                write!(
                    f,
                    "House-of-Stake subscription requires signing in with a NEAR wallet"
                )
            }
            Self::NearRpcError(msg) => write!(f, "NEAR RPC error: {}", msg),
        }
    }
}

impl std::error::Error for SubscriptionError {}

impl From<anyhow::Error> for SubscriptionError {
    fn from(err: anyhow::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct StripeUpdateSubscriptionParams {
    pub cancel_at_period_end: Option<bool>,
    pub item_id: Option<String>,
    pub price_id: Option<String>,
    pub proration_behavior: Option<ProrationBehavior>,
    pub payment_behavior: Option<PaymentBehavior>,
    pub billing_cycle_anchor: Option<BillingCycleAnchor>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProrationBehavior {
    CreateProrations,
    AlwaysInvoice,
    None,
}

impl ProrationBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProrationBehavior::CreateProrations => "create_prorations",
            ProrationBehavior::AlwaysInvoice => "always_invoice",
            ProrationBehavior::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PaymentBehavior {
    PendingIfIncomplete,
    ErrorIfIncomplete,
    DefaultIncomplete,
}

impl PaymentBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentBehavior::PendingIfIncomplete => "pending_if_incomplete",
            PaymentBehavior::ErrorIfIncomplete => "error_if_incomplete",
            PaymentBehavior::DefaultIncomplete => "default_incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BillingCycleAnchor {
    Unchanged,
    Automatic,
}

impl BillingCycleAnchor {
    pub fn as_str(&self) -> &'static str {
        match self {
            BillingCycleAnchor::Unchanged => "unchanged",
            BillingCycleAnchor::Automatic => "automatic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StripePortalSessionResult {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct StripeCheckoutLineItemRef {
    pub price_id: String,
    pub quantity: i64,
}

#[derive(Debug, Clone)]
pub struct StripeCheckoutSessionResult {
    pub id: String,
    pub url: Option<String>,
    pub line_items: Option<Vec<StripeCheckoutLineItemRef>>,
    pub line_items_has_more: bool,
}

#[derive(Debug, Clone)]
pub struct StripeSubscriptionSnapshot {
    pub id: String,
    pub customer_id: String,
    pub price_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub first_item_id: String,
}

#[derive(Debug, Clone)]
pub struct StripeCustomerRef {
    pub id: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct StripeCreateSubscriptionCheckoutParams {
    pub customer_id: String,
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
    pub trial_period_days: Option<u32>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct StripeCreateCreditsCheckoutParams {
    pub customer_id: String,
    pub price_id: String,
    pub credits: u64,
    pub success_url: String,
    pub cancel_url: String,
    pub user_id: String,
    pub idempotency_key: String,
}

#[async_trait]
pub trait StripeClientPort: Send + Sync {
    async fn verify_webhook_signature(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<(), SubscriptionError>;

    async fn create_customer(
        &self,
        email: Option<&str>,
        name: Option<&str>,
        user_id: &str,
        test_clock_id: Option<&str>,
    ) -> Result<String, SubscriptionError>;

    async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, SubscriptionError>;

    async fn create_subscription_checkout_session(
        &self,
        params: StripeCreateSubscriptionCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError>;

    async fn create_credits_checkout_session(
        &self,
        params: StripeCreateCreditsCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError>;

    async fn retrieve_checkout_session(
        &self,
        checkout_session_id: &str,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError>;

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError>;

    async fn update_subscription(
        &self,
        subscription_id: &str,
        params: StripeUpdateSubscriptionParams,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError>;

    async fn create_billing_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<StripePortalSessionResult, SubscriptionError>;
}

/// Repository trait for Stripe customer mappings
#[async_trait]
pub trait StripeCustomerRepository: Send + Sync {
    /// Get Stripe customer ID for a user
    async fn get_customer_id(&self, user_id: UserId) -> anyhow::Result<Option<String>>;

    /// Create or update customer mapping (upsert)
    async fn create_customer_mapping(
        &self,
        user_id: UserId,
        customer_id: String,
    ) -> anyhow::Result<StripeCustomer>;
}

/// Repository trait for subscription records
#[async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Insert or update a subscription
    async fn upsert_subscription(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription: Subscription,
    ) -> anyhow::Result<Subscription>;

    /// Get all subscriptions for a user
    async fn get_user_subscriptions(&self, user_id: UserId) -> anyhow::Result<Vec<Subscription>>;

    /// Get active subscriptions for a user (status IN ('active', 'trialing') AND period not ended)
    async fn get_active_subscriptions(&self, user_id: UserId) -> anyhow::Result<Vec<Subscription>>;

    /// Get active subscription for a user (status IN ('active', 'trialing'))
    async fn get_active_subscription(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<Subscription>>;

    /// `current_period_end` of the most recently canceled subscription row for this user
    /// (ordered by `updated_at`; canceled status is stored as the string `canceled`). Used to align free-plan billing months with the boundary
    /// where the latest cancellation period ended; if none exist, callers fall back to a calendar month.
    async fn last_cancelled_subscription_period_end_for_user(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<DateTime<Utc>>>;

    /// List subscriptions with pagination, optionally filtered by user_id.
    /// Returns (items, total_count).
    async fn list_subscriptions(
        &self,
        user_id: Option<UserId>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<Subscription>, i64)>;

    /// Delete a subscription record
    async fn delete_subscription(&self, subscription_id: &str) -> anyhow::Result<()>;

    /// Delete a subscription row inside an existing transaction.
    async fn delete_subscription_txn(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<()>;

    /// Deactivate all subscriptions for a user (set status = 'canceled').
    /// Used when admin sets a new subscription to ensure only one active plan.
    async fn deactivate_user_subscriptions(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
    ) -> anyhow::Result<()>;

    /// Fetch a pending-downgrade row with row lock.
    /// Returns None when no pending intent exists or row is locked by another transaction.
    async fn get_pending_downgrade_for_update_skip_locked(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<Option<Subscription>>;

    /// Fetch current status of a subscription with a row lock (FOR UPDATE).
    /// Returns None if the subscription does not exist yet.
    /// Used to detect first-time status transitions (e.g. active → canceled) under concurrent webhooks.
    async fn get_subscription_status_for_update(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<Option<String>>;

    /// Fetch a subscription row with a row lock (FOR UPDATE).
    /// Returns None if the subscription does not exist.
    async fn get_subscription_for_update(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<Option<Subscription>>;

    /// Replace exactly one existing subscription row selected by subscription_id.
    /// Returns None if the row does not exist.
    async fn replace_subscription(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
        replacement: SubscriptionReplacement,
    ) -> anyhow::Result<Option<Subscription>>;

    /// Unconditionally clear all pending-downgrade fields for a subscription.
    /// Used when an upgrade or explicit cancellation makes the pending intent obsolete.
    async fn clear_pending_downgrade(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<()>;
}

/// Single credit transaction record (purchase, grant, admin adjustment).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreditTransaction {
    pub id: uuid::Uuid,
    pub user_id: UserId,
    /// Amount in nano-USD (positive for credits added, negative for debits if ever used).
    pub amount: i64,
    /// Transaction type: 'purchase', 'grant', or 'admin_adjust'.
    pub r#type: String,
    /// Optional external reference (e.g. Stripe session id or admin reason).
    pub reference_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait CreditsRepository: Send + Sync {
    /// Remaining purchased credits for a user (0 if no row). Computed as total_nano_usd - spent_nano_usd.
    async fn get_balance(&self, user_id: UserId) -> anyhow::Result<i64>;

    /// Remaining, total purchased, spent purchased (nano-USD). Zeros if no row.
    async fn get_purchased_breakdown(&self, user_id: UserId) -> anyhow::Result<(i64, i64, i64)>;

    /// Add credits to user balance (upsert). Returns new balance.
    async fn add_credits(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
    ) -> anyhow::Result<i64>;

    /// Record a credit transaction (for audit/idempotency). Returns false if duplicate.
    async fn try_record_purchase(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
        reference_id: &str,
    ) -> anyhow::Result<bool>;

    /// Record an admin grant transaction (for manual/admin adjustments).
    async fn record_grant(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
        reason: Option<String>,
    ) -> anyhow::Result<()>;

    /// List credit transactions for a user, newest first, with total count.
    async fn list_transactions(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<CreditTransaction>, i64)>;

    /// Reconcile used_purchased and remaining balance from usage in period vs plan allowance.
    async fn reconcile_purchased_after_usage(
        &self,
        user_id: UserId,
        plan_credits_nano_usd: i64,
        period_start: chrono::DateTime<chrono::Utc>,
        period_end: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()>;
}

/// Repository trait for payment webhook events
#[async_trait]
pub trait PaymentWebhookRepository: Send + Sync {
    /// Store webhook event (idempotent via UNIQUE constraint).
    /// Returns the webhook and whether it was newly inserted (true) or already existed (false).
    async fn store_webhook(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        provider: String,
        event_id: String,
        payload: serde_json::Value,
    ) -> anyhow::Result<StoreWebhookResult>;
}

/// Subscription plan with optional plan limits/features
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPlan {
    pub name: String,
    /// Plan price in cents (e.g. 999 for $9.99, 0 for free)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<i64>,
    /// Free trial period in days before first charge
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_period_days: Option<u32>,
    /// Agent instance limits (e.g. { "max": 1 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_instances: Option<PlanLimitConfig>,
    /// Monthly token limits (legacy/backward compatibility).
    /// When present, represents the plan limit in tokens (not nano-USD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_tokens: Option<PlanLimitConfig>,
    /// Monthly credit limits in nano-USD (e.g. { "max": 1000000000 } for $1; $1 = 1_000_000_000 nano-USD). When missing, defaults to 1_000_000_000. Used for quota enforcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_credits: Option<PlanLimitConfig>,
    /// List of model IDs allowed for this plan (e.g. ["gpt-3.5-turbo", "gpt-4o"])
    /// None = allow all models (default); Some(vec) = only allow models in the list.
    /// An empty list denies all models.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
}

/// Result of [`SubscriptionService::create_subscription`]: Stripe redirect or HoS catalog `price_id` for a client-side `lock_for_subscription`.
///
/// Serialized JSON:
/// - **Stripe** — legacy flat object `{"checkout_url":"..."}`.
/// - **HoS** — `{"kind":"house_of_stake","price_id":"..."}` (contract, network, and call shape live in the app).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum CreateSubscriptionOutcome {
    /// Complete checkout on Stripe (`checkout_url`).
    StripeCheckout { checkout_url: String },
    /// Catalog recurring price id for `lock_for_subscription` (client supplies `product_id` xor `price_id` per contract rules).
    NearStakeLock { price_id: String },
}

impl Serialize for CreateSubscriptionOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            CreateSubscriptionOutcome::StripeCheckout { checkout_url } => {
                let mut st = serializer.serialize_struct("StripeCheckout", 1)?;
                st.serialize_field("checkout_url", checkout_url)?;
                st.end()
            }
            CreateSubscriptionOutcome::NearStakeLock { price_id } => {
                let mut st = serializer.serialize_struct("NearStakeLock", 2)?;
                st.serialize_field("kind", &"house_of_stake")?;
                st.serialize_field("price_id", price_id)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CreateSubscriptionOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(deserializer)?;
        let obj = v
            .as_object()
            .ok_or_else(|| D::Error::custom("create subscription outcome must be a JSON object"))?;
        if let Some(url) = obj.get("checkout_url").and_then(|x| x.as_str()) {
            return Ok(CreateSubscriptionOutcome::StripeCheckout {
                checkout_url: url.to_string(),
            });
        }
        if let Some(kind) = obj.get("kind").and_then(|x| x.as_str()) {
            if kind == "house_of_stake" || kind == "near_stake_lock" {
                let price_id = obj
                    .get("price_id")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| D::Error::custom("missing price_id"))?
                    .to_string();
                return Ok(CreateSubscriptionOutcome::NearStakeLock { price_id });
            }
        }
        if let Some(pid) = obj.get("price_id").and_then(|x| x.as_str()) {
            return Ok(CreateSubscriptionOutcome::NearStakeLock {
                price_id: pid.to_string(),
            });
        }
        Err(D::Error::custom(
            "invalid create subscription outcome: expected checkout_url or kind house_of_stake with price_id",
        ))
    }
}

/// Service trait for subscription management
#[async_trait]
pub trait SubscriptionService: Send + Sync {
    /// Get available subscription plans (`provider`: `None` or `"stripe"` → Stripe catalog; `"house-of-stake"` → HoS catalog).
    async fn get_available_plans(
        &self,
        provider: Option<&str>,
    ) -> Result<Vec<SubscriptionPlan>, SubscriptionError>;

    /// Create a subscription checkout session for a user
    /// Returns either a Stripe checkout URL or House-of-Stake contract call parameters.
    /// provider: payment provider name (e.g. "stripe", "house-of-stake")
    /// test_clock_id: optional test clock ID to bind customer to (requires STRIPE_TEST_CLOCK_ENABLED)
    async fn create_subscription(
        &self,
        user_id: UserId,
        provider: String,
        plan: String,
        success_url: String,
        cancel_url: String,
        test_clock_id: Option<String>,
    ) -> Result<CreateSubscriptionOutcome, SubscriptionError>;

    /// Cancel a user's active subscription (at period end), or return NEAR wallet intents for HoS.
    async fn cancel_subscription(
        &self,
        user_id: UserId,
    ) -> Result<CancelSubscriptionOutcome, SubscriptionError>;

    /// Resume a subscription that was scheduled to cancel at period end, or return NEAR wallet intents for HoS.
    async fn resume_subscription(
        &self,
        user_id: UserId,
    ) -> Result<ResumeSubscriptionOutcome, SubscriptionError>;

    /// Re-fetch staking subscription from RPC and upsert/delete the local `house-of-stake` row.
    async fn sync_near_staking_subscription(
        &self,
        user_id: UserId,
    ) -> Result<NearStakingSyncSummary, SubscriptionError>;

    /// Change the user's subscription to a different plan.
    /// Upgrades are applied immediately; downgrades are scheduled for period-end checks.
    async fn change_plan(
        &self,
        user_id: UserId,
        target_plan: String,
    ) -> Result<ChangePlanOutcome, SubscriptionError>;

    /// Get subscriptions for a user with plan names resolved
    /// If active_only is true, returns only active (not expired) subscriptions
    async fn get_user_subscriptions(
        &self,
        user_id: UserId,
        active_only: bool,
    ) -> Result<Vec<SubscriptionWithPlan>, SubscriptionError>;

    /// Handle incoming webhook from payment provider
    async fn handle_stripe_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), SubscriptionError>;

    /// Create a customer portal session for managing subscriptions
    /// Returns the portal URL
    async fn create_customer_portal_session(
        &self,
        user_id: UserId,
        return_url: String,
    ) -> Result<String, SubscriptionError>;

    /// Check if user has a paid subscription (active subscription, plan is not "free").
    /// Used to skip NEAR balance checks for paid users only; free plan subscribers still get the check.
    async fn has_paid_subscription(&self, user_id: UserId) -> Result<bool, SubscriptionError>;

    /// Check that user has an active subscription for proxy/chat access.
    /// Returns Ok(()) when allowed, Err(NoActiveSubscription) when subscription required but not found.
    /// When Stripe is not configured (NotConfigured), returns Ok(()) to allow access (no gating).
    async fn require_subscription_for_proxy(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError>;

    /// Check if the user has access to the specified model based on their subscription plan.
    /// Returns Ok(()) if allowed, Err(ModelNotAllowedInPlan) if the model is not in the plan's allowlist.
    /// If the plan has no allowlist (None), all models are allowed.
    /// If the user has no active subscription, uses `subscription_plans.free.allowed_models` as fallback.
    async fn check_model_access(
        &self,
        user_id: UserId,
        model_id: &str,
    ) -> Result<(), SubscriptionError>;

    /// Admin only: Set subscription for a user directly (for testing/manual management).
    /// If a subscription for the given plan/provider already exists, it updates it.
    /// Otherwise, creates a new one.
    async fn admin_set_subscription(
        &self,
        user_id: UserId,
        provider: String,
        plan: String,
        current_period_end: DateTime<Utc>,
    ) -> Result<SubscriptionWithPlan, SubscriptionError>;

    /// Admin only: Cancel all subscriptions for a user.
    async fn admin_cancel_user_subscriptions(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError>;

    /// Admin only: List subscriptions with pagination, optionally filtered by user_id.
    async fn admin_list_subscriptions(
        &self,
        user_id: Option<UserId>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Subscription>, i64), SubscriptionError>;

    /// Admin only: Fully replace exactly one existing subscription row by subscription_id.
    async fn admin_replace_subscription(
        &self,
        admin_user_id: UserId,
        subscription_id: String,
        replacement: SubscriptionReplacement,
    ) -> Result<Subscription, SubscriptionError>;

    /// Create checkout session for purchasing credits. Returns checkout URL.
    async fn create_credit_purchase_checkout(
        &self,
        user_id: UserId,
        credits: u64,
        success_url: String,
        cancel_url: String,
    ) -> Result<String, SubscriptionError>;

    /// Get user's credits: remaining balance, totals, used in period, effective max.
    async fn get_credits(&self, user_id: UserId) -> Result<CreditsSummary, SubscriptionError>;

    /// Get the user's current billing period boundaries.
    async fn get_current_billing_period(
        &self,
        user_id: UserId,
    ) -> Result<BillingPeriod, SubscriptionError>;

    /// After recording usage with cost, reconcile purchased used/remaining from period usage vs plan.
    /// No-op if Stripe not configured or user has no purchased pool.
    async fn reconcile_purchased_after_usage(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError>;

    /// Admin-only: grant credits (nano-USD) directly to a user.
    /// Records a 'grant' transaction and updates user_credits balance.
    async fn admin_grant_credits(
        &self,
        user_id: UserId,
        amount_nano_usd: i64,
        reason: Option<String>,
    ) -> Result<i64, SubscriptionError>;

    /// Admin-only: list credit transactions for a user (for payment history / audit).
    async fn admin_get_credit_history(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<CreditTransaction>, i64), SubscriptionError>;
}

/// Summary of user's credits (balance, used, effective limit).
///
/// **Unit: nano-USD** (1 credit = 1e-9 USD; 1_000_000_000 = $1). All fields use this unit so they
/// can be compared: usage is recorded as `cost_nano_usd`, plan limits and purchased balance
/// are in the same unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreditsSummary {
    /// Remaining purchased credits (nano-USD); can spend from this pool after plan allowance.
    pub balance: i64,
    /// Cumulative purchased+granted credits (nano-USD).
    pub total_purchased_nano_usd: i64,
    /// Purchased credits already spent (lifetime), capped by total.
    pub spent_purchased_nano_usd: i64,
    /// Spend in the current period (sum of cost_nano_usd).
    pub period_spent_credits: i64,
    /// Plan credit limit (nano-USD).
    pub plan_credits: i64,
}
