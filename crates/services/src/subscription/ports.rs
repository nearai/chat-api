use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::system_configs::ports::PlanLimitConfig;
use crate::UserId;

/// Database model for subscription records (generic, supports multiple providers e.g. Stripe)
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
}

/// API response model with plan name resolved from price_id
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionWithPlan {
    pub subscription_id: String,
    pub user_id: String,
    pub provider: String,
    pub plan: String, // Resolved from price_id
    pub status: String,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// Monthly token limit exceeded (used >= limit)
    MonthlyTokenLimitExceeded { used: i64, limit: u64 },
    /// Subscription is not scheduled for cancellation (cannot resume)
    SubscriptionNotScheduledForCancellation,
    /// User has no Stripe customer record
    NoStripeCustomer,
    /// Stripe API error
    StripeError(String),
    /// Database error
    DatabaseError(String),
    /// Webhook verification failed
    WebhookVerificationFailed(String),
    /// Internal error
    InternalError(String),
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
            Self::MonthlyTokenLimitExceeded { used, limit } => {
                write!(
                    f,
                    "Monthly token limit exceeded: used {} of {} tokens",
                    used, limit
                )
            }
            Self::SubscriptionNotScheduledForCancellation => {
                write!(f, "Subscription is not scheduled for cancellation")
            }
            Self::NoStripeCustomer => write!(f, "User has no Stripe customer record"),
            Self::StripeError(msg) => write!(f, "Stripe error: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::WebhookVerificationFailed(msg) => {
                write!(f, "Webhook verification failed: {}", msg)
            }
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for SubscriptionError {}

impl From<anyhow::Error> for SubscriptionError {
    fn from(err: anyhow::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
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

    /// Delete a subscription record
    async fn delete_subscription(&self, subscription_id: &str) -> anyhow::Result<()>;
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
    /// Private assistant instance limits (e.g. { "max": 1 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_assistant_instances: Option<PlanLimitConfig>,
    /// Monthly token limits (e.g. { "max": 1000000 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_tokens: Option<PlanLimitConfig>,
}

/// Service trait for subscription management
#[async_trait]
pub trait SubscriptionService: Send + Sync {
    /// Get available subscription plans
    async fn get_available_plans(&self) -> Result<Vec<SubscriptionPlan>, SubscriptionError>;

    /// Create a subscription checkout session for a user
    /// Returns the checkout URL
    /// provider: payment provider name (e.g. "stripe")
    async fn create_subscription(
        &self,
        user_id: UserId,
        provider: String,
        plan: String,
        success_url: String,
        cancel_url: String,
    ) -> Result<String, SubscriptionError>;

    /// Cancel a user's active subscription (at period end)
    async fn cancel_subscription(&self, user_id: UserId) -> Result<(), SubscriptionError>;

    /// Resume a subscription that was scheduled to cancel at period end
    async fn resume_subscription(&self, user_id: UserId) -> Result<(), SubscriptionError>;

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

    /// Check that user has an active subscription for proxy/chat access.
    /// Returns Ok(()) when allowed, Err(NoActiveSubscription) when subscription required but not found.
    /// When Stripe is not configured (NotConfigured), returns Ok(()) to allow access (no gating).
    async fn require_subscription_for_proxy(
        &self,
        user_id: UserId,
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
}
