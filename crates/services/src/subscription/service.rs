use super::ports::{
    PaymentWebhookRepository, StripeCustomerRepository, Subscription, SubscriptionError,
    SubscriptionPlan, SubscriptionRepository, SubscriptionService, SubscriptionWithPlan,
};
use crate::agent::ports::AgentService;
use crate::system_configs::ports::{SubscriptionPlanConfig, SystemConfigsService};
use crate::user::ports::UserRepository;
use crate::user_usage::ports::UserUsageRepository;
use crate::UserId;
use async_trait::async_trait;
use chrono::{Datelike, NaiveTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use stripe::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCheckoutSessionSubscriptionData,
    Customer, CustomerId, RequestStrategy, Subscription as StripeSubscription, Webhook,
    WebhookError,
};
use tokio::sync::RwLock;

/// Configuration for SubscriptionServiceImpl
pub struct SubscriptionServiceConfig {
    pub db_pool: deadpool_postgres::Pool,
    pub stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    pub subscription_repo: Arc<dyn SubscriptionRepository>,
    pub webhook_repo: Arc<dyn PaymentWebhookRepository>,
    pub system_configs_service: Arc<dyn SystemConfigsService>,
    pub user_repository: Arc<dyn UserRepository>,
    pub user_usage_repo: Arc<dyn UserUsageRepository>,
    pub agent_service: Arc<dyn AgentService>,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
}

/// Cached token limit for a user. Invalid after TTL_CACHE_SECS (10 mins) or when plan changes.
struct CachedTokenLimit {
    max_tokens: u64,
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    cached_at: Instant,
}

const TTL_CACHE_SECS: u64 = 600; // 10 minutes

pub struct SubscriptionServiceImpl {
    db_pool: deadpool_postgres::Pool,
    stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    subscription_repo: Arc<dyn SubscriptionRepository>,
    webhook_repo: Arc<dyn PaymentWebhookRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
    user_repository: Arc<dyn UserRepository>,
    user_usage_repo: Arc<dyn UserUsageRepository>,
    agent_service: Arc<dyn AgentService>,
    stripe_secret_key: String,
    stripe_webhook_secret: String,
    token_limit_cache: Arc<RwLock<HashMap<UserId, CachedTokenLimit>>>,
}

impl SubscriptionServiceImpl {
    pub fn new(config: SubscriptionServiceConfig) -> Self {
        Self {
            db_pool: config.db_pool,
            stripe_customer_repo: config.stripe_customer_repo,
            subscription_repo: config.subscription_repo,
            webhook_repo: config.webhook_repo,
            system_configs_service: config.system_configs_service,
            user_repository: config.user_repository,
            user_usage_repo: config.user_usage_repo,
            agent_service: config.agent_service,
            stripe_secret_key: config.stripe_secret_key,
            stripe_webhook_secret: config.stripe_webhook_secret,
            token_limit_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Invalidate token limit cache for a user (e.g. when plan changes via webhook or cancel/resume).
    async fn invalidate_token_limit_cache(&self, user_id: UserId) {
        let mut guard = self.token_limit_cache.write().await;
        guard.remove(&user_id);
        tracing::debug!("Invalidated token limit cache for user_id={}", user_id);
    }

    /// Get subscription plans for a provider from system configs (lazy loading)
    /// Returns HashMap<plan_name, price_id> for the given provider
    async fn get_plans_for_provider(
        &self,
        provider: &str,
    ) -> Result<HashMap<String, String>, SubscriptionError> {
        tracing::debug!(
            "Getting subscription plans for provider={} from system configs",
            provider
        );

        // Treat missing/empty Stripe secrets as "not configured" when provider is stripe
        if provider.to_lowercase() == "stripe"
            && (self.stripe_secret_key.is_empty() || self.stripe_webhook_secret.is_empty())
        {
            tracing::debug!(
                "Stripe secrets are not set (secret_key_empty={}, webhook_secret_empty={}), Stripe not configured",
                self.stripe_secret_key.is_empty(),
                self.stripe_webhook_secret.is_empty(),
            );
            return Err(SubscriptionError::NotConfigured);
        }

        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get system configs");
                SubscriptionError::InternalError(e.to_string())
            })?;

        tracing::debug!("System configs retrieved: has_config={}", configs.is_some());

        let subscription_plans = match configs {
            None => {
                tracing::debug!("No system configs found, subscriptions not configured");
                return Err(SubscriptionError::NotConfigured);
            }
            Some(c) => {
                tracing::debug!(
                    "System configs found, checking subscription_plans: has_plans={}",
                    c.subscription_plans.is_some()
                );
                c.subscription_plans
                    .ok_or(SubscriptionError::NotConfigured)?
            }
        };

        // Extract plan_name -> price_id for the requested provider
        let mut plans = HashMap::new();
        for (plan_name, plan_config) in subscription_plans {
            if let Some(provider_config) = plan_config.providers.get(provider) {
                plans.insert(plan_name, provider_config.price_id.clone());
            }
        }

        if plans.is_empty() {
            tracing::debug!(
                "No plans found for provider={}, subscriptions not configured",
                provider
            );
            return Err(SubscriptionError::NotConfigured);
        }

        tracing::debug!(
            "Subscription plans found for {}: {} entries",
            provider,
            plans.len()
        );
        Ok(plans)
    }

    /// Get Stripe client
    fn get_stripe_client(&self) -> Client {
        Client::new(&self.stripe_secret_key)
    }

    /// Get or create Stripe customer for user
    async fn get_or_create_stripe_customer(
        &self,
        user_id: UserId,
    ) -> Result<String, SubscriptionError> {
        // Check if customer already exists
        if let Some(customer_id) = self
            .stripe_customer_repo
            .get_customer_id(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
        {
            tracing::debug!(
                "Stripe customer already exists: user_id={}, customer_id={}",
                user_id,
                customer_id
            );
            return Ok(customer_id);
        }

        // Fetch user to get email and name for Stripe customer
        let user = self
            .user_repository
            .get_user(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .ok_or_else(|| {
                SubscriptionError::InternalError(
                    "User not found when creating Stripe customer".to_string(),
                )
            })?;

        // Skip email for NEAR wallet users (they have placeholder like account_id@near)
        let email_for_stripe = (!user.email.ends_with("@near")).then_some(user.email.as_str());

        // Create new Stripe customer with email and name for Stripe Dashboard/receipts
        tracing::info!("Creating new Stripe customer for user_id={}", user_id);
        let client = self.get_stripe_client();

        let customer = Customer::create(
            &client,
            stripe::CreateCustomer {
                email: email_for_stripe,
                name: user.name.as_deref(),
                metadata: Some(
                    vec![("user_id".to_string(), user_id.0.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        // Store customer mapping
        self.stripe_customer_repo
            .create_customer_mapping(user_id, customer.id.to_string())
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Stripe customer created: user_id={}, customer_id={}",
            user_id,
            customer.id
        );

        Ok(customer.id.to_string())
    }

    /// Check if switching from old_price_id to new_price_id is a downgrade.
    /// A downgrade means the new plan has lower limits (monthly_tokens.max or agent_instances.max).
    fn is_downgrade(
        old_price_id: &str,
        new_price_id: &str,
        provider: &str,
        plans: &HashMap<String, SubscriptionPlanConfig>,
    ) -> bool {
        let old_plan = resolve_plan_name_from_config(provider, old_price_id, plans);
        let new_plan = resolve_plan_name_from_config(provider, new_price_id, plans);

        let old_config = plans.get(&old_plan);
        let new_config = plans.get(&new_plan);

        let old_tokens = old_config
            .and_then(|c| c.monthly_tokens.as_ref())
            .map(|l| l.max)
            .unwrap_or(0);
        let new_tokens = new_config
            .and_then(|c| c.monthly_tokens.as_ref())
            .map(|l| l.max)
            .unwrap_or(0);

        let old_instances = old_config
            .and_then(|c| c.agent_instances.as_ref())
            .map(|l| l.max)
            .unwrap_or(0);
        let new_instances = new_config
            .and_then(|c| c.agent_instances.as_ref())
            .map(|l| l.max)
            .unwrap_or(0);

        new_tokens < old_tokens || new_instances < old_instances
    }

    /// Apply a pending downgrade if it is due (downgrade_effective_at <= now).
    /// Called lazily from require_subscription_for_proxy as a safety net.
    async fn apply_pending_downgrade_if_due(
        &self,
        subscription: &Subscription,
    ) -> Result<Option<Subscription>, SubscriptionError> {
        let effective_at = match subscription.downgrade_effective_at {
            Some(dt) => dt,
            None => return Ok(None),
        };

        if Utc::now() < effective_at {
            return Ok(None);
        }

        tracing::info!(
            "Applying due pending downgrade: subscription_id={}, user_id={}, effective_at={}",
            subscription.subscription_id,
            subscription.user_id,
            effective_at
        );

        let mut client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        let updated = self
            .subscription_repo
            .apply_pending_downgrade(&txn, &subscription.subscription_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        if updated.is_some() {
            self.invalidate_token_limit_cache(subscription.user_id)
                .await;
        }

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        match updated {
            Some(updated) => {
                // Stop excess instances for the new (lower) plan
                self.stop_excess_instances(subscription.user_id, &updated.price_id)
                    .await;

                Ok(Some(updated))
            }
            None => {
                // Another concurrent request already applied the downgrade — no-op
                tracing::info!(
                    "Pending downgrade already applied by another request: subscription_id={}",
                    subscription.subscription_id
                );
                Ok(None)
            }
        }
    }

    /// Stop instances that exceed the plan's agent_instances.max limit.
    /// Keeps the newest N instances (by created_at), stops the rest.
    async fn stop_excess_instances(&self, user_id: UserId, price_id: &str) {
        let plans = match self.get_subscription_plans().await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "Failed to get subscription plans for instance enforcement: user_id={}, error={}",
                    user_id, e
                );
                return;
            }
        };

        let plan_name = resolve_plan_name_from_config("stripe", price_id, &plans);
        let max_instances = plans
            .get(&plan_name)
            .and_then(|c| c.agent_instances.as_ref())
            .map(|l| l.max)
            .unwrap_or(0) as usize;

        // List all user instances (use a large limit)
        let (mut instances, total) = match self.agent_service.list_instances(user_id, 1000, 0).await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    "Failed to list instances for enforcement: user_id={}, error={}",
                    user_id,
                    e
                );
                return;
            }
        };

        if total > 1000 {
            tracing::warn!(
                "User user_id={} has {} total instances, exceeding fetch limit of 1000. Some excess instances may not be stopped.",
                user_id, total
            );
        }

        if instances.len() <= max_instances {
            return;
        }

        // Sort by created_at DESC (newest first) — keep the most recent ones
        instances.sort_by_key(|i| std::cmp::Reverse(i.created_at));

        let to_stop = &instances[max_instances..];
        tracing::info!(
            "Stopping {} excess instance(s) for user_id={} (plan={}, max={})",
            to_stop.len(),
            user_id,
            plan_name,
            max_instances
        );

        for instance in to_stop {
            if let Err(e) = self.agent_service.stop_instance(instance.id, user_id).await {
                tracing::error!(
                    "Failed to stop excess instance: instance_id={}, user_id={}, error={}",
                    instance.id,
                    user_id,
                    e
                );
            }
        }
    }

    /// Stop ALL instances for a user (used when subscription ends entirely).
    async fn stop_all_user_instances(&self, user_id: UserId) {
        let (instances, total) = match self.agent_service.list_instances(user_id, 1000, 0).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    "Failed to list instances for cancellation cleanup: user_id={}, error={}",
                    user_id,
                    e
                );
                return;
            }
        };

        if total > 1000 {
            tracing::warn!(
                "User user_id={} has {} total instances, exceeding fetch limit of 1000. Some instances may not be stopped on cancellation.",
                user_id, total
            );
        }

        if instances.is_empty() {
            return;
        }

        tracing::info!(
            "Stopping all {} instance(s) for user_id={} (subscription ended)",
            instances.len(),
            user_id
        );

        for instance in &instances {
            if let Err(e) = self.agent_service.stop_instance(instance.id, user_id).await {
                tracing::error!(
                    "Failed to stop instance on cancellation: instance_id={}, user_id={}, error={}",
                    instance.id,
                    user_id,
                    e
                );
            }
        }
    }

    /// Get subscription plans from system configs
    async fn get_subscription_plans(
        &self,
    ) -> Result<HashMap<String, SubscriptionPlanConfig>, SubscriptionError> {
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        Ok(configs
            .and_then(|c| c.subscription_plans)
            .unwrap_or_default())
    }

    /// Supported payment providers
    const SUPPORTED_PROVIDERS: &[&str] = &["stripe"];

    /// Validate that the provider is supported
    fn validate_provider(provider: &str) -> Result<(), SubscriptionError> {
        let provider_lower = provider.to_lowercase();
        if Self::SUPPORTED_PROVIDERS.contains(&provider_lower.as_str()) {
            Ok(())
        } else {
            Err(SubscriptionError::InvalidProvider(format!(
                "Unsupported provider: '{}'. Supported: {}",
                provider,
                Self::SUPPORTED_PROVIDERS.join(", ")
            )))
        }
    }

    /// Convert Stripe subscription to our Subscription model
    fn stripe_subscription_to_model(
        &self,
        stripe_sub: &StripeSubscription,
        user_id: UserId,
        provider: &str,
    ) -> Result<Subscription, SubscriptionError> {
        let price_id = stripe_sub
            .items
            .data
            .first()
            .and_then(|item| item.price.as_ref())
            .map(|price| price.id.to_string())
            .ok_or_else(|| {
                SubscriptionError::StripeError("No price found in subscription".into())
            })?;

        // Extract customer_id from Expandable<Customer>
        let customer_id = match &stripe_sub.customer {
            stripe::Expandable::Id(id) => id.to_string(),
            stripe::Expandable::Object(customer) => customer.id.to_string(),
        };

        Ok(Subscription {
            subscription_id: stripe_sub.id.to_string(),
            user_id,
            provider: provider.to_string(),
            customer_id,
            price_id,
            status: stripe_sub.status.to_string(),
            current_period_end: chrono::DateTime::from_timestamp(stripe_sub.current_period_end, 0)
                .ok_or_else(|| SubscriptionError::StripeError("Invalid timestamp".into()))?,
            cancel_at_period_end: stripe_sub.cancel_at_period_end,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            pending_price_id: None,
            downgrade_effective_at: None,
        })
    }
}

/// Subtract one calendar month from a datetime, keeping the same day when possible.
/// E.g. March 15 00:00 → Feb 15 00:00. March 31 → Feb 28/29 (last day of month).
fn sub_one_month_same_day(dt: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    use chrono::NaiveDate;
    let d = dt.date_naive();
    let (y, m, day) = (d.year(), d.month(), d.day());
    let (new_y, new_m) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    let new_d = NaiveDate::from_ymd_opt(new_y, new_m, day).unwrap_or_else(|| {
        // Day overflow (e.g. March 31 -> Feb 31 doesn't exist): use last day of month
        let (next_y, next_m) = if new_m == 12 {
            (new_y + 1, 1)
        } else {
            (new_y, new_m + 1)
        };
        NaiveDate::from_ymd_opt(next_y, next_m, 1)
            .and_then(|first_of_next| first_of_next.pred_opt())
            .unwrap_or_else(|| {
                NaiveDate::from_ymd_opt(new_y, new_m, 28).expect("28th day of month exists")
            })
    });
    chrono::DateTime::from_naive_utc_and_offset(new_d.and_time(dt.time()), Utc)
}

/// Returns (period_start, period_end) for the current calendar month.
/// period_start = 00:00 on the 1st, period_end = 00:00 on the 1st of next month (24:00 on last day).
fn current_calendar_month_period(
    now: chrono::DateTime<Utc>,
) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    use chrono::NaiveDate;
    let (y, m, _) = (now.year(), now.month(), now.day());
    let midnight = NaiveTime::from_hms_opt(0, 0, 0).expect("midnight is valid");
    let period_start = NaiveDate::from_ymd_opt(y, m, 1)
        .map(|d| chrono::DateTime::from_naive_utc_and_offset(d.and_time(midnight), Utc))
        .expect("first of month is valid");
    let (next_y, next_m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let period_end = NaiveDate::from_ymd_opt(next_y, next_m, 1)
        .map(|d| chrono::DateTime::from_naive_utc_and_offset(d.and_time(midnight), Utc))
        .expect("first of next month is valid");
    (period_start, period_end)
}

/// Resolve plan name from provider, price_id and subscription_plans config
fn resolve_plan_name_from_config(
    provider: &str,
    price_id: &str,
    plans: &HashMap<String, SubscriptionPlanConfig>,
) -> String {
    plans
        .iter()
        .find(|(_, config)| {
            config
                .providers
                .get(provider)
                .map(|p| p.price_id.as_str() == price_id)
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Generate idempotency key for checkout session creation
/// Format: SHA-256(user_id:price_id:time_window)
/// Time window: current timestamp / 3600 (1 hour window)
fn generate_checkout_idempotency_key(user_id: &UserId, price_id: &str) -> String {
    use sha2::{Digest, Sha256};

    // Use 1-hour time window: same key within 1 hour, new key after
    let time_window = chrono::Utc::now().timestamp() / 3600;

    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", user_id.0, price_id, time_window).as_bytes());
    format!("{:x}", hasher.finalize())
}

#[async_trait]
impl SubscriptionService for SubscriptionServiceImpl {
    async fn get_available_plans(&self) -> Result<Vec<SubscriptionPlan>, SubscriptionError> {
        tracing::debug!("Getting available subscription plans");

        // Return Stripe plans (primary provider for now) with limits from config
        let stripe_plans = self.get_plans_for_provider("stripe").await?;

        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let subscription_plans = configs
            .and_then(|c| c.subscription_plans)
            .unwrap_or_default();

        let plans: Vec<SubscriptionPlan> = stripe_plans
            .into_keys()
            .map(|name| {
                let plan_config = subscription_plans.get(&name);
                let agent_instances = plan_config.and_then(|c| c.agent_instances.clone());
                let monthly_tokens = plan_config.and_then(|c| c.monthly_tokens.clone());
                let trial_period_days = plan_config.and_then(|c| c.trial_period_days);
                SubscriptionPlan {
                    name,
                    trial_period_days,
                    agent_instances,
                    monthly_tokens,
                }
            })
            .collect();

        Ok(plans)
    }

    async fn create_subscription(
        &self,
        user_id: UserId,
        provider: String,
        plan: String,
        success_url: String,
        cancel_url: String,
    ) -> Result<String, SubscriptionError> {
        tracing::info!(
            "Creating subscription checkout for user_id={}, provider={}, plan={}",
            user_id,
            provider,
            plan
        );

        // Validate provider (only stripe supported for now)
        Self::validate_provider(&provider)?;

        // Get plans for provider from system configs
        let provider_plans = self.get_plans_for_provider(&provider).await?;

        // Check if user already has active subscription
        if self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .is_some()
        {
            return Err(SubscriptionError::ActiveSubscriptionExists);
        }

        // Validate plan and get price_id
        let price_id = provider_plans
            .get(&plan)
            .ok_or_else(|| SubscriptionError::InvalidPlan(plan.clone()))?
            .clone();

        // Fetch trial_period_days from subscription plan config
        let trial_period_days = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?
            .and_then(|c| c.subscription_plans)
            .and_then(|plans| plans.get(&plan).cloned())
            .and_then(|p| p.trial_period_days)
            // Stripe supports a maximum trial period of 730 days
            .filter(|&n| n > 0 && n <= 730);

        // Get or create Stripe customer
        let customer_id = self.get_or_create_stripe_customer(user_id).await?;

        // Create Stripe checkout session
        let base_client = self.get_stripe_client();

        // Generate idempotency key with 1-hour time window
        let idempotency_key = generate_checkout_idempotency_key(&user_id, &price_id);

        // Clone client and set request strategy with idempotency key
        let client = base_client
            .clone()
            .with_strategy(RequestStrategy::Idempotent(idempotency_key.clone()));

        let mut params = CreateCheckoutSession::new();
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.customer = Some(
            customer_id
                .parse()
                .map_err(|_| SubscriptionError::StripeError("Invalid customer ID".to_string()))?,
        );
        params.success_url = Some(&success_url);
        params.cancel_url = Some(&cancel_url);
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id.clone()),
            quantity: Some(1),
            ..Default::default()
        }]);

        // Set trial period when plan has trial_period_days
        if let Some(days) = trial_period_days {
            params.subscription_data = Some(CreateCheckoutSessionSubscriptionData {
                trial_period_days: Some(days),
                ..Default::default()
            });
        }

        let session = CheckoutSession::create(&client, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        let checkout_url = session
            .url
            .ok_or_else(|| SubscriptionError::StripeError("No checkout URL returned".into()))?;

        tracing::info!(
            "Checkout session created: user_id={}, session_id={}, idempotency_key={}...",
            user_id,
            session.id,
            &idempotency_key.chars().take(16).collect::<String>()
        );

        Ok(checkout_url)
    }

    async fn cancel_subscription(&self, user_id: UserId) -> Result<(), SubscriptionError> {
        tracing::info!("Canceling subscription for user_id={}", user_id);

        // Get active subscription
        let subscription = self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .ok_or(SubscriptionError::NoActiveSubscription)?;

        // Cancel subscription via Stripe API (at period end)
        let client = self.get_stripe_client();
        let subscription_id: stripe::SubscriptionId = subscription
            .subscription_id
            .parse()
            .map_err(|_| SubscriptionError::StripeError("Invalid subscription ID".into()))?;

        // Update subscription to cancel at period end
        let params = stripe::UpdateSubscription {
            cancel_at_period_end: Some(true),
            ..Default::default()
        };

        let updated_sub = StripeSubscription::update(&client, &subscription_id, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        // Update database (with transaction)
        let mut updated_model =
            self.stripe_subscription_to_model(&updated_sub, user_id, &subscription.provider)?;
        // Preserve pending downgrade fields from existing subscription
        updated_model.pending_price_id = subscription.pending_price_id.clone();
        updated_model.downgrade_effective_at = subscription.downgrade_effective_at;

        let mut db_client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = db_client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        self.subscription_repo
            .upsert_subscription(&txn, updated_model)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        self.invalidate_token_limit_cache(user_id).await;

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Subscription canceled at period end: user_id={}, subscription_id={}",
            user_id,
            subscription.subscription_id
        );

        Ok(())
    }

    async fn resume_subscription(&self, user_id: UserId) -> Result<(), SubscriptionError> {
        tracing::info!("Resuming subscription for user_id={}", user_id);

        // Get active subscription
        let subscription = self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .ok_or(SubscriptionError::NoActiveSubscription)?;

        // Only allow resume when subscription is scheduled to cancel at period end
        if !subscription.cancel_at_period_end {
            return Err(SubscriptionError::SubscriptionNotScheduledForCancellation);
        }

        // Resume subscription via Stripe API (clear cancel_at_period_end)
        let client = self.get_stripe_client();
        let subscription_id: stripe::SubscriptionId = subscription
            .subscription_id
            .parse()
            .map_err(|_| SubscriptionError::StripeError("Invalid subscription ID".into()))?;

        let params = stripe::UpdateSubscription {
            cancel_at_period_end: Some(false),
            ..Default::default()
        };

        let updated_sub = StripeSubscription::update(&client, &subscription_id, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        // Update database (with transaction)
        let mut updated_model =
            self.stripe_subscription_to_model(&updated_sub, user_id, &subscription.provider)?;
        // Preserve pending downgrade fields from existing subscription
        updated_model.pending_price_id = subscription.pending_price_id.clone();
        updated_model.downgrade_effective_at = subscription.downgrade_effective_at;

        let mut db_client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = db_client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        self.subscription_repo
            .upsert_subscription(&txn, updated_model)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        self.invalidate_token_limit_cache(user_id).await;

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Subscription resumed: user_id={}, subscription_id={}",
            user_id,
            subscription.subscription_id
        );

        Ok(())
    }

    async fn get_user_subscriptions(
        &self,
        user_id: UserId,
        active_only: bool,
    ) -> Result<Vec<SubscriptionWithPlan>, SubscriptionError> {
        tracing::debug!(
            "Fetching subscriptions for user_id={}, active_only={}",
            user_id,
            active_only
        );

        // Verify subscriptions are configured (at least Stripe provider has plans)
        self.get_plans_for_provider("stripe").await?;

        // Get subscription_plans from config for plan name resolution across providers
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let subscription_plans = configs
            .and_then(|c| c.subscription_plans)
            .unwrap_or_default();

        // Get subscriptions from database
        let subscriptions = if active_only {
            self.subscription_repo
                .get_active_subscriptions(user_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
        } else {
            self.subscription_repo
                .get_user_subscriptions(user_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
        };

        // Map to API response model with plan names resolved
        let result: Vec<SubscriptionWithPlan> = subscriptions
            .into_iter()
            .map(|sub| {
                let plan = resolve_plan_name_from_config(
                    &sub.provider,
                    &sub.price_id,
                    &subscription_plans,
                );
                let pending_plan = sub.pending_price_id.as_ref().map(|pid| {
                    resolve_plan_name_from_config(&sub.provider, pid, &subscription_plans)
                });
                SubscriptionWithPlan {
                    subscription_id: sub.subscription_id,
                    user_id: sub.user_id.0.to_string(),
                    provider: sub.provider,
                    plan,
                    status: sub.status,
                    current_period_end: sub.current_period_end,
                    cancel_at_period_end: sub.cancel_at_period_end,
                    created_at: sub.created_at,
                    updated_at: sub.updated_at,
                    pending_plan,
                    downgrade_effective_at: sub.downgrade_effective_at,
                }
            })
            .collect();

        Ok(result)
    }

    async fn handle_stripe_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), SubscriptionError> {
        tracing::info!("Processing Stripe webhook");

        // Convert payload to string for webhook verification
        let payload_str = std::str::from_utf8(payload).map_err(|e| {
            SubscriptionError::WebhookVerificationFailed(format!("Invalid UTF-8: {}", e))
        })?;

        // Verify webhook signature FIRST (CRITICAL - use library, never hand-write)
        // This prevents unauthenticated requests from consuming server resources
        // Note: construct_event does BOTH signature verification AND event parsing
        // We only care about signature verification at this stage
        if let Err(e) =
            Webhook::construct_event(payload_str, signature, &self.stripe_webhook_secret)
        {
            match e {
                // Security-critical errors - reject the webhook immediately
                WebhookError::BadKey
                | WebhookError::BadSignature
                | WebhookError::BadTimestamp(_)
                | WebhookError::BadHeader(_) => {
                    tracing::error!("Webhook signature verification failed: error={}", e);
                    return Err(SubscriptionError::WebhookVerificationFailed(e.to_string()));
                }
                // Parsing error - signature is OK, we can continue
                WebhookError::BadParse(_) => {
                    tracing::debug!("Webhook event parsing failed (signature OK): error={}", e);
                }
            }
        } else {
            tracing::debug!("Webhook signature verified and parsed successfully");
        }

        // Only parse JSON after signature verification succeeds
        let payload_json: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| SubscriptionError::InternalError(format!("Invalid JSON: {}", e)))?;

        let event_id = payload_json
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let event_type = payload_json
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        tracing::info!(
            "Processing verified webhook: event_id={}, type={}",
            event_id,
            event_type
        );

        // Check if this is a subscription event
        let is_subscription_event = event_type.starts_with("customer.subscription.");

        // Start transaction early to check webhook idempotency BEFORE calling Stripe API
        // This prevents duplicate Stripe API calls on webhook retries
        let mut client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Store webhook (idempotent via UNIQUE constraint)
        let store_result = self
            .webhook_repo
            .store_webhook(
                &txn,
                "stripe".to_string(),
                event_id.to_string(),
                payload_json.clone(),
            )
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Skip processing if this webhook was already processed (duplicate/retry)
        if !store_result.is_new {
            tracing::info!(
                "Webhook already processed (duplicate): event_id={}, type={}, original_created_at={}",
                event_id,
                event_type,
                store_result.webhook.created_at
            );
            // Commit transaction and return success without calling Stripe API
            txn.commit()
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            return Ok(());
        }

        // For subscription events, fetch data from Stripe API (after idempotency check)
        let subscription_data = if is_subscription_event {
            // Extract subscription_id from JSON: data.object.id
            let subscription_id = payload_json
                .get("data")
                .and_then(|d| d.get("object"))
                .and_then(|o| o.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| {
                    SubscriptionError::InternalError(format!(
                        "Cannot extract subscription_id from webhook: event_id={}, type={}",
                        event_id, event_type
                    ))
                })?;

            tracing::info!(
                "Processing subscription event: event_id={}, type={}, subscription_id={}",
                event_id,
                event_type,
                subscription_id
            );

            // Fetch latest subscription state from Stripe API
            // (only called for new webhooks after idempotency check)
            let stripe_client = self.get_stripe_client();
            let stripe_sub = StripeSubscription::retrieve(
                &stripe_client,
                &subscription_id.parse().map_err(|_| {
                    SubscriptionError::InternalError(format!(
                        "Invalid subscription_id: {}",
                        subscription_id
                    ))
                })?,
                &[],
            )
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

            // Extract user_id from customer metadata
            let customer_id = match &stripe_sub.customer {
                stripe::Expandable::Id(id) => id.clone(),
                stripe::Expandable::Object(customer) => customer.id.clone(),
            };
            let customer = Customer::retrieve(&stripe_client, &customer_id, &[])
                .await
                .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

            let user_id_str = customer
                .metadata
                .as_ref()
                .and_then(|m| m.get("user_id"))
                .ok_or_else(|| {
                    SubscriptionError::InternalError("No user_id in customer metadata".into())
                })?;

            let user_id = UserId(uuid::Uuid::parse_str(user_id_str).map_err(|e| {
                SubscriptionError::InternalError(format!("Invalid user_id: {}", e))
            })?);

            // Convert to our model (Stripe webhook => provider is stripe)
            let subscription = self.stripe_subscription_to_model(&stripe_sub, user_id, "stripe")?;
            Some((subscription_id.to_string(), subscription))
        } else {
            None
        };

        // Upsert subscription if we have data, with downgrade detection
        let mut user_id_to_invalidate: Option<UserId> = None;
        // Track if we need to stop instances after commit (cancellation/payment failure)
        let mut stop_all_instances_for: Option<UserId> = None;
        // Track if we need to stop excess instances after commit (downgrade applied)
        let mut stop_excess_instances_for: Option<(UserId, String)> = None;

        if let Some((subscription_id, mut subscription)) = subscription_data {
            let user_id = subscription.user_id;

            // Check for terminal statuses that mean subscription has ended
            let is_terminal_status = matches!(
                subscription.status.as_str(),
                "canceled" | "unpaid" | "incomplete_expired"
            );

            if is_terminal_status {
                // Subscription ended — clear any pending downgrade (superseded)
                subscription.pending_price_id = None;
                subscription.downgrade_effective_at = None;
                stop_all_instances_for = Some(user_id);
            } else {
                // Check if price_id changed (plan switch via Stripe portal)
                // Read through the transaction to avoid TOCTOU race with concurrent webhooks
                let existing = self
                    .subscription_repo
                    .get_active_subscription_in_txn(&txn, user_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

                if let Some(ref existing_sub) = existing {
                    if existing_sub.price_id != subscription.price_id {
                        // Price changed — determine if it's a downgrade or upgrade
                        let plans = self.get_subscription_plans().await?;

                        if Self::is_downgrade(
                            &existing_sub.price_id,
                            &subscription.price_id,
                            &subscription.provider,
                            &plans,
                        ) {
                            if existing_sub.pending_price_id.as_deref()
                                == Some(&subscription.price_id)
                            {
                                // Stripe renewed at the pending (lower) price — the grace period
                                // has ended and Stripe is now billing at the new rate. Apply the
                                // downgrade immediately instead of re-deferring (which would loop
                                // indefinitely).
                                tracing::info!(
                                    "Applying deferred downgrade (Stripe renewed at pending price): subscription_id={}, user_id={}, new_price={}",
                                    subscription_id, user_id, subscription.price_id
                                );
                                subscription.pending_price_id = None;
                                subscription.downgrade_effective_at = None;
                                // price_id is already the new (lower) price from Stripe
                                stop_excess_instances_for =
                                    Some((user_id, subscription.price_id.clone()));
                            } else {
                                // New downgrade target — defer the price change.
                                // Use Stripe's latest current_period_end (from the incoming webhook)
                                // rather than the DB's existing value, which may be stale if a renewal
                                // webhook arrived concurrently.
                                tracing::info!(
                                    "Deferring downgrade: subscription_id={}, user_id={}, old_price={}, new_price={}, effective_at={}",
                                    subscription_id, user_id,
                                    existing_sub.price_id, subscription.price_id,
                                    subscription.current_period_end
                                );
                                // Swap: new price → pending, old price → current (preserves old limits during grace period)
                                subscription.pending_price_id = Some(subscription.price_id.clone());
                                subscription.downgrade_effective_at =
                                    Some(subscription.current_period_end);
                                subscription.price_id = existing_sub.price_id.clone();
                                // NOTE: We intentionally do NOT call stop_excess_instances here.
                                // During the grace period the user keeps the old plan's instance
                                // limits. Instance enforcement happens when the downgrade applies
                                // (in apply_pending_downgrade_if_due).
                            }
                        } else {
                            // UPGRADE: apply immediately, clear any pending downgrade
                            tracing::info!(
                                "Applying upgrade immediately: subscription_id={}, user_id={}",
                                subscription_id,
                                user_id
                            );
                            subscription.pending_price_id = None;
                            subscription.downgrade_effective_at = None;
                        }
                    } else {
                        // Same price_id (renewal, status update, etc.)
                        // Preserve existing pending downgrade fields
                        subscription.pending_price_id = existing_sub.pending_price_id.clone();
                        subscription.downgrade_effective_at = existing_sub.downgrade_effective_at;

                        // Check if pending downgrade is now due
                        if let Some(effective_at) = subscription.downgrade_effective_at {
                            if Utc::now() >= effective_at {
                                tracing::info!(
                                    "Pending downgrade is due during webhook: subscription_id={}, user_id={}",
                                    subscription_id, user_id
                                );
                                // Apply the downgrade inline
                                if let Some(ref pending) = subscription.pending_price_id {
                                    subscription.price_id = pending.clone();
                                    stop_excess_instances_for = Some((user_id, pending.clone()));
                                }
                                subscription.pending_price_id = None;
                                subscription.downgrade_effective_at = None;
                            }
                        }
                    }
                }
            }

            self.subscription_repo
                .upsert_subscription(&txn, subscription)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            tracing::info!(
                "Subscription synced to database: subscription_id={}, user_id={}",
                subscription_id,
                user_id
            );
            user_id_to_invalidate = Some(user_id);
        } else {
            tracing::debug!(
                "Non-subscription webhook stored: event_id={}, type={}",
                event_id,
                event_type
            );
        }

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        if let Some(user_id) = user_id_to_invalidate {
            self.invalidate_token_limit_cache(user_id).await;
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // After commit: stop all instances if subscription ended
        if let Some(user_id) = stop_all_instances_for {
            self.stop_all_user_instances(user_id).await;
        }

        // After commit: stop excess instances if downgrade was applied
        if let Some((uid, ref price_id)) = stop_excess_instances_for {
            self.stop_excess_instances(uid, price_id).await;
        }

        tracing::info!(
            "Webhook processed successfully: event_id={}, type={}",
            event_id,
            event_type
        );

        Ok(())
    }

    async fn create_customer_portal_session(
        &self,
        user_id: UserId,
        return_url: String,
    ) -> Result<String, SubscriptionError> {
        tracing::info!("Creating portal session for user_id={}", user_id);

        // Check Stripe configuration
        if self.stripe_secret_key.is_empty() || self.stripe_webhook_secret.is_empty() {
            tracing::debug!(
                "Stripe secrets not configured (secret_key_empty={}, webhook_secret_empty={})",
                self.stripe_secret_key.is_empty(),
                self.stripe_webhook_secret.is_empty()
            );
            return Err(SubscriptionError::NotConfigured);
        }

        // Get user's Stripe customer ID
        let customer_id = self
            .stripe_customer_repo
            .get_customer_id(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .ok_or(SubscriptionError::NoStripeCustomer)?;

        tracing::debug!(
            "Found Stripe customer: user_id={}, customer_id={}",
            user_id,
            customer_id
        );

        // Parse customer ID
        let customer_id_parsed: CustomerId = customer_id
            .parse()
            .map_err(|_| SubscriptionError::InternalError("Invalid customer ID format".into()))?;

        // Create billing portal session
        let client = self.get_stripe_client();
        let mut params = CreateBillingPortalSession::new(customer_id_parsed);
        params.return_url = Some(&return_url);

        let session = BillingPortalSession::create(&client, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        tracing::info!(
            "Portal session created: user_id={}, session_id={}",
            user_id,
            session.id
        );

        Ok(session.url)
    }

    async fn require_subscription_for_proxy(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError> {
        // When Stripe is not configured, allow access (no subscription gating)
        match self.get_plans_for_provider("stripe").await {
            Err(SubscriptionError::NotConfigured) => {
                tracing::debug!(
                    "Subscription gating skipped: Stripe not configured, allowing user_id={}",
                    user_id
                );
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }

        // 1. Determine max token limit (with 10-min cache unless plan changed)
        let cached_limit = {
            let cache_guard = self.token_limit_cache.read().await;
            if let Some(cached) = cache_guard.get(&user_id) {
                if cached.cached_at.elapsed().as_secs() < TTL_CACHE_SECS {
                    tracing::debug!(
                        "Using cached token limit for user_id={} (max={}, age_secs={})",
                        user_id,
                        cached.max_tokens,
                        cached.cached_at.elapsed().as_secs()
                    );
                    Some((cached.max_tokens, cached.period_start, cached.period_end))
                } else {
                    None
                }
            } else {
                None
            }
        };

        let (max_tokens, period_start, period_end) = match cached_limit {
            Some((max, start, end)) => (max, start, end),
            None => {
                // Cache miss or expired: compute and store
                let configs = self
                    .system_configs_service
                    .get_configs()
                    .await
                    .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
                let subscription_plans = configs
                    .and_then(|c| c.subscription_plans)
                    .unwrap_or_default();

                let computed = match self
                    .subscription_repo
                    .get_active_subscription(user_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
                {
                    Some(ref sub) => {
                        // Lazy safety net: apply pending downgrade if due
                        let effective_sub = if sub.downgrade_effective_at.is_some() {
                            match self.apply_pending_downgrade_if_due(sub).await {
                                Ok(Some(updated)) => updated,
                                Ok(None) => sub.clone(),
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to apply pending downgrade for user_id={}: {}",
                                        user_id,
                                        e
                                    );
                                    sub.clone()
                                }
                            }
                        } else {
                            sub.clone()
                        };
                        let plan_name = resolve_plan_name_from_config(
                            "stripe",
                            &effective_sub.price_id,
                            &subscription_plans,
                        );
                        let max_tokens = subscription_plans
                            .get(&plan_name)
                            .and_then(|c| c.monthly_tokens.as_ref())
                            .map(|l| l.max)
                            .unwrap_or(1_000_000);
                        let period_end = effective_sub.current_period_end;
                        // TODO: sub_one_month_same_day assumes monthly billing. If yearly plans
                        // are added, use Stripe's current_period_start instead.
                        let period_start = sub_one_month_same_day(period_end);
                        (max_tokens, period_start, period_end)
                    }
                    None => {
                        let max_tokens = subscription_plans
                            .get("free")
                            .and_then(|c| c.monthly_tokens.as_ref())
                            .map(|l| l.max)
                            .unwrap_or(1_000_000);
                        // Free users: calendar month — 00:00 on 1st through 24:00 on last day
                        let (period_start, period_end) = current_calendar_month_period(Utc::now());
                        (max_tokens, period_start, period_end)
                    }
                };

                // Store in cache
                {
                    let mut cache_guard = self.token_limit_cache.write().await;
                    cache_guard.insert(
                        user_id,
                        CachedTokenLimit {
                            max_tokens: computed.0,
                            period_start: computed.1,
                            period_end: computed.2,
                            cached_at: Instant::now(),
                        },
                    );
                }
                computed
            }
        };

        // 2. Get used tokens in the period
        let used = self
            .user_usage_repo
            .get_usage_by_user_id(user_id, Some(period_start), Some(period_end))
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?
            .map(|s| s.token_sum)
            .unwrap_or(0);

        // 3. Enforce limit
        if used >= max_tokens as i64 {
            tracing::info!(
                "Blocking proxy access for user_id={}: monthly token limit exceeded (used {} of {})",
                user_id, used, max_tokens
            );
            return Err(SubscriptionError::MonthlyTokenLimitExceeded {
                used,
                limit: max_tokens,
            });
        }

        tracing::debug!(
            "User user_id={} within token limit (used {} of {}), allowing proxy access",
            user_id,
            used,
            max_tokens
        );
        Ok(())
    }

    /// Admin only: Set subscription for a user directly (for testing/manual management).
    async fn admin_set_subscription(
        &self,
        user_id: UserId,
        provider: String,
        plan: String,
        current_period_end: chrono::DateTime<chrono::Utc>,
    ) -> Result<SubscriptionWithPlan, SubscriptionError> {
        tracing::info!(
            "Admin: Setting subscription for user_id={}, provider={}, plan={}",
            user_id,
            provider,
            plan
        );

        // Get available plans
        let plans = self.get_plans_for_provider(&provider).await?;

        let price_id = plans.get(&plan).ok_or_else(|| {
            SubscriptionError::InvalidPlan(format!(
                "Plan '{}' not found for provider '{}'",
                plan, provider
            ))
        })?;

        // Reuse existing admin_sub_ subscription if present, otherwise create new one
        let existing = self
            .subscription_repo
            .get_user_subscriptions(user_id)
            .await?;
        let subscription_id = existing
            .iter()
            .find(|s| s.subscription_id.starts_with("admin_sub_"))
            .map(|s| s.subscription_id.clone())
            .unwrap_or_else(|| format!("admin_sub_{}", uuid::Uuid::new_v4()));

        // Get or create a dummy customer ID for admin subscriptions
        let customer_id = format!("admin_{}", user_id);

        let subscription = Subscription {
            subscription_id: subscription_id.clone(),
            user_id,
            provider: provider.clone(),
            customer_id,
            price_id: price_id.clone(),
            status: "active".to_string(),
            current_period_end,
            cancel_at_period_end: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            pending_price_id: None,
            downgrade_effective_at: None,
        };

        // Upsert subscription in transaction
        let mut client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Deactivate any existing active subscriptions so the user has only one active plan
        self.subscription_repo
            .deactivate_user_subscriptions(&txn, user_id)
            .await?;

        let result = self
            .subscription_repo
            .upsert_subscription(&txn, subscription)
            .await?;

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate token limit cache
        self.invalidate_token_limit_cache(user_id).await;

        // Plan name is just the plan key from the config
        let plan_name = plan.clone();

        Ok(SubscriptionWithPlan {
            subscription_id: result.subscription_id,
            user_id: user_id.to_string(),
            provider: result.provider,
            plan: plan_name,
            status: result.status,
            current_period_end: result.current_period_end,
            cancel_at_period_end: result.cancel_at_period_end,
            created_at: result.created_at,
            updated_at: result.updated_at,
            pending_plan: None,
            downgrade_effective_at: None,
        })
    }

    /// Admin only: Cancel all subscriptions for a user.
    async fn admin_cancel_user_subscriptions(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError> {
        tracing::info!("Admin: Canceling all subscriptions for user_id={}", user_id);

        let subscriptions = self
            .subscription_repo
            .get_user_subscriptions(user_id)
            .await?;

        for subscription in subscriptions {
            self.subscription_repo
                .delete_subscription(&subscription.subscription_id)
                .await?;
        }

        // Invalidate token limit cache
        self.invalidate_token_limit_cache(user_id).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_configs::ports::{
        PaymentProviderConfig, PlanLimitConfig, SubscriptionPlanConfig,
    };

    /// Build a HashMap of plan configs for testing is_downgrade and resolve_plan_name_from_config.
    fn test_plans() -> HashMap<String, SubscriptionPlanConfig> {
        let mut plans = HashMap::new();

        plans.insert(
            "byok".to_string(),
            SubscriptionPlanConfig {
                providers: {
                    let mut p = HashMap::new();
                    p.insert(
                        "stripe".to_string(),
                        PaymentProviderConfig {
                            price_id: "price_byok".to_string(),
                        },
                    );
                    p
                },
                agent_instances: Some(PlanLimitConfig { max: 2 }),
                monthly_tokens: Some(PlanLimitConfig { max: 500_000 }),
                trial_period_days: None,
            },
        );

        plans.insert(
            "pro".to_string(),
            SubscriptionPlanConfig {
                providers: {
                    let mut p = HashMap::new();
                    p.insert(
                        "stripe".to_string(),
                        PaymentProviderConfig {
                            price_id: "price_pro".to_string(),
                        },
                    );
                    p
                },
                agent_instances: Some(PlanLimitConfig { max: 5 }),
                monthly_tokens: Some(PlanLimitConfig { max: 5_000_000 }),
                trial_period_days: None,
            },
        );

        plans.insert(
            "enterprise".to_string(),
            SubscriptionPlanConfig {
                providers: {
                    let mut p = HashMap::new();
                    p.insert(
                        "stripe".to_string(),
                        PaymentProviderConfig {
                            price_id: "price_enterprise".to_string(),
                        },
                    );
                    p
                },
                agent_instances: Some(PlanLimitConfig { max: 10 }),
                monthly_tokens: Some(PlanLimitConfig { max: 50_000_000 }),
                trial_period_days: None,
            },
        );

        plans
    }

    // --- resolve_plan_name_from_config tests ---

    #[test]
    fn test_resolve_plan_name_known_price() {
        let plans = test_plans();
        assert_eq!(
            resolve_plan_name_from_config("stripe", "price_pro", &plans),
            "pro"
        );
        assert_eq!(
            resolve_plan_name_from_config("stripe", "price_byok", &plans),
            "byok"
        );
    }

    #[test]
    fn test_resolve_plan_name_unknown_price() {
        let plans = test_plans();
        assert_eq!(
            resolve_plan_name_from_config("stripe", "price_unknown", &plans),
            "unknown"
        );
    }

    #[test]
    fn test_resolve_plan_name_wrong_provider() {
        let plans = test_plans();
        assert_eq!(
            resolve_plan_name_from_config("paypal", "price_pro", &plans),
            "unknown"
        );
    }

    // --- is_downgrade tests ---

    #[test]
    fn test_downgrade_pro_to_byok() {
        let plans = test_plans();
        // Pro (5 instances, 5M tokens) -> BYOK (2 instances, 500K tokens) = downgrade
        assert!(SubscriptionServiceImpl::is_downgrade(
            "price_pro",
            "price_byok",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_upgrade_byok_to_pro() {
        let plans = test_plans();
        // BYOK (2 instances, 500K tokens) -> Pro (5 instances, 5M tokens) = NOT downgrade
        assert!(!SubscriptionServiceImpl::is_downgrade(
            "price_byok",
            "price_pro",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_upgrade_pro_to_enterprise() {
        let plans = test_plans();
        // Pro -> Enterprise = NOT downgrade
        assert!(!SubscriptionServiceImpl::is_downgrade(
            "price_pro",
            "price_enterprise",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_downgrade_enterprise_to_byok() {
        let plans = test_plans();
        // Enterprise -> BYOK = downgrade
        assert!(SubscriptionServiceImpl::is_downgrade(
            "price_enterprise",
            "price_byok",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_same_plan_not_downgrade() {
        let plans = test_plans();
        // Same plan is not a downgrade
        assert!(!SubscriptionServiceImpl::is_downgrade(
            "price_pro",
            "price_pro",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_unknown_old_plan_not_downgrade() {
        let plans = test_plans();
        // Unknown old plan (0 defaults) -> known plan = NOT downgrade (new has higher limits)
        assert!(!SubscriptionServiceImpl::is_downgrade(
            "price_unknown",
            "price_pro",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_known_plan_to_unknown_is_downgrade() {
        let plans = test_plans();
        // Known plan -> unknown (0 defaults) = downgrade
        assert!(SubscriptionServiceImpl::is_downgrade(
            "price_pro",
            "price_unknown",
            "stripe",
            &plans
        ));
    }

    #[test]
    fn test_downgrade_only_instances_lower() {
        // Test case where only one dimension is lower
        let mut plans = HashMap::new();
        plans.insert(
            "plan_a".to_string(),
            SubscriptionPlanConfig {
                providers: {
                    let mut p = HashMap::new();
                    p.insert(
                        "stripe".to_string(),
                        PaymentProviderConfig {
                            price_id: "price_a".to_string(),
                        },
                    );
                    p
                },
                agent_instances: Some(PlanLimitConfig { max: 5 }),
                monthly_tokens: Some(PlanLimitConfig { max: 1_000_000 }),
                trial_period_days: None,
            },
        );
        plans.insert(
            "plan_b".to_string(),
            SubscriptionPlanConfig {
                providers: {
                    let mut p = HashMap::new();
                    p.insert(
                        "stripe".to_string(),
                        PaymentProviderConfig {
                            price_id: "price_b".to_string(),
                        },
                    );
                    p
                },
                // Same tokens but fewer instances
                agent_instances: Some(PlanLimitConfig { max: 2 }),
                monthly_tokens: Some(PlanLimitConfig { max: 1_000_000 }),
                trial_period_days: None,
            },
        );

        // A -> B: instances decrease (5 -> 2), tokens same. This IS a downgrade.
        assert!(SubscriptionServiceImpl::is_downgrade(
            "price_a", "price_b", "stripe", &plans
        ));
    }

    // --- sub_one_month_same_day tests ---

    #[test]
    fn test_sub_one_month_normal() {
        let dt = chrono::DateTime::parse_from_rfc3339("2025-03-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let result = sub_one_month_same_day(dt);
        assert_eq!(result.month(), 2);
        assert_eq!(result.day(), 15);
    }

    #[test]
    fn test_sub_one_month_january_wraps_to_december() {
        let dt = chrono::DateTime::parse_from_rfc3339("2025-01-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let result = sub_one_month_same_day(dt);
        assert_eq!(result.year(), 2024);
        assert_eq!(result.month(), 12);
        assert_eq!(result.day(), 15);
    }

    #[test]
    fn test_sub_one_month_day_overflow() {
        // March 31 -> Feb doesn't have 31 days -> should use last day of Feb
        let dt = chrono::DateTime::parse_from_rfc3339("2025-03-31T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let result = sub_one_month_same_day(dt);
        assert_eq!(result.month(), 2);
        assert_eq!(result.day(), 28);
    }

    // --- current_calendar_month_period tests ---

    #[test]
    fn test_calendar_month_period_mid_month() {
        let dt = chrono::DateTime::parse_from_rfc3339("2025-06-15T14:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let (start, end) = current_calendar_month_period(dt);
        assert_eq!(start.month(), 6);
        assert_eq!(start.day(), 1);
        assert_eq!(end.month(), 7);
        assert_eq!(end.day(), 1);
    }

    #[test]
    fn test_calendar_month_period_december() {
        let dt = chrono::DateTime::parse_from_rfc3339("2025-12-25T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let (start, end) = current_calendar_month_period(dt);
        assert_eq!(start.year(), 2025);
        assert_eq!(start.month(), 12);
        assert_eq!(end.year(), 2026);
        assert_eq!(end.month(), 1);
    }
}
