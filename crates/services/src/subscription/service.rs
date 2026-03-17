use super::ports::{
    ChangePlanOutcome, CreditsRepository, CreditsSummary, DowngradeIntentStatus,
    PaymentWebhookRepository, StripeCustomerRepository, Subscription, SubscriptionError,
    SubscriptionPlan, SubscriptionRepository, SubscriptionService, SubscriptionWithPlan,
    DEFAULT_MONTHLY_TOKEN_LIMIT,
};
use crate::agent::ports::AgentRepository;
use crate::agent::ports::AgentService;
use crate::system_configs::ports::{SubscriptionPlanConfig, SystemConfigsService};
use crate::user::ports::UserRepository;
use crate::user_usage::ports::UserUsageRepository;
use crate::UserId;
use async_trait::async_trait;
use chrono::{Datelike, Duration, NaiveTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use stripe::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCheckoutSessionSubscriptionData,
    Customer, CustomerId, RequestStrategy, Subscription as StripeSubscription,
    UpdateSubscriptionItems, Webhook, WebhookError,
};
use tokio::sync::RwLock;

/// Configuration for SubscriptionServiceImpl
pub struct SubscriptionServiceConfig {
    pub db_pool: deadpool_postgres::Pool,
    pub stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    pub subscription_repo: Arc<dyn SubscriptionRepository>,
    pub webhook_repo: Arc<dyn PaymentWebhookRepository>,
    pub credits_repo: Arc<dyn CreditsRepository>,
    pub system_configs_service: Arc<dyn SystemConfigsService>,
    pub user_repository: Arc<dyn UserRepository>,
    pub user_usage_repo: Arc<dyn UserUsageRepository>,
    pub agent_repo: Arc<dyn AgentRepository>,
    pub agent_service: Arc<dyn AgentService>,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
}

/// Cached credit limit for a user. Invalid after TTL_CACHE_SECS (10 mins) or when plan/credits change.
struct CachedCreditLimit {
    max_credits: u64, // plan_monthly_credits + purchased_balance
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    cached_at: Instant,
}

const TTL_CACHE_SECS: u64 = 600; // 10 minutes
/// Default monthly credits when plan has no monthly_credits config. 1 USD in nano-dollars ($1 = 1_000_000_000).
const DEFAULT_MONTHLY_CREDITS_NANO_USD: u64 = 1_000_000_000;
/// When falling back from monthly_tokens: 1.5 USD per M tokens. M = 1 million tokens.
const TOKENS_TO_CREDITS_PER_M: u64 = 1_000_000;
/// 1.5 USD in nano-USD. Used for monthly_tokens fallback: limit_nano_usd = (monthly_tokens / M) * this.
const NANO_USD_PER_1_5_USD: u64 = 1_500_000_000;
const DOWNGRADE_CHECK_WINDOW_HOURS: i64 = 24;
const TX_LOCK_TIMEOUT_MS: i64 = 1500;

pub struct SubscriptionServiceImpl {
    db_pool: deadpool_postgres::Pool,
    stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    subscription_repo: Arc<dyn SubscriptionRepository>,
    webhook_repo: Arc<dyn PaymentWebhookRepository>,
    credits_repo: Arc<dyn CreditsRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
    user_repository: Arc<dyn UserRepository>,
    user_usage_repo: Arc<dyn UserUsageRepository>,
    agent_repo: Arc<dyn AgentRepository>,
    agent_service: Arc<dyn AgentService>,
    stripe_secret_key: String,
    stripe_webhook_secret: String,
    credit_limit_cache: Arc<RwLock<HashMap<UserId, CachedCreditLimit>>>,
}

impl SubscriptionServiceImpl {
    /// Returns true when Stripe is configured well enough to perform API calls.
    fn is_stripe_configured(&self) -> bool {
        !self.stripe_secret_key.is_empty() && !self.stripe_webhook_secret.is_empty()
    }

    pub fn new(config: SubscriptionServiceConfig) -> Self {
        Self {
            db_pool: config.db_pool,
            stripe_customer_repo: config.stripe_customer_repo,
            subscription_repo: config.subscription_repo,
            webhook_repo: config.webhook_repo,
            credits_repo: config.credits_repo,
            system_configs_service: config.system_configs_service,
            user_repository: config.user_repository,
            user_usage_repo: config.user_usage_repo,
            agent_repo: config.agent_repo,
            agent_service: config.agent_service,
            stripe_secret_key: config.stripe_secret_key,
            stripe_webhook_secret: config.stripe_webhook_secret,
            credit_limit_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Invalidate credit limit cache for a user (e.g. when plan/credits change via webhook).
    async fn invalidate_credit_limit_cache(&self, user_id: UserId) {
        let mut guard = self.credit_limit_cache.write().await;
        guard.remove(&user_id);
        tracing::debug!("Invalidated credit limit cache for user_id={}", user_id);
    }

    /// Convert a whole-number credit count into nano-USD (1 credit == $1 == 1_000_000_000 nano-USD).
    /// Returns None when the multiplication would overflow i64.
    fn credits_to_nano_usd(credits: i64) -> Option<i64> {
        if credits <= 0 {
            return None;
        }
        let v = (credits as i128) * 1_000_000_000_i128;
        i64::try_from(v).ok()
    }

    /// Maximum number of retries when stopping instances after subscription cancel.
    const STOP_INSTANCE_MAX_RETRIES: u32 = 1;

    /// Stop all active instances for a user after their subscription is canceled.
    /// Runs asynchronously after the webhook transaction commits.
    /// Each instance stop is attempted up to STOP_INSTANCE_MAX_RETRIES+1 times.
    /// Failures are logged but do not affect the webhook response.
    async fn stop_user_instances_with_retry(agent_service: Arc<dyn AgentService>, user_id: UserId) {
        let instances = match agent_service.list_instances(user_id, 1000, 0).await {
            Ok((list, _)) => list,
            Err(e) => {
                tracing::error!(
                    "Failed to list instances for cancel cleanup: user_id={}, err={}",
                    user_id,
                    e
                );
                return;
            }
        };

        let active_instances: Vec<_> = instances
            .into_iter()
            .filter(|i| i.status == "active")
            .collect();

        if active_instances.is_empty() {
            return;
        }

        tracing::info!(
            "Stopping {} active instance(s) after subscription cancel: user_id={}",
            active_instances.len(),
            user_id
        );

        for instance in &active_instances {
            let mut last_err = None;
            for attempt in 0..=Self::STOP_INSTANCE_MAX_RETRIES {
                match agent_service.stop_instance(instance.id, user_id).await {
                    Ok(()) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to stop instance (attempt {}): instance_id={}, err={}",
                            attempt + 1,
                            instance.id,
                            e
                        );
                        last_err = Some(e);
                    }
                }
            }
            if let Some(e) = last_err {
                tracing::error!(
                    "All retries exhausted for instance stop: instance_id={}, user_id={}, err={}",
                    instance.id,
                    user_id,
                    e
                );
            }
        }
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
        if provider.to_lowercase() == "stripe" && !self.is_stripe_configured() {
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
        test_clock_id: Option<String>,
    ) -> Result<String, SubscriptionError> {
        // Check if customer already exists
        if let Some(customer_id) = self
            .stripe_customer_repo
            .get_customer_id(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
        {
            // Reject test_clock_id for existing customers - Stripe doesn't support retroactive association
            if test_clock_id.is_some() {
                return Err(SubscriptionError::TestClockNotAllowedForExistingCustomer);
            }

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
                test_clock: test_clock_id.as_deref(),
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

        let current_period_end = chrono::DateTime::from_timestamp(stripe_sub.current_period_end, 0)
            .ok_or_else(|| SubscriptionError::StripeError("Invalid current_period_end".into()))?;
        Ok(Subscription {
            subscription_id: stripe_sub.id.to_string(),
            user_id,
            provider: provider.to_string(),
            customer_id,
            price_id,
            status: stripe_sub.status.to_string(),
            current_period_end,
            cancel_at_period_end: stripe_sub.cancel_at_period_end,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            pending_downgrade_target_price_id: None,
            pending_downgrade_from_price_id: None,
            pending_downgrade_expected_period_end: None,
            pending_downgrade_status: None,
        })
    }

    /// Resolve plan monthly credits (nano-USD) and billing period for credit reconciliation.
    async fn resolve_plan_period_for_user(
        &self,
        user_id: UserId,
    ) -> Result<(i64, chrono::DateTime<Utc>, chrono::DateTime<Utc>), SubscriptionError> {
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let subscription_plans = configs
            .and_then(|c| c.subscription_plans)
            .unwrap_or_default();

        let (plan_credits, period_start, period_end) = match self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
        {
            Some(ref sub) => {
                let plan_name =
                    resolve_plan_name_from_config("stripe", &sub.price_id, &subscription_plans);
                let plan_credits = plan_name
                    .as_ref()
                    .and_then(|n| subscription_plans.get(n))
                    .map(Self::plan_limit_max)
                    .unwrap_or(DEFAULT_MONTHLY_CREDITS_NANO_USD);
                let period_end = sub.current_period_end;
                let period_start = sub_one_month_same_day(sub.current_period_end);
                (plan_credits, period_start, period_end)
            }
            None => {
                let plan_credits = subscription_plans
                    .get("free")
                    .map(Self::plan_limit_max)
                    .unwrap_or(DEFAULT_MONTHLY_CREDITS_NANO_USD);
                let (period_start, period_end) = current_calendar_month_period(Utc::now());
                (plan_credits, period_start, period_end)
            }
        };

        // Clamp to i64::MAX so CreditsSummary.effective_max_credits and comparisons don't overflow
        let plan_credits_i64 = plan_credits.min(i64::MAX as u64) as i64;
        Ok((plan_credits_i64, period_start, period_end))
    }

    fn mark_downgrade_pending(subscription: &mut Subscription, target_price_id: String) {
        subscription.pending_downgrade_target_price_id = Some(target_price_id);
        subscription.pending_downgrade_from_price_id = Some(subscription.price_id.clone());
        subscription.pending_downgrade_expected_period_end = Some(subscription.current_period_end);
        subscription.pending_downgrade_status = Some(DowngradeIntentStatus::Pending);
    }

    fn mark_downgrade_terminal(subscription: &mut Subscription, status: DowngradeIntentStatus) {
        subscription.pending_downgrade_target_price_id = None;
        subscription.pending_downgrade_from_price_id = None;
        subscription.pending_downgrade_expected_period_end = None;
        subscription.pending_downgrade_status = Some(status);
    }

    /// Returns the plan's monthly credit limit in nano-USD (see `credits_max_nano_usd`).
    fn plan_limit_max(config: &SubscriptionPlanConfig) -> u64 {
        credits_max_nano_usd(Some(config))
    }

    fn should_check_pending_downgrade(subscription: &Subscription) -> bool {
        if subscription.pending_downgrade_status != Some(DowngradeIntentStatus::Pending) {
            return false;
        }

        let Some(expected_end) = subscription.pending_downgrade_expected_period_end else {
            return false;
        };

        let check_from = expected_end - Duration::hours(DOWNGRADE_CHECK_WINDOW_HOURS);
        Utc::now() >= check_from
    }

    async fn try_apply_pending_downgrade_in_txn(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> Result<Option<Subscription>, SubscriptionError> {
        txn.batch_execute(&format!(
            "SET LOCAL lock_timeout = '{}ms'",
            TX_LOCK_TIMEOUT_MS
        ))
        .await
        .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        let pending = match self
            .subscription_repo
            .get_pending_downgrade_for_update_skip_locked(txn, subscription_id)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                let is_lock_timeout = e
                    .downcast_ref::<tokio_postgres::Error>()
                    .and_then(|pg_err| pg_err.as_db_error())
                    .map(|db_err| {
                        db_err.code() == &tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE
                    })
                    .unwrap_or(false);
                if is_lock_timeout {
                    return Ok(None);
                }
                return Err(SubscriptionError::DatabaseError(e.to_string()));
            }
        };

        let Some(pending) = pending else {
            return Ok(None);
        };

        let stripe_client = self.get_stripe_client();
        let stripe_sub_id: stripe::SubscriptionId = pending
            .subscription_id
            .parse()
            .map_err(|_| SubscriptionError::StripeError("Invalid subscription ID".into()))?;

        let stripe_sub = StripeSubscription::retrieve(&stripe_client, &stripe_sub_id, &[])
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        let mut current_model =
            self.stripe_subscription_to_model(&stripe_sub, pending.user_id, &pending.provider)?;

        let (Some(target_price_id), Some(from_price_id), Some(expected_period_end)) = (
            pending.pending_downgrade_target_price_id.clone(),
            pending.pending_downgrade_from_price_id.clone(),
            pending.pending_downgrade_expected_period_end,
        ) else {
            Self::mark_downgrade_terminal(&mut current_model, DowngradeIntentStatus::Missed);
            let updated = self
                .subscription_repo
                .upsert_subscription(txn, current_model)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            return Ok(Some(updated));
        };

        if current_model.price_id == target_price_id {
            Self::mark_downgrade_terminal(&mut current_model, DowngradeIntentStatus::Applied);
            let updated = self
                .subscription_repo
                .upsert_subscription(txn, current_model)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            return Ok(Some(updated));
        }

        if current_model.current_period_end != expected_period_end {
            Self::mark_downgrade_terminal(&mut current_model, DowngradeIntentStatus::Missed);
            let updated = self
                .subscription_repo
                .upsert_subscription(txn, current_model)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            return Ok(Some(updated));
        }

        if current_model.price_id == from_price_id
            && current_model.current_period_end == expected_period_end
        {
            let plans = self.get_subscription_plans().await?;
            let target_plan_name =
                resolve_plan_name_from_config(&pending.provider, &target_price_id, &plans)
                    .ok_or_else(|| {
                        SubscriptionError::InternalError(format!(
                            "Cannot resolve plan for price_id={}, provider={}",
                            target_price_id, pending.provider
                        ))
                    })?;
            let target_limits = effective_limits(plans.get(&target_plan_name));
            let instance_count = self
                .agent_repo
                .count_user_instances(pending.user_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
                as u64;

            if instance_count > target_limits.instances_max {
                Self::mark_downgrade_terminal(
                    &mut current_model,
                    DowngradeIntentStatus::Unsatisfied,
                );
                let updated = self
                    .subscription_repo
                    .upsert_subscription(txn, current_model)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                return Ok(Some(updated));
            }

            let subscription_item_id = stripe_sub
                .items
                .data
                .first()
                .map(|item| item.id.to_string())
                .ok_or_else(|| {
                    SubscriptionError::StripeError("No subscription item found".into())
                })?;
            let update_item = UpdateSubscriptionItems {
                id: Some(subscription_item_id),
                price: Some(target_price_id),
                ..Default::default()
            };
            let params = stripe::UpdateSubscription {
                items: Some(vec![update_item]),
                proration_behavior: Some(
                    stripe::generated::billing::subscription::SubscriptionProrationBehavior::CreateProrations,
                ),
                ..Default::default()
            };

            let updated_sub = StripeSubscription::update(&stripe_client, &stripe_sub_id, params)
                .await
                .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

            let mut updated_model = self.stripe_subscription_to_model(
                &updated_sub,
                pending.user_id,
                &pending.provider,
            )?;
            Self::mark_downgrade_terminal(&mut updated_model, DowngradeIntentStatus::Applied);
            let updated = self
                .subscription_repo
                .upsert_subscription(txn, updated_model)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            return Ok(Some(updated));
        }

        Ok(None)
    }

    async fn try_apply_pending_downgrade(
        &self,
        subscription_id: &str,
    ) -> Result<Option<Subscription>, SubscriptionError> {
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
            .try_apply_pending_downgrade_in_txn(&txn, subscription_id)
            .await?;

        if let Some(ref sub) = updated {
            self.invalidate_credit_limit_cache(sub.user_id).await;
        }

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        Ok(updated)
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
) -> Option<String> {
    let result = plans
        .iter()
        .find(|(_, config)| {
            config
                .providers
                .get(provider)
                .map(|p| p.price_id.as_str() == price_id)
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone());

    if result.is_none() {
        tracing::error!(
            "Failed to resolve plan name: provider={}, price_id={}, configured_plans=[{}]",
            provider,
            price_id,
            plans.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }

    result
}

#[derive(Debug, Clone, Copy)]
struct EffectivePlanLimits {
    tokens_max: u64,
    credits_max_nano_usd: u64,
    instances_max: u64,
}

/// Monthly credit limit in nano-USD: from monthly_credits, or from monthly_tokens converted at 1.5 USD per M tokens, or default.
fn credits_max_nano_usd(plan_config: Option<&SubscriptionPlanConfig>) -> u64 {
    let Some(config) = plan_config else {
        return DEFAULT_MONTHLY_CREDITS_NANO_USD;
    };
    if let Some(ref lim) = config.monthly_credits {
        return lim.max;
    }
    if let Some(ref lim) = config.monthly_tokens {
        let nano_usd = (lim.max as u128 * NANO_USD_PER_1_5_USD as u128
            / TOKENS_TO_CREDITS_PER_M as u128)
            .min(u64::MAX as u128) as u64;
        return nano_usd;
    }
    DEFAULT_MONTHLY_CREDITS_NANO_USD
}

fn effective_limits(plan_config: Option<&SubscriptionPlanConfig>) -> EffectivePlanLimits {
    EffectivePlanLimits {
        tokens_max: plan_config
            .and_then(|c| c.monthly_tokens.as_ref())
            .map(|l| l.max)
            .unwrap_or(DEFAULT_MONTHLY_TOKEN_LIMIT),
        credits_max_nano_usd: credits_max_nano_usd(plan_config),
        instances_max: plan_config
            .and_then(|c| c.agent_instances.as_ref())
            .map(|l| l.max)
            .unwrap_or(u64::MAX),
    }
}

fn is_downgrade_by_limits(
    old_price_id: &str,
    new_price_id: &str,
    provider: &str,
    plans: &HashMap<String, SubscriptionPlanConfig>,
) -> bool {
    let old_plan = resolve_plan_name_from_config(provider, old_price_id, plans);
    let new_plan = resolve_plan_name_from_config(provider, new_price_id, plans);
    let old_limits = effective_limits(old_plan.as_deref().and_then(|n| plans.get(n)));
    let new_limits = effective_limits(new_plan.as_deref().and_then(|n| plans.get(n)));
    new_limits.tokens_max < old_limits.tokens_max
        || new_limits.credits_max_nano_usd < old_limits.credits_max_nano_usd
        || new_limits.instances_max < old_limits.instances_max
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

/// Generate idempotency key for credit checkout session creation.
/// Format: SHA-256(user_id:credits:success_url:cancel_url:time_window)
/// Time window: current timestamp / 3600 (1 hour window). Within the same window and with
/// identical inputs, Stripe will reuse the same session; changing URLs or credits yields
/// a different key even within the same window.
fn generate_credit_checkout_idempotency_key(
    user_id: &UserId,
    credits: u64,
    success_url: &str,
    cancel_url: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let time_window = chrono::Utc::now().timestamp() / 3600;

    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "{}:{}:{}:{}:{}",
            user_id.0, credits, success_url, cancel_url, time_window
        )
        .as_bytes(),
    );
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
                let price = plan_config.and_then(|c| c.price);
                let agent_instances = plan_config.and_then(|c| c.agent_instances.clone());
                let monthly_credits = plan_config.and_then(|c| c.monthly_credits.clone());
                let trial_period_days = plan_config.and_then(|c| c.trial_period_days);
                SubscriptionPlan {
                    name,
                    price,
                    trial_period_days,
                    agent_instances,
                    monthly_credits,
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
        test_clock_id: Option<String>,
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

        // Validate instance count: user may have leftover instances from a prior higher-tier plan.
        // Fail before checkout to avoid subscribing to a lower-tier plan they cannot use.
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let plan_config = configs
            .and_then(|c| c.subscription_plans)
            .and_then(|plans| plans.get(&plan).cloned());
        let max_instances = plan_config
            .as_ref()
            .and_then(|c| c.agent_instances.as_ref())
            .map(|l| l.max)
            .unwrap_or(u64::MAX);

        let instance_count =
            self.agent_repo
                .count_user_instances(user_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))? as u64;
        if instance_count > max_instances {
            return Err(SubscriptionError::InstanceLimitExceeded {
                current: instance_count,
                max: max_instances,
            });
        }

        // Fetch trial_period_days from subscription plan config (reuse plan_config from instance check)
        let trial_period_days = plan_config
            .and_then(|p| p.trial_period_days)
            // Stripe supports a maximum trial period of 730 days
            .filter(|&n| n > 0 && n <= 730);

        // Get or create Stripe customer
        let customer_id = self
            .get_or_create_stripe_customer(user_id, test_clock_id)
            .await?;

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
        let updated_model =
            self.stripe_subscription_to_model(&updated_sub, user_id, &subscription.provider)?;
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

        // Cancel is a stronger intent than downgrade — clear any pending downgrade
        self.subscription_repo
            .clear_pending_downgrade(&txn, &subscription.subscription_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        self.invalidate_credit_limit_cache(user_id).await;

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
        let updated_model =
            self.stripe_subscription_to_model(&updated_sub, user_id, &subscription.provider)?;
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

        // Resume is a stronger intent than downgrade — clear any pending downgrade
        self.subscription_repo
            .clear_pending_downgrade(&txn, &subscription.subscription_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        self.invalidate_credit_limit_cache(user_id).await;

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

    async fn change_plan(
        &self,
        user_id: UserId,
        target_plan: String,
    ) -> Result<ChangePlanOutcome, SubscriptionError> {
        tracing::info!(
            "Changing plan for user_id={} to plan={}",
            user_id,
            target_plan
        );

        // Get provider plans (stripe)
        let provider_plans = self.get_plans_for_provider("stripe").await?;
        let price_id = provider_plans
            .get(&target_plan)
            .cloned()
            .ok_or_else(|| SubscriptionError::InvalidPlan(target_plan.clone()))?;

        // Get active subscription first (fail fast before instance count validation)
        let subscription = self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
            .ok_or(SubscriptionError::NoActiveSubscription)?;

        // Same plan requested: cancel pending downgrade if one exists, otherwise no-op
        if subscription.price_id == price_id {
            if subscription.pending_downgrade_status == Some(DowngradeIntentStatus::Pending) {
                let mut client = self
                    .db_pool
                    .get()
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                let txn = client
                    .transaction()
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                self.subscription_repo
                    .clear_pending_downgrade(&txn, &subscription.subscription_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                txn.commit()
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                self.invalidate_credit_limit_cache(user_id).await;
                tracing::info!(
                    "Pending downgrade cancelled: user_id={}, subscription_id={}",
                    user_id,
                    subscription.subscription_id
                );
                return Ok(ChangePlanOutcome::DowngradeCancelled);
            } else {
                return Ok(ChangePlanOutcome::NoOp);
            }
        }

        let plans = self.get_subscription_plans().await?;
        let is_downgrade = is_downgrade_by_limits(
            &subscription.price_id,
            &price_id,
            &subscription.provider,
            &plans,
        );

        if is_downgrade {
            let mut pending_model = subscription.clone();
            Self::mark_downgrade_pending(&mut pending_model, price_id.clone());

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
                .upsert_subscription(&txn, pending_model)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            self.invalidate_credit_limit_cache(user_id).await;

            txn.commit()
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            tracing::info!(
                "Downgrade scheduled for period end: user_id={}, subscription_id={}, target_price_id={}",
                user_id,
                subscription.subscription_id,
                price_id
            );

            return Ok(ChangePlanOutcome::ScheduledForPeriodEnd);
        }

        // Retrieve current Stripe subscription to get subscription item ID
        let client = self.get_stripe_client();
        let subscription_id: stripe::SubscriptionId = subscription
            .subscription_id
            .parse()
            .map_err(|_| SubscriptionError::StripeError("Invalid subscription ID".into()))?;

        // Clear any pending downgrade before applying the upgrade.
        // The user's intent is now to upgrade, so the pending intent is obsolete regardless of
        // whether the Stripe call succeeds.
        if subscription.pending_downgrade_status.is_some() {
            let mut client = self
                .db_pool
                .get()
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            let txn = client
                .transaction()
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            self.subscription_repo
                .clear_pending_downgrade(&txn, &subscription.subscription_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            txn.commit()
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            self.invalidate_credit_limit_cache(user_id).await;
        }

        let stripe_sub = StripeSubscription::retrieve(&client, &subscription_id, &[])
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        let subscription_item_id = stripe_sub
            .items
            .data
            .first()
            .map(|item| item.id.to_string())
            .ok_or_else(|| SubscriptionError::StripeError("No subscription item found".into()))?;

        // Update subscription to new price
        let update_item = UpdateSubscriptionItems {
            id: Some(subscription_item_id),
            price: Some(price_id.clone()),
            ..Default::default()
        };
        let params = stripe::UpdateSubscription {
            items: Some(vec![update_item]),
            proration_behavior: Some(
                stripe::generated::billing::subscription::SubscriptionProrationBehavior::CreateProrations,
            ),
            ..Default::default()
        };

        let updated_sub = StripeSubscription::update(&client, &subscription_id, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        // Update database
        let updated_model =
            self.stripe_subscription_to_model(&updated_sub, user_id, &subscription.provider)?;
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

        self.invalidate_credit_limit_cache(user_id).await;

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Plan changed immediately in Stripe: user_id={}, target_plan={}, subscription_id={}",
            user_id,
            target_plan,
            subscription.subscription_id
        );

        Ok(ChangePlanOutcome::ChangedImmediately)
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
        let mut result: Vec<SubscriptionWithPlan> = Vec::new();
        for sub in subscriptions {
            let plan =
                resolve_plan_name_from_config(&sub.provider, &sub.price_id, &subscription_plans)
                    .ok_or_else(|| {
                        SubscriptionError::InternalError(format!(
                            "Cannot resolve plan for price_id={}, provider={}",
                            sub.price_id, sub.provider
                        ))
                    })?;
            let pending_downgrade_plan =
                sub.pending_downgrade_target_price_id
                    .as_deref()
                    .and_then(|pid| {
                        resolve_plan_name_from_config(&sub.provider, pid, &subscription_plans)
                    });
            result.push(SubscriptionWithPlan {
                subscription_id: sub.subscription_id,
                user_id: sub.user_id.0.to_string(),
                provider: sub.provider,
                plan,
                status: sub.status,
                current_period_end: sub.current_period_end,
                cancel_at_period_end: sub.cancel_at_period_end,
                created_at: sub.created_at,
                updated_at: sub.updated_at,
                pending_downgrade_plan,
                pending_downgrade_status: sub.pending_downgrade_status,
                pending_downgrade_period_end: sub.pending_downgrade_expected_period_end,
            });
        }

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
        let payload_json: serde_json::Value = serde_json::from_slice(payload).map_err(|e| {
            SubscriptionError::WebhookVerificationFailed(format!("Invalid JSON: {}", e))
        })?;

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
        let is_invoice_event = matches!(event_type, "invoice.upcoming" | "invoice.created");

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

        // For checkout.session.completed with mode=payment: process credit purchase.
        // Credits are determined from Stripe line items (quantity) and validated against configured price id.
        let credit_purchase_user_id = if event_type == "checkout.session.completed" {
            let obj = payload_json
                .get("data")
                .and_then(|d| d.get("object"))
                .and_then(|o| o.as_object());
            let mode = obj
                .as_ref()
                .and_then(|o| o.get("mode"))
                .and_then(|m| m.as_str());
            if mode == Some("payment") {
                let payment_status = obj
                    .as_ref()
                    .and_then(|o| o.get("payment_status"))
                    .and_then(|v| v.as_str());
                if payment_status != Some("paid") {
                    tracing::warn!(
                        "Skipping credit purchase: payment_status={:?} (expected 'paid')",
                        payment_status
                    );
                    None
                } else {
                    let metadata = obj
                        .as_ref()
                        .and_then(|o| o.get("metadata"))
                        .and_then(|m| m.as_object());
                    let session_id = obj
                        .as_ref()
                        .and_then(|o| o.get("id"))
                        .and_then(|v| v.as_str());
                    if let (Some(meta), Some(sid)) = (metadata, session_id) {
                        let user_id_str = meta.get("user_id").and_then(|v| v.as_str());
                        if let Some(uid) = user_id_str {
                            let user_uuid = match uuid::Uuid::parse_str(uid) {
                                Ok(uuid) => Some(uuid),
                                Err(_) => {
                                    tracing::warn!(
                                        "Invalid user_id in checkout.session.completed metadata: user_id={:?}",
                                        user_id_str
                                    );
                                    None
                                }
                            };

                            let credit_price_id = self
                                .system_configs_service
                                .get_configs()
                                .await
                                .map_err(|e| SubscriptionError::InternalError(e.to_string()))?
                                .and_then(|c| c.credits)
                                .map(|c| c.credit_price_id);

                            if user_uuid.is_none() {
                                None
                            } else if credit_price_id.is_none() {
                                tracing::warn!(
                                    "Credit purchase event received but credits not configured"
                                );
                                None
                            } else if let (Some(user_uuid), Some(credit_price_id)) =
                                (user_uuid, credit_price_id)
                            {
                                let stripe_client = self.get_stripe_client();
                                let session_id: stripe::CheckoutSessionId =
                                    sid.parse().map_err(|_| {
                                        SubscriptionError::StripeError(
                                            "Invalid checkout session id".into(),
                                        )
                                    })?;

                                let session = CheckoutSession::retrieve(
                                    &stripe_client,
                                    &session_id,
                                    &["line_items"],
                                )
                                .await
                                .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

                                if let Some(line_items) = session.line_items {
                                    if line_items.has_more {
                                        tracing::warn!(
                                            "Checkout session line_items truncated (has_more=true): session_id={}",
                                            sid
                                        );
                                        None
                                    } else {
                                        let mut credits_count: i64 = 0;
                                        let mut bad_price = false;
                                        for item in &line_items.data {
                                            let item_price_id = item
                                                .price
                                                .as_ref()
                                                .map(|p| p.id.to_string())
                                                .unwrap_or_default();
                                            if item_price_id != credit_price_id {
                                                tracing::warn!(
                                                    "Unexpected price id in credit checkout: session_id={}, expected={}, got={}",
                                                    sid,
                                                    credit_price_id,
                                                    item_price_id
                                                );
                                                bad_price = true;
                                                break;
                                            }
                                            let qty = item.quantity.unwrap_or(0);
                                            let qty_i64 = qty.min(i64::MAX as u64) as i64;
                                            credits_count = credits_count.saturating_add(qty_i64);
                                        }

                                        if bad_price {
                                            None
                                        } else if credits_count <= 0 {
                                            tracing::warn!(
                                                "No credits quantity found in checkout session: session_id={}",
                                                sid
                                            );
                                            None
                                        } else if let Some(amount_nano_usd) =
                                            Self::credits_to_nano_usd(credits_count)
                                        {
                                            let user_id = UserId(user_uuid);
                                            let inserted = self
                                                .credits_repo
                                                .try_record_purchase(
                                                    &txn,
                                                    user_id,
                                                    amount_nano_usd,
                                                    sid,
                                                )
                                                .await
                                                .map_err(|e| {
                                                    SubscriptionError::DatabaseError(e.to_string())
                                                })?;
                                            if inserted {
                                                self.credits_repo
                                                    .add_credits(&txn, user_id, amount_nano_usd)
                                                    .await
                                                    .map_err(|e| {
                                                        SubscriptionError::DatabaseError(
                                                            e.to_string(),
                                                        )
                                                    })?;
                                                tracing::info!(
                                                    "Credits added for user_id={}, amount_nano_usd={}, credits_count={}",
                                                    user_id,
                                                    amount_nano_usd,
                                                    credits_count
                                                );
                                                Some(user_id)
                                            } else {
                                                tracing::info!(
                                                    "Credit purchase already processed (duplicate): session_id={}",
                                                    sid
                                                );
                                                None
                                            }
                                        } else {
                                            tracing::error!(
                                                "Overflow converting credits_count={} to nano-USD for session_id={}",
                                                credits_count,
                                                sid
                                            );
                                            None
                                        }
                                    }
                                } else {
                                    tracing::warn!(
                                        "Missing line_items in checkout session: session_id={}",
                                        sid
                                    );
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            tracing::warn!(
                                "Missing user_id in checkout.session.completed payment metadata"
                            );
                            None
                        }
                    } else {
                        tracing::warn!(
                            "Missing metadata or id in checkout.session.completed payment event"
                        );
                        None
                    }
                } // close payment_status == "paid" else block
            } else {
                None
            }
        } else {
            None
        };

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

        // Upsert subscription if we have data
        let mut user_id_to_invalidate: Option<UserId> = None;
        let mut user_id_to_kill_instances: Option<UserId> = None;
        if let Some((subscription_id, subscription)) = subscription_data {
            let user_id = subscription.user_id;

            // Read current status with row lock to detect first-time cancel transition.
            // FOR UPDATE serializes concurrent webhooks for the same subscription.
            let old_status = self
                .subscription_repo
                .get_subscription_status_for_update(&txn, &subscription_id)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            let new_sub = self
                .subscription_repo
                .upsert_subscription(&txn, subscription)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            // Detect first transition to canceled: trigger async instance kill
            if old_status.as_deref() != Some("canceled") && new_sub.status == "canceled" {
                user_id_to_kill_instances = Some(user_id);
                // Subscription is canceled — clear any stale pending downgrade intent
                self.subscription_repo
                    .clear_pending_downgrade(&txn, &subscription_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
            }

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

        if is_invoice_event {
            let invoice_obj = payload_json.get("data").and_then(|d| d.get("object"));
            let subscription_id = invoice_obj
                .and_then(|o| o.get("subscription"))
                .and_then(|s| s.as_str())
                .or_else(|| {
                    // invoice.upcoming stores subscription under parent.subscription_details.subscription
                    invoice_obj
                        .and_then(|o| o.get("parent"))
                        .and_then(|p| p.get("subscription_details"))
                        .and_then(|sd| sd.get("subscription"))
                        .and_then(|s| s.as_str())
                });
            if let Some(subscription_id) = subscription_id {
                if let Some(updated) = self
                    .try_apply_pending_downgrade_in_txn(&txn, subscription_id)
                    .await?
                {
                    user_id_to_invalidate = Some(updated.user_id);
                }
            }
        }

        user_id_to_invalidate = user_id_to_invalidate.or(credit_purchase_user_id);

        // Invalidate cache before commit so no request sees stale cache after DB is updated
        if let Some(user_id) = user_id_to_invalidate {
            self.invalidate_credit_limit_cache(user_id).await;
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Webhook processed successfully: event_id={}, type={}",
            event_id,
            event_type
        );

        // After commit: spawn async stop task for canceled subscriptions.
        // The FOR UPDATE above ensures only the first webhook to detect the transition spawns this.
        if let Some(uid) = user_id_to_kill_instances {
            tracing::info!(
                "Subscription canceled, spawning instance stop task: user_id={}",
                uid
            );
            let agent_svc = self.agent_service.clone();
            tokio::spawn(async move {
                Self::stop_user_instances_with_retry(agent_svc, uid).await;
            });
        }

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

    async fn has_paid_subscription(&self, user_id: UserId) -> Result<bool, SubscriptionError> {
        let sub = self
            .subscription_repo
            .get_active_subscription(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let Some(ref sub) = sub else {
            return Ok(false);
        };
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let subscription_plans = configs
            .and_then(|c| c.subscription_plans)
            .unwrap_or_default();
        // Find the plan whose provider config matches this subscription's provider + price_id
        let plan_config = subscription_plans.iter().find_map(|(_, plan)| {
            plan.providers
                .get(&sub.provider)
                .filter(|p| p.price_id == sub.price_id)
                .map(|_| plan)
        });

        // Use plan-level price to determine paid:
        // - No matching plan        => NOT paid (defensive: do NEAR balance check)
        // - price = None            => legacy config, treated as paid
        // - price = Some(0)         => free plan, NOT paid (do NEAR balance check)
        // - price = Some(>0)        => paid plan
        let is_paid = match plan_config {
            None => false,
            Some(plan) => match plan.price {
                None => true,
                Some(price) => price > 0,
            },
        };
        Ok(is_paid)
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

        // 1. Determine max credits (plan monthly_credits + purchased). Cache 10 mins.
        let cached_limit = {
            let cache_guard = self.credit_limit_cache.read().await;
            if let Some(cached) = cache_guard.get(&user_id) {
                if cached.cached_at.elapsed().as_secs() < TTL_CACHE_SECS {
                    tracing::debug!(
                        "Using cached credit limit for user_id={} (max={}, age_secs={})",
                        user_id,
                        cached.max_credits,
                        cached.cached_at.elapsed().as_secs()
                    );
                    Some((cached.max_credits, cached.period_start, cached.period_end))
                } else {
                    None
                }
            } else {
                None
            }
        };

        let (max_credits, period_start, period_end) = match cached_limit {
            Some((max, start, end)) => (max, start, end),
            None => {
                let configs = self
                    .system_configs_service
                    .get_configs()
                    .await
                    .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
                let subscription_plans = configs
                    .and_then(|c| c.subscription_plans)
                    .unwrap_or_default();

                // Use monthly_credits when set (nano USD); else monthly_tokens → nano USD at 1.5 USD per M tokens. Never fail for missing config.
                let (plan_credits, period_start, period_end) = match self
                    .subscription_repo
                    .get_active_subscription(user_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?
                {
                    Some(ref sub) => {
                        let effective_sub = if Self::should_check_pending_downgrade(sub) {
                            match self.try_apply_pending_downgrade(&sub.subscription_id).await {
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
                        let plan_credits = plan_name
                            .as_deref()
                            .and_then(|n| subscription_plans.get(n))
                            .map(Self::plan_limit_max)
                            .unwrap_or_else(|| {
                                tracing::warn!(
                                    "Falling back to default monthly credits for unmatched plan '{:?}'; using {} nano-USD",
                                    plan_name,
                                    DEFAULT_MONTHLY_CREDITS_NANO_USD
                                );
                                DEFAULT_MONTHLY_CREDITS_NANO_USD
                            });
                        let period_end = effective_sub.current_period_end;
                        let period_start = sub_one_month_same_day(effective_sub.current_period_end);
                        (plan_credits, period_start, period_end)
                    }
                    None => {
                        let plan_credits = subscription_plans
                            .get("free")
                            .map(Self::plan_limit_max)
                            .unwrap_or_else(|| {
                                tracing::warn!(
                                    "Falling back to default monthly credits for missing 'free' plan; using {} nano-USD",
                                    DEFAULT_MONTHLY_CREDITS_NANO_USD
                                );
                                DEFAULT_MONTHLY_CREDITS_NANO_USD
                            });
                        // Free users: calendar month — 00:00 on 1st through 24:00 on last day
                        let (period_start, period_end) = current_calendar_month_period(Utc::now());
                        (plan_credits, period_start, period_end)
                    }
                };

                let purchased = self
                    .credits_repo
                    .get_balance(user_id)
                    .await
                    .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
                let max_credits = plan_credits.saturating_add(purchased.max(0) as u64);

                {
                    let mut cache_guard = self.credit_limit_cache.write().await;
                    cache_guard.insert(
                        user_id,
                        CachedCreditLimit {
                            max_credits,
                            period_start,
                            period_end,
                            cached_at: Instant::now(),
                        },
                    );
                }
                (max_credits, period_start, period_end)
            }
        };

        // 2. Get used credits (cost_nano_usd) in the period
        let used_credits = self
            .user_usage_repo
            .get_usage_by_user_id(user_id, Some(period_start), Some(period_end))
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?
            .map(|s| s.cost_nano_usd)
            .unwrap_or(0);

        // 3. Enforce limit (compare without casting max_credits to i64 to avoid wrap-around DoS when max_credits > i64::MAX)
        if used_credits >= 0 && (used_credits as u64) >= max_credits {
            tracing::info!(
                "Blocking proxy access for user_id={}: monthly credit limit exceeded (used {} of {})",
                user_id, used_credits, max_credits
            );
            return Err(SubscriptionError::MonthlyCreditLimitExceeded {
                used: used_credits,
                limit: max_credits,
            });
        }

        tracing::debug!(
            "User user_id={} within credit limit (used {} of {}), allowing proxy access",
            user_id,
            used_credits,
            max_credits
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
            pending_downgrade_target_price_id: None,
            pending_downgrade_from_price_id: None,
            pending_downgrade_expected_period_end: None,
            pending_downgrade_status: None,
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
        self.invalidate_credit_limit_cache(user_id).await;

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
            pending_downgrade_plan: None,
            pending_downgrade_status: None,
            pending_downgrade_period_end: None,
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

        self.invalidate_credit_limit_cache(user_id).await;

        Ok(())
    }

    async fn create_credit_purchase_checkout(
        &self,
        user_id: UserId,
        credits: u64,
        success_url: String,
        cancel_url: String,
    ) -> Result<String, SubscriptionError> {
        const MAX_CREDITS_PER_PURCHASE: u64 = 1_000_000_000;

        // When Stripe is not configured, credit purchase is not available.
        if !self.is_stripe_configured() {
            tracing::debug!(
                "Credit purchase skipped: Stripe not configured (secret_key_empty={}, webhook_secret_empty={})",
                self.stripe_secret_key.is_empty(),
                self.stripe_webhook_secret.is_empty(),
            );
            return Err(SubscriptionError::CreditsNotConfigured);
        }
        if credits == 0 {
            return Err(SubscriptionError::InvalidCredits(
                "credits must be positive".to_string(),
            ));
        }
        if credits > MAX_CREDITS_PER_PURCHASE {
            return Err(SubscriptionError::InvalidCredits(format!(
                "credits exceeds maximum of {} per purchase",
                MAX_CREDITS_PER_PURCHASE
            )));
        }

        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?;
        let credit_price_id = configs
            .and_then(|c| c.credits)
            .map(|c| c.credit_price_id)
            .ok_or(SubscriptionError::CreditsNotConfigured)?;

        let customer_id = self.get_or_create_stripe_customer(user_id, None).await?;

        let base_client = self.get_stripe_client();
        let idempotency_key =
            generate_credit_checkout_idempotency_key(&user_id, credits, &success_url, &cancel_url);
        let client = base_client
            .clone()
            .with_strategy(RequestStrategy::Idempotent(idempotency_key));

        let mut params = CreateCheckoutSession::new();
        params.mode = Some(CheckoutSessionMode::Payment);
        params.customer = Some(
            customer_id
                .parse()
                .map_err(|_| SubscriptionError::StripeError("Invalid customer ID".to_string()))?,
        );
        params.success_url = Some(&success_url);
        params.cancel_url = Some(&cancel_url);
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(credit_price_id),
            quantity: Some(credits),
            ..Default::default()
        }]);
        let mut metadata = HashMap::new();
        metadata.insert("user_id".to_string(), user_id.to_string());
        metadata.insert("credits".to_string(), credits.to_string());
        params.metadata = Some(metadata);

        let session = CheckoutSession::create(&client, params)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;

        let checkout_url = session
            .url
            .ok_or_else(|| SubscriptionError::StripeError("No checkout URL returned".into()))?;

        tracing::info!(
            "Credit checkout session created: user_id={}, credits={}",
            user_id,
            credits
        );

        Ok(checkout_url)
    }

    async fn reconcile_purchased_after_usage(
        &self,
        user_id: UserId,
    ) -> Result<(), SubscriptionError> {
        let (plan_credits, period_start, period_end) =
            self.resolve_plan_period_for_user(user_id).await?;
        self.credits_repo
            .reconcile_purchased_after_usage(user_id, plan_credits, period_start, period_end)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        self.invalidate_credit_limit_cache(user_id).await;
        Ok(())
    }

    async fn get_credits(&self, user_id: UserId) -> Result<CreditsSummary, SubscriptionError> {
        // Refresh remaining balance from period usage vs plan before returning summary
        if let Err(e) = self.reconcile_purchased_after_usage(user_id).await {
            tracing::warn!(error = ?e, "Failed to reconcile purchased credits before get_credits");
        }

        let (plan_credits, period_start, period_end) =
            self.resolve_plan_period_for_user(user_id).await?;

        let (balance, total_purchased_nano_usd, used_purchased_nano_usd) = self
            .credits_repo
            .get_purchased_breakdown(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        let used_credits = self
            .user_usage_repo
            .get_usage_by_user_id(user_id, Some(period_start), Some(period_end))
            .await
            .map_err(|e| SubscriptionError::InternalError(e.to_string()))?
            .map(|s| s.cost_nano_usd)
            .unwrap_or(0);

        let effective_max_credits = plan_credits.saturating_add(balance);

        Ok(CreditsSummary {
            balance,
            total_purchased_nano_usd,
            used_purchased_nano_usd,
            used_credits,
            effective_max_credits,
        })
    }

    async fn admin_grant_credits(
        &self,
        user_id: UserId,
        amount_nano_usd: i64,
        reason: Option<String>,
    ) -> Result<i64, SubscriptionError> {
        if amount_nano_usd <= 0 {
            return Err(SubscriptionError::InvalidCredits(
                "grant amount must be positive".to_string(),
            ));
        }

        let mut client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        self.credits_repo
            .record_grant(&txn, user_id, amount_nano_usd, reason)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        let new_balance = self
            .credits_repo
            .add_credits(&txn, user_id, amount_nano_usd)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        txn.commit()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Invalidate cache so future checks see updated purchased balance
        self.invalidate_credit_limit_cache(user_id).await;

        Ok(new_balance)
    }

    async fn admin_get_credit_history(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<super::ports::CreditTransaction>, i64), SubscriptionError> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);

        self.credits_repo
            .list_transactions(user_id, limit, offset)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_configs::ports::{PaymentProviderConfig, SubscriptionPlanConfig};
    use crate::UserId;
    use std::collections::HashMap;

    fn plan_config(price_id: &str, tokens: u64, instances: u64) -> SubscriptionPlanConfig {
        SubscriptionPlanConfig {
            providers: HashMap::from([(
                "stripe".to_string(),
                PaymentProviderConfig {
                    price_id: price_id.to_string(),
                },
            )]),
            price: None,
            trial_period_days: None,
            agent_instances: Some(crate::system_configs::ports::PlanLimitConfig { max: instances }),
            monthly_tokens: Some(crate::system_configs::ports::PlanLimitConfig { max: tokens }),
            monthly_credits: None,
        }
    }

    fn base_subscription() -> Subscription {
        let period_end = Utc::now() + Duration::days(7);
        Subscription {
            subscription_id: "sub_test".to_string(),
            user_id: UserId::new(),
            provider: "stripe".to_string(),
            customer_id: "cus_test".to_string(),
            price_id: "price_basic".to_string(),
            status: "active".to_string(),
            current_period_end: period_end,
            cancel_at_period_end: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            pending_downgrade_target_price_id: None,
            pending_downgrade_from_price_id: None,
            pending_downgrade_expected_period_end: None,
            pending_downgrade_status: None,
        }
    }

    #[test]
    fn test_effective_limits_defaults() {
        let limits = effective_limits(None);
        assert_eq!(limits.tokens_max, DEFAULT_MONTHLY_TOKEN_LIMIT);
        assert_eq!(
            limits.credits_max_nano_usd,
            DEFAULT_MONTHLY_CREDITS_NANO_USD
        );
        assert_eq!(limits.instances_max, u64::MAX);
    }

    #[test]
    fn test_is_downgrade_by_limits_tokens() {
        let mut plans = HashMap::new();
        plans.insert(
            "basic".to_string(),
            plan_config("price_basic", 1_000_000, 5),
        );
        plans.insert(
            "starter".to_string(),
            plan_config("price_starter", 100_000, 5),
        );

        assert!(
            is_downgrade_by_limits("price_basic", "price_starter", "stripe", &plans),
            "Lower token limit should be a downgrade"
        );
    }

    #[test]
    fn test_is_downgrade_by_limits_instances() {
        let mut plans = HashMap::new();
        plans.insert(
            "basic".to_string(),
            plan_config("price_basic", 1_000_000, 5),
        );
        plans.insert(
            "starter".to_string(),
            plan_config("price_starter", 1_000_000, 1),
        );

        assert!(
            is_downgrade_by_limits("price_basic", "price_starter", "stripe", &plans),
            "Lower instance limit should be a downgrade"
        );
    }

    #[test]
    fn test_is_downgrade_by_limits_not_downgrade() {
        let mut plans = HashMap::new();
        plans.insert(
            "basic".to_string(),
            plan_config("price_basic", 1_000_000, 1),
        );
        plans.insert("pro".to_string(), plan_config("price_pro", 5_000_000, 10));

        assert!(
            !is_downgrade_by_limits("price_basic", "price_pro", "stripe", &plans),
            "Higher limits should not be a downgrade"
        );
    }

    #[test]
    fn test_should_check_pending_downgrade_window() {
        let mut sub = base_subscription();
        sub.pending_downgrade_status = Some(DowngradeIntentStatus::Pending);
        sub.pending_downgrade_expected_period_end = Some(Utc::now() + Duration::hours(12));

        assert!(
            SubscriptionServiceImpl::should_check_pending_downgrade(&sub),
            "Within 24h window should be eligible"
        );

        sub.pending_downgrade_expected_period_end = Some(Utc::now() + Duration::hours(36));
        assert!(
            !SubscriptionServiceImpl::should_check_pending_downgrade(&sub),
            "Outside 24h window should not be eligible"
        );

        sub.pending_downgrade_status = Some(DowngradeIntentStatus::Applied);
        sub.pending_downgrade_expected_period_end = Some(Utc::now() + Duration::hours(12));
        assert!(
            !SubscriptionServiceImpl::should_check_pending_downgrade(&sub),
            "Non-pending status should not be eligible"
        );

        sub.pending_downgrade_status = Some(DowngradeIntentStatus::Pending);
        sub.pending_downgrade_expected_period_end = None;
        assert!(
            !SubscriptionServiceImpl::should_check_pending_downgrade(&sub),
            "Missing expected_period_end should not be eligible"
        );
    }

    #[test]
    fn test_mark_downgrade_pending_and_terminal() {
        let mut sub = base_subscription();
        let original_end = sub.current_period_end;
        let target_price = "price_starter".to_string();

        SubscriptionServiceImpl::mark_downgrade_pending(&mut sub, target_price.clone());
        assert_eq!(
            sub.pending_downgrade_target_price_id.as_deref(),
            Some(target_price.as_str())
        );
        assert_eq!(
            sub.pending_downgrade_from_price_id.as_deref(),
            Some("price_basic")
        );
        assert_eq!(
            sub.pending_downgrade_expected_period_end,
            Some(original_end)
        );
        assert_eq!(
            sub.pending_downgrade_status,
            Some(DowngradeIntentStatus::Pending)
        );

        SubscriptionServiceImpl::mark_downgrade_terminal(&mut sub, DowngradeIntentStatus::Applied);
        assert!(sub.pending_downgrade_target_price_id.is_none());
        assert!(sub.pending_downgrade_from_price_id.is_none());
        assert!(sub.pending_downgrade_expected_period_end.is_none());
        assert_eq!(
            sub.pending_downgrade_status,
            Some(DowngradeIntentStatus::Applied)
        );
    }

    #[test]
    fn test_resolve_plan_name_from_config() {
        let mut plans = HashMap::new();
        plans.insert(
            "basic".to_string(),
            plan_config("price_basic", 1_000_000, 5),
        );
        plans.insert("pro".to_string(), plan_config("price_pro", 5_000_000, 10));

        assert_eq!(
            resolve_plan_name_from_config("stripe", "price_pro", &plans),
            Some("pro".to_string())
        );
        assert_eq!(
            resolve_plan_name_from_config("stripe", "price_unknown", &plans),
            None
        );
    }
}
