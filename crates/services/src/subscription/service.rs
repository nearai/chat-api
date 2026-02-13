use super::ports::{
    PaymentWebhookRepository, StripeCustomerRepository, Subscription, SubscriptionError,
    SubscriptionPlan, SubscriptionRepository, SubscriptionService, SubscriptionWithPlan,
};
use crate::system_configs::ports::{SubscriptionPlanConfig, SystemConfigsService};
use crate::UserId;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use stripe::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, Customer, CustomerId, RequestStrategy,
    Subscription as StripeSubscription, Webhook, WebhookError,
};

/// Configuration for SubscriptionServiceImpl
pub struct SubscriptionServiceConfig {
    pub db_pool: deadpool_postgres::Pool,
    pub stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    pub subscription_repo: Arc<dyn SubscriptionRepository>,
    pub webhook_repo: Arc<dyn PaymentWebhookRepository>,
    pub system_configs_service: Arc<dyn SystemConfigsService>,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
}

pub struct SubscriptionServiceImpl {
    db_pool: deadpool_postgres::Pool,
    stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    subscription_repo: Arc<dyn SubscriptionRepository>,
    webhook_repo: Arc<dyn PaymentWebhookRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
    stripe_secret_key: String,
    stripe_webhook_secret: String,
}

impl SubscriptionServiceImpl {
    pub fn new(config: SubscriptionServiceConfig) -> Self {
        Self {
            db_pool: config.db_pool,
            stripe_customer_repo: config.stripe_customer_repo,
            subscription_repo: config.subscription_repo,
            webhook_repo: config.webhook_repo,
            system_configs_service: config.system_configs_service,
            stripe_secret_key: config.stripe_secret_key,
            stripe_webhook_secret: config.stripe_webhook_secret,
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

        // Create new Stripe customer
        tracing::info!("Creating new Stripe customer for user_id={}", user_id);
        let client = self.get_stripe_client();

        let customer = Customer::create(
            &client,
            stripe::CreateCustomer {
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
        })
    }
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
            .into_iter()
            .map(|(name, _price_id)| {
                let max_deployments = subscription_plans
                    .get(&name)
                    .and_then(|c| c.deployments.as_ref())
                    .map(|d| d.max);
                let max_monthly_tokens = subscription_plans
                    .get(&name)
                    .and_then(|c| c.monthly_tokens.as_ref())
                    .map(|m| m.max);
                SubscriptionPlan {
                    name,
                    max_deployments,
                    max_monthly_tokens,
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
                }
            })
            .collect();

        Ok(result)
    }

    async fn handle_webhook(
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

        // Upsert subscription if we have data
        if let Some((subscription_id, subscription)) = subscription_data {
            let user_id = subscription.user_id;
            self.subscription_repo
                .upsert_subscription(&txn, subscription)
                .await
                .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

            tracing::info!(
                "Subscription synced to database: subscription_id={}, user_id={}",
                subscription_id,
                user_id
            );
        } else {
            tracing::debug!(
                "Non-subscription webhook stored: event_id={}, type={}",
                event_id,
                event_type
            );
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
}
