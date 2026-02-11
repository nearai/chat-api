use super::ports::{
    PaymentWebhookRepository, StripeCustomerRepository, Subscription, SubscriptionError,
    SubscriptionRepository, SubscriptionService, SubscriptionWithPlan,
};
use crate::system_configs::ports::SystemConfigsService;
use crate::UserId;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use stripe::{
    CheckoutSession, CheckoutSessionMode, Client, CreateCheckoutSession,
    CreateCheckoutSessionLineItems, Customer, Subscription as StripeSubscription, Webhook,
    WebhookError,
};

pub struct SubscriptionServiceImpl {
    db_pool: deadpool_postgres::Pool,
    stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
    subscription_repo: Arc<dyn SubscriptionRepository>,
    webhook_repo: Arc<dyn PaymentWebhookRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
    stripe_secret_key: String,
    stripe_webhook_secret: String,
    checkout_success_url: String,
    checkout_cancel_url: String,
}

impl SubscriptionServiceImpl {
    pub fn new(
        db_pool: deadpool_postgres::Pool,
        stripe_customer_repo: Arc<dyn StripeCustomerRepository>,
        subscription_repo: Arc<dyn SubscriptionRepository>,
        webhook_repo: Arc<dyn PaymentWebhookRepository>,
        system_configs_service: Arc<dyn SystemConfigsService>,
        stripe_secret_key: String,
        stripe_webhook_secret: String,
        checkout_success_url: String,
        checkout_cancel_url: String,
    ) -> Self {
        Self {
            db_pool,
            stripe_customer_repo,
            subscription_repo,
            webhook_repo,
            system_configs_service,
            stripe_secret_key,
            stripe_webhook_secret,
            checkout_success_url,
            checkout_cancel_url,
        }
    }

    /// Get stripe plans configuration from system configs (lazy loading)
    async fn get_stripe_plans(&self) -> Result<HashMap<String, String>, SubscriptionError> {
        tracing::debug!("Getting stripe plans from system configs");
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get system configs");
                SubscriptionError::InternalError(e.to_string())
            })?;

        tracing::debug!("System configs retrieved: has_config={}", configs.is_some());

        // If configs is None or stripe_plans is None, Stripe is not configured
        let plans = match configs {
            None => {
                tracing::debug!("No system configs found, Stripe not configured");
                return Err(SubscriptionError::NotConfigured);
            }
            Some(c) => {
                tracing::debug!(
                    "System configs found, checking stripe_plans: has_plans={}",
                    c.stripe_plans.is_some()
                );
                c.stripe_plans.ok_or(SubscriptionError::NotConfigured)?
            }
        };

        if plans.is_empty() {
            tracing::debug!("Stripe plans is empty, Stripe not configured");
            return Err(SubscriptionError::NotConfigured);
        }

        tracing::debug!("Stripe plans found with {} entries", plans.len());
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

    /// Convert Stripe subscription to our Subscription model
    fn stripe_subscription_to_model(
        &self,
        stripe_sub: &StripeSubscription,
        user_id: UserId,
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

    /// Resolve plan name from price_id
    fn resolve_plan_name(&self, price_id: &str, plans: &HashMap<String, String>) -> String {
        plans
            .iter()
            .find(|(_, v)| v.as_str() == price_id)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

#[async_trait]
impl SubscriptionService for SubscriptionServiceImpl {
    async fn create_subscription(
        &self,
        user_id: UserId,
        plan: String,
    ) -> Result<String, SubscriptionError> {
        tracing::info!(
            "Creating subscription checkout for user_id={}, plan={}",
            user_id,
            plan
        );

        // Get stripe plans from system configs
        let stripe_plans = self.get_stripe_plans().await?;

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
        let price_id = stripe_plans
            .get(&plan)
            .ok_or_else(|| SubscriptionError::InvalidPlan(plan.clone()))?;

        // Get or create Stripe customer
        let customer_id = self.get_or_create_stripe_customer(user_id).await?;

        // Create Stripe checkout session
        let client = self.get_stripe_client();

        let mut params = CreateCheckoutSession::new();
        params.mode = Some(CheckoutSessionMode::Subscription);
        params.customer = Some(
            customer_id
                .parse()
                .map_err(|_| SubscriptionError::StripeError("Invalid customer ID".to_string()))?,
        );
        params.success_url = Some(&self.checkout_success_url);
        params.cancel_url = Some(&self.checkout_cancel_url);
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
            "Checkout session created: user_id={}, session_id={}",
            user_id,
            session.id
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
        let updated_model = self.stripe_subscription_to_model(&updated_sub, user_id)?;
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
    ) -> Result<Vec<SubscriptionWithPlan>, SubscriptionError> {
        tracing::debug!("Fetching subscriptions for user_id={}", user_id);

        // Get stripe plans from system configs
        let stripe_plans = self.get_stripe_plans().await?;

        // Get subscriptions from database
        let subscriptions = self
            .subscription_repo
            .get_user_subscriptions(user_id)
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Map to API response model with plan names resolved
        let result: Vec<SubscriptionWithPlan> = subscriptions
            .into_iter()
            .map(|sub| {
                let plan = self.resolve_plan_name(&sub.price_id, &stripe_plans);
                SubscriptionWithPlan {
                    subscription_id: sub.subscription_id,
                    user_id: sub.user_id.0.to_string(),
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

        // Parse JSON to get event metadata
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

        // Check if this is a subscription event
        let is_subscription_event = event_type.starts_with("customer.subscription.");

        // Verify webhook signature (CRITICAL - use library, never hand-write)
        // Note: construct_event does BOTH signature verification AND event parsing
        // We only care about signature verification, not parsing success
        if let Err(e) =
            Webhook::construct_event(payload_str, signature, &self.stripe_webhook_secret)
        {
            match e {
                // Security-critical errors - reject the webhook
                WebhookError::BadKey
                | WebhookError::BadSignature
                | WebhookError::BadTimestamp(_)
                | WebhookError::BadHeader(_) => {
                    tracing::error!(
                        "Webhook signature verification failed: event_id={}, error={}",
                        event_id,
                        e
                    );
                    return Err(SubscriptionError::WebhookVerificationFailed(e.to_string()));
                }
                // Parsing error - signature is OK, we can continue
                WebhookError::BadParse(_) => {
                    tracing::debug!(
                        "Webhook event parsing failed (signature OK): event_id={}, type={}, error={}",
                        event_id,
                        event_type,
                        e
                    );
                }
            }
        } else {
            tracing::debug!(
                "Webhook signature verified and parsed: event_id={}, type={}",
                event_id,
                event_type
            );
        }

        // For subscription events, fetch data from Stripe API BEFORE starting transaction
        // This avoids holding DB connection during network calls
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

            // Fetch latest subscription state from Stripe API (BEFORE transaction)
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

            // Convert to our model (before transaction)
            let subscription = self.stripe_subscription_to_model(&stripe_sub, user_id)?;
            Some((subscription_id.to_string(), subscription))
        } else {
            None
        };

        // Now start transaction for all database operations (atomic)
        let mut client = self
            .db_pool
            .get()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;
        let txn = client
            .transaction()
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

        // Store webhook
        self.webhook_repo
            .store_webhook(
                &txn,
                "stripe".to_string(),
                event_id.to_string(),
                payload_json.clone(),
            )
            .await
            .map_err(|e| SubscriptionError::DatabaseError(e.to_string()))?;

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
}
