use async_trait::async_trait;
use chrono::Utc;
use services::subscription::ports::{
    StripeCheckoutLineItemRef, StripeCheckoutSessionResult, StripeClientPort, StripeCustomerRef,
    StripePortalSessionResult, StripeSubscriptionSnapshot, SubscriptionError,
};
use stripe_client::client::{
    CreateCreditsCheckoutParams, CreateCustomerParams, CreateSubscriptionCheckoutParams,
    UpdateSubscriptionParams,
};
use stripe_client::{StripeClient, StripeWebhookVerifier};

pub struct StripeClientAdapter {
    client: StripeClient,
    webhook_verifier: StripeWebhookVerifier,
}

impl StripeClientAdapter {
    pub fn new(secret_key: String) -> Self {
        Self {
            client: StripeClient::new(secret_key),
            webhook_verifier: StripeWebhookVerifier::default(),
        }
    }
}

#[async_trait]
impl StripeClientPort for StripeClientAdapter {
    async fn verify_webhook_signature(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<(), SubscriptionError> {
        self.webhook_verifier
            .verify(payload, signature, secret, Utc::now())
            .map(|_| ())
            .map_err(|e| SubscriptionError::WebhookVerificationFailed(e.to_string()))
    }

    async fn create_customer(
        &self,
        email: Option<&str>,
        name: Option<&str>,
        user_id: &str,
        test_clock_id: Option<&str>,
    ) -> Result<String, SubscriptionError> {
        self.client
            .create_customer(CreateCustomerParams {
                email,
                name,
                user_id,
                test_clock_id,
            })
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))
    }

    async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, SubscriptionError> {
        let customer = self
            .client
            .retrieve_customer(customer_id)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(StripeCustomerRef {
            id: customer.id,
            metadata: customer.metadata,
        })
    }

    async fn create_subscription_checkout_session(
        &self,
        params: services::subscription::ports::StripeCreateSubscriptionCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        let session = self
            .client
            .create_subscription_checkout_session(CreateSubscriptionCheckoutParams {
                customer_id: &params.customer_id,
                price_id: &params.price_id,
                success_url: &params.success_url,
                cancel_url: &params.cancel_url,
                trial_period_days: params.trial_period_days,
                idempotency_key: &params.idempotency_key,
            })
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(map_checkout_session(session))
    }

    async fn create_credits_checkout_session(
        &self,
        params: services::subscription::ports::StripeCreateCreditsCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        let session = self
            .client
            .create_credits_checkout_session(CreateCreditsCheckoutParams {
                customer_id: &params.customer_id,
                price_id: &params.price_id,
                credits: params.credits,
                success_url: &params.success_url,
                cancel_url: &params.cancel_url,
                user_id: &params.user_id,
                idempotency_key: &params.idempotency_key,
            })
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(map_checkout_session(session))
    }

    async fn retrieve_checkout_session(
        &self,
        checkout_session_id: &str,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        let session = self
            .client
            .retrieve_checkout_session(checkout_session_id)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(map_checkout_session(session))
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        let snapshot = self
            .client
            .retrieve_subscription(subscription_id)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(StripeSubscriptionSnapshot {
            id: snapshot.id,
            customer_id: snapshot.customer_id,
            price_id: snapshot.price_id,
            status: snapshot.status,
            current_period_end: snapshot.current_period_end,
            cancel_at_period_end: snapshot.cancel_at_period_end,
            first_item_id: snapshot.first_item_id,
        })
    }

    async fn update_subscription(
        &self,
        subscription_id: &str,
        params: services::subscription::ports::StripeUpdateSubscriptionParams,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        let snapshot = self
            .client
            .update_subscription(
                subscription_id,
                UpdateSubscriptionParams {
                    cancel_at_period_end: params.cancel_at_period_end,
                    item_id: params.item_id.as_deref(),
                    price_id: params.price_id.as_deref(),
                    proration_behavior: params.proration_behavior.map(|p| p.as_str()),
                    payment_behavior: params.payment_behavior.map(|p| p.as_str()),
                    billing_cycle_anchor: params.billing_cycle_anchor.map(|b| b.as_str()),
                },
            )
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(StripeSubscriptionSnapshot {
            id: snapshot.id,
            customer_id: snapshot.customer_id,
            price_id: snapshot.price_id,
            status: snapshot.status,
            current_period_end: snapshot.current_period_end,
            cancel_at_period_end: snapshot.cancel_at_period_end,
            first_item_id: snapshot.first_item_id,
        })
    }

    async fn create_billing_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<StripePortalSessionResult, SubscriptionError> {
        let session = self
            .client
            .create_billing_portal_session(customer_id, return_url)
            .await
            .map_err(|e| SubscriptionError::StripeError(e.to_string()))?;
        Ok(StripePortalSessionResult {
            id: session.id,
            url: session.url,
        })
    }
}

fn map_checkout_session(
    session: stripe_client::StripeCheckoutSession,
) -> StripeCheckoutSessionResult {
    StripeCheckoutSessionResult {
        id: session.id,
        url: session.url,
        line_items_has_more: session
            .line_items
            .as_ref()
            .map(|l| l.has_more)
            .unwrap_or(false),
        line_items: session.line_items.map(|items| {
            items
                .data
                .into_iter()
                .map(|item| StripeCheckoutLineItemRef {
                    price_id: item.price_id,
                    quantity: item.quantity,
                })
                .collect()
        }),
    }
}
