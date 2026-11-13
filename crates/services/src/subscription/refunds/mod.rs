mod store;
pub mod types;
use crate::{db_pool::DbPool, subscription::ports::StripeClientPort};
use std::time::Duration;
use store::Store;
use stripe_client::refunds::{RefundEvidence, StripeRefund};
pub use types::*;
use uuid::Uuid;

pub struct Refunds<'a> {
    pub pool: &'a DbPool,
    pub stripe: &'a dyn StripeClientPort,
    pub enabled: bool,
}
impl Refunds<'_> {
    pub async fn list(&self, sub: Option<&str>, limit: i64, offset: i64) -> Result<RefundList> {
        if !(1..=100).contains(&limit) || offset < 0 {
            return Err(RefundError::Invalid("Invalid pagination"));
        }
        Store(self.pool)
            .list(sub, limit, offset, self.enabled)
            .await
    }
    pub async fn prepare(
        &self,
        r: PrepareRefund,
        customer: &str,
        actor: Uuid,
    ) -> Result<RefundOperation> {
        r.validate()?;
        let store = Store(self.pool);
        if let Some(op) = store.by_invoice(&r.invoice_id, &r.subscription_id).await? {
            return if op.matches(&r) {
                Ok(op)
            } else {
                Err(RefundError::Conflict(
                    "A different approved refund already exists for this invoice",
                ))
            };
        }
        let e = tokio::time::timeout(
            Duration::from_secs(90),
            self.stripe
                .refund_evidence(&r.invoice_id, &r.subscription_id, customer),
        )
        .await
        .map_err(|_| RefundError::Upstream)?
        .map_err(|_| RefundError::Upstream)?;
        if e.invoice_id != r.invoice_id
            || e.customer_id != customer
            || e.currency != r.currency
            || r.amount > e.amount_paid
        {
            return Err(RefundError::Invalid(
                "Approved amount or payment does not match the invoice",
            ));
        }
        if e.amount_refunded != 0 || !e.refunds.is_empty() {
            return Err(RefundError::Conflict(
                "This payment has refund history; reconcile it before preparing another refund",
            ));
        }
        store.create(&r, &e, actor).await
    }
    pub async fn run(
        &self,
        id: Uuid,
        action: Action,
        confirmation: Option<RefundConfirmation>,
        actor: Option<Uuid>,
    ) -> Result<RefundOperation> {
        if action != Action::Sync && !self.enabled {
            return Err(RefundError::Disabled);
        }
        if action != Action::Sync
            && (!confirmation.as_ref().is_some_and(|c| c.confirmed) || actor.is_none())
        {
            return Err(RefundError::Invalid("Explicit confirmation is required"));
        }
        let store = Store(self.pool);
        let token = Uuid::new_v4();
        store.claim(id, token).await?;
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            self.process(id, token, action, confirmation, actor),
        )
        .await;
        let result = match result {
            Ok(r) => r,
            Err(_) => {
                // A timed-out POST might have reached Stripe. Its committed attempt/key remain immutable.
                if let Ok(op) = store.get(id).await {
                    if let Ok(a) = op.current() {
                        let _ = store
                            .error(
                                id,
                                token,
                                a.id,
                                "action_timed_out",
                                a.status == "submitting",
                            )
                            .await;
                    }
                }
                Err(RefundError::Upstream)
            }
        };
        let released = store.release(id, token).await;
        released?;
        result
    }
    async fn process(
        &self,
        id: Uuid,
        token: Uuid,
        action: Action,
        confirmation: Option<RefundConfirmation>,
        actor: Option<Uuid>,
    ) -> Result<RefundOperation> {
        let store = Store(self.pool);
        let op = store.get(id).await?;
        if confirmation.as_ref().is_some_and(|c| {
            c.expected_attempt_id != op.current().map(|a| a.id).unwrap_or_default()
        }) {
            return Err(RefundError::Conflict(
                "The refund attempt changed; refresh and confirm the current attempt",
            ));
        }
        let evidence = match self
            .stripe
            .refund_evidence(&op.invoice_id, &op.subscription_id, &op.customer_id)
            .await
        {
            Ok(e) => e,
            Err(_) => {
                store
                    .error(id, token, op.current()?.id, "stripe_read_failed", false)
                    .await?;
                return Err(RefundError::Upstream);
            }
        };
        let matches = match reconcile(&op, &evidence) {
            Ok(matches) => matches,
            Err(reason) => {
                store.review(id, token, Some(reason)).await?;
                return store.get(id).await;
            }
        };
        for (attempt, refund) in matches {
            store.save(id, token, attempt, refund).await?;
        }
        store.review(id, token, None).await?;
        let mut op = store.get(id).await?;
        if action == Action::Sync {
            return Ok(op);
        }
        let current = op.current()?;
        if matches!(
            current.status.as_str(),
            "succeeded" | "pending" | "requires_action"
        ) {
            return Ok(op);
        }
        if action == Action::RetryFailed {
            if !matches!(current.status.as_str(), "failed" | "canceled")
                || current.stripe_refund_id.is_none()
            {
                return Err(RefundError::Conflict(
                    "Only a Stripe-confirmed failed or canceled refund can start a new attempt",
                ));
            }
            if evidence.amount_refunded != 0 {
                store
                    .review(id, token, Some("refunded_balance_requires_review"))
                    .await?;
                return store.get(id).await;
            }
            store
                .new_attempt(
                    &op,
                    token,
                    actor.ok_or(RefundError::Invalid("Admin required"))?,
                )
                .await?;
            op = store.get(id).await?;
        } else if matches!(current.status.as_str(), "failed" | "canceled") {
            return Err(RefundError::Conflict(
                "Confirm a new attempt to retry a failed or canceled refund",
            ));
        }
        let attempt = op.current()?;
        if !store.may_resubmit(attempt.id).await? {
            store
                .review(id, token, Some("idempotency_window_expired"))
                .await?;
            return store.get(id).await;
        }
        if evidence.amount_refunded != 0 {
            store
                .review(id, token, Some("refunded_balance_requires_review"))
                .await?;
            return store.get(id).await;
        }
        // Commit before the network call, so a crash never loses the original idempotency key/window.
        store
            .mark_submitting(
                id,
                token,
                attempt.id,
                actor.ok_or(RefundError::Invalid("Admin required"))?,
            )
            .await?;
        match self
            .stripe
            .create_sunset_refund(
                &op.charge_id,
                op.amount,
                &id.to_string(),
                &attempt.id.to_string(),
            )
            .await
        {
            Ok(refund)
                if valid_refund(&op, &refund)
                    && refund.metadata.get("sunset_attempt_id")
                        == Some(&attempt.id.to_string())
                    && refund.metadata.get("sunset_operation_id") == Some(&id.to_string()) =>
            {
                store.save(id, token, attempt.id, &refund).await?;
            }
            Ok(_) => {
                store
                    .error(id, token, attempt.id, "stripe_response_mismatch", true)
                    .await?;
                store
                    .review(id, token, Some("stripe_response_mismatch"))
                    .await?;
            }
            Err(_) => {
                store
                    .error(id, token, attempt.id, "stripe_result_unknown", true)
                    .await?;
            }
        }
        store.get(id).await
    }
    pub async fn sync_charge(&self, charge: &str) -> Result<()> {
        if let Some(id) = Store(self.pool).by_charge(charge).await? {
            self.run(id, Action::Sync, None, None).await?;
        }
        Ok(())
    }
}

fn valid_refund(op: &RefundOperation, r: &StripeRefund) -> bool {
    !r.id.is_empty()
        && r.charge == op.charge_id
        && r.amount == op.amount
        && r.currency == op.currency
        && matches!(
            r.status.as_str(),
            "pending" | "requires_action" | "succeeded" | "failed" | "canceled"
        )
}
fn reconcile<'a>(
    op: &RefundOperation,
    e: &'a RefundEvidence,
) -> std::result::Result<Vec<(Uuid, &'a StripeRefund)>, &'static str> {
    if e.invoice_id != op.invoice_id
        || e.charge_id != op.charge_id
        || e.customer_id != op.customer_id
        || e.currency != op.currency
        || e.livemode != op.livemode
        || op.amount > e.amount_paid
    {
        return Err("payment_evidence_changed");
    }
    let mut matches = vec![];
    for refund in &e.refunds {
        let attempt = op
            .attempts
            .iter()
            .find(|a| {
                a.stripe_refund_id.as_deref() == Some(&refund.id)
                    || (refund.metadata.get("sunset_operation_id") == Some(&op.id.to_string())
                        && refund.metadata.get("sunset_attempt_id") == Some(&a.id.to_string()))
            })
            .ok_or("external_refund_requires_reconciliation")?;
        if !valid_refund(op, refund)
            || attempt
                .stripe_refund_id
                .as_ref()
                .is_some_and(|id| id != &refund.id)
            || matches.iter().any(|(id, _)| *id == attempt.id)
        {
            return Err("refund_evidence_mismatch");
        }
        matches.push((attempt.id, refund));
    }
    for attempt in &op.attempts {
        if attempt.stripe_refund_id.is_some() && !matches.iter().any(|(id, _)| *id == attempt.id) {
            return Err("known_refund_missing_from_stripe");
        }
    }
    let active: Vec<_> = matches
        .iter()
        .filter(|(_, r)| !matches!(r.status.as_str(), "failed" | "canceled"))
        .collect();
    if active.len() > 1
        || active
            .first()
            .is_some_and(|(id, _)| op.current().is_ok_and(|a| a.id != *id))
    {
        return Err("multiple_attempts_require_reconciliation");
    }
    Ok(matches)
}
