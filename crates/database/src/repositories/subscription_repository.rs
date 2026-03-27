use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::{DowngradeIntentStatus, Subscription, SubscriptionRepository};
use services::UserId;

fn row_to_subscription(row: &tokio_postgres::Row) -> Subscription {
    Subscription {
        subscription_id: row.get("subscription_id"),
        user_id: row.get("user_id"),
        provider: row.get("provider"),
        customer_id: row.get("customer_id"),
        price_id: row.get("price_id"),
        status: row.get("status"),
        current_period_end: row.get("current_period_end"),
        cancel_at_period_end: row.get("cancel_at_period_end"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        pending_downgrade_target_price_id: row.get("pending_downgrade_target_price_id"),
        pending_downgrade_from_price_id: row.get("pending_downgrade_from_price_id"),
        pending_downgrade_expected_period_end: row.get("pending_downgrade_expected_period_end"),
        pending_downgrade_status: row
            .get::<_, Option<String>>("pending_downgrade_status")
            .and_then(|v| v.parse::<DowngradeIntentStatus>().ok()),
    }
}

pub struct PostgresSubscriptionRepository {
    pool: DbPool,
}

impl PostgresSubscriptionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SubscriptionRepository for PostgresSubscriptionRepository {
    async fn upsert_subscription(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription: Subscription,
    ) -> anyhow::Result<Subscription> {
        tracing::info!(
            "Repository: Upserting subscription - subscription_id={}, user_id={}",
            subscription.subscription_id,
            subscription.user_id
        );

        let pending_downgrade_status = subscription
            .pending_downgrade_status
            .map(DowngradeIntentStatus::as_str);

        let pending_downgrade_updated_at: Option<chrono::DateTime<chrono::Utc>> =
            if pending_downgrade_status.is_some() {
                Some(chrono::Utc::now())
            } else {
                None
            };

        let row = txn
            .query_one(
                "INSERT INTO subscriptions (
                    subscription_id, user_id, provider, customer_id, price_id,
                    status, current_period_end, cancel_at_period_end,
                    pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status,
                    pending_downgrade_updated_at
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                 ON CONFLICT (subscription_id)
                 DO UPDATE SET
                     user_id = EXCLUDED.user_id,
                     provider = EXCLUDED.provider,
                     customer_id = EXCLUDED.customer_id,
                     price_id = EXCLUDED.price_id,
                     status = EXCLUDED.status,
                     current_period_end = EXCLUDED.current_period_end,
                     cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                     pending_downgrade_target_price_id = CASE
                         WHEN EXCLUDED.pending_downgrade_status IS NULL
                             THEN subscriptions.pending_downgrade_target_price_id
                         ELSE EXCLUDED.pending_downgrade_target_price_id
                     END,
                     pending_downgrade_from_price_id = CASE
                         WHEN EXCLUDED.pending_downgrade_status IS NULL
                             THEN subscriptions.pending_downgrade_from_price_id
                         ELSE EXCLUDED.pending_downgrade_from_price_id
                     END,
                     pending_downgrade_expected_period_end = CASE
                         WHEN EXCLUDED.pending_downgrade_status IS NULL
                             THEN subscriptions.pending_downgrade_expected_period_end
                         ELSE EXCLUDED.pending_downgrade_expected_period_end
                     END,
                     pending_downgrade_status = COALESCE(
                         EXCLUDED.pending_downgrade_status,
                         subscriptions.pending_downgrade_status
                     ),
                     pending_downgrade_updated_at = CASE
                         WHEN EXCLUDED.pending_downgrade_status IS NULL
                             THEN subscriptions.pending_downgrade_updated_at
                         ELSE NOW()
                     END,
                     updated_at = NOW()
                 RETURNING subscription_id, user_id, provider, customer_id, price_id, status,
                           current_period_end, cancel_at_period_end, created_at, updated_at,
                           pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                           pending_downgrade_expected_period_end, pending_downgrade_status",
                &[
                    &subscription.subscription_id,
                    &subscription.user_id,
                    &subscription.provider,
                    &subscription.customer_id,
                    &subscription.price_id,
                    &subscription.status,
                    &subscription.current_period_end,
                    &subscription.cancel_at_period_end,
                    &subscription.pending_downgrade_target_price_id,
                    &subscription.pending_downgrade_from_price_id,
                    &subscription.pending_downgrade_expected_period_end,
                    &pending_downgrade_status,
                    &pending_downgrade_updated_at,
                ],
            )
            .await
            .map_err(|e| {
                if let Some(db_err) = e.as_db_error() {
                    tracing::debug!(
                        "upsert_subscription DB error: severity={}, code={}, message={}, detail={:?}, hint={:?}",
                        db_err.severity(), db_err.code().code(), db_err.message(),
                        db_err.detail(), db_err.hint()
                    );
                } else {
                    tracing::debug!("upsert_subscription non-DB error: {:?}", e);
                }
                e
            })?;

        Ok(row_to_subscription(&row))
    }

    async fn get_user_subscriptions(&self, user_id: UserId) -> anyhow::Result<Vec<Subscription>> {
        tracing::debug!(
            "Repository: Fetching all subscriptions for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT subscription_id, user_id, provider, customer_id, price_id, status,
                        current_period_end, cancel_at_period_end, created_at, updated_at,
                        pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                        pending_downgrade_expected_period_end, pending_downgrade_status
                 FROM subscriptions
                 WHERE user_id = $1
                 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows.iter().map(row_to_subscription).collect())
    }

    async fn get_active_subscription(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<Subscription>> {
        tracing::debug!(
            "Repository: Fetching active subscription for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT subscription_id, user_id, provider, customer_id, price_id, status,
                        current_period_end, cancel_at_period_end, created_at, updated_at,
                        pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                        pending_downgrade_expected_period_end, pending_downgrade_status
                 FROM subscriptions
                 WHERE user_id = $1 AND status IN ('active', 'trialing')
                 ORDER BY created_at DESC
                 LIMIT 1",
                &[&user_id],
            )
            .await?;

        Ok(row.as_ref().map(row_to_subscription))
    }

    async fn last_cancelled_subscription_period_end_for_user(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
        let client = self.pool.get().await?;
        // Stripe `SubscriptionStatus::Canceled` serializes as `canceled` (US spelling).
        let row = client
            .query_one(
                "SELECT MAX(current_period_end) AS m FROM subscriptions \
                 WHERE user_id = $1 AND status = 'canceled'",
                &[&user_id],
            )
            .await?;
        Ok(row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("m"))
    }

    async fn list_subscriptions(
        &self,
        user_id: Option<UserId>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<Subscription>, i64)> {
        let client = self.pool.get().await?;

        let total_row = client
            .query_one(
                "SELECT COUNT(*) FROM subscriptions WHERE ($1::uuid IS NULL OR user_id = $1)",
                &[&user_id],
            )
            .await?;
        let total: i64 = total_row.get(0);

        if total == 0 {
            return Ok((vec![], 0));
        }

        let rows = client
            .query(
                "SELECT subscription_id, user_id, provider, customer_id, price_id, status,
                        current_period_end, cancel_at_period_end, created_at, updated_at,
                        pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                        pending_downgrade_expected_period_end, pending_downgrade_status
                 FROM subscriptions
                 WHERE ($1::uuid IS NULL OR user_id = $1)
                 ORDER BY created_at DESC
                 LIMIT $2 OFFSET $3",
                &[&user_id, &limit, &offset],
            )
            .await?;

        Ok((rows.iter().map(row_to_subscription).collect(), total))
    }

    async fn get_active_subscriptions(&self, user_id: UserId) -> anyhow::Result<Vec<Subscription>> {
        tracing::debug!(
            "Repository: Fetching active subscriptions for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT subscription_id, user_id, provider, customer_id, price_id, status,
                        current_period_end, cancel_at_period_end, created_at, updated_at,
                        pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                        pending_downgrade_expected_period_end, pending_downgrade_status
                 FROM subscriptions
                 WHERE user_id = $1 AND status IN ('active', 'trialing')
                 ORDER BY current_period_end DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows.iter().map(row_to_subscription).collect())
    }

    async fn delete_subscription(&self, subscription_id: &str) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Deleting subscription - subscription_id={}",
            subscription_id
        );

        let client = self.pool.get().await?;

        client
            .execute(
                "DELETE FROM subscriptions WHERE subscription_id = $1",
                &[&subscription_id],
            )
            .await?;

        Ok(())
    }

    async fn deactivate_user_subscriptions(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
    ) -> anyhow::Result<()> {
        let n = txn
            .execute(
                "UPDATE subscriptions SET status = 'canceled', updated_at = NOW() WHERE user_id = $1 AND status IN ('active', 'trialing')",
                &[&user_id],
            )
            .await?;
        if n > 0 {
            tracing::info!(
                "Repository: Deactivated {} subscription(s) for user_id={}",
                n,
                user_id
            );
        }
        Ok(())
    }

    async fn get_pending_downgrade_for_update_skip_locked(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<Option<Subscription>> {
        let pending_status = DowngradeIntentStatus::Pending.as_str();
        let row = txn
            .query_opt(
                "SELECT subscription_id, user_id, provider, customer_id, price_id, status,
                        current_period_end, cancel_at_period_end, created_at, updated_at,
                        pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                        pending_downgrade_expected_period_end, pending_downgrade_status
                 FROM subscriptions
                 WHERE subscription_id = $1
                   AND status IN ('active', 'trialing')
                   AND pending_downgrade_status = $2
                 FOR UPDATE SKIP LOCKED",
                &[&subscription_id, &pending_status],
            )
            .await?;

        Ok(row.as_ref().map(row_to_subscription))
    }

    async fn get_subscription_status_for_update(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = txn
            .query_opt(
                "SELECT status FROM subscriptions WHERE subscription_id = $1 FOR UPDATE",
                &[&subscription_id],
            )
            .await?;
        Ok(row.map(|r| r.get(0)))
    }

    async fn clear_pending_downgrade(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        subscription_id: &str,
    ) -> anyhow::Result<()> {
        txn.execute(
            "UPDATE subscriptions
                 SET pending_downgrade_target_price_id = NULL,
                     pending_downgrade_from_price_id = NULL,
                     pending_downgrade_expected_period_end = NULL,
                     pending_downgrade_status = NULL,
                     pending_downgrade_updated_at = NOW(),
                     updated_at = NOW()
                 WHERE subscription_id = $1",
            &[&subscription_id],
        )
        .await?;
        Ok(())
    }
}
