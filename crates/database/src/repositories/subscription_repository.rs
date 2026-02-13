use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::{Subscription, SubscriptionRepository};
use services::UserId;

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

        let row = txn
            .query_one(
                "INSERT INTO subscriptions (
                    subscription_id, user_id, provider, customer_id, price_id,
                    status, current_period_end, cancel_at_period_end
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (subscription_id)
                 DO UPDATE SET
                     user_id = EXCLUDED.user_id,
                     provider = EXCLUDED.provider,
                     customer_id = EXCLUDED.customer_id,
                     price_id = EXCLUDED.price_id,
                     status = EXCLUDED.status,
                     current_period_end = EXCLUDED.current_period_end,
                     cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                     updated_at = NOW()
                 RETURNING subscription_id, user_id, provider, customer_id, price_id, status,
                           current_period_end, cancel_at_period_end, created_at, updated_at",
                &[
                    &subscription.subscription_id,
                    &subscription.user_id,
                    &subscription.provider,
                    &subscription.customer_id,
                    &subscription.price_id,
                    &subscription.status,
                    &subscription.current_period_end,
                    &subscription.cancel_at_period_end,
                ],
            )
            .await?;

        Ok(Subscription {
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
        })
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
                        current_period_end, cancel_at_period_end, created_at, updated_at
                 FROM subscriptions
                 WHERE user_id = $1
                 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;

        let subscriptions = rows
            .into_iter()
            .map(|row| Subscription {
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
            })
            .collect();

        Ok(subscriptions)
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
                        current_period_end, cancel_at_period_end, created_at, updated_at
                 FROM subscriptions
                 WHERE user_id = $1 AND status IN ('active', 'trialing')
                 ORDER BY created_at DESC
                 LIMIT 1",
                &[&user_id],
            )
            .await?;

        Ok(row.map(|row| Subscription {
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
        }))
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
                        current_period_end, cancel_at_period_end, created_at, updated_at
                 FROM subscriptions
                 WHERE user_id = $1 AND status IN ('active', 'trialing')
                   AND current_period_end > NOW()
                 ORDER BY current_period_end DESC",
                &[&user_id],
            )
            .await?;

        let subscriptions = rows
            .into_iter()
            .map(|row| Subscription {
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
            })
            .collect();

        Ok(subscriptions)
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
}
