use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::{StripeCustomer, StripeCustomerRepository};
use services::UserId;

pub struct PostgresStripeCustomerRepository {
    pool: DbPool,
}

impl PostgresStripeCustomerRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl StripeCustomerRepository for PostgresStripeCustomerRepository {
    async fn get_customer_id(&self, user_id: UserId) -> anyhow::Result<Option<String>> {
        tracing::debug!(
            "Repository: Fetching Stripe customer_id for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT customer_id FROM stripe_customers WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        Ok(row.map(|r| r.get("customer_id")))
    }

    async fn create_customer_mapping(
        &self,
        user_id: UserId,
        customer_id: String,
    ) -> anyhow::Result<StripeCustomer> {
        tracing::info!(
            "Repository: Creating/updating Stripe customer mapping - user_id={}, customer_id={}",
            user_id,
            customer_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO stripe_customers (user_id, customer_id)
                 VALUES ($1, $2)
                 ON CONFLICT (user_id)
                 DO UPDATE SET customer_id = EXCLUDED.customer_id, updated_at = NOW()
                 RETURNING user_id, customer_id, created_at, updated_at",
                &[&user_id, &customer_id],
            )
            .await?;

        Ok(StripeCustomer {
            user_id: row.get("user_id"),
            customer_id: row.get("customer_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}
