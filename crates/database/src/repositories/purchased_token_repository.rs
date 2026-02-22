//! PostgreSQL implementation of the purchased token repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::PurchasedTokenRepository;
use services::UserId;

pub struct PostgresPurchasedTokenRepository {
    pool: DbPool,
}

impl PostgresPurchasedTokenRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PurchasedTokenRepository for PostgresPurchasedTokenRepository {
    async fn get_balance(&self, user_id: UserId) -> anyhow::Result<Option<i64>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT balance FROM purchased_tokens WHERE user_id = $1",
                &[&user_id],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, i64>("balance")))
    }

    async fn credit(&self, user_id: UserId, amount: i64) -> anyhow::Result<()> {
        if amount <= 0 {
            return Ok(());
        }
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
                INSERT INTO purchased_tokens (user_id, balance, total_purchased)
                VALUES ($1, $2, $2)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    balance = purchased_tokens.balance + EXCLUDED.balance,
                    total_purchased = purchased_tokens.total_purchased + EXCLUDED.total_purchased,
                    updated_at = NOW()
                "#,
                &[&user_id, &amount],
            )
            .await?;
        Ok(())
    }

    async fn credit_with_txn(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
    ) -> anyhow::Result<()> {
        if amount <= 0 {
            return Ok(());
        }
        txn.execute(
            r#"
                INSERT INTO purchased_tokens (user_id, balance, total_purchased)
                VALUES ($1, $2, $2)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    balance = purchased_tokens.balance + EXCLUDED.balance,
                    total_purchased = purchased_tokens.total_purchased + EXCLUDED.total_purchased,
                    updated_at = NOW()
                "#,
            &[&user_id, &amount],
        )
        .await?;
        Ok(())
    }

    async fn debit(&self, user_id: UserId, amount: i64) -> anyhow::Result<bool> {
        if amount <= 0 {
            return Ok(true);
        }
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                UPDATE purchased_tokens
                SET balance = balance - $1, updated_at = NOW()
                WHERE user_id = $2 AND balance >= $1
                RETURNING balance
                "#,
                &[&amount, &user_id],
            )
            .await?;
        Ok(!rows.is_empty())
    }
}
