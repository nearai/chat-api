//! PostgreSQL implementation of the credits repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use services::subscription::ports::CreditsRepository;
use services::UserId;

pub struct PostgresCreditsRepository {
    pool: DbPool,
}

impl PostgresCreditsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CreditsRepository for PostgresCreditsRepository {
    async fn get_balance(&self, user_id: UserId) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT balance FROM user_credits WHERE user_id = $1",
                &[&user_id],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, i64>("balance")).unwrap_or(0))
    }

    async fn add_credits(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
    ) -> anyhow::Result<i64> {
        let row = txn
            .query_one(
                r#"
                INSERT INTO user_credits (user_id, balance)
                VALUES ($1, $2)
                ON CONFLICT (user_id)
                DO UPDATE SET balance = user_credits.balance + EXCLUDED.balance, updated_at = NOW()
                RETURNING balance
                "#,
                &[&user_id, &amount],
            )
            .await?;
        Ok(row.get::<_, i64>("balance"))
    }

    async fn try_record_purchase(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
        reference_id: &str,
    ) -> anyhow::Result<bool> {
        let result = txn
            .execute(
                r#"
                INSERT INTO credit_transactions (user_id, amount, type, reference_id)
                VALUES ($1, $2, 'purchase', $3)
                "#,
                &[&user_id, &amount, &reference_id],
            )
            .await;

        match result {
            Ok(n) => Ok(n == 1),
            Err(e) => {
                if let Some(db_err) = e.code() {
                    if *db_err == tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                        return Ok(false);
                    }
                }
                Err(e.into())
            }
        }
    }
}
