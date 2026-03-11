//! PostgreSQL implementation of the credits repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::subscription::ports::{CreditTransaction, CreditsRepository};
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

    async fn get_purchased_breakdown(&self, user_id: UserId) -> anyhow::Result<(i64, i64, i64)> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT balance, total_purchased_nano_usd, used_purchased_nano_usd
                FROM user_credits WHERE user_id = $1
                "#,
                &[&user_id],
            )
            .await?;
        Ok(match row {
            Some(r) => (
                r.get::<_, i64>("balance"),
                r.get::<_, i64>("total_purchased_nano_usd"),
                r.get::<_, i64>("used_purchased_nano_usd"),
            ),
            None => (0, 0, 0),
        })
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
                INSERT INTO user_credits (user_id, balance, total_purchased_nano_usd)
                VALUES ($1, $2, $2)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    balance = user_credits.balance + EXCLUDED.balance,
                    total_purchased_nano_usd = user_credits.total_purchased_nano_usd + EXCLUDED.balance,
                    updated_at = NOW()
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

    async fn record_grant(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        amount: i64,
        reason: Option<String>,
    ) -> anyhow::Result<()> {
        txn.execute(
            r#"
            INSERT INTO credit_transactions (user_id, amount, type, reference_id)
            VALUES ($1, $2, 'grant', $3)
            "#,
            &[&user_id, &amount, &reason],
        )
        .await?;
        Ok(())
    }

    async fn list_transactions(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<CreditTransaction>, i64)> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                SELECT
                    id,
                    user_id,
                    amount,
                    type,
                    reference_id,
                    created_at,
                    COUNT(*) OVER() AS total_count
                FROM credit_transactions
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
                &[&user_id, &limit, &offset],
            )
            .await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let txs = rows
            .into_iter()
            .map(|r| CreditTransaction {
                id: r.get("id"),
                user_id: r.get("user_id"),
                amount: r.get("amount"),
                r#type: r.get("type"),
                reference_id: r.get("reference_id"),
                created_at: r.get("created_at"),
            })
            .collect();

        Ok((txs, total_count))
    }

    async fn reconcile_purchased_after_usage(
        &self,
        user_id: UserId,
        plan_credits_nano_usd: i64,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut client = self.pool.get().await?;
        let txn = client.transaction().await?;

        let row = txn
            .query_opt(
                r#"
                SELECT total_purchased_nano_usd, used_purchased_nano_usd
                FROM user_credits
                WHERE user_id = $1
                FOR UPDATE
                "#,
                &[&user_id],
            )
            .await?;

        let (total_purchased, _old_used) = match row {
            Some(r) => (
                r.get::<_, i64>("total_purchased_nano_usd"),
                r.get::<_, i64>("used_purchased_nano_usd"),
            ),
            None => return Ok(()), // no purchased pool
        };

        if total_purchased <= 0 {
            txn.commit().await?;
            return Ok(());
        }

        let usage_row = txn
            .query_one(
                r#"
                SELECT COALESCE(SUM(COALESCE(cost_nano_usd, 0)), 0)::bigint AS cost_sum
                FROM user_usage_event
                WHERE user_id = $1
                  AND created_at >= $2
                  AND created_at < $3
                "#,
                &[&user_id, &period_start, &period_end],
            )
            .await?;
        let u: i64 = usage_row.get("cost_sum");

        let plan = plan_credits_nano_usd.max(0);
        let over_plan = (u - plan).max(0);
        let new_used = over_plan.min(total_purchased).max(0);
        let new_balance = (total_purchased - new_used).max(0);

        txn.execute(
            r#"
            UPDATE user_credits
            SET used_purchased_nano_usd = $2,
                balance = $3,
                updated_at = NOW()
            WHERE user_id = $1
            "#,
            &[&user_id, &new_used, &new_balance],
        )
        .await?;

        txn.commit().await?;
        Ok(())
    }
}
