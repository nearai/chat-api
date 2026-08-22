//! PostgreSQL implementation of the credits repository.
//! Remaining credits = total_nano_usd - spent_nano_usd (no stored balance column).

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

fn purchased_reconciliation_update(
    old_spent: i64,
    total_purchased: i64,
    last_over_plan: i64,
    current_over_plan: i64,
    is_same_period: bool,
) -> (i64, i64) {
    let already_applied = if is_same_period {
        last_over_plan.max(0)
    } else {
        0
    };
    let delta_over_plan = (current_over_plan - already_applied).max(0);
    let new_spent = (old_spent + delta_over_plan).min(total_purchased).max(0);
    let reconciled_over_plan = if is_same_period {
        last_over_plan.max(current_over_plan).max(0)
    } else {
        current_over_plan.max(0)
    };
    (new_spent, reconciled_over_plan)
}

fn is_same_reconciliation_period(
    last_period_start: Option<DateTime<Utc>>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> bool {
    let Some(last_period_start) = last_period_start else {
        return false;
    };
    if last_period_start == period_start {
        return true;
    }

    let start_delta_ms = last_period_start
        .signed_duration_since(period_start)
        .num_milliseconds()
        .abs();
    if start_delta_ms <= 1_000 {
        return true;
    }

    last_period_start >= period_start && last_period_start < period_end
}

#[async_trait]
impl CreditsRepository for PostgresCreditsRepository {
    /// Remaining purchased credits: total_purchased - used_purchased (computed).
    async fn get_balance(&self, user_id: UserId) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT (total_nano_usd - spent_nano_usd)::bigint AS remaining
                FROM user_credits WHERE user_id = $1
                "#,
                &[&user_id],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, i64>("remaining")).unwrap_or(0))
    }

    async fn get_purchased_breakdown(&self, user_id: UserId) -> anyhow::Result<(i64, i64, i64)> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT
                    total_nano_usd,
                    spent_nano_usd,
                    (total_nano_usd - spent_nano_usd)::bigint AS remaining
                FROM user_credits WHERE user_id = $1
                "#,
                &[&user_id],
            )
            .await?;
        Ok(match row {
            Some(r) => (
                r.get::<_, i64>("remaining"),
                r.get::<_, i64>("total_nano_usd"),
                r.get::<_, i64>("spent_nano_usd"),
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
                INSERT INTO user_credits (user_id, total_nano_usd)
                VALUES ($1, $2)
                ON CONFLICT (user_id)
                DO UPDATE SET
                    total_nano_usd = user_credits.total_nano_usd + EXCLUDED.total_nano_usd,
                    updated_at = NOW()
                RETURNING (total_nano_usd - spent_nano_usd)::bigint AS remaining
                "#,
                &[&user_id, &amount],
            )
            .await?;
        Ok(row.get::<_, i64>("remaining"))
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
                SELECT total_nano_usd, spent_nano_usd, last_reconciled_period_start, last_reconciled_over_plan_nano_usd
                FROM user_credits
                WHERE user_id = $1
                FOR UPDATE
                "#,
                &[&user_id],
            )
            .await?;

        let (total_purchased, old_spent, last_period_start, last_over_plan) = match row {
            Some(r) => (
                r.get::<_, i64>("total_nano_usd"),
                r.get::<_, i64>("spent_nano_usd"),
                r.get::<_, Option<DateTime<Utc>>>("last_reconciled_period_start"),
                r.get::<_, i64>("last_reconciled_over_plan_nano_usd"),
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
        let current_over_plan = (u - plan).max(0);

        let is_same_period =
            is_same_reconciliation_period(last_period_start, period_start, period_end);
        // We treat spent_nano_usd as lifetime spent. The over-plan cursor is a period high-water
        // mark because stake-backed plan limits can increase after usage has already consumed
        // purchased credits; lowering the cursor would charge the same overage twice.
        let (new_spent, reconciled_over_plan) = purchased_reconciliation_update(
            old_spent,
            total_purchased,
            last_over_plan,
            current_over_plan,
            is_same_period,
        );

        txn.execute(
            r#"
            UPDATE user_credits
            SET spent_nano_usd = $2,
                last_reconciled_period_start = $3,
                last_reconciled_over_plan_nano_usd = $4,
                updated_at = NOW()
            WHERE user_id = $1
            "#,
            &[&user_id, &new_spent, &period_start, &reconciled_over_plan],
        )
        .await?;

        txn.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{is_same_reconciliation_period, purchased_reconciliation_update};
    use chrono::Duration;

    #[test]
    fn purchased_reconciliation_keeps_same_period_overage_high_water() {
        let (spent_after_increase, cursor_after_increase) =
            purchased_reconciliation_update(1_000_000_000, 10_000_000_000, 1_000_000_000, 0, true);
        assert_eq!(spent_after_increase, 1_000_000_000);
        assert_eq!(cursor_after_increase, 1_000_000_000);

        let (spent_after_more_usage, cursor_after_more_usage) = purchased_reconciliation_update(
            spent_after_increase,
            10_000_000_000,
            cursor_after_increase,
            1_000_000_000,
            true,
        );
        assert_eq!(spent_after_more_usage, 1_000_000_000);
        assert_eq!(cursor_after_more_usage, 1_000_000_000);
    }

    #[test]
    fn purchased_reconciliation_tolerates_equivalent_period_start_changes() {
        let period_start = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let period_end = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert!(is_same_reconciliation_period(
            Some(period_start + Duration::milliseconds(250)),
            period_start,
            period_end,
        ));
        assert!(is_same_reconciliation_period(
            Some(period_start + Duration::days(1)),
            period_start,
            period_end,
        ));
        assert!(!is_same_reconciliation_period(
            Some(period_start - Duration::days(30)),
            period_start,
            period_end,
        ));
    }
}
