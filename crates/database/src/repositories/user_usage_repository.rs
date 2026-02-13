//! PostgreSQL implementation of the user usage repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::Duration;
use services::user_usage::{UsageRankBy, UserUsageRepository, UserUsageSummary};
use services::UserId;

pub struct PostgresUserUsageRepository {
    pool: DbPool,
}

impl PostgresUserUsageRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserUsageRepository for PostgresUserUsageRepository {
    async fn record_usage_event(
        &self,
        user_id: UserId,
        metric_key: &str,
        quantity: i64,
        cost_nano_usd: Option<i64>,
        model_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
                INSERT INTO user_usage_event (user_id, metric_key, quantity, cost_nano_usd, model_id)
                VALUES ($1, $2, $3, $4, $5)
                "#,
                &[&user_id, &metric_key, &quantity, &cost_nano_usd, &model_id],
            )
            .await?;
        Ok(())
    }

    async fn get_token_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;
        // Scalar subquery always returns one row; NULL when no matching rows -> COALESCE to 0
        let row = client
            .query_one(
                r#"
                SELECT COALESCE((
                    SELECT SUM(quantity)
                    FROM user_usage_event
                    WHERE user_id = $1 AND metric_key = 'llm.tokens'
                      AND created_at >= NOW() - make_interval(secs => $2::bigint)
                ), 0)::bigint as total
                "#,
                &[&user_id, &window_duration.num_seconds()],
            )
            .await?;
        Ok(row.get(0))
    }

    async fn get_cost_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;
        // Scalar subquery always returns one row; NULL when no matching rows -> COALESCE to 0
        let row = client
            .query_one(
                r#"
                SELECT COALESCE((
                    SELECT SUM(COALESCE(cost_nano_usd, 0))
                    FROM user_usage_event
                    WHERE user_id = $1
                      AND created_at >= NOW() - make_interval(secs => $2::bigint)
                ), 0)::bigint as total
                "#,
                &[&user_id, &window_duration.num_seconds()],
            )
            .await?;
        Ok(row.get(0))
    }

    async fn get_usage_by_user_id(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<UserUsageSummary>> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                r#"
                SELECT
                    COALESCE(SUM(CASE WHEN metric_key = 'llm.tokens' THEN quantity ELSE 0 END), 0)::bigint AS token_sum,
                    COALESCE(SUM(COALESCE(cost_nano_usd, 0)), 0)::bigint AS cost_nano_usd
                FROM user_usage_event
                WHERE user_id = $1
                "#,
                &[&user_id],
            )
            .await?;
        let token_sum: i64 = row.get(0);
        let cost_nano_usd: i64 = row.get(1);
        Ok(Some(UserUsageSummary {
            user_id,
            token_sum,
            cost_nano_usd,
        }))
    }

    async fn get_top_users_usage(
        &self,
        limit: i64,
        rank_by: UsageRankBy,
    ) -> anyhow::Result<Vec<UserUsageSummary>> {
        let client = self.pool.get().await?;
        let order = match rank_by {
            UsageRankBy::Token => "token_sum DESC",
            UsageRankBy::Cost => "cost_nano_usd DESC",
        };
        let query = format!(
            r#"
            WITH agg AS (
                SELECT
                    user_id,
                    COALESCE(SUM(CASE WHEN metric_key = 'llm.tokens' THEN quantity ELSE 0 END), 0)::bigint AS token_sum,
                    COALESCE(SUM(COALESCE(cost_nano_usd, 0)), 0)::bigint AS cost_nano_usd
                FROM user_usage_event
                GROUP BY user_id
            )
            SELECT user_id, token_sum, cost_nano_usd
            FROM agg
            ORDER BY {}
            LIMIT $1
            "#,
            order
        );
        let rows = client.query(&query, &[&limit]).await?;
        Ok(rows
            .iter()
            .map(|row| UserUsageSummary {
                user_id: row.get(0),
                token_sum: row.get(1),
                cost_nano_usd: row.get(2),
            })
            .collect())
    }
}
