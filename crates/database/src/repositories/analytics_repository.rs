//! PostgreSQL implementation of the analytics repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use services::{
    analytics::{
        ActivityLogEntry, ActivityMetricsSummary, AnalyticsRepository, AnalyticsSummary,
        AuthMethodBreakdown, DailyUsageSnapshot, RecordActivityRequest, RecordDailyUsageRequest,
        TopActiveUser, UserMetricsSummary,
    },
    UserId,
};

pub struct PostgresAnalyticsRepository {
    pool: DbPool,
}

impl PostgresAnalyticsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AnalyticsRepository for PostgresAnalyticsRepository {
    async fn record_activity(&self, request: RecordActivityRequest) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        let activity_type = request.activity_type.as_str();
        let auth_method = request.auth_method.map(|m| m.as_str().to_string());

        client
            .execute(
                r#"
                INSERT INTO user_activity_log (user_id, activity_type, auth_method, metadata)
                VALUES ($1, $2, $3, $4)
                "#,
                &[
                    &request.user_id,
                    &activity_type,
                    &auth_method,
                    &request.metadata,
                ],
            )
            .await?;

        Ok(())
    }

    async fn get_analytics_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<AnalyticsSummary> {
        let client = self.pool.get().await?;

        // Get total users
        let total_users_row = client
            .query_one("SELECT COUNT(*)::bigint FROM users", &[])
            .await?;
        let total_users: i64 = total_users_row.get(0);

        // Get new users in period
        let new_users_row = client
            .query_one(
                r#"
                SELECT COUNT(*)::bigint FROM users
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;
        let new_users: i64 = new_users_row.get(0);

        // Get active users in period (users with any activity)
        let active_users_row = client
            .query_one(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM user_activity_log
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;
        let active_users: i64 = active_users_row.get(0);

        // Get login count in period
        let login_count_row = client
            .query_one(
                r#"
                SELECT COUNT(*)::bigint FROM user_activity_log
                WHERE activity_type = 'login' AND created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;
        let total_logins: i64 = login_count_row.get(0);

        // Get signup count in period
        let signup_count_row = client
            .query_one(
                r#"
                SELECT COUNT(*)::bigint FROM user_activity_log
                WHERE activity_type = 'signup' AND created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;
        let total_signups: i64 = signup_count_row.get(0);

        // Get activity counts
        let activity_counts_row = client
            .query_one(
                r#"
                SELECT 
                    COALESCE(SUM(CASE WHEN activity_type = 'response' THEN 1 ELSE 0 END), 0)::bigint as responses,
                    COALESCE(SUM(CASE WHEN activity_type = 'conversation' THEN 1 ELSE 0 END), 0)::bigint as conversations,
                    COALESCE(SUM(CASE WHEN activity_type = 'file_upload' THEN 1 ELSE 0 END), 0)::bigint as file_uploads
                FROM user_activity_log
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;

        let total_responses: i64 = activity_counts_row.get(0);
        let total_conversations: i64 = activity_counts_row.get(1);
        let total_file_uploads: i64 = activity_counts_row.get(2);

        // Get breakdown by auth method
        let auth_method_rows = client
            .query(
                r#"
                SELECT 
                    auth_method,
                    COUNT(DISTINCT user_id)::bigint as user_count,
                    COALESCE(SUM(CASE WHEN activity_type = 'login' THEN 1 ELSE 0 END), 0)::bigint as login_count,
                    COALESCE(SUM(CASE WHEN activity_type = 'signup' THEN 1 ELSE 0 END), 0)::bigint as signup_count
                FROM user_activity_log
                WHERE auth_method IS NOT NULL
                  AND created_at >= $1 AND created_at < $2
                GROUP BY auth_method
                ORDER BY user_count DESC
                "#,
                &[&start, &end],
            )
            .await?;

        let by_auth_method: Vec<AuthMethodBreakdown> = auth_method_rows
            .iter()
            .map(|row| AuthMethodBreakdown {
                auth_method: row.get(0),
                user_count: row.get(1),
                login_count: row.get(2),
                signup_count: row.get(3),
            })
            .collect();

        Ok(AnalyticsSummary {
            period_start: start,
            period_end: end,
            user_metrics: UserMetricsSummary {
                total_users,
                new_users,
                active_users,
                total_logins,
                total_signups,
            },
            activity_metrics: ActivityMetricsSummary {
                total_responses,
                total_conversations,
                total_file_uploads,
            },
            by_auth_method,
        })
    }

    async fn get_daily_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;

        let start = date.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let end = start + Duration::days(1);

        let start_utc = DateTime::<Utc>::from_naive_utc_and_offset(start, Utc);
        let end_utc = DateTime::<Utc>::from_naive_utc_and_offset(end, Utc);

        let row = client
            .query_one(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM user_activity_log
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start_utc, &end_utc],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn get_weekly_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;

        let end = date;
        let start = end - Duration::days(7);

        let row = client
            .query_one(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM user_activity_log
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn get_monthly_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;

        let end = date;
        let start = end - Duration::days(30);

        let row = client
            .query_one(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM user_activity_log
                WHERE created_at >= $1 AND created_at < $2
                "#,
                &[&start, &end],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn get_user_activity(
        &self,
        user_id: UserId,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> anyhow::Result<Vec<ActivityLogEntry>> {
        let client = self.pool.get().await?;

        let limit = limit.unwrap_or(50);
        let offset = offset.unwrap_or(0);

        let rows = client
            .query(
                r#"
                SELECT id, user_id, activity_type, auth_method, metadata, created_at
                FROM user_activity_log
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
                &[&user_id, &limit, &offset],
            )
            .await?;

        Ok(rows
            .iter()
            .map(|row| ActivityLogEntry {
                id: row.get(0),
                user_id: row.get(1),
                activity_type: row.get(2),
                auth_method: row.get(3),
                metadata: row.get(4),
                created_at: row.get(5),
            })
            .collect())
    }

    async fn get_top_active_users(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
    ) -> anyhow::Result<Vec<TopActiveUser>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                r#"
                SELECT 
                    u.id as user_id,
                    u.email,
                    COUNT(a.id)::bigint as activity_count,
                    MAX(a.created_at) as last_active
                FROM users u
                INNER JOIN user_activity_log a ON u.id = a.user_id
                WHERE a.created_at >= $1 AND a.created_at < $2
                GROUP BY u.id, u.email
                ORDER BY activity_count DESC
                LIMIT $3
                "#,
                &[&start, &end, &limit],
            )
            .await?;

        Ok(rows
            .iter()
            .map(|row| TopActiveUser {
                user_id: row.get(0),
                email: row.get(1),
                activity_count: row.get(2),
                last_active: row.get(3),
            })
            .collect())
    }

    async fn record_daily_usage(&self, request: RecordDailyUsageRequest) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                r#"
                INSERT INTO user_daily_usage (user_id, usage_date, request_count)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, usage_date) DO UPDATE
                  SET request_count = user_daily_usage.request_count + $3,
                      updated_at = NOW()
                "#,
                &[
                    &request.user_id,
                    &request.usage_date,
                    &request.request_increment,
                ],
            )
            .await?;

        Ok(())
    }

    async fn increment_daily_usage_if_below_limit(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
        limit: i64,
    ) -> anyhow::Result<(i64, bool)> {
        // Fast path: limit <= 0 means the increment is never allowed.
        // Returning (0, false) avoids a DB round-trip; callers should treat incremented=false
        // as "blocked by limit".
        if limit <= 0 {
            return Ok((0, false));
        }

        let client = self.pool.get().await?;

        // Atomically increment count if still below limit. If already at/over limit, do not update.
        // This is designed to be multi-instance safe and to avoid write amplification after a user
        // has reached their daily limit.
        let row = client
            .query_one(
                r#"
                WITH updated AS (
                    INSERT INTO user_daily_usage (user_id, usage_date, request_count)
                    VALUES ($1, $2, 1)
                    ON CONFLICT (user_id, usage_date) DO UPDATE
                      SET request_count = user_daily_usage.request_count + 1,
                          updated_at = NOW()
                      WHERE user_daily_usage.request_count < $3
                    RETURNING request_count
                )
                SELECT
                    request_count,
                    true as incremented
                FROM updated
                UNION ALL
                SELECT
                    u.request_count,
                    false as incremented
                FROM user_daily_usage u
                WHERE u.user_id = $1 AND u.usage_date = $2
                  AND NOT EXISTS (SELECT 1 FROM updated)
                "#,
                &[&user_id, &usage_date, &limit],
            )
            .await?;

        let count: i64 = row.get(0);
        let incremented: bool = row.get(1);
        Ok((count, incremented))
    }

    async fn get_user_daily_usage(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
    ) -> anyhow::Result<DailyUsageSnapshot> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                r#"
                SELECT user_id, usage_date, request_count, updated_at
                FROM user_daily_usage
                WHERE user_id = $1 AND usage_date = $2
                "#,
                &[&user_id, &usage_date],
            )
            .await?;

        if let Some(row) = row {
            Ok(DailyUsageSnapshot {
                user_id: row.get(0),
                usage_date: row.get(1),
                request_count: row.get(2),
                updated_at: row.get(3),
            })
        } else {
            Ok(DailyUsageSnapshot::zero(user_id, usage_date))
        }
    }
}
