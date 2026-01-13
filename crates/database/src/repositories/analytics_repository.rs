//! PostgreSQL implementation of the analytics repository.

use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use services::analytics::CheckAndRecordActivityRequest;
use services::{
    analytics::{
        ActivityLogEntry, ActivityMetricsSummary, ActivityType, AnalyticsRepository,
        AnalyticsSummary, AuthMethodBreakdown, CheckAndRecordActivityResult, RecordActivityRequest,
        TimeWindow, TopActiveUser, UserMetricsSummary,
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

    /// Check if usage is below limit and atomically record activity if allowed.
    /// Uses sliding window based on activity_log table.
    async fn check_and_record_activity(
        &self,
        request: CheckAndRecordActivityRequest,
    ) -> anyhow::Result<CheckAndRecordActivityResult> {
        // Fast path: limit <= 0 means the increment is never allowed.
        if request.limit <= 0 {
            return Ok(CheckAndRecordActivityResult {
                current_count: 0,
                was_recorded: false,
            });
        }

        let client = self.pool.get().await?;
        let activity_type_str = request.activity_type.as_str();

        // Use a single query to atomically:
        // 1. Count activities in the sliding window
        // 2. Insert new activity if below limit
        // 3. Return the count and whether insertion happened
        let window_days = request.window.days as i64;
        let row = client
            .query_one(
                r#"
                WITH window_start AS (
                    SELECT NOW() - make_interval(days => $3) as start_time
                ),
                current_count AS (
                    SELECT COUNT(*)::bigint as cnt
                    FROM user_activity_log, window_start
                    WHERE user_id = $1
                      AND activity_type = $2
                      AND created_at >= window_start.start_time
                ),
                can_insert AS (
                    SELECT (SELECT cnt FROM current_count) < $4 as allowed
                ),
                inserted AS (
                    INSERT INTO user_activity_log (user_id, activity_type, metadata, created_at)
                    SELECT $1, $2, $5, NOW()
                    WHERE (SELECT allowed FROM can_insert) = true
                    RETURNING id
                )
                SELECT 
                    (SELECT cnt FROM current_count) + 
                    CASE WHEN EXISTS (SELECT 1 FROM inserted) THEN 1 ELSE 0 END as total_count,
                    EXISTS (SELECT 1 FROM inserted) as was_inserted
                "#,
                &[
                    &request.user_id,
                    &activity_type_str,
                    &window_days,
                    &request.limit,
                    &request.metadata,
                ],
            )
            .await?;

        let count: i64 = row.get(0);
        let was_inserted: bool = row.get(1);

        Ok(CheckAndRecordActivityResult {
            current_count: count,
            was_recorded: was_inserted,
        })
    }

    async fn check_activity_count(
        &self,
        user_id: UserId,
        activity_type: ActivityType,
        window: TimeWindow,
    ) -> anyhow::Result<i64> {
        let client = self.pool.get().await?;
        let activity_type_str = activity_type.as_str();
        let window_days = window.days as i64;

        let row = client
            .query_one(
                r#"
                WITH window_start AS (
                    SELECT NOW() - make_interval(days => $3) as start_time
                )
                SELECT COUNT(*)::bigint as cnt
                FROM user_activity_log, window_start
                WHERE user_id = $1
                  AND activity_type = $2
                  AND created_at >= window_start.start_time
                "#,
                &[&user_id, &activity_type_str, &window_days],
            )
            .await?;

        Ok(row.get(0))
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
}
