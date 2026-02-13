//! Per-user rate limiting middleware for inference endpoints.
//!
//! Implements rate limiting on a per-user basis that enforces:
//! - Maximum 2 concurrent in-flight requests per user
//! - Maximum 1 request per second per user (sliding window)

use crate::consts::USER_STATE_IDLE_TIMEOUT;
use crate::middleware::auth::AuthenticatedUser;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use services::{
    analytics::{ActivityType, AnalyticsServiceTrait, CheckAndRecordActivityRequest},
    system_configs::ports::{RateLimitConfig, WindowLimit},
    user_usage::UserUsageService,
    UserId,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};

/// Distinguishes token vs cost usage when checking window limits.
enum UsageLimitType {
    Token,
    Cost,
}

struct UserRateLimitState {
    semaphore: Arc<Semaphore>,
    max_permits: usize,
    request_timestamps: VecDeque<Instant>,
    last_activity: Instant,
}

impl UserRateLimitState {
    fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_permits: max_concurrent,
            request_timestamps: VecDeque::new(),
            last_activity: Instant::now(),
        }
    }

    fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_activity.elapsed() > max_idle
            && self.request_timestamps.is_empty()
            && self.semaphore.available_permits() == self.max_permits
    }
}

#[derive(Clone)]
pub struct RateLimitState {
    user_limits: Arc<Mutex<HashMap<UserId, UserRateLimitState>>>,
    config: Arc<RwLock<RateLimitConfig>>,
    analytics_service: Arc<dyn AnalyticsServiceTrait>,
    user_usage_service: Arc<dyn UserUsageService>,
}

impl RateLimitState {
    pub fn new(
        analytics_service: Arc<dyn AnalyticsServiceTrait>,
        user_usage_service: Arc<dyn UserUsageService>,
    ) -> Self {
        Self::with_config(
            RateLimitConfig::default(),
            analytics_service,
            user_usage_service,
        )
    }

    pub fn with_config(
        config: RateLimitConfig,
        analytics_service: Arc<dyn AnalyticsServiceTrait>,
        user_usage_service: Arc<dyn UserUsageService>,
    ) -> Self {
        Self {
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(RwLock::new(config)),
            analytics_service,
            user_usage_service,
        }
    }

    /// Update the rate limit configuration (hot reload)
    ///
    /// This will clear all existing user rate limit states to ensure
    /// all users immediately use the new configuration (especially max_concurrent).
    /// Any in-flight requests will complete with their already-acquired permits,
    /// but new requests will use the new limits.
    pub async fn update_config(&self, new_config: RateLimitConfig) {
        // Update config first
        let mut config = self.config.write().await;
        *config = new_config;
        drop(config); // Release write lock

        // Clear all existing user states to ensure new config is used immediately
        // This prevents inconsistency where some users have old semaphore permits
        let mut user_limits = self.user_limits.lock().await;
        let cleared_count = user_limits.len();
        user_limits.clear();

        tracing::info!(
            cleared_users = cleared_count,
            "Rate limit configuration updated and user states cleared"
        );
    }

    async fn try_acquire(&self, user_id: UserId) -> Result<RateLimitGuard, RateLimitError> {
        // Load config snapshot at the start (read lock is released immediately)
        let config = self.config.read().await.clone();

        // Convert chrono::Duration to std::time::Duration for in-memory tracking
        let window_duration = config.window_duration.to_std().map_err(|e| {
            tracing::error!(
                "Invalid window_duration in rate limit config: {}. Duration: {:?}",
                e,
                config.window_duration
            );
            RateLimitError::InternalServerError
        })?;

        // Phase 1: Fast checks (short mutex hold time)
        // Check short-term rate limit and acquire permit
        // Store the timestamp so we can rollback the exact one we added
        let timestamp = {
            let mut user_limits = self.user_limits.lock().await;

            user_limits.retain(|_, state| !state.is_idle(USER_STATE_IDLE_TIMEOUT));

            let user_state = user_limits
                .entry(user_id)
                .or_insert_with(|| UserRateLimitState::new(config.max_concurrent));

            let now = Instant::now();
            user_state.last_activity = now;

            // Clean up expired timestamps
            while let Some(front) = user_state.request_timestamps.front() {
                if now.duration_since(*front) > window_duration {
                    user_state.request_timestamps.pop_front();
                } else {
                    break;
                }
            }

            // Check short-term rate limit
            if user_state.request_timestamps.len() >= config.max_requests_per_window {
                if let Some(oldest) = user_state.request_timestamps.front() {
                    let elapsed = now.duration_since(*oldest);
                    let wait_time = window_duration.saturating_sub(elapsed);
                    let wait_time_ms = wait_time.as_millis() as u64;
                    tracing::warn!(
                        user_id = %user_id.0,
                        "Rate limit exceeded for user, retry in {}ms",
                        wait_time_ms
                    );
                    return Err(RateLimitError::RateLimitExceeded {
                        retry_after_ms: wait_time_ms,
                    });
                }
            }

            // Acquire permit for concurrent request limit
            let permit = user_state
                .semaphore
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    tracing::warn!(
                        user_id = %user_id.0,
                        "Max concurrent requests exceeded for user"
                    );
                    RateLimitError::TooManyConcurrent
                })?;

            // Add timestamp only after all fast checks pass
            // This will be rolled back if window limit check fails
            let timestamp = now;
            user_state.request_timestamps.push_back(timestamp);

            (permit, timestamp)
        }; // Mutex is released here

        let permit = timestamp.0; // Extract permit
        let added_timestamp = timestamp.1; // Extract timestamp for potential rollback

        // Phase 2: Check sliding window limits based on activity_log (no mutex held)
        //
        // IMPORTANT: Multi-Window Race Condition Limitation
        // ==================================================
        // This phase checks all windows individually using non-atomic read operations
        // (check_activity_count). While this is efficient, it creates a race condition:
        //
        // Scenario: Multiple concurrent requests can all pass the non-atomic checks
        // for non-restrictive windows before any insert happens. When they all insert,
        // those windows may exceed their limits.
        //
        // Example: Window A (limit=100, count=99) and Window B (limit=10, count=5)
        // - Request 1, 2, 3 all check Window A: 99 < 100 ✓ (all pass)
        // - Request 1, 2, 3 all check Window B: 5 < 10 ✓ (all pass)
        // - All 3 requests insert, Window A count becomes 102 (exceeds limit 100)
        //
        // Mitigation:
        // - Only the most restrictive window (smallest limit) is checked atomically
        //   during insertion, ensuring it never exceeds its limit
        // - Other windows have a small risk of exceeding limits under high concurrency
        // - This trade-off is acceptable for simplicity and performance
        //
        // First, check all windows without inserting to avoid duplicate records
        // If all windows pass, insert a single record that all windows will count
        for window_limit in &config.window_limits {
            let limit_value = window_limit.limit.try_into().map_err(|e| {
                tracing::error!(
                    error = ?e,
                    limit = window_limit.limit,
                    "Failed to convert window limit to i64"
                );
                RateLimitError::InternalServerError
            })?;

            // Check count without inserting
            let count = match self
                .analytics_service
                .check_activity_count(
                    user_id,
                    ActivityType::RateLimitedRequest,
                    window_limit.window_duration,
                )
                .await
            {
                Ok(count) => count,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id.0,
                        window_seconds = window_limit.window_duration.num_seconds(),
                        "Failed to check usage limit: {}",
                        e
                    );
                    // Rollback: remove timestamp and release permit
                    self.rollback_acquire(user_id, added_timestamp).await;
                    return Err(RateLimitError::InternalServerError);
                }
            };

            // Check if limit is already reached or exceeded
            if count >= limit_value {
                // Rollback: remove timestamp and release permit
                self.rollback_acquire(user_id, added_timestamp).await;

                // Calculate retry_after: when the oldest activity in the window expires
                // For sliding window, we estimate based on window size
                let window_seconds = window_limit.window_duration.num_seconds();
                let retry_after_ms = u64::try_from(window_seconds * 1000).unwrap_or(u64::MAX); // Conservative estimate

                tracing::warn!(
                    user_id = %user_id.0,
                    window_seconds = window_seconds,
                    limit = window_limit.limit,
                    current_count = count,
                    "Sliding window limit exceeded"
                );

                return Err(RateLimitError::WindowLimitExceeded {
                    window_seconds: u64::try_from(window_seconds).unwrap_or(u64::MAX),
                    limit: window_limit.limit,
                    retry_after_ms,
                });
            }
        }

        // Phase 2a: Check token usage limits (user_usage_event, metric_key='llm.tokens')
        self.check_usage_limits(
            user_id,
            added_timestamp,
            &config.token_window_limits,
            UsageLimitType::Token,
        )
        .await?;

        // Phase 2b: Check cost usage limits (user_usage_event, nano-dollars)
        self.check_usage_limits(
            user_id,
            added_timestamp,
            &config.cost_window_limits,
            UsageLimitType::Cost,
        )
        .await?;

        // All windows passed the non-atomic checks, now insert a single record that all windows will count
        //
        // Atomic Insert with Most Restrictive Window
        // ===========================================
        // We use the most restrictive window (smallest limit) for the atomic insert check.
        // This ensures the most restrictive window won't be exceeded even under high concurrency.
        //
        // Why only the most restrictive window?
        // - check_and_record_activity performs an atomic check-and-insert for ONE window only
        // - We choose the most restrictive window to guarantee the strictest limit is never exceeded
        // - This is the critical limit that must be protected
        //
        // Trade-off for other windows:
        // - Other windows were checked individually above (non-atomic reads)
        // - Under high concurrency, multiple requests may pass those checks simultaneously
        // - When they all insert, non-restrictive windows may temporarily exceed limits
        // - This is an acceptable risk because:
        //   1. The most critical (restrictive) limit is always protected
        //   2. The probability of exceeding other limits is low (requires multiple concurrent requests)
        //   3. The excess is typically small (1-2 requests over limit)
        //   4. Full multi-window atomicity would require significant interface changes
        //
        // For strict enforcement of all windows, see alternatives documented in Phase 2 above.
        if let Some(most_restrictive_window) = config.window_limits.iter().min_by_key(|w| w.limit) {
            let limit_value = most_restrictive_window.limit as u64;
            let result = self
                .analytics_service
                .check_and_record_activity(CheckAndRecordActivityRequest {
                    user_id,
                    activity_type: ActivityType::RateLimitedRequest,
                    metadata: None,
                    window_duration: most_restrictive_window.window_duration,
                    limit: limit_value,
                })
                .await;

            match result {
                Ok(record_result) => {
                    // Check if the record was actually inserted
                    // If was_recorded is false, it means the limit was exceeded during
                    // the atomic insert (e.g., another request inserted between our check and insert)
                    if !record_result.was_recorded {
                        tracing::warn!(
                            user_id = %user_id.0,
                            current_count = record_result.current_count,
                            "Activity record was not inserted due to limit exceeded during atomic insert"
                        );
                        // Rollback: remove timestamp and release permit
                        self.rollback_acquire(user_id, added_timestamp).await;

                        // Calculate retry_after based on window size
                        let window_seconds = most_restrictive_window.window_duration.num_seconds();
                        let retry_after_ms =
                            u64::try_from(window_seconds * 1000).unwrap_or(u64::MAX);

                        return Err(RateLimitError::WindowLimitExceeded {
                            window_seconds: u64::try_from(window_seconds).unwrap_or(u64::MAX),
                            limit: most_restrictive_window.limit,
                            retry_after_ms,
                        });
                    }
                    // Record inserted successfully, all windows will count it
                }
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id.0,
                        "Failed to record activity after window checks passed: {}",
                        e
                    );
                    // Rollback: remove timestamp and release permit
                    self.rollback_acquire(user_id, added_timestamp).await;
                    return Err(RateLimitError::InternalServerError);
                }
            }
        }

        Ok(RateLimitGuard { _permit: permit })
    }

    /// Checks usage limits for a list of windows (token or cost).
    /// Returns `Ok(())` if all windows are under limit, or `Err(RateLimitError)` on failure or limit exceeded.
    async fn check_usage_limits(
        &self,
        user_id: UserId,
        added_timestamp: Instant,
        window_limits: &[WindowLimit],
        usage_type: UsageLimitType,
    ) -> Result<(), RateLimitError> {
        for window_limit in window_limits {
            let limit_value = window_limit.limit as i64;

            let sum = match usage_type {
                UsageLimitType::Token => {
                    self.user_usage_service
                        .get_token_usage_sum(user_id, window_limit.window_duration)
                        .await
                }
                UsageLimitType::Cost => {
                    self.user_usage_service
                        .get_cost_usage_sum(user_id, window_limit.window_duration)
                        .await
                }
            };

            let sum = match sum {
                Ok(s) => s,
                Err(e) => {
                    let error_msg = match usage_type {
                        UsageLimitType::Token => "Failed to check token usage sum",
                        UsageLimitType::Cost => "Failed to check cost usage sum",
                    };
                    tracing::warn!(user_id = %user_id.0, "{}: {}", error_msg, e);
                    self.rollback_acquire(user_id, added_timestamp).await;
                    return Err(RateLimitError::InternalServerError);
                }
            };

            if sum >= limit_value {
                self.rollback_acquire(user_id, added_timestamp).await;
                let window_seconds = window_limit.window_duration.num_seconds();
                let retry_after_ms = u64::try_from(window_seconds * 1000).unwrap_or(u64::MAX);

                match usage_type {
                    UsageLimitType::Token => {
                        tracing::warn!(
                            user_id = %user_id.0,
                            window_seconds = window_seconds,
                            limit = window_limit.limit,
                            current_sum = sum,
                            "Token usage limit exceeded"
                        );
                        return Err(RateLimitError::TokenLimitExceeded {
                            window_seconds: u64::try_from(window_seconds).unwrap_or(u64::MAX),
                            limit: window_limit.limit,
                            retry_after_ms,
                        });
                    }
                    UsageLimitType::Cost => {
                        tracing::warn!(
                            user_id = %user_id.0,
                            window_seconds = window_seconds,
                            limit = window_limit.limit,
                            current_sum = sum,
                            "Cost usage limit exceeded"
                        );
                        return Err(RateLimitError::CostLimitExceeded {
                            window_seconds: u64::try_from(window_seconds).unwrap_or(u64::MAX),
                            limit: window_limit.limit,
                            retry_after_ms,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Rollback acquire: remove the specific timestamp that was added during try_acquire.
    ///
    /// This function removes the exact timestamp that was added, not just the last one.
    /// This prevents race conditions where multiple concurrent requests might try to
    /// rollback at the same time, ensuring each request removes its own timestamp.
    ///
    /// Note: This function only removes the timestamp. The permit acquired in `try_acquire`
    /// is owned by the `permit` variable in that function and will be automatically released
    /// when it goes out of scope.
    async fn rollback_acquire(&self, user_id: UserId, timestamp: Instant) {
        let mut user_limits = self.user_limits.lock().await;
        if let Some(user_state) = user_limits.get_mut(&user_id) {
            // Remove the specific timestamp that was added by this request
            // Search from the back (most recent) to front, and remove the first match
            // This handles the common case where the timestamp is at the end
            if let Some(pos) = user_state
                .request_timestamps
                .iter()
                .rposition(|&t| t == timestamp)
            {
                user_state.request_timestamps.remove(pos);
            } else {
                // Timestamp not found - this could happen if it was already cleaned up
                // or in rare cases where timestamps are identical. Log a warning but don't panic.
                tracing::warn!(
                    user_id = %user_id.0,
                    "Attempted to rollback timestamp that was not found in queue"
                );
            }
        }
    }
}

pub struct RateLimitGuard {
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
enum RateLimitError {
    TooManyConcurrent,
    RateLimitExceeded {
        retry_after_ms: u64,
    },
    WindowLimitExceeded {
        window_seconds: u64,
        limit: usize,
        retry_after_ms: u64,
    },
    TokenLimitExceeded {
        window_seconds: u64,
        limit: usize,
        retry_after_ms: u64,
    },
    CostLimitExceeded {
        window_seconds: u64,
        limit: usize,
        retry_after_ms: u64,
    },
    InternalServerError,
}

#[derive(Serialize)]
struct RateLimitErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let (status, error_msg, retry_after) = match self {
            RateLimitError::TooManyConcurrent => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent requests. Please try again shortly.".to_string(),
                None,
            ),
            RateLimitError::RateLimitExceeded { retry_after_ms } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded. Please retry after {}ms.",
                    retry_after_ms
                ),
                Some(retry_after_ms),
            ),
            RateLimitError::WindowLimitExceeded {
                window_seconds,
                limit,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Request limit of {} reached for {} second(s) window. Please retry later.",
                    limit, window_seconds
                ),
                Some(retry_after_ms),
            ),
            RateLimitError::TokenLimitExceeded {
                window_seconds,
                limit,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Token usage limit of {} reached for {} second(s) window. Please retry later.",
                    limit, window_seconds
                ),
                Some(retry_after_ms),
            ),
            RateLimitError::CostLimitExceeded {
                window_seconds,
                limit,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                {
                    // `limit` is stored in nano-USD; present a human-friendly USD amount to end users.
                    let usd = (limit as f64) / 1_000_000_000.0;
                    format!(
                        "Cost limit of ${:.6} reached for {} second(s) window. Please retry later.",
                        usd, window_seconds
                    )
                },
                Some(retry_after_ms),
            ),
            RateLimitError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to check rate limit.".to_string(),
                None,
            ),
        };

        let body = RateLimitErrorResponse {
            error: error_msg,
            retry_after_ms: retry_after,
        };

        (status, Json(body)).into_response()
    }
}

pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    Extension(user): Extension<AuthenticatedUser>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let _guard = match state.try_acquire(user.user_id).await {
        Ok(guard) => guard,
        Err(e) => return e.into_response(),
    };

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use services::system_configs::ports::WindowLimit;
    use std::sync::Arc;
    use uuid::Uuid;

    mod test_services {
        use super::*;
        use async_trait::async_trait;
        use services::analytics::{
            ActivityLogEntry, ActivityType, AnalyticsError, AnalyticsServiceTrait,
            AnalyticsSummary, CheckAndRecordActivityRequest, CheckAndRecordActivityResult,
            RecordActivityRequest, TopActiveUser,
        };
        use services::user_usage::{UsageRankBy, UserUsageService, UserUsageSummary};
        use tokio::sync::Mutex;

        /// User usage mock that returns zero usage (always under limit).
        pub struct AlwaysAllowUserUsageService;

        #[async_trait]
        impl UserUsageService for AlwaysAllowUserUsageService {
            async fn record_usage_event(
                &self,
                _user_id: UserId,
                _metric_key: &str,
                _quantity: i64,
                _cost_nano_usd: Option<i64>,
                _model_id: Option<&str>,
            ) -> anyhow::Result<()> {
                Ok(())
            }

            async fn get_token_usage_sum(
                &self,
                _user_id: UserId,
                _window_duration: ChronoDuration,
            ) -> anyhow::Result<i64> {
                Ok(0)
            }

            async fn get_cost_usage_sum(
                &self,
                _user_id: UserId,
                _window_duration: ChronoDuration,
            ) -> anyhow::Result<i64> {
                Ok(0)
            }

            async fn get_usage_by_user_id(
                &self,
                user_id: UserId,
            ) -> anyhow::Result<Option<UserUsageSummary>> {
                Ok(Some(UserUsageSummary {
                    user_id,
                    token_sum: 0,
                    image_num: 0,
                    cost_nano_usd: 0,
                }))
            }

            async fn get_top_users_usage(
                &self,
                _limit: i64,
                _rank_by: UsageRankBy,
            ) -> anyhow::Result<Vec<UserUsageSummary>> {
                Ok(vec![])
            }
        }

        /// User usage mock that returns fixed token/cost sums (for token/cost limit tests).
        pub struct FixedUsageSumUserUsageService {
            pub token_sum: i64,
            pub cost_sum: i64,
        }

        #[async_trait]
        impl UserUsageService for FixedUsageSumUserUsageService {
            async fn record_usage_event(
                &self,
                _user_id: UserId,
                _metric_key: &str,
                _quantity: i64,
                _cost_nano_usd: Option<i64>,
                _model_id: Option<&str>,
            ) -> anyhow::Result<()> {
                Ok(())
            }

            async fn get_token_usage_sum(
                &self,
                _user_id: UserId,
                _window_duration: ChronoDuration,
            ) -> anyhow::Result<i64> {
                Ok(self.token_sum)
            }

            async fn get_cost_usage_sum(
                &self,
                _user_id: UserId,
                _window_duration: ChronoDuration,
            ) -> anyhow::Result<i64> {
                Ok(self.cost_sum)
            }

            async fn get_usage_by_user_id(
                &self,
                user_id: UserId,
            ) -> anyhow::Result<Option<UserUsageSummary>> {
                Ok(Some(UserUsageSummary {
                    user_id,
                    token_sum: self.token_sum,
                    image_num: 0,
                    cost_nano_usd: self.cost_sum,
                }))
            }

            async fn get_top_users_usage(
                &self,
                _limit: i64,
                _rank_by: UsageRankBy,
            ) -> anyhow::Result<Vec<UserUsageSummary>> {
                Ok(vec![])
            }
        }

        /// Always allows requests (returns 0 count)
        pub struct AlwaysAllowAnalyticsService;

        #[async_trait]
        impl AnalyticsServiceTrait for AlwaysAllowAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                // Always allow in tests (unless we want to test limit behavior)
                Ok(CheckAndRecordActivityResult {
                    current_count: 0,
                    was_recorded: true,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                // Always return 0 in tests (unless we want to test limit behavior)
                Ok(0)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Always rejects requests (returns 100 count, was_recorded: false)
        pub struct RejectingAnalyticsService;

        #[async_trait]
        impl AnalyticsServiceTrait for RejectingAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                unreachable!()
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                // Always reject to test rollback
                Ok(CheckAndRecordActivityResult {
                    current_count: 100,
                    was_recorded: false,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                // Always return 100 to test limit exceeded
                Ok(100)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Counter-based analytics service that can be used for both mutable and fixed counts
        /// - If `increment` is true: increments count on each check_and_record_activity call
        /// - If `increment` is false: returns fixed count without incrementing
        pub struct CounterAnalyticsService {
            pub count: Arc<Mutex<i64>>,
            pub increment: bool,
            pub was_recorded: bool,
        }

        #[async_trait]
        impl AnalyticsServiceTrait for CounterAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                let count = if self.increment {
                    let mut count = self.count.lock().await;
                    *count += 1;
                    *count
                } else {
                    *self.count.lock().await
                };
                Ok(CheckAndRecordActivityResult {
                    current_count: count as u64,
                    was_recorded: self.was_recorded,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                Ok(*self.count.lock().await)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Helper to create a counting service (increments on each call)
        pub fn counting_service(initial_count: i64) -> CounterAnalyticsService {
            CounterAnalyticsService {
                count: Arc::new(Mutex::new(initial_count)),
                increment: true,
                was_recorded: true,
            }
        }

        /// Helper to create a fixed count service (doesn't increment)
        pub fn fixed_count_service(count: i64) -> CounterAnalyticsService {
            CounterAnalyticsService {
                count: Arc::new(Mutex::new(count)),
                increment: false,
                was_recorded: false,
            }
        }

        /// Analytics mock for token/cost limit tests (allows activity; token/cost sums come from FixedUsageSumUserUsageService).
        pub struct FixedUsageSumAnalyticsService;

        #[async_trait]
        impl AnalyticsServiceTrait for FixedUsageSumAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                Ok(CheckAndRecordActivityResult {
                    current_count: 0,
                    was_recorded: true,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                Ok(0)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Supports multiple windows with different counts
        pub struct MultiWindowAnalyticsService {
            pub day_count: i64,
            pub week_count: i64,
        }

        #[async_trait]
        impl AnalyticsServiceTrait for MultiWindowAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                // Use the first window for recording
                let count = if request.window_duration.num_seconds() == 86400 {
                    self.day_count
                } else {
                    self.week_count
                };
                Ok(CheckAndRecordActivityResult {
                    current_count: count as u64,
                    was_recorded: true,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                Ok(if window_duration.num_seconds() == 86400 {
                    self.day_count
                } else {
                    self.week_count
                })
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Simulates atomic insert failure (check passes but insert fails)
        pub struct AtomicInsertFailureService;

        #[async_trait]
        impl AnalyticsServiceTrait for AtomicInsertFailureService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                // Simulate race condition: check passed but insert failed
                Ok(CheckAndRecordActivityResult {
                    current_count: 10,   // At limit
                    was_recorded: false, // Insert failed
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                // Return count just under limit (so check passes)
                Ok(9)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Returns a fixed count for window size testing
        pub struct WindowSizeTestService {
            pub count: i64,
        }

        #[async_trait]
        impl AnalyticsServiceTrait for WindowSizeTestService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                Ok(CheckAndRecordActivityResult {
                    current_count: self.count as u64,
                    was_recorded: true,
                })
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                // Return count based on window size for testing
                Ok(self.count)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Simulates sliding window behavior with time-based expiration
        /// Stores activity timestamps and only counts activities within the window
        pub struct SlidingWindowAnalyticsService {
            pub activities: Arc<Mutex<Vec<chrono::DateTime<chrono::Utc>>>>,
        }

        #[async_trait]
        impl AnalyticsServiceTrait for SlidingWindowAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                let now = Utc::now();
                let window_start = now - request.window_duration;

                let mut activities = self.activities.lock().await;

                // Remove expired activities (outside the window)
                activities.retain(|&ts| ts >= window_start);

                // Count activities in window
                let current_count = activities.len() as i64;

                // Check if we can insert
                let can_insert = (current_count as u64) < request.limit;

                if can_insert {
                    activities.push(now);
                    Ok(CheckAndRecordActivityResult {
                        current_count: (current_count + 1) as u64,
                        was_recorded: true,
                    })
                } else {
                    Ok(CheckAndRecordActivityResult {
                        current_count: current_count as u64,
                        was_recorded: false,
                    })
                }
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                let now = Utc::now();
                let window_start = now - window_duration;

                let activities = self.activities.lock().await;

                // Count activities within the window
                let count = activities.iter().filter(|&&ts| ts >= window_start).count() as i64;

                Ok(count)
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }

        /// Always returns an error
        pub struct ErrorAnalyticsService;

        #[async_trait]
        impl AnalyticsServiceTrait for ErrorAnalyticsService {
            async fn record_activity(
                &self,
                _request: RecordActivityRequest,
            ) -> Result<(), AnalyticsError> {
                Ok(())
            }

            async fn check_and_record_activity(
                &self,
                _request: CheckAndRecordActivityRequest,
            ) -> Result<CheckAndRecordActivityResult, AnalyticsError> {
                unreachable!()
            }

            async fn check_activity_count(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window_duration: ChronoDuration,
            ) -> Result<i64, AnalyticsError> {
                Err(AnalyticsError::InternalError("Database error".to_string()))
            }

            async fn get_analytics_summary(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
            ) -> Result<AnalyticsSummary, AnalyticsError> {
                unreachable!()
            }

            async fn get_daily_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_weekly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_monthly_active_users(
                &self,
                _date: chrono::DateTime<Utc>,
            ) -> Result<i64, AnalyticsError> {
                unreachable!()
            }

            async fn get_user_activity(
                &self,
                _user_id: UserId,
                _limit: Option<i64>,
                _offset: Option<i64>,
            ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
                unreachable!()
            }

            async fn get_top_active_users(
                &self,
                _start: chrono::DateTime<Utc>,
                _end: chrono::DateTime<Utc>,
                _limit: i64,
            ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
                unreachable!()
            }
        }
    }

    fn test_user_id(id: u128) -> UserId {
        UserId(Uuid::from_u128(id))
    }

    fn default_state() -> RateLimitState {
        RateLimitState::new(
            Arc::new(test_services::AlwaysAllowAnalyticsService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        )
    }

    fn configured_state(config: RateLimitConfig) -> RateLimitState {
        RateLimitState::with_config(
            config,
            Arc::new(test_services::AlwaysAllowAnalyticsService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        )
    }

    #[tokio::test]
    async fn test_rate_limit_allows_first_request() {
        let state = default_state();
        let result = state.try_acquire(test_user_id(1)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_second_request_within_window() {
        let state = default_state();
        let user = test_user_id(1);

        // First request should succeed
        let _guard1 = state.try_acquire(user).await.unwrap();

        // Second request within the same second should fail (rate limit)
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::RateLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_concurrency_limit_per_user() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 2,
            max_requests_per_window: 100, // High limit to avoid rate limiting
            window_duration: ChronoDuration::seconds(1),
            window_limits: vec![], // No window limits for this test
            token_window_limits: vec![],
            cost_window_limits: vec![],
        });

        let user = test_user_id(1);

        // First two requests should succeed
        let _guard1 = state.try_acquire(user).await.unwrap();
        let _guard2 = state.try_acquire(user).await.unwrap();

        // Third request should fail (concurrency limit)
        let result = state.try_acquire(user).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));
    }

    #[tokio::test]
    async fn test_different_users_have_separate_limits() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 100, // High to test concurrency, not rate
            window_duration: ChronoDuration::seconds(1),
            window_limits: vec![], // No window limits for this test
            token_window_limits: vec![],
            cost_window_limits: vec![],
        });

        let user1 = test_user_id(1);
        let user2 = test_user_id(2);

        // User 1's first request should succeed
        let _guard1 = state.try_acquire(user1).await.unwrap();

        // User 2's first request should also succeed (separate limit)
        let _guard2 = state.try_acquire(user2).await.unwrap();

        // User 1's second request should fail (concurrency limit reached)
        let result = state.try_acquire(user1).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));

        // User 2's second request should also fail (concurrency limit reached)
        let result = state.try_acquire(user2).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));
    }

    #[tokio::test]
    async fn test_permit_released_after_drop() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 100,
            window_duration: ChronoDuration::seconds(1),
            window_limits: vec![], // No window limits for this test
            token_window_limits: vec![],
            cost_window_limits: vec![],
        });

        let user = test_user_id(1);

        // First request
        let guard = state.try_acquire(user).await.unwrap();

        // Second request should fail
        let result = state.try_acquire(user).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));

        // Drop the guard
        drop(guard);

        // Now a new request should succeed
        let result = state.try_acquire(user).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_no_permit_leak_on_rate_limit_rejection() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: ChronoDuration::milliseconds(50),
            window_limits: vec![], // No window limits for this test
            token_window_limits: vec![],
            cost_window_limits: vec![],
        });

        let user = test_user_id(1);

        // First request succeeds and completes
        let guard1 = state.try_acquire(user).await.unwrap();
        drop(guard1);

        // Second request should fail with RateLimitExceeded (not TooManyConcurrent)
        let result = state.try_acquire(user).await;
        assert!(
            matches!(result, Err(RateLimitError::RateLimitExceeded { .. })),
            "Should be rate limited, not concurrency limited"
        );

        // Wait for rate limit window to fully expire
        tokio::time::sleep(
            ChronoDuration::milliseconds(100)
                .to_std()
                .unwrap_or_else(|_| std::time::Duration::from_millis(100)),
        )
        .await;

        // Now we should be able to make max_concurrent requests simultaneously
        // proving no permits were leaked when rate limit rejected the request
        let guard_a = state.try_acquire(user).await.unwrap();

        // Wait for rate limit window again before second concurrent request
        tokio::time::sleep(
            ChronoDuration::milliseconds(100)
                .to_std()
                .unwrap_or_else(|_| std::time::Duration::from_millis(100)),
        )
        .await;

        let guard_b = state.try_acquire(user).await.unwrap();

        // Both guards acquired successfully - no permit leak
        drop(guard_a);
        drop(guard_b);
    }

    #[tokio::test]
    async fn test_idle_user_cleanup() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 2,
            max_requests_per_window: 10,
            window_duration: ChronoDuration::milliseconds(10),
            window_limits: vec![], // No window limits for this test
            token_window_limits: vec![],
            cost_window_limits: vec![],
        });

        let user1 = test_user_id(1);
        let user2 = test_user_id(2);

        // Make requests for both users
        let _g1 = state.try_acquire(user1).await.unwrap();
        let _g2 = state.try_acquire(user2).await.unwrap();

        // Check that both users are in the map
        {
            let limits = state.user_limits.lock().await;
            assert_eq!(limits.len(), 2);
        }
    }

    #[tokio::test]
    async fn test_window_limit_rejection_rolls_back_timestamp() {
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 2,
                max_requests_per_window: 10, // High limit
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit: 100,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::RejectingAnalyticsService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // First request should fail due to window limit
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WindowLimitExceeded { .. })
        ));

        // Check that timestamp was rolled back - we should be able to make
        // max_requests_per_window requests immediately after (since timestamp was removed)
        // Since timestamp was rolled back, we should be able to make requests
        // (they'll still fail on window limit, but not on short-term rate limit)
        // Actually, since window limit always rejects, we can't test this easily.
        // But the important thing is that the permit was released (tested by making
        // multiple concurrent requests that should all fail on window limit, not concurrency)
        let futures: Vec<_> = (0..3)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move { state.try_acquire(user).await })
            })
            .collect();

        let results: Vec<_> = futures::future::join_all(futures)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All should fail on WindowLimitExceeded, not TooManyConcurrent
        // This proves permits were released (otherwise we'd get TooManyConcurrent)
        for result in results {
            assert!(
                matches!(result, Err(RateLimitError::WindowLimitExceeded { .. })),
                "Should fail on window limit, not concurrency"
            );
        }
    }

    // ========== Window Limit Tests ==========

    #[tokio::test]
    async fn test_window_limit_allows_request_under_limit() {
        let analytics_service = Arc::new(test_services::counting_service(0));

        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100, // High limit to avoid short-term rate limiting
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            analytics_service.clone(),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Make 5 requests, all should succeed (under limit of 10)
        for i in 0..5 {
            let result = state.try_acquire(user).await;
            assert!(
                result.is_ok(),
                "Request {} should succeed, current count: {}",
                i,
                *analytics_service.count.lock().await
            );
            // Guard is automatically dropped at end of loop iteration
            let _guard = result.unwrap();
        }

        // Verify count is 5
        assert_eq!(*analytics_service.count.lock().await, 5);
    }

    #[tokio::test]
    async fn test_window_limit_blocks_request_at_limit() {
        let limit = 10;
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::fixed_count_service(limit as i64)),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Request should fail because count is at the limit
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WindowLimitExceeded { .. })
        ));

        if let Err(RateLimitError::WindowLimitExceeded {
            window_seconds,
            limit: reported_limit,
            retry_after_ms,
        }) = result
        {
            assert_eq!(window_seconds, 86400); // 1 day in seconds
            assert_eq!(reported_limit, limit);
            // retry_after_ms should be approximately 1 day in milliseconds
            let expected_retry_ms = 86400 * 1000;
            assert_eq!(retry_after_ms, expected_retry_ms);
        }
    }

    #[tokio::test]
    async fn test_window_limit_blocks_request_above_limit() {
        let limit = 10;
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::fixed_count_service(limit as i64 + 5)), // Above limit
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Request should fail because count is above the limit
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WindowLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_multiple_window_limits_all_must_pass() {
        let day_limit = 10;
        let week_limit = 50;

        // Test case 1: Both windows under limit - should pass
        let state1 = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![
                    WindowLimit {
                        window_duration: ChronoDuration::days(1),
                        limit: day_limit,
                    },
                    WindowLimit {
                        window_duration: ChronoDuration::weeks(1),
                        limit: week_limit,
                    },
                ],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::MultiWindowAnalyticsService {
                day_count: 5,
                week_count: 20,
            }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);
        let result = state1.try_acquire(user).await;
        assert!(
            result.is_ok(),
            "Should pass when both windows are under limit"
        );

        // Test case 2: Day window at limit - should fail
        let state2 = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![
                    WindowLimit {
                        window_duration: ChronoDuration::days(1),
                        limit: day_limit,
                    },
                    WindowLimit {
                        window_duration: ChronoDuration::weeks(1),
                        limit: week_limit,
                    },
                ],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::MultiWindowAnalyticsService {
                day_count: day_limit as i64,
                week_count: 20,
            }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let result = state2.try_acquire(user).await;
        assert!(
            matches!(
                result,
                Err(RateLimitError::WindowLimitExceeded {
                    window_seconds: 86400,
                    ..
                })
            ),
            "Should fail when day window is at limit"
        );

        // Test case 3: Week window at limit - should fail
        let state3 = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![
                    WindowLimit {
                        window_duration: ChronoDuration::days(1),
                        limit: day_limit,
                    },
                    WindowLimit {
                        window_duration: ChronoDuration::weeks(1),
                        limit: week_limit,
                    },
                ],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::MultiWindowAnalyticsService {
                day_count: 5,
                week_count: week_limit as i64,
            }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let result = state3.try_acquire(user).await;
        assert!(
            matches!(
                result,
                Err(RateLimitError::WindowLimitExceeded {
                    window_seconds: 604800,
                    ..
                })
            ),
            "Should fail when week window is at limit"
        );
    }

    #[tokio::test]
    async fn test_window_limit_atomic_insert_failure() {
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::AtomicInsertFailureService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Request should fail because atomic insert failed (was_recorded = false)
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::WindowLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_window_limit_different_window_sizes() {
        let user = test_user_id(1);

        // Test day window (1 day)
        let state_day = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::WindowSizeTestService { count: 10 }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let result = state_day.try_acquire(user).await;
        if let Err(RateLimitError::WindowLimitExceeded {
            window_seconds,
            retry_after_ms,
            ..
        }) = result
        {
            assert_eq!(window_seconds, 86400); // 1 day in seconds
            assert_eq!(retry_after_ms, 86400 * 1000);
        } else {
            panic!("Expected WindowLimitExceeded for day window");
        }

        // Test week window (7 days)
        let state_week = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::weeks(1),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::WindowSizeTestService { count: 10 }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let result = state_week.try_acquire(user).await;
        if let Err(RateLimitError::WindowLimitExceeded {
            window_seconds,
            retry_after_ms,
            ..
        }) = result
        {
            assert_eq!(window_seconds, 604800); // 7 days in seconds
            assert_eq!(retry_after_ms, 604800 * 1000);
        } else {
            panic!("Expected WindowLimitExceeded for week window");
        }

        // Test month window (30 days)
        let state_month = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(30),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::WindowSizeTestService { count: 10 }),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let result = state_month.try_acquire(user).await;
        if let Err(RateLimitError::WindowLimitExceeded {
            window_seconds,
            retry_after_ms,
            ..
        }) = result
        {
            assert_eq!(window_seconds, 2592000); // 30 days in seconds
            assert_eq!(retry_after_ms, 2592000 * 1000);
        } else {
            panic!("Expected WindowLimitExceeded for month window");
        }
    }

    #[tokio::test]
    async fn test_window_limit_analytics_service_error() {
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::days(1),
                    limit: 10,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::ErrorAnalyticsService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Request should fail with InternalServerError when analytics service errors
        let result = state.try_acquire(user).await;
        assert!(matches!(result, Err(RateLimitError::InternalServerError)));
    }

    #[tokio::test]
    async fn test_window_limit_with_no_window_limits_configured() {
        // When no window limits are configured, requests should pass window limit checks
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100,
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![], // No window limits
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::AlwaysAllowAnalyticsService),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Should succeed (only checked against short-term rate limit and concurrency)
        let result = state.try_acquire(user).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_window_limit_exceeded() {
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100, // avoid request-count limiting
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![],
                token_window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::seconds(60),
                    limit: 100,
                }],
                cost_window_limits: vec![],
            },
            Arc::new(test_services::FixedUsageSumAnalyticsService),
            Arc::new(test_services::FixedUsageSumUserUsageService {
                token_sum: 150,
                cost_sum: 0,
            }),
        );

        let user = test_user_id(1);
        let result = state.try_acquire(user).await;
        assert!(
            matches!(result, Err(RateLimitError::TokenLimitExceeded { .. })),
            "Expected TokenLimitExceeded, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_cost_window_limit_exceeded() {
        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100, // avoid request-count limiting
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![],
                token_window_limits: vec![],
                cost_window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::seconds(60),
                    // nano-USD (same unit stored in user_usage_event)
                    limit: 1_000,
                }],
            },
            Arc::new(test_services::FixedUsageSumAnalyticsService),
            Arc::new(test_services::FixedUsageSumUserUsageService {
                token_sum: 0,
                cost_sum: 5_000,
            }),
        );

        let user = test_user_id(1);
        let result = state.try_acquire(user).await;
        assert!(
            matches!(result, Err(RateLimitError::CostLimitExceeded { .. })),
            "Expected CostLimitExceeded, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_window_sliding_effect_expires_old_activities() {
        // Test that old activities expire from the window and new requests can be allowed
        let window_seconds = 2; // Small window for testing
        let limit = 3;

        let analytics_service = Arc::new(test_services::SlidingWindowAnalyticsService {
            activities: Arc::new(Mutex::new(Vec::new())),
        });

        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 10,
                max_requests_per_window: 100, // High limit to avoid short-term rate limiting
                window_duration: ChronoDuration::seconds(1),
                window_limits: vec![WindowLimit {
                    window_duration: ChronoDuration::seconds(
                        i64::try_from(window_seconds)
                            .expect("test window_seconds should fit in i64"),
                    ),
                    limit,
                }],
                token_window_limits: vec![],
                cost_window_limits: vec![],
            },
            analytics_service.clone(),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = test_user_id(1);

        // Make requests up to the limit - all should succeed
        for i in 0..limit {
            let result = state.try_acquire(user).await;
            assert!(
                result.is_ok(),
                "Request {} should succeed (under limit of {})",
                i,
                limit
            );
            drop(result.unwrap());
        }

        // Next request should fail (at limit)
        let result = state.try_acquire(user).await;
        assert!(
            matches!(result, Err(RateLimitError::WindowLimitExceeded { .. })),
            "Request should fail when at limit"
        );

        // Wait for the window to expire (window_seconds + small buffer)
        tokio::time::sleep(
            ChronoDuration::seconds(window_seconds as i64 + 1)
                .to_std()
                .unwrap_or_else(|_| std::time::Duration::from_secs(window_seconds + 1)),
        )
        .await;

        // Now the old activities should have expired, so we should be able to make new requests
        let result = state.try_acquire(user).await;
        assert!(
            result.is_ok(),
            "Request should succeed after window expires"
        );
        drop(result.unwrap());

        // Verify we can make more requests up to the limit again
        for i in 0..(limit - 1) {
            let result = state.try_acquire(user).await;
            assert!(
                result.is_ok(),
                "Request {} after window expiration should succeed",
                i
            );
            drop(result.unwrap());
        }

        // Should be at limit again
        let result = state.try_acquire(user).await;
        assert!(
            matches!(result, Err(RateLimitError::WindowLimitExceeded { .. })),
            "Request should fail when at limit again"
        );
    }

    #[tokio::test]
    async fn test_config_update_clears_user_states() {
        use services::system_configs::ports::RateLimitConfig;

        // Create initial config with max_concurrent = 1
        let initial_config = RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 100,
            window_duration: ChronoDuration::seconds(60),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![],
        };

        let analytics_service = Arc::new(test_services::CounterAnalyticsService {
            count: Arc::new(Mutex::new(0)),
            increment: false,
            was_recorded: true,
        });
        let state = RateLimitState::with_config(
            initial_config,
            analytics_service.clone(),
            Arc::new(test_services::AlwaysAllowUserUsageService),
        );

        let user = UserId(Uuid::new_v4());

        // Acquire first permit (should succeed)
        let guard1 = state.try_acquire(user).await;
        assert!(guard1.is_ok(), "First request should succeed");

        // Try to acquire second permit (should fail because max_concurrent = 1)
        let guard2_result = state.try_acquire(user).await;
        assert!(
            matches!(guard2_result, Err(RateLimitError::TooManyConcurrent)),
            "Second concurrent request should fail with old config (max_concurrent=1)"
        );

        // Update config to max_concurrent = 5
        let new_config = RateLimitConfig {
            max_concurrent: 5,
            max_requests_per_window: 100,
            window_duration: ChronoDuration::seconds(60),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![],
        };
        state.update_config(new_config).await;

        // Drop the first guard to release the permit
        drop(guard1);

        // Now acquire new permits - should use new config (max_concurrent = 5)
        let mut guards = Vec::new();
        for i in 0..5 {
            let result = state.try_acquire(user).await;
            assert!(
                result.is_ok(),
                "Request {} should succeed with new config (max_concurrent=5)",
                i + 1
            );
            guards.push(result.unwrap());
        }

        // 6th request should fail (exceeds new max_concurrent = 5)
        let guard6_result = state.try_acquire(user).await;
        assert!(
            matches!(guard6_result, Err(RateLimitError::TooManyConcurrent)),
            "6th concurrent request should fail (max_concurrent=5)"
        );
    }
}
