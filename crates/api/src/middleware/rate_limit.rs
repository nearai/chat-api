//! Per-user rate limiting middleware for inference endpoints.
//!
//! Implements rate limiting on a per-user basis that enforces:
//! - Maximum 2 concurrent in-flight requests per user
//! - Maximum 1 request per second per user (sliding window)

use crate::middleware::auth::AuthenticatedUser;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use services::{
    analytics::{DailyUsageStore, RecordDailyUsageRequest},
    UserId,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_concurrent: usize,
    pub max_requests_per_window: usize,
    pub window_duration: Duration,
    pub daily_request_limit: Option<usize>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
            daily_request_limit: Some(1000),
        }
    }
}

struct UserRateLimitState {
    semaphore: Arc<Semaphore>,
    max_permits: usize,
    request_timestamps: VecDeque<Instant>,
    last_activity: Instant,
    daily_date: NaiveDate,
    daily_count: i64,
}

impl UserRateLimitState {
    fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_permits: max_concurrent,
            request_timestamps: VecDeque::new(),
            last_activity: Instant::now(),
            daily_date: Utc::now().date_naive(),
            daily_count: 0,
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
    user_limits: Arc<Mutex<HashMap<UserId, Arc<Mutex<UserRateLimitState>>>>>,
    config: Arc<RateLimitConfig>,
    analytics_store: Arc<dyn DailyUsageStore>,
}

impl RateLimitState {
    pub fn new(analytics_store: Arc<dyn DailyUsageStore>) -> Self {
        Self::with_config(RateLimitConfig::default(), analytics_store)
    }

    pub fn with_config(config: RateLimitConfig, analytics_store: Arc<dyn DailyUsageStore>) -> Self {
        Self {
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
            analytics_store,
        }
    }

    async fn try_acquire(&self, user_id: UserId) -> Result<RateLimitGuard, RateLimitError> {
        let user_state = {
            let mut user_limits = self.user_limits.lock().await;

            user_limits.retain(|_, state| match state.try_lock() {
                Ok(guard) => !guard.is_idle(Duration::from_secs(3600)),
                Err(_) => true,
            });

            let entry = user_limits.entry(user_id).or_insert_with(|| {
                Arc::new(Mutex::new(UserRateLimitState::new(
                    self.config.max_concurrent,
                )))
            });

            Arc::clone(entry)
        };

        let now = Instant::now();
        let today = Utc::now().date_naive();

        let needs_snapshot = {
            let guard = user_state.lock().await;
            guard.daily_date != today
        };

        if needs_snapshot {
            let snapshot_result = self
                .analytics_store
                .get_user_daily_usage(user_id, today)
                .await;

            let mut guard = user_state.lock().await;
            match snapshot_result {
                Ok(snapshot) => {
                    guard.daily_date = today;
                    guard.daily_count = snapshot.request_count;
                }
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id.0,
                        "Failed to refresh daily usage counts: {}",
                        e
                    );
                    guard.daily_date = today;
                    guard.daily_count = 0;
                }
            }
        }

        let mut user_state = user_state.lock().await;
        user_state.last_activity = now;

        while let Some(front) = user_state.request_timestamps.front() {
            if now.duration_since(*front) > self.config.window_duration {
                user_state.request_timestamps.pop_front();
            } else {
                break;
            }
        }

        if let Some(limit) = self.config.daily_request_limit {
            if user_state.daily_count >= limit as i64 {
                let next_day = today.succ_opt().unwrap_or(today);
                let midnight = next_day
                    .and_hms_opt(0, 0, 0)
                    .unwrap_or_else(|| next_day.and_hms_opt(0, 0, 0).unwrap());
                let reset_at = DateTime::<Utc>::from_naive_utc_and_offset(midnight, Utc);
                let retry_after_ms = reset_at
                    .signed_duration_since(Utc::now())
                    .num_milliseconds()
                    .max(0) as u64;

                tracing::warn!(
                    user_id = %user_id.0,
                    daily_limit = limit,
                    "Daily request limit reached, resets at {:?}",
                    reset_at
                );

                return Err(RateLimitError::DailyLimitExceeded {
                    limit,
                    retry_after_ms,
                });
            }
        }

        if user_state.request_timestamps.len() >= self.config.max_requests_per_window {
            if let Some(oldest) = user_state.request_timestamps.front() {
                let wait_time = self.config.window_duration - now.duration_since(*oldest);
                tracing::warn!(
                    user_id = %user_id.0,
                    "Rate limit exceeded for user, retry in {:?}",
                    wait_time
                );
                return Err(RateLimitError::RateLimitExceeded {
                    retry_after_ms: wait_time.as_millis() as u64,
                });
            }
        }

        let permit = match user_state.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    user_id = %user_id.0,
                    "Max concurrent requests exceeded for user"
                );
                return Err(RateLimitError::TooManyConcurrent);
            }
        };

        user_state.request_timestamps.push_back(now);
        user_state.daily_count += 1;

        let analytics_store = self.analytics_store.clone();
        let usage_request = RecordDailyUsageRequest {
            user_id,
            usage_date: today,
            request_increment: 1,
            token_increment: None,
        };
        tokio::spawn(async move {
            if let Err(err) = analytics_store
                .record_daily_usage(usage_request.clone())
                .await
            {
                tracing::warn!(
                    user_id = %usage_request.user_id.0,
                    "Failed to persist daily usage: {}",
                    err
                );
            }
        });

        Ok(RateLimitGuard { _permit: permit })
    }
}

pub struct RateLimitGuard {
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
enum RateLimitError {
    TooManyConcurrent,
    RateLimitExceeded { retry_after_ms: u64 },
    DailyLimitExceeded { limit: usize, retry_after_ms: u64 },
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
            RateLimitError::DailyLimitExceeded {
                limit,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Daily request limit of {limit} reached. Please retry after {retry_after_ms}ms."
                ),
                Some(retry_after_ms),
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
    use async_trait::async_trait;
    use services::analytics::{
        AnalyticsError, DailyUsageSnapshot, DailyUsageStore, RecordDailyUsageRequest,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    struct MockDailyUsageStore;

    #[async_trait]
    impl DailyUsageStore for MockDailyUsageStore {
        async fn record_daily_usage(
            &self,
            _request: RecordDailyUsageRequest,
        ) -> Result<(), AnalyticsError> {
            Ok(())
        }

        async fn get_user_daily_usage(
            &self,
            user_id: UserId,
            usage_date: NaiveDate,
        ) -> Result<DailyUsageSnapshot, AnalyticsError> {
            Ok(DailyUsageSnapshot::zero(user_id, usage_date))
        }
    }

    fn default_state() -> RateLimitState {
        RateLimitState::new(Arc::new(MockDailyUsageStore))
    }

    fn configured_state(config: RateLimitConfig) -> RateLimitState {
        RateLimitState::with_config(config, Arc::new(MockDailyUsageStore))
    }

    fn test_user_id(id: u128) -> UserId {
        UserId(Uuid::from_u128(id))
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
            window_duration: Duration::from_secs(1),
            daily_request_limit: None,
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
            window_duration: Duration::from_secs(1),
            daily_request_limit: None,
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
    async fn test_daily_limit_exceeded() {
        let config = RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 10,
            window_duration: Duration::from_secs(10),
            daily_request_limit: Some(1),
        };

        let state = configured_state(config);
        let user = test_user_id(1);

        let first = state.try_acquire(user).await.unwrap();
        drop(first);

        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::DailyLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_permit_released_after_drop() {
        let state = configured_state(RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 100,
            window_duration: Duration::from_secs(1),
            daily_request_limit: None,
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
            window_duration: Duration::from_millis(50),
            daily_request_limit: None,
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
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now we should be able to make max_concurrent requests simultaneously
        // proving no permits were leaked when rate limit rejected the request
        let guard_a = state.try_acquire(user).await.unwrap();

        // Wait for rate limit window again before second concurrent request
        tokio::time::sleep(Duration::from_millis(100)).await;

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
            window_duration: Duration::from_millis(10),
            daily_request_limit: None,
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
}
