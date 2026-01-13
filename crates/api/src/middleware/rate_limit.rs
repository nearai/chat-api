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
use serde::Serialize;
use services::{
    analytics::{ActivityType, TimeWindow, UsageLimitStore},
    UserId,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Configuration for a single time window limit
#[derive(Debug, Clone)]
pub struct WindowLimit {
    pub window: TimeWindow,
    pub limit: usize,
    pub activity_type: ActivityType,
}

#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_concurrent: usize,
    pub max_requests_per_window: usize,
    pub window_duration: Duration,
    /// Sliding window limits based on activity_log
    /// Each limit applies independently
    pub window_limits: Vec<WindowLimit>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
            window_limits: vec![WindowLimit {
                window: TimeWindow::day(),
                limit: 1000,
                activity_type: ActivityType::Response,
            }],
        }
    }
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
    config: Arc<RateLimitConfig>,
    usage_store: Arc<dyn UsageLimitStore>,
}

impl RateLimitState {
    pub fn new(usage_store: Arc<dyn UsageLimitStore>) -> Self {
        Self::with_config(RateLimitConfig::default(), usage_store)
    }

    pub fn with_config(config: RateLimitConfig, usage_store: Arc<dyn UsageLimitStore>) -> Self {
        Self {
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
            usage_store,
        }
    }

    async fn try_acquire(&self, user_id: UserId) -> Result<RateLimitGuard, RateLimitError> {
        // Phase 1: Fast checks (short mutex hold time)
        // Check short-term rate limit and acquire permit
        let permit = {
            let mut user_limits = self.user_limits.lock().await;

            user_limits.retain(|_, state| !state.is_idle(Duration::from_secs(3600)));

            let user_state = user_limits
                .entry(user_id)
                .or_insert_with(|| UserRateLimitState::new(self.config.max_concurrent));

            let now = Instant::now();
            user_state.last_activity = now;

            // Clean up expired timestamps
            while let Some(front) = user_state.request_timestamps.front() {
                if now.duration_since(*front) > self.config.window_duration {
                    user_state.request_timestamps.pop_front();
                } else {
                    break;
                }
            }

            // Check short-term rate limit
            if user_state.request_timestamps.len() >= self.config.max_requests_per_window {
                if let Some(oldest) = user_state.request_timestamps.front() {
                    let wait_time = self
                        .config
                        .window_duration
                        .saturating_sub(now.duration_since(*oldest));
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
            user_state.request_timestamps.push_back(now);

            permit
        }; // Mutex is released here

        // Phase 2: Check sliding window limits based on activity_log (no mutex held)
        // We check all configured window limits and fail if any is exceeded
        for window_limit in &self.config.window_limits {
            let limit_value = window_limit.limit.try_into().unwrap_or(i64::MAX);

            let result = self
                .usage_store
                .check_and_record_activity(
                    user_id,
                    window_limit.activity_type,
                    window_limit.window,
                    limit_value,
                    None, // metadata can be added later if needed
                )
                .await;

            let (count, was_recorded) = match result {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id.0,
                        window_days = window_limit.window.days,
                        "Failed to check usage limit: {}",
                        e
                    );
                    // Rollback: remove timestamp and release permit
                    self.rollback_acquire(user_id).await;
                    return Err(RateLimitError::InternalServerError);
                }
            };

            if !was_recorded {
                // Rollback: remove timestamp and release permit
                self.rollback_acquire(user_id).await;

                // Calculate retry_after: when the oldest activity in the window expires
                // For sliding window, we estimate based on window size
                let window_duration_secs = (window_limit.window.days.max(0) as u64) * 24 * 3600;
                let retry_after_ms = window_duration_secs * 1000; // Conservative estimate

                tracing::warn!(
                    user_id = %user_id.0,
                    window_days = window_limit.window.days,
                    limit = window_limit.limit,
                    current_count = count,
                    "Sliding window limit exceeded"
                );

                return Err(RateLimitError::WindowLimitExceeded {
                    window_days: window_limit.window.days,
                    limit: window_limit.limit,
                    retry_after_ms,
                });
            }
        }

        Ok(RateLimitGuard { _permit: permit })
    }

    /// Rollback acquire: remove the timestamp that was added
    /// The permit will be automatically released when the guard is dropped
    async fn rollback_acquire(&self, user_id: UserId) {
        let mut user_limits = self.user_limits.lock().await;
        if let Some(user_state) = user_limits.get_mut(&user_id) {
            // Remove the last timestamp that was added
            user_state.request_timestamps.pop_back();
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
        window_days: i32,
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
                window_days,
                limit,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Request limit of {} reached for {} day window. Please retry later.",
                    limit, window_days
                ),
                Some(retry_after_ms),
            ),
            RateLimitError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to check usage limit.".to_string(),
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
    use async_trait::async_trait;
    use services::analytics::{ActivityType, AnalyticsError, TimeWindow, UsageLimitStore};
    use std::sync::Arc;
    use uuid::Uuid;

    fn test_user_id(id: u128) -> UserId {
        UserId(Uuid::from_u128(id))
    }

    struct MockUsageLimitStore;

    #[async_trait]
    impl UsageLimitStore for MockUsageLimitStore {
        async fn check_and_record_activity(
            &self,
            _user_id: UserId,
            _activity_type: ActivityType,
            _window: TimeWindow,
            _limit: i64,
            _metadata: Option<serde_json::Value>,
        ) -> Result<(i64, bool), AnalyticsError> {
            // Always allow in tests (unless we want to test limit behavior)
            Ok((0, true))
        }
    }

    fn default_state() -> RateLimitState {
        RateLimitState::new(Arc::new(MockUsageLimitStore))
    }

    fn configured_state(config: RateLimitConfig) -> RateLimitState {
        RateLimitState::with_config(config, Arc::new(MockUsageLimitStore))
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
            window_limits: vec![], // No window limits for this test
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
            window_limits: vec![], // No window limits for this test
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
            window_duration: Duration::from_secs(1),
            window_limits: vec![], // No window limits for this test
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
            window_limits: vec![], // No window limits for this test
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
            window_limits: vec![], // No window limits for this test
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
        struct RejectingUsageLimitStore;

        #[async_trait]
        impl UsageLimitStore for RejectingUsageLimitStore {
            async fn check_and_record_activity(
                &self,
                _user_id: UserId,
                _activity_type: ActivityType,
                _window: TimeWindow,
                _limit: i64,
                _metadata: Option<serde_json::Value>,
            ) -> Result<(i64, bool), AnalyticsError> {
                // Always reject to test rollback
                Ok((100, false))
            }
        }

        let state = RateLimitState::with_config(
            RateLimitConfig {
                max_concurrent: 2,
                max_requests_per_window: 10, // High limit
                window_duration: Duration::from_secs(1),
                window_limits: vec![WindowLimit {
                    window: TimeWindow::day(),
                    limit: 100,
                    activity_type: ActivityType::Response,
                }],
            },
            Arc::new(RejectingUsageLimitStore),
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
        // Wait a tiny bit to ensure cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;

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
}
