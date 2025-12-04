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
use services::UserId;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Configuration for the rate limiter
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum number of concurrent requests per user
    pub max_concurrent: usize,
    /// Maximum requests per window per user
    pub max_requests_per_window: usize,
    /// Time window for rate limiting
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
        }
    }
}

/// Per-user rate limit tracking
struct UserRateLimitState {
    /// Semaphore for concurrency limiting (per user)
    semaphore: Arc<Semaphore>,
    /// Sliding window timestamps for rate limiting (per user)
    request_timestamps: VecDeque<Instant>,
}

impl UserRateLimitState {
    fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            request_timestamps: VecDeque::new(),
        }
    }
}

/// Shared state for per-user rate limiting
#[derive(Clone)]
pub struct RateLimitState {
    /// Per-user rate limit tracking
    user_limits: Arc<Mutex<HashMap<UserId, UserRateLimitState>>>,
    /// Configuration
    config: Arc<RateLimitConfig>,
}

impl RateLimitState {
    /// Create a new rate limit state with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a new rate limit state with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    /// Try to acquire a permit for the request for a specific user
    /// Returns Ok(guard) if the request is allowed, Err with the appropriate response otherwise
    async fn try_acquire(&self, user_id: UserId) -> Result<RateLimitGuard, RateLimitError> {
        let mut user_limits = self.user_limits.lock().await;

        // Get or create user's rate limit state
        let user_state = user_limits
            .entry(user_id.clone())
            .or_insert_with(|| UserRateLimitState::new(self.config.max_concurrent));

        // First, check concurrency limit
        let permit = match user_state.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    user_id = %user_id.0,
                    "Rate limit: max concurrent requests ({}) exceeded for user",
                    self.config.max_concurrent
                );
                return Err(RateLimitError::TooManyConcurrent);
            }
        };

        // Then, check rate limit (sliding window)
        let now = Instant::now();

        // Remove timestamps outside the window
        while let Some(front) = user_state.request_timestamps.front() {
            if now.duration_since(*front) > self.config.window_duration {
                user_state.request_timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check if we're within the rate limit
        if user_state.request_timestamps.len() >= self.config.max_requests_per_window {
            // Calculate time until next request is allowed
            if let Some(oldest) = user_state.request_timestamps.front() {
                let wait_time = self.config.window_duration - now.duration_since(*oldest);
                tracing::warn!(
                    user_id = %user_id.0,
                    "Rate limit: {} requests per {:?} exceeded for user, retry in {:?}",
                    self.config.max_requests_per_window,
                    self.config.window_duration,
                    wait_time
                );
                return Err(RateLimitError::RateLimitExceeded {
                    retry_after_ms: wait_time.as_millis() as u64,
                });
            }
        }

        // Record this request
        user_state.request_timestamps.push_back(now);

        Ok(RateLimitGuard { _permit: permit })
    }
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that holds the semaphore permit for the duration of the request
pub struct RateLimitGuard {
    _permit: OwnedSemaphorePermit,
}

/// Errors that can occur during rate limiting
#[derive(Debug)]
enum RateLimitError {
    TooManyConcurrent,
    RateLimitExceeded { retry_after_ms: u64 },
}

/// Error response for rate limit exceeded
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
        };

        let body = RateLimitErrorResponse {
            error: error_msg,
            retry_after_ms: retry_after,
        };

        (status, Json(body)).into_response()
    }
}

/// Per-user rate limiting middleware
pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    Extension(user): Extension<AuthenticatedUser>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let user_id = user.user_id;

    let _guard = match state.try_acquire(user_id.clone()).await {
        Ok(guard) => guard,
        Err(e) => return e.into_response(),
    };

    tracing::debug!(user_id = %user_id.0, "Rate limit: request permitted");

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_user_id(id: u128) -> UserId {
        UserId(Uuid::from_u128(id))
    }

    #[tokio::test]
    async fn test_rate_limit_allows_first_request() {
        let state = RateLimitState::new();
        let result = state.try_acquire(test_user_id(1)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_second_request_within_window() {
        let state = RateLimitState::new();
        let user = test_user_id(1);

        // First request should succeed
        let _guard1 = state.try_acquire(user.clone()).await.unwrap();

        // Second request within the same second should fail (rate limit)
        let result = state.try_acquire(user).await;
        assert!(matches!(
            result,
            Err(RateLimitError::RateLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_concurrency_limit_per_user() {
        let state = RateLimitState::with_config(RateLimitConfig {
            max_concurrent: 2,
            max_requests_per_window: 100, // High limit to avoid rate limiting
            window_duration: Duration::from_secs(1),
        });

        let user = test_user_id(1);

        // First two requests should succeed
        let _guard1 = state.try_acquire(user.clone()).await.unwrap();
        let _guard2 = state.try_acquire(user.clone()).await.unwrap();

        // Third request should fail (concurrency limit)
        let result = state.try_acquire(user).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));
    }

    #[tokio::test]
    async fn test_different_users_have_separate_limits() {
        let state = RateLimitState::with_config(RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
        });

        let user1 = test_user_id(1);
        let user2 = test_user_id(2);

        // User 1's first request should succeed
        let _guard1 = state.try_acquire(user1.clone()).await.unwrap();

        // User 2's first request should also succeed (separate limit)
        let _guard2 = state.try_acquire(user2.clone()).await.unwrap();

        // User 1's second request should fail (their limit is reached)
        let result = state.try_acquire(user1).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));

        // User 2's second request should also fail (their limit is reached)
        let result = state.try_acquire(user2).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));
    }

    #[tokio::test]
    async fn test_permit_released_after_drop() {
        let state = RateLimitState::with_config(RateLimitConfig {
            max_concurrent: 1,
            max_requests_per_window: 100, // High limit to avoid rate limiting
            window_duration: Duration::from_secs(1),
        });

        let user = test_user_id(1);

        // First request
        let guard = state.try_acquire(user.clone()).await.unwrap();

        // Second request should fail
        let result = state.try_acquire(user.clone()).await;
        assert!(matches!(result, Err(RateLimitError::TooManyConcurrent)));

        // Drop the guard
        drop(guard);

        // Now a new request should succeed
        let result = state.try_acquire(user).await;
        assert!(result.is_ok());
    }
}
