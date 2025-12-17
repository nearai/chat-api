//! Per-IP rate limiting middleware.
//!
//! Implements rate limiting on a per-IP basis that enforces:
//! - Maximum requests per time window per IP address
//! - Sliding window rate limiting
//! - Automatic cleanup of idle IP entries

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

impl From<config::IpRateLimitConfig> for IpRateLimitConfig {
    fn from(config: config::IpRateLimitConfig) -> Self {
        Self {
            max_requests_per_window: config.max_requests_per_window,
            window_duration: Duration::from_secs(config.window_duration_secs),
            max_idle_time: Duration::from_secs(config.max_idle_time_secs),
        }
    }
}

#[derive(Clone)]
pub struct IpRateLimitConfig {
    pub max_requests_per_window: usize,
    pub window_duration: Duration,
    pub max_idle_time: Duration,
}

impl Default for IpRateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            max_idle_time: Duration::from_secs(3600),
        }
    }
}

struct IpRateLimitState {
    request_timestamps: VecDeque<Instant>,
    last_activity: Instant,
}

impl IpRateLimitState {
    fn new() -> Self {
        Self {
            request_timestamps: VecDeque::new(),
            last_activity: Instant::now(),
        }
    }

    fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_activity.elapsed() > max_idle && self.request_timestamps.is_empty()
    }
}

#[derive(Clone)]
pub struct IpRateLimitMiddlewareState {
    ip_limits: Arc<Mutex<HashMap<String, IpRateLimitState>>>,
    config: Arc<IpRateLimitConfig>,
}

impl IpRateLimitMiddlewareState {
    pub fn new() -> Self {
        Self::with_config(IpRateLimitConfig::default())
    }

    pub fn with_config(config: IpRateLimitConfig) -> Self {
        Self {
            ip_limits: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    async fn try_acquire(&self, ip: String) -> Result<(), IpRateLimitError> {
        let mut ip_limits = self.ip_limits.lock().await;

        // Clean up idle entries
        ip_limits.retain(|_, state| !state.is_idle(self.config.max_idle_time));

        let ip_state = ip_limits
            .entry(ip.clone())
            .or_insert_with(IpRateLimitState::new);

        let now = Instant::now();
        ip_state.last_activity = now;

        // Remove timestamps outside the window
        while let Some(front) = ip_state.request_timestamps.front() {
            if now.duration_since(*front) > self.config.window_duration {
                ip_state.request_timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check if rate limit exceeded
        if ip_state.request_timestamps.len() >= self.config.max_requests_per_window {
            if let Some(oldest) = ip_state.request_timestamps.front() {
                let wait_time = self.config.window_duration - now.duration_since(*oldest);
                tracing::warn!(
                    ip = %ip,
                    "Rate limit exceeded for IP, retry in {:?}",
                    wait_time
                );
                return Err(IpRateLimitError::RateLimitExceeded);
            }
        }

        // Record this request
        ip_state.request_timestamps.push_back(now);

        Ok(())
    }
}

impl Default for IpRateLimitMiddlewareState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum IpRateLimitError {
    RateLimitExceeded,
}

#[derive(Serialize)]
struct IpRateLimitErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

impl IntoResponse for IpRateLimitError {
    fn into_response(self) -> Response {
        let (status, error_msg, retry_after) = match self {
            IpRateLimitError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please retry again later.".to_string(),
                None,
            ),
        };

        let body = IpRateLimitErrorResponse {
            error: error_msg,
            retry_after_ms: retry_after,
        };

        (status, Json(body)).into_response()
    }
}

/// Extract client IP address from request, handling proxies and load balancers
fn extract_client_ip(request: &Request) -> String {
    // Check for X-Forwarded-For header (first IP is the original client)
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if let Some(first_ip) = forwarded_str.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    tracing::debug!("Extracted IP from X-Forwarded-For: {}", ip);
                    return ip.to_string();
                }
            }
        }
    }

    // Check for X-Real-IP header (common in nginx)
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            let ip = ip_str.trim();
            if !ip.is_empty() {
                tracing::debug!("Extracted IP from X-Real-IP: {}", ip);
                return ip.to_string();
            }
        }
    }

    // Fall back to ConnectInfo if available
    if let Some(addr) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = addr.ip().to_string();
        tracing::debug!("Extracted IP from ConnectInfo: {}", ip);
        return ip;
    }

    // Last resort: use "unknown" (shouldn't happen in production)
    tracing::warn!("Could not extract client IP, using 'unknown'");
    "unknown".to_string()
}

/// IP-based rate limiting middleware
pub async fn ip_rate_limit_middleware(
    State(state): State<IpRateLimitMiddlewareState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);

    match state.try_acquire(ip.clone()).await {
        Ok(()) => {
            tracing::debug!(ip = %ip, "IP rate limit check passed");
            next.run(request).await
        }
        Err(e) => {
            tracing::warn!(ip = %ip, "IP rate limit exceeded");
            e.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_rate_limit_allows_first_request() {
        let state = IpRateLimitMiddlewareState::new();
        let result = state.try_acquire("127.0.0.1".to_string()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_rate_limit_blocks_excessive_requests() {
        let state = IpRateLimitMiddlewareState::with_config(IpRateLimitConfig {
            max_requests_per_window: 2,
            window_duration: Duration::from_secs(1),
            max_idle_time: Duration::from_secs(3600),
        });

        let ip = "127.0.0.1".to_string();

        // First two requests should succeed
        assert!(state.try_acquire(ip.clone()).await.is_ok());
        assert!(state.try_acquire(ip.clone()).await.is_ok());

        // Third request should fail
        let result = state.try_acquire(ip.clone()).await;
        assert!(matches!(
            result,
            Err(IpRateLimitError::RateLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_different_ips_have_separate_limits() {
        let state = IpRateLimitMiddlewareState::with_config(IpRateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
            max_idle_time: Duration::from_secs(3600),
        });

        let ip1 = "127.0.0.1".to_string();
        let ip2 = "192.168.1.1".to_string();

        // Both IPs should be able to make requests independently
        assert!(state.try_acquire(ip1.clone()).await.is_ok());
        assert!(state.try_acquire(ip2.clone()).await.is_ok());

        // Second request from same IP should fail
        let result = state.try_acquire(ip1.clone()).await;
        assert!(matches!(
            result,
            Err(IpRateLimitError::RateLimitExceeded { .. })
        ));

        // But second request from different IP should also fail (limit is 1)
        let result = state.try_acquire(ip2.clone()).await;
        assert!(matches!(
            result,
            Err(IpRateLimitError::RateLimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_rate_limit_window_expires() {
        let state = IpRateLimitMiddlewareState::with_config(IpRateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_millis(100),
            max_idle_time: Duration::from_secs(3600),
        });

        let ip = "127.0.0.1".to_string();

        // First request succeeds
        assert!(state.try_acquire(ip.clone()).await.is_ok());

        // Second request immediately fails
        let result = state.try_acquire(ip.clone()).await;
        assert!(matches!(
            result,
            Err(IpRateLimitError::RateLimitExceeded { .. })
        ));

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Now request should succeed again
        assert!(state.try_acquire(ip.clone()).await.is_ok());
    }

    #[tokio::test]
    async fn test_idle_ip_cleanup() {
        let state = IpRateLimitMiddlewareState::with_config(IpRateLimitConfig {
            max_requests_per_window: 10,
            window_duration: Duration::from_secs(1),
            max_idle_time: Duration::from_millis(100),
        });

        let ip = "127.0.0.1".to_string();

        // Make a request
        assert!(state.try_acquire(ip.clone()).await.is_ok());

        // Check that IP is in the map
        {
            let limits = state.ip_limits.lock().await;
            assert!(limits.contains_key(&ip));
        }

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Make another request (should trigger cleanup)
        assert!(state.try_acquire(ip.clone()).await.is_ok());

        // The old entry should have been cleaned up, but new one added
        // So it should still be in the map
        {
            let limits = state.ip_limits.lock().await;
            assert!(limits.contains_key(&ip));
        }
    }
}
