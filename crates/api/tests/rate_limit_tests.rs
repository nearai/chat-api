mod common;

use chrono::Duration;
use common::{create_test_server_with_config, mock_login, TestServerConfig};
use futures::future::join_all;
use serde_json::json;
use services::system_configs::ports::RateLimitConfig;
use std::sync::Arc;

async fn create_rate_limited_test_server() -> axum_test::TestServer {
    create_test_server_with_config(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
        }),
        ..Default::default()
    })
    .await
}

#[tokio::test]
async fn test_rate_limit_first_request_succeeds() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "rate-limit-test-1@example.com").await;

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "test-model",
            "input": "Hello"
        }))
        .await;

    // Should not be rate limited (may fail for other reasons like no upstream)
    assert_ne!(
        response.status_code(),
        429,
        "First request should not be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limit_blocks_rapid_requests() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "rate-limit-test-2@example.com").await;

    let request_body = json!({
        "model": "test-model",
        "input": "Hello"
    });

    // First request
    let _response1 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&request_body)
        .await;

    // Second request immediately after should be rate limited
    let response2 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response2.status_code(),
        429,
        "Second rapid request should be rate limited"
    );

    let body: serde_json::Value = response2.json();
    assert!(
        body.get("error").is_some(),
        "Rate limit response should have error field"
    );
}

#[tokio::test]
async fn test_rate_limit_per_user_isolation() {
    let server = create_rate_limited_test_server().await;
    let token1 = mock_login(&server, "rate-limit-user-a@example.com").await;
    let token2 = mock_login(&server, "rate-limit-user-b@example.com").await;

    let request_body = json!({
        "model": "test-model",
        "input": "Hello"
    });

    // User 1 first request
    let _response1 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token1)).unwrap(),
        )
        .json(&request_body)
        .await;

    // User 2 first request should NOT be rate limited (separate user)
    let response2 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token2)).unwrap(),
        )
        .json(&request_body)
        .await;

    assert_ne!(
        response2.status_code(),
        429,
        "Different user should not be affected by first user's rate limit"
    );
}

#[tokio::test]
async fn test_non_rate_limited_endpoints_unaffected() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "rate-limit-test-3@example.com").await;

    // Make multiple rapid requests to model/list (not rate limited)
    for i in 0..5 {
        let response = server
            .get("/v1/model/list")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_ne!(
            response.status_code(),
            429,
            "Request {} to non-rate-limited endpoint should not be rate limited",
            i + 1
        );
    }
}

#[tokio::test]
async fn test_concurrent_requests_rate_limited() {
    let server = Arc::new(create_rate_limited_test_server().await);
    let token = Arc::new(mock_login(&server, "rate-limit-concurrent@example.com").await);

    let request_body = json!({
        "model": "test-model",
        "input": "Hello"
    });

    // Spawn 3 concurrent requests
    let futures: Vec<_> = (0..3)
        .map(|_| {
            let server = Arc::clone(&server);
            let token = Arc::clone(&token);
            let body = request_body.clone();
            tokio::spawn(async move {
                server
                    .post("/v1/responses")
                    .add_header(
                        http::HeaderName::from_static("authorization"),
                        http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
                    )
                    .json(&body)
                    .await
                    .status_code()
            })
        })
        .collect();

    let results: Vec<_> = join_all(futures)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // At least one request should be rate limited (429)
    // With config: max 1 req/sec, max 2 concurrent, at least 2 of 3 should be rejected
    let rate_limited_count = results.iter().filter(|&&s| s == 429).count();
    assert!(
        rate_limited_count >= 2,
        "Expected at least 2 rate-limited responses, got {} (results: {:?})",
        rate_limited_count,
        results
    );
}
