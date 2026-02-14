mod common;

use api::routes::api::USER_BANNED_ERROR_MESSAGE;
use chrono::Duration;
use common::{
    create_test_server, create_test_server_and_db, create_test_server_with_config, mock_login,
    restrictive_rate_limit_config, TestServerConfig,
};
use futures::future::join_all;
use serde_json::json;
use services::system_configs::ports::{RateLimitConfig, WindowLimit};
use services::user::ports::UserRepository;
use services::user_usage::{UserUsageRepository, METRIC_KEY_LLM_TOKENS};
use std::future::IntoFuture;
use std::sync::Arc;
use tokio::time::sleep;

async fn create_rate_limited_test_server() -> axum_test::TestServer {
    create_test_server_with_config(TestServerConfig {
        rate_limit_config: Some(restrictive_rate_limit_config()),
        ..Default::default()
    })
    .await
}

/// Test rate limiting for /v1/chat/completions endpoint
#[tokio::test]
async fn test_chat_completions_rate_limit_first_request_succeeds() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "chat-completions-rate-limit-1@example.com").await;

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should not be rate limited (may fail for other reasons like no upstream)
    assert_ne!(
        response.status_code(),
        429,
        "First request should not be rate limited"
    );
}

/// Test rate limiting blocks rapid requests for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_rate_limit_blocks_rapid_requests() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "chat-completions-rate-limit-2@example.com").await;

    let request_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    // First request (spawn so it is in flight when second is sent)
    let response1 = tokio::spawn(
        server
            .post("/v1/chat/completions")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .json(&request_body)
            .into_future(),
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Second request immediately after should be rate limited
    let response2 = server
        .post("/v1/chat/completions")
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

    response1.await.unwrap();
}

/// Test rate limiting per-user isolation for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_rate_limit_per_user_isolation() {
    let server = create_rate_limited_test_server().await;
    let token1 = mock_login(&server, "chat-completions-user-a@example.com").await;
    let token2 = mock_login(&server, "chat-completions-user-b@example.com").await;

    let request_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    // User 1 first request
    let _response1 = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token1)).unwrap(),
        )
        .json(&request_body)
        .await;

    // User 2 first request should NOT be rate limited (separate user)
    let response2 = server
        .post("/v1/chat/completions")
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

/// Test concurrent requests rate limiting for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_concurrent_requests_rate_limited() {
    let server = Arc::new(create_rate_limited_test_server().await);
    let token = Arc::new(mock_login(&server, "chat-completions-concurrent@example.com").await);

    let request_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    // Spawn 3 concurrent requests
    let futures: Vec<_> = (0..3)
        .map(|_| {
            let server = Arc::clone(&server);
            let token = Arc::clone(&token);
            let body = request_body.clone();
            tokio::spawn(async move {
                server
                    .post("/v1/chat/completions")
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

    // With config: max 1 req/sec, max 2 concurrent, at least 2 of 3 should be rate limited (429)
    let rate_limited_count = results.iter().filter(|&&s| s == 429).count();
    assert!(
        rate_limited_count >= 2,
        "Expected at least 2 rate-limited responses, got {} (results: {:?})",
        rate_limited_count,
        results
    );
}

/// Token window limit: when user's token usage exceeds limit, next /v1/chat/completions request returns 429.
#[tokio::test]
async fn test_chat_completions_token_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 100,
            }],
            cost_window_limits: vec![],
        }),
        ..Default::default()
    })
    .await;

    let email = "chat-completions-token-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, None, None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when token usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("token"),
        "Error message should mention token limit, got: {}",
        error
    );
}

/// Cost window limit: when user's cost usage exceeds limit, next /v1/chat/completions request returns 429.
#[tokio::test]
async fn test_chat_completions_cost_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 1_000,
            }],
        }),
        ..Default::default()
    })
    .await;

    let email = "chat-completions-cost-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 0, Some(2_000), None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when cost usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("cost") || error.to_lowercase().contains("nano"),
        "Error message should mention cost limit, got: {}",
        error
    );
}

/// Test NEAR balance check skipped when no NEAR-linked account for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_near_balance_skipped_when_no_near_linked_account() {
    let server = create_test_server().await;

    // Use mock_login helper which does NOT set oauth_provider, so no NEAR linked account
    let token = mock_login(&server, "chat-completions-no-near@example.com").await;

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Request without NEAR-linked account should not be blocked by NEAR balance check"
    );
}

/// Test NEAR balance allows rich account for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_near_balance_allows_rich_account() {
    let server = create_test_server().await;

    // Real account in mainnet
    let rich_account = "near";

    let login_request = json!({
        "email": format!("{}@near", rich_account),
        "name": "Rich NEAR User",
        "oauth_provider": "near"
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Mock login with NEAR provider should succeed"
    );

    let body: serde_json::Value = response.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Rich NEAR account should not be blocked by NEAR balance check"
    );
}

/// Test NEAR balance blocks poor account for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_near_balance_blocks_poor_account() {
    let server = create_test_server().await;

    // Use a different account than near_balance_tests to avoid conflicts
    // Real account in mainnet with zero balance
    let poor_account = "zero-balance-2.near";

    let login_request = json!({
        "email": format!("{}@near", poor_account),
        "name": "Poor NEAR User",
        "oauth_provider": "near"
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Mock login with NEAR provider should succeed for poor account"
    );

    let body: serde_json::Value = response.json();
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .expect("Auth response should contain token");

    let first_response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // First call should NOT yet be blocked by NEAR balance check, since the check is asynchronous
    assert_ne!(
        first_response.status_code(),
        403,
        "First request from poor NEAR account should not be synchronously blocked"
    );

    // Wait long enough to avoid being affected by per-user rate limit (1 req/sec)
    sleep(std::time::Duration::from_millis(1100)).await;

    // Second call should be blocked by blacklist (user ban), after async NEAR check has run
    let second_response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello again"}]
        }))
        .await;

    assert_eq!(
        second_response.status_code(),
        403,
        "Subsequent requests from poor NEAR account should be blocked by NEAR balance ban"
    );

    let body: serde_json::Value = second_response.json();
    let error = body.get("error").and_then(|v| v.as_str());
    assert_eq!(
        error,
        Some(USER_BANNED_ERROR_MESSAGE),
        "Ban error message should indicate a temporary ban without exposing NEAR balance details"
    );
}

/// Test rate limiting for /v1/images/generations endpoint
#[tokio::test]
async fn test_image_generations_rate_limit_first_request_succeeds() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "image-generations-rate-limit-1@example.com").await;

    let response = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "prompt": "A beautiful sunset",
            "n": 1,
            "size": "1024x1024"
        }))
        .await;

    // Should not be rate limited (may fail for other reasons like no upstream)
    assert_ne!(
        response.status_code(),
        429,
        "First request should not be rate limited"
    );
}

/// Test rate limiting blocks rapid requests for /v1/images/generations
#[tokio::test]
async fn test_image_generations_rate_limit_blocks_rapid_requests() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "image-generations-rate-limit-2@example.com").await;

    let request_body = json!({
        "prompt": "A beautiful sunset",
        "n": 1,
        "size": "1024x1024"
    });

    // First request (spawn so it is in flight when second is sent)
    let response1 = tokio::spawn(
        server
            .post("/v1/images/generations")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .json(&request_body)
            .into_future(),
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Second request immediately after should be rate limited
    let response2 = server
        .post("/v1/images/generations")
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

    response1.await.unwrap();
}

/// Token window limit: when user's token usage exceeds limit, next /v1/images/generations request returns 429.
#[tokio::test]
async fn test_image_generations_token_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 100,
            }],
            cost_window_limits: vec![],
        }),
        ..Default::default()
    })
    .await;

    let email = "image-generations-token-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, None, None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "prompt": "A beautiful sunset",
            "n": 1,
            "size": "1024x1024"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when token usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("token"),
        "Error message should mention token limit, got: {}",
        error
    );
}

/// Cost window limit: when user's cost usage exceeds limit, next /v1/images/generations request returns 429.
#[tokio::test]
async fn test_image_generations_cost_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 1_000,
            }],
        }),
        ..Default::default()
    })
    .await;

    let email = "image-generations-cost-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 0, Some(2_000), None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "prompt": "A beautiful sunset",
            "n": 1,
            "size": "1024x1024"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when cost usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("cost") || error.to_lowercase().contains("nano"),
        "Error message should mention cost limit, got: {}",
        error
    );
}

/// Test NEAR balance check skipped when no NEAR-linked account for /v1/images/generations
#[tokio::test]
async fn test_image_generations_near_balance_skipped_when_no_near_linked_account() {
    let server = create_test_server().await;

    // Use mock_login helper which does NOT set oauth_provider, so no NEAR linked account
    let token = mock_login(&server, "image-generations-no-near@example.com").await;

    let response = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "prompt": "A beautiful sunset",
            "n": 1,
            "size": "1024x1024"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Request without NEAR-linked account should not be blocked by NEAR balance check"
    );
}

/// Test rate limiting for /v1/images/edits endpoint
#[tokio::test]
async fn test_image_edits_rate_limit_first_request_succeeds() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "image-edits-rate-limit-1@example.com").await;

    // Note: /v1/images/edits accepts multipart/form-data, but for rate limit testing
    // we can use JSON and it will fail at the proxy level, not rate limit level
    let response = server
        .post("/v1/images/edits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "image": "test",
            "prompt": "Make it better"
        }))
        .await;

    // Should not be rate limited (may fail for other reasons like no upstream or invalid format)
    assert_ne!(
        response.status_code(),
        429,
        "First request should not be rate limited"
    );
}

/// Test rate limiting blocks rapid requests for /v1/images/edits
#[tokio::test]
async fn test_image_edits_rate_limit_blocks_rapid_requests() {
    let server = create_rate_limited_test_server().await;
    let token = mock_login(&server, "image-edits-rate-limit-2@example.com").await;

    let request_body = json!({
        "image": "test",
        "prompt": "Make it better"
    });

    // First request (spawn so it is in flight when second is sent)
    let response1 = tokio::spawn(
        server
            .post("/v1/images/edits")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .json(&request_body)
            .into_future(),
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Second request immediately after should be rate limited
    let response2 = server
        .post("/v1/images/edits")
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

    response1.await.unwrap();
}

/// Token window limit: when user's token usage exceeds limit, next /v1/images/edits request returns 429.
#[tokio::test]
async fn test_image_edits_token_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 100,
            }],
            cost_window_limits: vec![],
        }),
        ..Default::default()
    })
    .await;

    let email = "image-edits-token-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, None, None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/images/edits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "image": "test",
            "prompt": "Make it better"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when token usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("token"),
        "Error message should mention token limit, got: {}",
        error
    );
}

/// Cost window limit: when user's cost usage exceeds limit, next /v1/images/edits request returns 429.
#[tokio::test]
async fn test_image_edits_cost_limit_blocks_request_when_usage_exceeds_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![WindowLimit {
                window_duration: Duration::seconds(60),
                limit: 1_000,
            }],
        }),
        ..Default::default()
    })
    .await;

    let email = "image-edits-cost-limit@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 0, Some(2_000), None)
        .await
        .expect("record usage");

    let response = server
        .post("/v1/images/edits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "image": "test",
            "prompt": "Make it better"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        429,
        "Request should be rate limited when cost usage exceeds window limit"
    );
    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error.to_lowercase().contains("cost") || error.to_lowercase().contains("nano"),
        "Error message should mention cost limit, got: {}",
        error
    );
}

/// Test NEAR balance check skipped when no NEAR-linked account for /v1/images/edits
#[tokio::test]
async fn test_image_edits_near_balance_skipped_when_no_near_linked_account() {
    let server = create_test_server().await;

    // Use mock_login helper which does NOT set oauth_provider, so no NEAR linked account
    let token = mock_login(&server, "image-edits-no-near@example.com").await;

    let response = server
        .post("/v1/images/edits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "image": "test",
            "prompt": "Make it better"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Request without NEAR-linked account should not be blocked by NEAR balance check"
    );
}

/// Requests with a model whose settings are non-public should be blocked with 403 for /v1/chat/completions.
#[tokio::test]
async fn test_chat_completions_block_non_public_model() {
    let server = create_test_server().await;

    // Use an admin account to configure model settings
    let admin_email = "chat-completions-visibility-non-public-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Explicitly create a non-public model via admin API
    let batch_body = json!({
        "test-chat-completions-non-public-model": {
            "public": false
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model as non-public"
    );

    // Now send a chat completions request using the non-public model
    let body = json!({
        "model": "test-chat-completions-non-public-model",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Requests with non-public model should be blocked with 403"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("This model is not available"),
        "Error message should indicate model is not available"
    );
}

/// Requests with a model whose settings are public should be allowed (not blocked by 403) for /v1/chat/completions.
#[tokio::test]
async fn test_chat_completions_allow_public_model() {
    let server = create_test_server().await;

    // Use an admin account to configure model settings
    let admin_email = "chat-completions-visibility-public-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Mark the model as public via admin API
    let batch_body = json!({
        "test-chat-completions-public-model": {
            "public": true
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model as public"
    );

    // Now send a chat completions request using the public model
    let body = json!({
        "model": "test-chat-completions-public-model",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // We only assert that our visibility check did not block the request with 403.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model should not be blocked by visibility check (status was {})",
        response.status_code()
    );
}

/// When a public model has a system_prompt and the client does NOT send a system message,
/// the proxy should inject a system message with the model system_prompt.
#[tokio::test]
async fn test_chat_completions_injects_system_prompt_when_system_message_missing() {
    let server = create_test_server().await;

    // Use an admin account to configure model settings (public + system_prompt)
    let admin_email = "chat-completions-system-prompt-no-system-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let system_prompt = "You are a helpful assistant (model-level for chat completions).";

    let batch_body = json!({
        "test-chat-completions-system-prompt-model-1": {
            "public": true,
            "system_prompt": system_prompt
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model with system_prompt"
    );

    // Now send a chat completions request WITHOUT system message
    let user_email = "chat-completions-system-prompt-no-system-user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let body = json!({
        "model": "test-chat-completions-system-prompt-model-1",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // We cannot directly inspect the upstream request in this test,
    // but at minimum the proxy should not block, since the model is public.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model and system_prompt should not be blocked (status was {})",
        response.status_code()
    );
}

/// When a public model has a system_prompt and the client already sends a system message,
/// the proxy should prepend the model system_prompt to the existing system message content.
#[tokio::test]
async fn test_chat_completions_prepends_system_prompt_when_system_message_present() {
    let server = create_test_server().await;

    // Use an admin account to configure model settings (public + system_prompt)
    let admin_email = "chat-completions-system-prompt-with-system-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let system_prompt = "You are a helpful assistant (model-level, prepend for chat completions).";

    let batch_body = json!({
        "test-chat-completions-system-prompt-model-2": {
            "public": true,
            "system_prompt": system_prompt
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model with system_prompt"
    );

    // Now send a chat completions request WITH client system message
    let user_email = "chat-completions-system-prompt-with-system-user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let body = json!({
        "model": "test-chat-completions-system-prompt-model-2",
        "messages": [
            {"role": "system", "content": "User provided system message."},
            {"role": "user", "content": "Hello"}
        ]
    });

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // Similarly, we cannot directly assert the final contents of the system message here,
    // but we can at least ensure that the request is not blocked by the visibility logic.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model and custom system message should not be blocked (status was {})",
        response.status_code()
    );
}

/// Requests without a `model` field should be allowed (no 403 from visibility logic) for /v1/chat/completions.
#[tokio::test]
async fn test_chat_completions_allow_without_model_field() {
    let server = create_test_server().await;

    let token = mock_login(&server, "chat-completions-visibility-no-model@example.com").await;

    // No `model` field in body
    let body = json!({
        "messages": [{"role": "user", "content": "Hello"}]
    });

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Requests without model field should not be blocked by visibility check (status was {})",
        response.status_code()
    );
}
