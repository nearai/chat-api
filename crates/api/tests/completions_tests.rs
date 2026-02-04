mod common;

use api::routes::api::USER_BANNED_ERROR_MESSAGE;
use common::{create_test_server, mock_login};
use futures::future::join_all;
use serde_json::json;
use std::sync::Arc;
use tokio::time::sleep;

/// Test rate limiting for /v1/chat/completions endpoint
#[tokio::test]
async fn test_chat_completions_rate_limit_first_request_succeeds() {
    let server = create_test_server().await;
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
    let server = create_test_server().await;
    let token = mock_login(&server, "chat-completions-rate-limit-2@example.com").await;

    let request_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });

    // First request
    let _response1 = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&request_body)
        .await;

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
}

/// Test rate limiting per-user isolation for /v1/chat/completions
#[tokio::test]
async fn test_chat_completions_rate_limit_per_user_isolation() {
    let server = create_test_server().await;
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
    let server = Arc::new(create_test_server().await);
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

    // Real account in mainnet
    let poor_account = "zero-balance.near";

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
    let server = create_test_server().await;
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
    let server = create_test_server().await;
    let token = mock_login(&server, "image-generations-rate-limit-2@example.com").await;

    let request_body = json!({
        "prompt": "A beautiful sunset",
        "n": 1,
        "size": "1024x1024"
    });

    // First request
    let _response1 = server
        .post("/v1/images/generations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&request_body)
        .await;

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
    let server = create_test_server().await;
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
    let server = create_test_server().await;
    let token = mock_login(&server, "image-edits-rate-limit-2@example.com").await;

    let request_body = json!({
        "image": "test",
        "prompt": "Make it better"
    });

    // First request
    let _response1 = server
        .post("/v1/images/edits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&request_body)
        .await;

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
