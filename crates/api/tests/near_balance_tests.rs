mod common;

use api::routes::api::USER_BANNED_ERROR_MESSAGE;
use common::create_test_server;
use serde_json::json;
use tokio::time::sleep;

/// When user has no NEAR-linked account, NEAR balance check should be skipped
/// and /v1/responses should not return 403 due to balance.
#[tokio::test]
async fn test_near_balance_skipped_when_no_near_linked_account() {
    let server = create_test_server().await;

    // Use mock_login helper which does NOT set oauth_provider, so no NEAR linked account
    let token = common::mock_login(&server, "no-near@example.com").await;

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

    assert_ne!(
        response.status_code(),
        403,
        "Request without NEAR-linked account should not be blocked by NEAR balance check"
    );
}

/// Integration test that verifies NEAR balance gating for a real NEAR account.
#[tokio::test]
async fn test_near_balance_allows_rich_account() {
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

    assert_ne!(
        response.status_code(),
        403,
        "Rich NEAR account should not be blocked by NEAR balance check"
    );
}

/// Integration test that verifies NEAR balance gating blocks a "poor" NEAR account.
#[tokio::test]
async fn test_near_balance_blocks_poor_account() {
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
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        )
        .json(&json!({
            "model": "test-model",
            "input": "Hello again"
        }))
        .await;

    // User without subscription will get 402 or 403
    // May be 402 (subscription validation) or 403 (ban after async check)
    let status = second_response.status_code();
    assert!(
        status == 402 || status == 403,
        "Subsequent requests should be blocked with 402 or 403, got {}",
        status
    );

    // If blocked by ban (403), verify the error message
    if status == 403 {
        let body: serde_json::Value = second_response.json();
        let error = body.get("error").and_then(|v| v.as_str());
        assert_eq!(
            error,
            Some(USER_BANNED_ERROR_MESSAGE),
            "Ban error message should indicate a temporary ban without exposing NEAR balance details"
        );
    }
}
