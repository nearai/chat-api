mod common;

use common::create_test_server;
use serde_json::json;

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

    // Real account in testnet
    let rich_account = "private-chat-rich-user.testnet";

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

    // Real account in testnet
    let poor_account = "private-chat-poor-user.testnet";

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

    assert_eq!(
        response.status_code(),
        403,
        "Poor NEAR account should be blocked by NEAR balance check"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("error").and_then(|v| v.as_str());
    assert_eq!(
        error,
        Some("NEAR balance is below 1 NEAR; please top up before using this feature")
    );
}
