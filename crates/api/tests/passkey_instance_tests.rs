mod common;

use common::{create_test_server_and_db, mock_login};
use serde_json::json;
use serial_test::serial;

/// Test that passkey instance endpoint requires authentication
#[tokio::test]
#[serial]
async fn test_create_passkey_instance_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    // Try without auth
    let response = server
        .post("/v1/agents/instances")
        .json(&json!({
            "name": "test-instance"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Passkey endpoint should require authentication"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_deployment_without_passkey_credentials() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-instance"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_deployment_with_invalid_service_type() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-instance",
            "service_type": "invalid-service-type"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_deployment_without_subscription() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-instance"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_create_passkey_instance_with_sse_header() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("accept"),
            http::HeaderValue::from_str("text/event-stream").unwrap(),
        )
        .json(&json!({
            "name": "test-instance"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_manager_token_deployment() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-instance"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

/// New activity remains closed for this request scenario.
#[tokio::test]
#[serial]
async fn test_sunset_blocks_passkey_deployment() {
    let (server, _db) = create_test_server_and_db(Default::default()).await;

    let user_email = "test_passkey_credentials@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("accept"),
            http::HeaderValue::from_str("text/event-stream").unwrap(),
        )
        .json(&json!({
            "name": "test-passkey-creds"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["code"],
        "agent_hosting_closed"
    );
}

// Bearer token resolution documentation moved to code comments in agent/service.rs
// and routes/agents.rs. The implementation ensures:
// • Credentials stored in DB are separate from session tokens
// • Session tokens are short-lived (compose-api responsibility)
// • Each operation fetches a fresh session token (no token reuse)
// • Fallback to manager tokens ensures robustness
// • Bearer tokens are never logged (see CLAUDE.md privacy rules)
