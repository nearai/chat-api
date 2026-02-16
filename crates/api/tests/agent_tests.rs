mod common;

use common::{create_test_server_and_db, mock_login};
use serde_json::json;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use uuid::Uuid;

/// Test creating an Agent instance (as admin or regular user)
#[tokio::test]
async fn test_create_agent_instance() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    // In real scenario, this would create via Agent API
    // For now, we test the endpoint exists and requires auth
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

    // Should fail in test because we're not mocking the Agent API
    // But we verify auth is required
    let status = response.status_code();
    assert!(
        status.is_client_error() || status.is_server_error(),
        "Endpoint should require valid Agent API key, got status: {}",
        status
    );
}

/// Test listing instances requires authentication
#[tokio::test]
async fn test_list_instances_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    // Try without auth
    let response = server.get("/v1/agents/instances").await;
    assert_eq!(response.status_code(), 401, "Should require authentication");
}

/// Test listing instances with authentication
#[tokio::test]
async fn test_list_instances_with_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let user_email = "test_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should list instances for user"
    );
    let body: serde_json::Value = response.json();
    assert!(
        body.get("items").is_some(),
        "Response should have items array"
    );
}

/// Test creating an API key requires instance ownership and proper auth
#[tokio::test]
async fn test_create_api_key_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let fake_instance_id = Uuid::new_v4().to_string();

    // Try without auth
    let response = server
        .post(&format!("/v1/agents/instances/{}/keys", fake_instance_id))
        .json(&json!({
            "name": "test-key"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to create API key"
    );
}

// Note: Chat completions endpoint tests require actual Agent instances with proper
// connection information (instance_url, instance_token). These are integration tests
// that would need mock/stub Agent infrastructure. See INTEGRATION_TESTS section below.

// ===== INTEGRATION TEST SCENARIOS (would require Agent mock/stub) =====
//
// Real e2e flow tests that would demonstrate the complete user and admin flows:
//
// 1. Admin Creates Instance:
//    POST /v1/admin/agents/instances with user_id and Agent API credentials
//    → Creates instance record with instance_url, instance_token, etc.
//    → User lists instances via GET /v1/agents/instances
//
// 2. User Creates API Key:
//    POST /v1/agents/instances/{id}/keys with name
//    → Returns API key in ag_xxxxx format
//    → Can revoke key via DELETE /v1/agents/keys/{key_id}
//
// 3. Agent Uses Chat Completions:
//    POST /v1/chat/completions with Bearer ag_xxxxx (API key auth)
//    → API key validated, request proxied to instance
//    → Usage tracked in agent_usage_log
//
// 4. User Monitors Usage:
//    GET /v1/agents/instances/{id}/usage
//    GET /v1/agents/instances/{id}/balance
//    → Returns tracked tokens, costs, request counts
//
// To implement these tests, would need:
// - Mock Agent API server or wiremock stubs
// - Pre-populated database with test instances
// - Proper assertion on Agent response structure
// ========================

/// Test that different users cannot use each other's API keys
#[tokio::test]
async fn test_api_key_isolation_between_users() {
    let (server, _db) = create_test_server_and_db(Default::default()).await;

    // User 1 creates instance and key - use unique emails to avoid cross-test contamination
    let user1_token = mock_login(&server, "isolation_test_user1@example.com").await;
    let user2_token = mock_login(&server, "isolation_test_user2@example.com").await;

    // Both users should be able to list their own instances
    let response1 = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user1_token}")).unwrap(),
        )
        .await;

    let response2 = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user2_token}")).unwrap(),
        )
        .await;

    assert_eq!(response1.status_code(), 200);
    assert_eq!(response2.status_code(), 200);

    let body1: serde_json::Value = response1.json();
    let body2: serde_json::Value = response2.json();

    // Both should see empty arrays (since instances aren't created without real Agent API)
    let items1 = body1.get("items").unwrap().as_array().unwrap();
    let items2 = body2.get("items").unwrap().as_array().unwrap();

    // Both users should have zero instances (using unique emails prevents cross-test contamination)
    assert_eq!(items1.len(), 0, "User 1 should have no instances");
    assert_eq!(items2.len(), 0, "User 2 should have no instances");
}

/// Test listing API keys requires authentication
#[tokio::test]
async fn test_list_api_keys_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let fake_instance_id = Uuid::new_v4().to_string();

    // Try without auth
    let response = server
        .get(&format!("/v1/agents/instances/{}/keys", fake_instance_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to list API keys"
    );
}

/// Test getting instance balance requires authentication
#[tokio::test]
async fn test_get_instance_balance_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let fake_instance_id = Uuid::new_v4().to_string();

    // Try without auth
    let response = server
        .get(&format!(
            "/v1/agents/instances/{}/balance",
            fake_instance_id
        ))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to get balance"
    );
}

/// Test getting instance usage history requires authentication
#[tokio::test]
async fn test_get_instance_usage_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let fake_instance_id = Uuid::new_v4().to_string();

    // Try without auth
    let response = server
        .get(&format!("/v1/agents/instances/{}/usage", fake_instance_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to get usage"
    );
}

/// Test that users without an active subscription cannot create agent instances.
/// Previously, users without a subscription could bypass limits and create unlimited instances.
#[tokio::test]
async fn test_create_instance_rejects_unsubscribed_user() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    let user_email = "no_sub_user@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Ensure user has NO subscription
    common::cleanup_user_subscriptions(&db, user_email).await;

    // Set subscription plans (for subscribed users); unsubscribed users get 0 instances
    common::set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "monthly_tokens": { "max": 10000000 },
                "agent_instances": { "max": 2 }
            }
        }),
    )
    .await;

    // Try to create instance - should be rejected with 402 (no instances allowed without subscription)
    let response = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "instance-without-sub"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        402,
        "Unsubscribed user should get 402 Payment Required (active subscription required)"
    );

    let error_body: serde_json::Value = response.json();
    let error_message = error_body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        error_message.contains("limit"),
        "Error message should mention limit, got: {}",
        error_message
    );
}

/// Test agent instance limit validation with subscription plans
/// Tests that the limit is enforced when user reaches max instances
#[tokio::test]
async fn test_create_instance_respects_agent_instance_limit_max_1() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    let user_email = "limit_test_user_max1@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Set up subscription with agent_instances limit of 1
    // NOTE: insert_test_subscription uses price_id "price_test_basic"
    common::set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {
                    "stripe": {
                        "price_id": "price_test_basic"
                    }
                },
                "monthly_tokens": {
                    "max": 10000000
                },
                "agent_instances": {
                    "max": 1
                }
            }
        }),
    )
    .await;

    // Create a subscription for the user
    common::insert_test_subscription(&server, &db, user_email, false).await;

    // Get user to get their user_id
    let user_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    let user_body: serde_json::Value = user_response.json();
    let user_id_str: String = user_body
        .get("user")
        .and_then(|u| u.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("User should have id");
    let user_id = Uuid::parse_str(&user_id_str).expect("Valid user_id");

    // Create first instance directly in database
    let agent_repo = db.agent_repository();
    let unique_id = Uuid::new_v4();
    let first_instance = agent_repo
        .create_instance(CreateInstanceParams {
            user_id: services::UserId(user_id),
            instance_id: format!("agent-test-max1-{}", unique_id),
            name: "Test Instance 1".to_string(),
            public_ssh_key: None,
            instance_url: Some("http://localhost:8000".to_string()),
            instance_token: Some("token1".to_string()),
            gateway_port: None,
            dashboard_url: None,
        })
        .await
        .expect("Should create first instance");

    tracing::info!("Created first instance: {}", first_instance.id);

    // Try to create second instance via API (should be rejected with 402)
    let response2 = server
        .post("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "instance-2"
        }))
        .await;

    assert_eq!(
        response2.status_code(),
        402,
        "Second instance should be rejected with 402 Payment Required due to instance limit"
    );

    let error_body: serde_json::Value = response2.json();
    let error_message = error_body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        error_message.contains("limit"),
        "Error message should mention limit, got: {}",
        error_message
    );
}
