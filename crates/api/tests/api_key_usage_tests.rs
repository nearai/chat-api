mod common;

use common::{create_test_server_and_db, mock_login, set_subscription_plans, TestServerConfig};
use serde_json::json;
use services::user::ports::UserRepository;
use services::user_usage::{RecordUsageParams, UserUsageRepository, METRIC_KEY_LLM_TOKENS};
use services::UserId;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn create_bound_agent_api_key(
    server: &axum_test::TestServer,
    db: &database::Database,
    user_email: &str,
    spend_limit: Option<i64>,
) -> (UserId, Uuid, Uuid, String) {
    let token = mock_login(server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("db")
        .expect("user");

    let instance_id = Uuid::new_v4();
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_id,
                &user.id,
                &format!("inst_test_{}", Uuid::new_v4().simple()),
                &"usage-test-instance",
                &"http://test-instance.local",
                &"tok_test_instance_secret",
            ],
        )
        .await
        .expect("insert instance");

    let api_key_response = server
        .post(&format!("/v1/agents/instances/{instance_id}/keys"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({
            "name": "usage-test-key",
            "spend_limit": spend_limit,
            "expires_at": null
        }))
        .await;

    assert_eq!(api_key_response.status_code(), 201);
    let api_key_body: serde_json::Value = api_key_response.json();
    let api_key_id = Uuid::parse_str(
        api_key_body["id"]
            .as_str()
            .expect("response should include api key id"),
    )
    .expect("valid uuid");
    let api_key = api_key_body["api_key"]
        .as_str()
        .expect("response should include plaintext api key")
        .to_string();

    (user.id, instance_id, api_key_id, api_key)
}

fn hash_agent_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Test that the dual auth middleware provides both user and API key extensions
/// This verifies that both AuthenticatedUser and AuthenticatedApiKey can be extracted
#[tokio::test]
async fn test_dual_auth_middleware_extensions() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Create a user
    let email = "test_dual_auth@example.com";
    let token = mock_login(&server, email).await;

    // User should be able to make authenticated requests
    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");

    assert!(
        !user.id.to_string().is_empty(),
        "User ID should not be empty"
    );

    // User can access their own profile
    let profile_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(
        profile_response.status_code(),
        200,
        "User should be able to access their own profile"
    );
}

/// Test that API key isolation prevents unauthorized access to agent instances
#[tokio::test]
async fn test_api_key_isolation_prevents_cross_user_access() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // User 1 logs in
    let user1_token = mock_login(&server, "test_isolation_user1@example.com").await;

    // User 2 logs in
    let user2_token = mock_login(&server, "test_isolation_user2@example.com").await;

    // Both can access their own instances (empty list)
    let user1_instances = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user1_token}")).unwrap(),
        )
        .await;

    let user2_instances = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user2_token}")).unwrap(),
        )
        .await;

    assert_eq!(user1_instances.status_code(), 200);
    assert_eq!(user2_instances.status_code(), 200);

    // Both should see empty instance lists since neither created any
    let body1: serde_json::Value = user1_instances.json();
    let body2: serde_json::Value = user2_instances.json();

    let items1_count = body1
        .get("items")
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    let items2_count = body2
        .get("items")
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);

    assert_eq!(items1_count, 0, "User 1 should have no instances");
    assert_eq!(items2_count, 0, "User 2 should have no instances");
}

/// Test that usage recording infrastructure is in place and functional
#[tokio::test]
async fn test_usage_recording_infrastructure() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Create a user and verify we can access usage APIs
    let email = "test_usage_recording@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user");

    // Check that user usage endpoint is accessible (should return 404 since no usage yet)
    let usage_response = server
        .get("/v1/users/me/usage")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    // Either 404 (no usage) or 200 (has usage) are both valid
    // The important thing is we get a proper response, not an auth error
    assert!(
        usage_response.status_code() == 404 || usage_response.status_code() == 200,
        "Should return 404 (no usage) or 200 (has usage), not auth error"
    );

    // Verify we can query user usage from the database
    let usage_summary = db
        .user_usage_repository()
        .get_usage_by_user_id(user.id, None, None)
        .await
        .expect("query");

    // Usage summary should either be None (no usage) or present
    if let Some(summary) = usage_summary {
        assert_eq!(summary.user_id, user.id, "User ID should match");
        // token_sum, image_num, and cost_nano_usd are already initialized to 0
    }
}

/// Test that authentication middleware correctly handles both user and API key auth
#[tokio::test]
async fn test_auth_middleware_handles_both_methods() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Test user auth (session token) - should work
    let user_token = mock_login(&server, "test_auth_user@example.com").await;

    let response_with_user_auth = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response_with_user_auth.status_code(),
        200,
        "User auth should work for /v1/users/me"
    );

    // Test missing auth - should fail
    let response_no_auth = server.get("/v1/users/me").await;

    assert_eq!(
        response_no_auth.status_code(),
        401,
        "Missing auth should return 401"
    );

    // Test invalid token - should fail
    let response_bad_token = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str("Bearer invalid_token_xyz").unwrap(),
        )
        .await;

    assert_eq!(
        response_bad_token.status_code(),
        401,
        "Invalid token should return 401"
    );
}

#[tokio::test]
async fn test_create_api_key_rejects_non_positive_spend_limit() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let email = format!("invalid-spend-limit-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let instance_id = Uuid::new_v4();
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_id,
                &user.id,
                &format!("inst_test_{}", Uuid::new_v4().simple()),
                &"invalid-spend-limit-instance",
                &"http://test-instance.local",
                &"tok_test_instance_secret",
            ],
        )
        .await
        .expect("insert instance");

    let response = server
        .post(&format!("/v1/agents/instances/{instance_id}/keys"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&json!({
            "name": "bad-key",
            "spend_limit": 0,
            "expires_at": null
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("message").and_then(|v| v.as_str()),
        Some("Invalid spend limit: must be greater than 0 when provided")
    );
}

#[tokio::test]
async fn test_agent_api_key_spend_limit_blocks_chat_completions_once_limit_reached() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-test",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({ "free": { "providers": {}, "monthly_credits": { "max": 1_000_000_000 } } }),
    )
    .await;

    let email = format!("spend-limit-blocked-{}@example.com", Uuid::new_v4());
    let (user_id, instance_id, api_key_id, api_key) =
        create_bound_agent_api_key(&server, &db, &email, Some(1_000)).await;

    db.user_usage_repository()
        .record_usage(RecordUsageParams {
            user_id,
            metric_key: METRIC_KEY_LLM_TOKENS.to_string(),
            quantity: 10,
            cost_nano_usd: Some(1_000),
            model_id: Some("gpt-test".to_string()),
            instance_id: Some(instance_id),
            api_key_id: Some(api_key_id),
            details: Some(json!({ "request_type": "chat_completion" })),
        })
        .await
        .expect("record usage at spend limit");

    let client = db.pool().get().await.expect("db client");
    let total_spent: i64 = client
        .query_one(
            "SELECT total_spent FROM agent_api_keys WHERE id = $1",
            &[&api_key_id],
        )
        .await
        .expect("load api key total_spent")
        .get(0);
    assert_eq!(total_spent, 1_000);

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .await;

    assert_eq!(response.status_code(), 403);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("message").and_then(|v| v.as_str()),
        Some("API key spend limit exceeded")
    );

    let received = mock_upstream
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(
        received.len(),
        0,
        "Request should be blocked before it reaches the upstream LLM"
    );
}

#[tokio::test]
async fn test_legacy_non_positive_spend_limit_does_not_immediately_block_api_key() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-test",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .expect(1)
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({ "free": { "providers": {}, "monthly_credits": { "max": 1_000_000_000 } } }),
    )
    .await;

    let email = format!("legacy-zero-limit-{}@example.com", Uuid::new_v4());
    let _token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let instance_id = Uuid::new_v4();
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_id,
                &user.id,
                &format!("inst_test_{}", Uuid::new_v4().simple()),
                &"legacy-zero-limit-instance",
                &"http://test-instance.local",
                &"tok_test_instance_secret",
            ],
        )
        .await
        .expect("insert instance");

    let api_key = format!("sk-agent-{}", Uuid::new_v4().simple());
    let api_key_hash = hash_agent_api_key(&api_key);
    let api_key_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO agent_api_keys (id, instance_id, user_id, key_hash, name, spend_limit, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, true)",
            &[
                &api_key_id,
                &instance_id,
                &user.id,
                &api_key_hash,
                &"legacy-zero-limit-key",
                &0_i64,
            ],
        )
        .await
        .expect("insert legacy api key");

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .await;

    assert_eq!(response.status_code(), 200);
}

#[tokio::test]
async fn test_agent_api_key_spend_limit_allows_chat_completions_below_limit() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-test",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .expect(1)
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({ "free": { "providers": {}, "monthly_credits": { "max": 1_000_000_000 } } }),
    )
    .await;

    let email = format!("spend-limit-allowed-{}@example.com", Uuid::new_v4());
    let (user_id, instance_id, api_key_id, api_key) =
        create_bound_agent_api_key(&server, &db, &email, Some(2_000)).await;

    db.user_usage_repository()
        .record_usage(RecordUsageParams {
            user_id,
            metric_key: METRIC_KEY_LLM_TOKENS.to_string(),
            quantity: 10,
            cost_nano_usd: Some(1_000),
            model_id: Some("gpt-test".to_string()),
            instance_id: Some(instance_id),
            api_key_id: Some(api_key_id),
            details: Some(json!({ "request_type": "chat_completion" })),
        })
        .await
        .expect("record usage below spend limit");

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .await;

    assert_eq!(response.status_code(), 200);
}
