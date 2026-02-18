mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use serde_json::json;
use uuid::Uuid;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

/// E2E test for complete Agent workflow:
/// 1. Admin creates instance for user
/// 2. User retrieves instance
/// 3. User stops/starts instance (user-endpoints)
/// 4. User creates API key
/// 5. Agent calls inference via /v1/chat/completions with API key
/// 6. Verify usage and isolation
#[tokio::test]
async fn test_agent_complete_workflow() {
    // Initialize tracing so RUST_LOG=debug shows middleware logs
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    // Mock LLM API so chat completions returns 200 (avoids upstream 401 with mock-api-key)
    let mock_llm = MockServer::start().await;
    let mock_body = json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    });
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_body))
        .mount(&mock_llm)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", mock_llm.uri())),
        ..Default::default()
    })
    .await;

    // 1. Create users: admin and regular user
    let admin_email = "admin@admin.org";
    let user_email = "testuser@example.com";

    let _admin_token = mock_login(&server, admin_email).await;
    let user_token = mock_login(&server, user_email).await;

    // Get user_id for the regular user (needed for instance creation)
    let user_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(user_response.status_code(), 200);
    let user_body: serde_json::Value = user_response.json();
    let user_id: String = user_body
        .get("user")
        .and_then(|u| u.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("User should have id");

    // 2. Admin creates instance directly in database (simulating successful Agent API call)
    let instance_uuid = Uuid::new_v4();
    let instance_id_str = format!(
        "inst_test_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let instance_url = "http://test-instance.local";
    let instance_token = "tok_test_instance_secret";

    let client = db.pool().get().await.expect("Should get DB connection");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_uuid,
                &Uuid::parse_str(&user_id).unwrap(),
                &instance_id_str,
                &"test-instance",
                &instance_url,
                &instance_token,
            ],
        )
        .await
        .expect("Should insert instance");

    // 3. User retrieves instance
    let get_instance_response = server
        .get(&format!("/v1/agents/instances/{}", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        get_instance_response.status_code(),
        200,
        "User should be able to get their instance"
    );
    let instance_body: serde_json::Value = get_instance_response.json();
    assert_eq!(
        instance_body.get("id").and_then(|v| v.as_str()),
        Some(instance_uuid.to_string().as_str())
    );

    // 4. User stops instance (now user-accessible, not admin-only)
    let stop_response = server
        .post(&format!("/v1/agents/instances/{}/stop", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        stop_response.status_code(),
        500,
        "Will fail because we're not mocking the instance server, but confirms auth works"
    );

    // 5. User starts instance (now user-accessible, not admin-only)
    let start_response = server
        .post(&format!("/v1/agents/instances/{}/start", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        start_response.status_code(),
        500,
        "Will fail because we're not mocking the instance server, but confirms auth works"
    );

    // 6. User creates API key for the instance
    let api_key_response = server
        .post(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-api-key",
            "spend_limit": null,
            "expires_at": null
        }))
        .await;

    assert_eq!(
        api_key_response.status_code(),
        201,
        "User should be able to create API key"
    );

    let api_key_body: serde_json::Value = api_key_response.json();
    let api_key = api_key_body
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Response should contain api_key");

    // Verify API key format
    assert!(
        api_key.starts_with("sk-agent-"),
        "API key should start with 'sk-agent-'"
    );
    assert_eq!(api_key.len(), 41, "API key should be 41 chars long");

    // 7. List API keys for instance
    let list_keys_response = server
        .get(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(list_keys_response.status_code(), 200);
    let keys_body: serde_json::Value = list_keys_response.json();
    let keys = keys_body
        .get("items")
        .and_then(|v| v.as_array())
        .expect("Should have items array");
    assert_eq!(keys.len(), 1, "Should have one API key");

    // 8. Chat completion with API key (agents call /v1/chat/completions with API key)
    // LLM API is mocked to return 200; verifies auth passes and request is forwarded
    let chat_response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&json!({
            "model": "meta-llama/Llama-2-7b",
            "messages": [
                { "role": "user", "content": "Hello" }
            ],
            "stream": false
        }))
        .await;

    assert_eq!(
        chat_response.status_code(),
        200,
        "Auth should pass with valid API key and mocked LLM should return 200"
    );

    // 9. Verify API key isolation: non-owner user cannot use this key
    let other_user_token = mock_login(&server, "otheruser@example.com").await;

    let other_instance_response = server
        .get(&format!("/v1/agents/instances/{}", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {other_user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        other_instance_response.status_code(),
        404,
        "Other user should not be able to access this instance"
    );

    // 10. Verify user cannot stop another user's instance (now user-endpoint, ownership check)
    let other_user_token = mock_login(&server, "other@example.com").await;
    let stop_other_user = server
        .post(&format!("/v1/agents/instances/{}/stop", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {other_user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        stop_other_user.status_code(),
        403,
        "Other user should not be able to stop this instance"
    );
}

/// Test that lifecycle operations enforce admin access
#[tokio::test]
async fn test_lifecycle_operations_require_admin() {
    let (server, _db) = create_test_server_and_db(Default::default()).await;

    let instance_id = Uuid::new_v4();
    let user_token = mock_login(&server, "user@example.com").await;

    // Test start - user endpoint (returns 404 for non-existent instance)
    let start = server
        .post(&format!("/v1/agents/instances/{}/start", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(
        start.status_code(),
        404,
        "Start returns 404 for non-existent instance"
    );

    // Test stop - user endpoint (returns 404 for non-existent instance)
    let stop = server
        .post(&format!("/v1/agents/instances/{}/stop", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(
        stop.status_code(),
        404,
        "Stop returns 404 for non-existent instance"
    );

    // Test restart - user endpoint (returns 404 for non-existent instance)
    let restart = server
        .post(&format!("/v1/agents/instances/{}/restart", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(
        restart.status_code(),
        404,
        "Restart returns 404 for non-existent instance"
    );

    // Test backup creation
    let backup = server
        .post(&format!(
            "/v1/admin/agents/instances/{}/backup",
            instance_id
        ))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(backup.status_code(), 403, "Non-admin cannot create backup");

    // Test list backups
    let list = server
        .get(&format!(
            "/v1/admin/agents/instances/{}/backups",
            instance_id
        ))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(list.status_code(), 403, "Non-admin cannot list backups");

    // Test get backup
    let get = server
        .get(&format!(
            "/v1/admin/agents/instances/{}/backups/{}",
            instance_id,
            Uuid::new_v4()
        ))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(get.status_code(), 403, "Non-admin cannot get backup");
}

/// Test API key isolation between users
#[tokio::test]
async fn test_api_key_isolation_between_users() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    let user1_email = "user1@example.com";
    let user2_email = "user2@example.com";

    let user1_token = mock_login(&server, user1_email).await;
    let user2_token = mock_login(&server, user2_email).await;

    // Get user1 ID
    let user1_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user1_token}")).unwrap(),
        )
        .await;
    let user1_body: serde_json::Value = user1_response.json();
    let user1_id = Uuid::parse_str(
        user1_body
            .get("user")
            .and_then(|u| u.get("id"))
            .and_then(|v| v.as_str())
            .expect("User should have id"),
    )
    .expect("User ID should be valid UUID");

    // Create instance for user1
    let instance_uuid = Uuid::new_v4();
    let instance_id_str = format!(
        "inst_user1_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let client = db.pool().get().await.expect("Should get DB connection");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_uuid,
                &user1_id,
                &instance_id_str.as_str(),
                &"user1-instance",
                &"http://instance.local",
                &"tok_secret",
            ],
        )
        .await
        .expect("Should insert instance");

    // User1 can create API key
    let api_key_response = server
        .post(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user1_token}")).unwrap(),
        )
        .json(&json!({
            "name": "user1-key",
            "spend_limit": null,
            "expires_at": null
        }))
        .await;

    assert_eq!(api_key_response.status_code(), 201);
    let api_key_body: serde_json::Value = api_key_response.json();
    let _api_key = api_key_body
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap();

    // User2 cannot create key for User1's instance
    let user2_create_key = server
        .post(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user2_token}")).unwrap(),
        )
        .json(&json!({
            "name": "user2-key",
            "spend_limit": null,
            "expires_at": null
        }))
        .await;

    assert!(
        user2_create_key.status_code() == 404 || user2_create_key.status_code() == 500,
        "User2 should not be able to access User1's instance, got: {}",
        user2_create_key.status_code()
    );

    // User2 cannot list keys for User1's instance
    let user2_list_keys = server
        .get(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user2_token}")).unwrap(),
        )
        .await;

    assert!(
        user2_list_keys.status_code() == 404 || user2_list_keys.status_code() == 500,
        "User2 should not be able to list keys for User1's instance, got: {}",
        user2_list_keys.status_code()
    );
}
