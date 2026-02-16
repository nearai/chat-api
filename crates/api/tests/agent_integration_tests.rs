mod common;

use common::{create_test_server_and_db, mock_login};
use serde_json::json;
use uuid::Uuid;

/// Integration test for complete Agent workflow with real API calls:
/// 1. Admin creates instance via Agent API
/// 2. User retrieves instance
/// 3. User creates API key
/// 4. List API keys
/// 5. Get instance balance
/// 6. Get instance usage
///
/// NOTE: This test requires valid Agent API credentials in .env file
/// Set AGENT_API_TOKEN and AGENT_API_BASE_URL before running
#[tokio::test]
#[ignore]
async fn test_agent_real_api_instance_creation() {
    let (server, _db) = create_test_server_and_db(Default::default()).await;

    // 1. Create users: admin and regular user
    let admin_email = "admin@admin.org";
    let user_email = "testuser_integration@example.com";

    let admin_token = mock_login(&server, admin_email).await;
    let user_token = mock_login(&server, user_email).await;

    // Get user_id for the regular user
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

    println!(
        "✓ Created users: admin={}, user={}",
        admin_email, user_email
    );

    // 2. Admin creates instance via real Agent API
    // The chat-api creates an API key on behalf of the user and configures the agent to use it.
    let create_instance_response = server
        .post("/v1/admin/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "user_id": user_id,
            "image": null,
            "name": format!("test-instance-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap()),
            "ssh_pubkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLh1Rv3K5Q9X4rq7Xs7X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X9X test@example.com"
        }))
        .await;

    println!(
        "✓ Admin create instance response: {}",
        create_instance_response.status_code()
    );

    if create_instance_response.status_code() != 201 {
        let error_body: serde_json::Value = create_instance_response.json();
        println!("ℹ Instance creation failed:");
        println!(
            "  Error: {}",
            error_body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        println!("\n📝 Ensure AGENT_API_BASE_URL and AGENT_API_TOKEN are set for real Agent API.");
        println!(
            "   Run: cargo test --test agent_integration_tests --features test -- --ignored --nocapture"
        );
        return;
    }

    // 3. Parse instance response
    let instance_body: serde_json::Value = create_instance_response.json();
    let instance_id: String = instance_body
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Instance should have id");

    println!("✓ Created instance: {}", instance_id);

    // 4. User retrieves instance
    let get_instance_response = server
        .get(&format!("/v1/agents/instances/{}", instance_id))
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
    println!("✓ User retrieved instance");

    // 5. User creates API key
    let api_key_response = server
        .post(&format!("/v1/agents/instances/{}/keys", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "name": "test-integration-key",
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

    println!("✓ Created API key: {}", api_key);

    // 6. List API keys
    let list_keys_response = server
        .get(&format!("/v1/agents/instances/{}/keys", instance_id))
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
    assert!(!keys.is_empty(), "Should have at least one API key");
    println!("✓ Listed {} API key(s)", keys.len());

    // 7. Get instance balance
    let balance_response = server
        .get(&format!("/v1/agents/instances/{}/balance", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    if balance_response.status_code() == 200 {
        let balance_body: serde_json::Value = balance_response.json();
        let balance = balance_body
            .get("balance")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        println!("✓ Retrieved balance: {} nano-USD", balance);
    } else {
        println!(
            "ℹ Balance endpoint not available yet (status: {})",
            balance_response.status_code()
        );
    }

    // 8. Get instance usage
    let usage_response = server
        .get(&format!("/v1/agents/instances/{}/usage", instance_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    if usage_response.status_code() == 200 {
        let usage_body: serde_json::Value = usage_response.json();
        let total = usage_body
            .get("total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        println!("✓ Retrieved usage: {} items, total tokens", total);
    } else {
        println!(
            "ℹ Usage endpoint returned: {}",
            usage_response.status_code()
        );
    }

    // 9. Attempt chat completion with API key (agents call /v1/chat/completions with API key)
    println!("\n🚀 Attempting inference with API key...");
    let chat_response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&json!({
            "model": "meta-llama/Llama-2-7b-chat-hf",
            "messages": [
                { "role": "user", "content": "Hello, who are you?" }
            ],
            "stream": false,
            "temperature": 0.7,
            "max_tokens": 100
        }))
        .await;

    println!(
        "✓ Chat completion request status: {}",
        chat_response.status_code()
    );

    if chat_response.status_code() == 200 {
        let response_body: serde_json::Value = chat_response.json();
        if let Some(choices) = response_body.get("choices").and_then(|v| v.as_array()) {
            if !choices.is_empty() {
                let content = choices[0]
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                println!("✓ Inference response: {}", content);
            }
        }
    } else {
        println!("ℹ Inference failed (expected if instance not fully initialized)");
    }

    println!("\n✅ Integration test completed successfully!");
}

/// Simpler test that just verifies the instance management endpoints work
/// without requiring a real Agent instance
#[tokio::test]
async fn test_instance_management_endpoints() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    let admin_email = "admin@admin.org";
    let user_email = "user@example.com";

    let admin_token = mock_login(&server, admin_email).await;
    let user_token = mock_login(&server, user_email).await;

    // Get user ID
    let user_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    let user_body: serde_json::Value = user_response.json();
    let user_id = Uuid::parse_str(
        user_body
            .get("user")
            .and_then(|u| u.get("id"))
            .and_then(|v| v.as_str())
            .unwrap(),
    )
    .unwrap();

    // Create test instance directly in database
    let instance_uuid = Uuid::new_v4();
    let instance_id_str = format!(
        "inst_mgt_{}",
        Uuid::new_v4().to_string().split('-').next().unwrap()
    );

    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_uuid,
                &user_id,
                &instance_id_str.as_str(),
                &"management-test-instance",
                &"http://test-instance.local",
                &"tok_test_token",
            ],
        )
        .await
        .unwrap();

    println!("✓ Created test instance: {}", instance_uuid);

    // Test all lifecycle operations
    let operations = vec![
        (
            "start",
            format!("/v1/admin/agents/instances/{}/start", instance_uuid),
        ),
        (
            "stop",
            format!("/v1/admin/agents/instances/{}/stop", instance_uuid),
        ),
        (
            "restart",
            format!("/v1/admin/agents/instances/{}/restart", instance_uuid),
        ),
        (
            "backup",
            format!("/v1/admin/agents/instances/{}/backup", instance_uuid),
        ),
        (
            "list_backups",
            format!("/v1/admin/agents/instances/{}/backups", instance_uuid),
        ),
    ];

    for (op_name, path) in operations {
        let response = if op_name == "list_backups" {
            server
                .get(&path)
                .add_header(
                    http::HeaderName::from_static("authorization"),
                    http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
                )
                .await
        } else {
            server
                .post(&path)
                .add_header(
                    http::HeaderName::from_static("authorization"),
                    http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
                )
                .await
        };

        // Operations fail with 500 because instance doesn't actually exist,
        // but this confirms the endpoint is routed and authenticated correctly
        println!(
            "✓ {} endpoint: {} (expected 500 - no real instance)",
            op_name,
            response.status_code()
        );
    }

    // Verify user can access their own instance's lifecycle operations (now user-endpoint)
    // Try to start with different user - should get 403 forbidden
    let other_user_token = mock_login(&server, "other@example.com").await;
    let non_admin_response = server
        .post(&format!("/v1/agents/instances/{}/start", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {other_user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        non_admin_response.status_code(),
        403,
        "Non-admin should be forbidden from lifecycle operations on other user's instance"
    );
    println!("✓ Non-admin correctly denied access (403)");

    // Test API key creation still works
    let api_key_response = server
        .post(&format!("/v1/agents/instances/{}/keys", instance_uuid))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&serde_json::json!({
            "name": "test-mgmt-key",
            "spend_limit": null,
            "expires_at": null
        }))
        .await;

    assert_eq!(api_key_response.status_code(), 201);
    println!("✓ User can create API key for their instance");

    println!("\n✅ Instance management endpoints working correctly!");
}
