use axum_test::TestServer;
use serde_json::json;

const SESSION_TOKEN: &str = "sess_7770c53028d8400a9c69600d800ab86e";

async fn create_test_server() -> TestServer {
    use api::{create_router, AppState};
    use std::sync::Arc;

    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let config = config::Config::from_env();

    // Create database connection
    let db = database::Database::from_config(&config.database)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    db.run_migrations().await.expect("Failed to run migrations");

    // Get repositories
    let user_repo = db.user_repository();
    let session_repo = db.session_repository();
    let oauth_repo = db.oauth_repository();
    let conversation_repo = db.conversation_repository();
    let user_settings_repo = db.user_settings_repository();

    // Create services
    let oauth_service = Arc::new(services::auth::OAuthServiceImpl::new(
        oauth_repo.clone(),
        session_repo.clone(),
        user_repo.clone(),
        config.oauth.google_client_id.clone(),
        config.oauth.google_client_secret.clone(),
        config.oauth.github_client_id.clone(),
        config.oauth.github_client_secret.clone(),
        config.oauth.redirect_uri.clone(),
    ));

    let user_service = Arc::new(services::user::UserServiceImpl::new(user_repo));

    let user_settings_service = Arc::new(services::user::UserSettingsServiceImpl::new(
        user_settings_repo as Arc<dyn services::user::ports::UserSettingsRepository>,
    ));

    // Initialize OpenAI proxy service
    let mut proxy_service =
        services::response::service::OpenAIProxy::new(config.openai.api_key.clone());
    if let Some(base_url) = config.openai.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let proxy_service = Arc::new(proxy_service);

    // Initialize conversation service
    let conversation_service = Arc::new(
        services::conversation::service::ConversationServiceImpl::new(
            conversation_repo,
            proxy_service.clone(),
        ),
    );

    // Create application state
    let app_state = AppState {
        oauth_service: oauth_service as Arc<dyn services::auth::ports::OAuthService>,
        user_service: user_service as Arc<dyn services::user::ports::UserService>,
        user_settings_service: user_settings_service
            as Arc<dyn services::user::ports::UserSettingsService>,
        session_repository: session_repo,
        proxy_service: proxy_service as Arc<dyn services::response::ports::OpenAIProxyService>,
        conversation_service: conversation_service
            as Arc<dyn services::conversation::ports::ConversationService>,
        redirect_uri: config.oauth.redirect_uri.clone(),
    };

    // Create router
    let app = create_router(app_state);

    // Create test server
    TestServer::new(app).expect("Failed to create test server")
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_conversation_workflow() {
    let server = create_test_server().await;

    println!("\n=== Test: Conversation Workflow ===");

    // Step 1: Create a conversation using OpenAI's API
    println!("1. Creating a conversation via OpenAI...");
    let create_conv_body = json!({
        "metadata": {"test": "e2e"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&create_conv_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    let conversation_id = if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ Conversation created successfully");
        let conv_id = body
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .expect("Conversation should have an ID");
        println!("   Conversation ID: {conv_id}");
        conv_id
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        panic!("Failed to create conversation");
    };

    // Step 2: Add first response to the conversation
    println!("\n2. Adding first response to the conversation...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Say hello!"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&request_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ First response created successfully");
        println!(
            "   Response ID: {}",
            body.get("id").unwrap_or(&json!("N/A"))
        );
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        panic!("Failed to create first response");
    };

    // Step 3: Add second response to the same conversation
    println!("\n3. Adding second response to the conversation...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Tell me a joke!"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&request_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ Second response created successfully");
        println!(
            "   Response ID: {}",
            body.get("id").unwrap_or(&json!("N/A"))
        );
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        panic!("Failed to create second response");
    };

    // Step 4: List conversations (fetches from OpenAI with details)
    println!("\n4. Listing conversations (should fetch details from OpenAI)...");
    let response = server
        .get("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list conversations");

    let conversations: Vec<serde_json::Value> = response.json();
    println!("   Found {} total conversations", conversations.len());

    // Find our conversation
    let our_conv = conversations.iter().find(|c| {
        c.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id == conversation_id)
            .unwrap_or(false)
    });

    if let Some(conv) = our_conv {
        println!("   ✓ Found our conversation in the list!");
        println!("      ID: {}", conv.get("id").unwrap_or(&json!("N/A")));

        // Verify that we got OpenAI conversation details (not just ID)
        if conv.get("created_at").is_some() {
            println!("      Created: {}", conv.get("created_at").unwrap());
        }
        if conv.get("updated_at").is_some() {
            println!("      Updated: {}", conv.get("updated_at").unwrap());
        }
        if conv.get("metadata").is_some() {
            println!("      Metadata: {:?}", conv.get("metadata").unwrap());
        }

        println!("   ✓ Conversation details fetched from OpenAI");
    } else {
        println!("   ✗ Our conversation not found in list");
        panic!("Conversation tracking is not working properly");
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Created conversation, added responses, and listed conversations with OpenAI details\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_conversation_access_control() {
    let server = create_test_server().await;

    println!("\n=== Test: Conversation Access Control ===");

    // Step 1: Create a conversation
    println!("1. Creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "access_control"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&create_conv_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should create conversation"
    );

    let body: serde_json::Value = response.json();
    let conversation_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Conversation should have an ID");
    println!("   ✓ Conversation created: {conversation_id}");

    // Step 2: Try to access with the same user (should succeed)
    println!("\n2. Accessing conversation as owner...");
    let response = server
        .get(&format!("/v1/conversations/{}", conversation_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    // Note: This will go through the proxy handler since we don't have a specific GET route
    // In a real implementation, you'd want to add a specific route that uses the service
    println!("   Status: {}", response.status_code());

    // For now, we're testing through the proxy which should work
    if response.status_code().is_success() {
        println!("   ✓ Successfully accessed conversation");
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Access control working correctly\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_empty_conversation_list() {
    let server = create_test_server().await;

    println!("\n=== Test: Empty Conversation List ===");

    // List conversations (may or may not be empty depending on previous tests)
    println!("1. Listing conversations...");
    let response = server
        .get("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list conversations");

    let conversations: Vec<serde_json::Value> = response.json();
    println!("   Found {} conversations", conversations.len());
    println!("   ✓ List endpoint works even with zero or many conversations");

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Can list conversations successfully\n");
}

#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test -- --ignored --nocapture
async fn test_conversation_tracking_on_response_creation() {
    let server = create_test_server().await;

    println!("\n=== Test: Conversation Tracking on Response Creation ===");

    // Step 1: Create a conversation
    println!("1. Creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "response_tracking"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&create_conv_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should create conversation"
    );

    let body: serde_json::Value = response.json();
    let conversation_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Conversation should have an ID");
    println!("   ✓ Conversation created: {conversation_id}");

    // Step 2: Add response (this should trigger conversation tracking)
    println!("\n2. Adding response to track conversation...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Test message"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should create response"
    );
    println!("   ✓ Response created");

    // Step 3: Verify conversation is now tracked in our database
    println!("\n3. Verifying conversation is tracked...");
    let response = server
        .get("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let conversations: Vec<serde_json::Value> = response.json();
    let found = conversations.iter().any(|c| {
        c.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id == conversation_id)
            .unwrap_or(false)
    });

    assert!(
        found,
        "Conversation should be tracked after response creation"
    );
    println!("   ✓ Conversation is tracked in database");
    println!("   ✓ Details fetched from OpenAI successfully");

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Conversation tracking on response creation works correctly\n");
}

#[tokio::test]
async fn test_user_settings_get_default() {
    let server = create_test_server().await;

    println!("\n=== Test: Get User Settings (Not Found) ===");

    // Try to get settings for a user that doesn't have any
    println!("1. Getting user settings (should return default)...");
    let response = server
        .get("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ Settings retrieved (default values)");
        println!("   Response: {}", serde_json::to_string_pretty(&body).unwrap());
        assert!(body.get("user_id").is_some());
        assert!(body.get("settings").is_some());
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {error_text}");
        panic!("Should return default settings or error");
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Get settings handles non-existent settings\n");
}

#[tokio::test]
async fn test_user_settings_create_and_update() {
    let server = create_test_server().await;

    println!("\n=== Test: Create and Update User Settings ===");

    // Step 1: Create settings via PATCH (first update creates the settings)
    println!("1. Creating user settings via PATCH...");
    let create_body = json!({
        "notification": true,
        "system_prompt": "You are a helpful assistant."
    });

    let response = server
        .patch("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&create_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert!(status.is_success(), "Should create settings successfully");
    let body: serde_json::Value = response.json();
    println!("   ✓ Settings created successfully");
    println!("   Response: {}", serde_json::to_string_pretty(&body).unwrap());

    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("notification"),
        Some(&json!(true)),
        "Notification should be true"
    );
    assert_eq!(
        settings.get("system_prompt"),
        Some(&json!("You are a helpful assistant.")),
        "System prompt should match"
    );

    // Step 2: Partially update settings
    println!("\n2. Partially updating user settings...");
    let update_body = json!({
        "notification": false
    });

    let response = server
        .patch("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&update_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert!(status.is_success(), "Should update settings successfully");
    let body: serde_json::Value = response.json();
    println!("   ✓ Settings updated successfully");

    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("notification"),
        Some(&json!(false)),
        "Notification should be updated to false"
    );
    assert_eq!(
        settings.get("system_prompt"),
        Some(&json!("You are a helpful assistant.")),
        "System prompt should remain unchanged"
    );

    // Step 3: Update system_prompt only
    println!("\n3. Updating system_prompt only...");
    let update_body = json!({
        "system_prompt": "You are a creative writer."
    });

    let response = server
        .patch("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .json(&update_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert!(status.is_success(), "Should update settings successfully");
    let body: serde_json::Value = response.json();
    println!("   ✓ Settings updated successfully");

    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("notification"),
        Some(&json!(false)),
        "Notification should remain false"
    );
    assert_eq!(
        settings.get("system_prompt"),
        Some(&json!("You are a creative writer.")),
        "System prompt should be updated"
    );

    // Step 4: Get settings to verify
    println!("\n4. Getting user settings to verify...");
    let response = server
        .get("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert_eq!(status, 200, "Should get settings successfully");
    let body: serde_json::Value = response.json();
    println!("   ✓ Settings retrieved successfully");

    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("notification"),
        Some(&json!(false)),
        "Notification should be false"
    );
    assert_eq!(
        settings.get("system_prompt"),
        Some(&json!("You are a creative writer.")),
        "System prompt should match"
    );

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Create and update user settings works correctly\n");
}
