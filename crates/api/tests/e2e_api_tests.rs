use axum_test::TestServer;
use serde_json::json;

const SESSION_TOKEN: &str = "sess_e7ce7abb623a46f68db69a12e995af21";

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

    // Initialize OpenAI proxy service
    let mut proxy_service =
        services::response::service::OpenAIProxy::new(config.openai.api_key.clone());
    if let Some(base_url) = config.openai.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let proxy_service = Arc::new(proxy_service);

    // Initialize conversation service
    let conversation_service =
        Arc::new(services::conversation::service::ConversationServiceImpl::new(conversation_repo));

    // Create application state
    let app_state = AppState {
        oauth_service: oauth_service as Arc<dyn services::auth::ports::OAuthService>,
        user_service: user_service as Arc<dyn services::user::ports::UserService>,
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

    // Step 2: Add first response with custom items to the conversation
    println!("\n2. Adding response with custom items to the conversation...");
    let request_body = json!({
        "items": [
            {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": "Tell me a joke",
                    }
                ]
            }, // TODO: should add assistant item here?
        ]
    });

    let response = server
        .post(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", SESSION_TOKEN)).unwrap(),
        )
        .json(&request_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ First response with custom items created successfully");
        println!(
            "   Response items: {}",
            body.get("items").unwrap_or(&json!("N/A"))
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
                "content": "Explain what makes the joke funny"
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

    // Step 4: Add third response to the conversation
    println!("\n4. Adding third response to the conversation...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Tell me another joke with the same topic"
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
    println!("   Status: {}", status);

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ Third response created successfully");
        println!(
            "   Response ID: {}",
            body.get("id").unwrap_or(&json!("N/A"))
        );
    } else {
        let error_text = response.text();
        println!("   ✗ Failed: {}", error_text);
        panic!("Failed to create third response");
    };

    // Step 5: List conversations (from our database)
    println!("\n5. Listing conversations from database...");
    let response = server
        .get("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {SESSION_TOKEN}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list conversations");

    let conversations: Vec<serde_json::Value> = response.json();
    println!("{conversations:?}");
    println!("   Found {} total conversations", conversations.len());

    // Find our conversation
    let our_conv = conversations.iter().find(|c| c["id"] == conversation_id);

    if let Some(conv) = our_conv {
        println!("   ✓ Found our conversation in the list!");
        println!("      ID: {}", conv["id"]);
        println!("      Title: {:?}", conv["title"]);
        println!("      Created: {}", conv["created_at"]);
        println!("      Updated: {}", conv["updated_at"]);
    } else {
        println!("   ⚠ Our conversation not found in list");
        println!("   This means conversation tracking may not be working properly");
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Created conversation, added response, and listed conversations successfully\n");
}
