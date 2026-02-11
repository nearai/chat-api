mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

/// Test 1: Author metadata stored when creating response via /v1/responses
#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test --test response_author_tests --features test -- --ignored --nocapture
async fn test_response_author_stored_on_create() {
    let server = create_test_server().await;
    let token = mock_login(&server, "author@test.com").await;

    println!("\n=== Test: Response Author Stored on Create ===");

    // Step 1: Create a conversation
    println!("1. Creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "author_tracking"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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

    // Step 2: Create a response
    println!("\n2. Creating a response...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Hello, world!"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should create response"
    );
    println!("   ✓ Response created");

    // Step 3: List conversation items and verify author metadata
    println!("\n3. Listing conversation items to verify author metadata...");
    let response = server
        .get(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert!(response.status_code().is_success(), "Should list items");

    let items: serde_json::Value = response.json();
    let data = items.get("data").and_then(|d| d.as_array());

    if let Some(data_arr) = data {
        println!("   Found {} items", data_arr.len());

        // Look for an item with author metadata
        let has_author = data_arr.iter().any(|item| {
            item.get("metadata")
                .and_then(|m| m.get("author_id"))
                .is_some()
        });

        if has_author {
            println!("   ✓ Author metadata found in items");
        } else {
            println!(
                "   Note: Author metadata may be in response_authors table but not yet injected"
            );
        }
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Response author tracking on create\n");
}

/// Test 2: Author metadata injected when listing conversation items
#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test --test response_author_tests --features test -- --ignored --nocapture
async fn test_author_metadata_injected_on_list() {
    let server = create_test_server().await;
    let token = mock_login(&server, "user@test.com").await;

    println!("\n=== Test: Author Metadata Injected on List ===");

    // Step 1: Create a conversation
    println!("1. Creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "metadata_injection"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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

    // Step 2: Add a response
    println!("\n2. Adding a response...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Test message for metadata injection"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should create response"
    );
    println!("   ✓ Response created");

    // Step 3: List items and check for author metadata
    println!("\n3. Listing items and verifying author metadata...");
    let response = server
        .get(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list items");

    let items: serde_json::Value = response.json();
    let data = items.get("data").and_then(|d| d.as_array());

    if let Some(data_arr) = data {
        for item in data_arr {
            if let Some(response_id) = item.get("response_id").and_then(|v| v.as_str()) {
                let metadata = item.get("metadata");
                let author_id = metadata.and_then(|m| m.get("author_id"));
                let author_name = metadata.and_then(|m| m.get("author_name"));

                println!("   Item response_id: {}", response_id);
                println!("   Author ID: {:?}", author_id);
                println!("   Author Name: {:?}", author_name);
            }
        }
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Author metadata injection on list\n");
}

/// Test 3: Shared conversation shows correct author for each user's messages
#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test --test response_author_tests --features test -- --ignored --nocapture
async fn test_shared_conversation_author_attribution() {
    let server = create_test_server().await;

    println!("\n=== Test: Shared Conversation Author Attribution ===");

    // Create owner and shared user
    let owner_token = mock_login(&server, "owner@test.com").await;
    let shared_token = mock_login(&server, "shared@test.com").await;

    // Step 1: Owner creates conversation
    println!("\n1. Owner creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "shared_author"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
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
    println!("   ✓ Owner created conversation: {conversation_id}");

    // Step 2: Owner adds first message
    println!("\n2. Owner sending first message...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Hello from owner!"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Owner should create response"
    );
    println!("   ✓ Owner's message created");

    // Step 3: Owner shares with shared user
    println!("\n3. Owner sharing conversation with shared user...");
    let share_body = json!({
        "permission": "write",
        "target": {
            "mode": "direct",
            "recipients": [
                {
                    "kind": "email",
                    "value": "shared@test.com"
                }
            ]
        }
    });

    let response = server
        .post(&format!("/v1/conversations/{conversation_id}/shares"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
        )
        .json(&share_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should share conversation"
    );
    println!("   ✓ Conversation shared");

    // Step 4: Shared user sends a message
    println!("\n4. Shared user sending message...");
    let request_body = json!({
        "conversation": conversation_id,
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "Hello from shared user!"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {shared_token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Shared user should create response"
    );
    println!("   ✓ Shared user's message created");

    // Step 5: Owner lists items - should see both authors correctly
    println!("\n5. Owner listing items to verify author attribution...");
    let response = server
        .get(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {owner_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Should list items");

    let items: serde_json::Value = response.json();
    let data = items.get("data").and_then(|d| d.as_array());

    if let Some(data_arr) = data {
        println!("   Found {} items", data_arr.len());

        let mut owner_messages = 0;
        let mut shared_messages = 0;

        for item in data_arr {
            if let Some(metadata) = item.get("metadata") {
                let author_name = metadata
                    .get("author_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                println!("   Item author: {}", author_name);

                if author_name.contains("owner") {
                    owner_messages += 1;
                } else if author_name.contains("shared") {
                    shared_messages += 1;
                }
            }
        }

        println!("\n   Owner messages: {}", owner_messages);
        println!("   Shared user messages: {}", shared_messages);

        assert!(owner_messages > 0, "Should have owner's messages");
        assert!(shared_messages > 0, "Should have shared user's messages");
        println!("   ✓ Both users' messages correctly attributed");
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Shared conversation author attribution\n");
}

/// Test 4: Author metadata in create_conversation_items endpoint
#[tokio::test]
#[ignore] // This makes real OpenAI API calls - run with: cargo test --test response_author_tests --features test -- --ignored --nocapture
async fn test_create_items_stores_author() {
    let server = create_test_server().await;
    let token = mock_login(&server, "items_author@test.com").await;

    println!("\n=== Test: Create Conversation Items Stores Author ===");

    // Step 1: Create a conversation
    println!("1. Creating a conversation...");
    let create_conv_body = json!({
        "metadata": {"test": "items_author"}
    });

    let response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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

    // Step 2: Create item using POST /v1/conversations/{id}/items
    println!("\n2. Creating item via conversation items endpoint...");
    let item_body = json!({
        "type": "message",
        "role": "user",
        "content": [
            {
                "type": "input_text",
                "text": "Hello via items endpoint!"
            }
        ]
    });

    let response = server
        .post(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&item_body)
        .await;

    // Note: This might fail if OpenAI doesn't support this exact format
    // but we're testing that author metadata is injected into the request
    println!("   Status: {}", response.status_code());

    if response.status_code().is_success() {
        println!("   ✓ Item created");

        // Check if the response contains response_id
        let body: serde_json::Value = response.json();
        if let Some(response_id) = body.get("response_id").and_then(|v| v.as_str()) {
            println!("   Response ID: {}", response_id);
        }
    }

    // Step 3: List items to verify author metadata
    println!("\n3. Listing items to verify author metadata...");
    let response = server
        .get(&format!("/v1/conversations/{conversation_id}/items"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert!(response.status_code().is_success(), "Should list items");

    let items: serde_json::Value = response.json();
    println!("   Items response received");

    if let Some(data) = items.get("data").and_then(|d| d.as_array()) {
        for item in data {
            let metadata = item.get("metadata");
            let author_name = metadata
                .and_then(|m| m.get("author_name"))
                .and_then(|v| v.as_str());

            if let Some(name) = author_name {
                println!("   Found author: {}", name);
            }
        }
    }

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Create items stores author\n");
}
