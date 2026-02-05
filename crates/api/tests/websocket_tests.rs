mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

/// Test that the typing indicator endpoint requires authentication
#[tokio::test]
async fn test_typing_indicator_requires_auth() {
    let server = create_test_server().await;

    // Try to send typing indicator without authentication
    let response = server.post("/v1/conversations/conv-123/typing").await;

    // Should get 401 Unauthorized
    assert_eq!(
        response.status_code(),
        401,
        "Typing indicator should require authentication"
    );
}

/// Test that the typing indicator endpoint returns 403 for non-existent conversation
#[tokio::test]
async fn test_typing_indicator_conversation_access() {
    let server = create_test_server().await;

    // Login as a user
    let token = mock_login(&server, "websocket-test@example.com").await;

    // Try to send typing indicator to a conversation that doesn't exist or user doesn't have access to
    let response = server
        .post("/v1/conversations/nonexistent-conv-123/typing")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    // Should get 403 Forbidden or 404 Not Found
    let status = response.status_code();
    assert!(
        status == 403 || status == 404,
        "Should deny access to non-existent conversation, got {}",
        status
    );
}

/// Test that the typing indicator endpoint returns 204 for valid conversation
/// Note: This test requires a real conversation to be created first
#[tokio::test]
#[ignore] // Requires OpenAI API - run with: cargo test --features test -- --ignored
async fn test_typing_indicator_success() {
    let server = create_test_server().await;

    // Login as a user
    let token = mock_login(&server, "websocket-typing-test@example.com").await;

    // First, create a conversation
    let create_conv_body = json!({
        "metadata": {"test": "websocket-typing"}
    });

    let create_response = server
        .post("/v1/conversations")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&create_conv_body)
        .await;

    assert_eq!(
        create_response.status_code(),
        200,
        "Should create conversation"
    );

    let conv: serde_json::Value = create_response.json();
    let conversation_id = conv
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Should have conversation ID");

    // Now send typing indicator
    let response = server
        .post(&format!("/v1/conversations/{conversation_id}/typing"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    // Should get 204 No Content
    assert_eq!(
        response.status_code(),
        204,
        "Typing indicator should return 204 No Content"
    );
}

/// Test WebSocket message serialization/deserialization
/// This tests the message format that would be sent over WebSocket
#[tokio::test]
async fn test_websocket_message_format() {
    use api::WebSocketMessage;

    // Test NewItems message
    let new_items = WebSocketMessage::NewItems {
        conversation_id: "conv-123".to_string(),
        items: json!([{"id": "item-1", "type": "message", "role": "user"}]),
    };
    let json_str = serde_json::to_string(&new_items).unwrap();
    assert!(json_str.contains("\"event_type\":\"new_items\""));
    assert!(json_str.contains("\"conversation_id\":\"conv-123\""));

    // Verify it can be deserialized back
    let parsed: WebSocketMessage = serde_json::from_str(&json_str).unwrap();
    match parsed {
        WebSocketMessage::NewItems {
            conversation_id, ..
        } => {
            assert_eq!(conversation_id, "conv-123");
        }
        _ => panic!("Expected NewItems"),
    }

    // Test ResponseCreated message
    let response_created = WebSocketMessage::ResponseCreated {
        conversation_id: "conv-456".to_string(),
        response_id: Some("resp-789".to_string()),
    };
    let json_str = serde_json::to_string(&response_created).unwrap();
    assert!(json_str.contains("\"event_type\":\"response_created\""));
    assert!(json_str.contains("\"response_id\":\"resp-789\""));

    // Test Typing message
    let typing = WebSocketMessage::Typing {
        conversation_id: "conv-abc".to_string(),
        user_id: "user-123".to_string(),
        user_name: Some("Test User".to_string()),
    };
    let json_str = serde_json::to_string(&typing).unwrap();
    assert!(json_str.contains("\"event_type\":\"typing\""));
    assert!(json_str.contains("\"user_name\":\"Test User\""));

    // Test Ping/Pong messages
    let ping = WebSocketMessage::Ping;
    let json_str = serde_json::to_string(&ping).unwrap();
    assert!(json_str.contains("\"event_type\":\"ping\""));

    let pong = WebSocketMessage::Pong;
    let json_str = serde_json::to_string(&pong).unwrap();
    assert!(json_str.contains("\"event_type\":\"pong\""));
}

/// Test ConnectionManager subscribe/broadcast cycle
#[tokio::test]
async fn test_connection_manager_integration() {
    use api::ConnectionManager;

    let manager = ConnectionManager::new();
    let conv_id = "integration-test-conv";

    // Subscribe two receivers
    let mut receiver1 = manager.subscribe(conv_id).await;
    let mut receiver2 = manager.subscribe(conv_id).await;

    // Verify channel count
    assert_eq!(manager.active_channels_count().await, 1);

    // Broadcast a message
    let items = json!([{"id": "test-item"}]);
    let count = manager.broadcast_new_items(conv_id, items.clone()).await;
    assert_eq!(count, 2, "Should broadcast to 2 subscribers");

    // Both receivers should get the message
    assert!(receiver1.try_recv().is_ok());
    assert!(receiver2.try_recv().is_ok());

    // Drop one receiver (simulates WebSocket disconnect)
    drop(receiver2);

    // Broadcast again - only receiver1 should receive
    let count = manager.broadcast_new_items(conv_id, items.clone()).await;
    assert_eq!(count, 1, "Should broadcast to 1 remaining subscriber");
    assert!(receiver1.try_recv().is_ok());

    // Unsubscribe (for cleanup tracking)
    manager.unsubscribe(conv_id).await;
    manager.unsubscribe(conv_id).await;

    // Channel should be cleaned up
    assert_eq!(manager.active_channels_count().await, 0);
}

/// Test that broadcasts to different conversations are isolated
#[tokio::test]
async fn test_broadcast_isolation() {
    use api::ConnectionManager;

    let manager = ConnectionManager::new();

    // Subscribe to two different conversations
    let mut receiver_conv1 = manager.subscribe("conv-1").await;
    let mut receiver_conv2 = manager.subscribe("conv-2").await;

    // Broadcast to conv-1 only
    let items = json!([{"message": "for conv-1"}]);
    let count = manager.broadcast_new_items("conv-1", items).await;
    assert_eq!(count, 1);

    // Only conv-1 receiver should get the message
    assert!(receiver_conv1.try_recv().is_ok());
    assert!(receiver_conv2.try_recv().is_err()); // Should be empty

    // Broadcast to conv-2 only
    let items = json!([{"message": "for conv-2"}]);
    let count = manager.broadcast_new_items("conv-2", items).await;
    assert_eq!(count, 1);

    // Only conv-2 receiver should get this message
    assert!(receiver_conv2.try_recv().is_ok());
    // conv-1 already received its message, no new messages
}

/// Test response_created broadcast
#[tokio::test]
async fn test_broadcast_response_created() {
    use api::{ConnectionManager, WebSocketMessage};

    let manager = ConnectionManager::new();
    let conv_id = "response-test-conv";

    // Subscribe
    let mut receiver = manager.subscribe(conv_id).await;

    // Broadcast response created
    let count = manager
        .broadcast_response_created(conv_id, Some("resp-abc123"))
        .await;
    assert_eq!(count, 1);

    // Check the message
    let msg = receiver.try_recv().unwrap();
    match msg {
        WebSocketMessage::ResponseCreated {
            conversation_id,
            response_id,
        } => {
            assert_eq!(conversation_id, conv_id);
            assert_eq!(response_id, Some("resp-abc123".to_string()));
        }
        _ => panic!("Expected ResponseCreated message"),
    }

    // Test with None response_id
    let count = manager.broadcast_response_created(conv_id, None).await;
    assert_eq!(count, 1);

    let msg = receiver.try_recv().unwrap();
    match msg {
        WebSocketMessage::ResponseCreated { response_id, .. } => {
            assert_eq!(response_id, None);
        }
        _ => panic!("Expected ResponseCreated message"),
    }
}

/// Test typing indicator broadcast
#[tokio::test]
async fn test_broadcast_typing() {
    use api::{ConnectionManager, WebSocketMessage};

    let manager = ConnectionManager::new();
    let conv_id = "typing-test-conv";

    // Subscribe
    let mut receiver = manager.subscribe(conv_id).await;

    // Broadcast typing with user name
    let count = manager
        .broadcast_typing(conv_id, "user-123", Some("Alice".to_string()))
        .await;
    assert_eq!(count, 1);

    // Check the message
    let msg = receiver.try_recv().unwrap();
    match msg {
        WebSocketMessage::Typing {
            conversation_id,
            user_id,
            user_name,
        } => {
            assert_eq!(conversation_id, conv_id);
            assert_eq!(user_id, "user-123");
            assert_eq!(user_name, Some("Alice".to_string()));
        }
        _ => panic!("Expected Typing message"),
    }

    // Broadcast typing without user name
    let count = manager.broadcast_typing(conv_id, "user-456", None).await;
    assert_eq!(count, 1);

    let msg = receiver.try_recv().unwrap();
    match msg {
        WebSocketMessage::Typing {
            user_id, user_name, ..
        } => {
            assert_eq!(user_id, "user-456");
            assert_eq!(user_name, None);
        }
        _ => panic!("Expected Typing message"),
    }
}
