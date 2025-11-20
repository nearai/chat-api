mod common;

use common::create_test_server;
use serde_json::json;

/// Helper function to create a user and get a session token via mock login
async fn create_user_and_get_token(server: &axum_test::TestServer, email: &str) -> String {
    let login_request = json!({
        "email": email,
        "name": format!("Test User {}", email),
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(response.status_code(), 200, "Mock login should succeed");

    let body: serde_json::Value = response.json();
    body.get("token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Response should contain token")
}

#[tokio::test]
async fn test_user_settings_get_default() {
    let server = create_test_server().await;

    println!("\n=== Test: Get Default User Settings ===");

    // Create a user and get token via mock login
    println!("\n0. Creating user via mock login...");
    let token = create_user_and_get_token(&server, "test_user_settings@example.com").await;
    println!("   ✓ User created and token obtained");

    // Try to get settings for a user that doesn't have any
    println!("\n1. Getting user settings (should return default)...");
    let response = server
        .get("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    if status.is_success() {
        let body: serde_json::Value = response.json();
        println!("   ✓ Settings retrieved (default values)");
        println!(
            "   Response: {}",
            serde_json::to_string_pretty(&body).unwrap()
        );
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

    // Create a user and get token via mock login
    println!("0. Creating user via mock login...");
    let token = create_user_and_get_token(&server, "test_user_settings_update@example.com").await;
    println!("   ✓ User created and token obtained");

    // Step 1: Create settings via PATCH (first update creates the settings)
    println!("\n1. Creating user settings via PATCH...");
    let create_body = json!({
        "notification": true,
        "system_prompt": "You are a helpful assistant."
    });

    let response = server
        .patch("/v1/users/me/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&create_body)
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert!(status.is_success(), "Should create settings successfully");
    let body: serde_json::Value = response.json();
    println!("   ✓ Settings created successfully");
    println!(
        "   Response: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

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
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
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
