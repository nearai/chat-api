mod common;

use common::create_test_server;
use serde_json::json;

const SESSION_TOKEN: &str = "sess_dac8f13b2dac4d9fbbef019098456472";

#[tokio::test]
#[ignore]
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
#[ignore]
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
