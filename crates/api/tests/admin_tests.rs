mod common;

use common::{create_test_server, mock_login};

#[tokio::test]
async fn test_admin_users_list_with_admin_account() {
    let server = create_test_server().await;

    println!("\n=== Test: List Users with Admin Account ===");

    // Create an admin user (email domain is admin.org)
    println!("\n0. Creating admin user via mock login...");
    let admin_email = "test_admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;
    println!("   ✓ Admin user created and token obtained");

    // Test listing users as admin
    println!("\n1. Listing users as admin...");
    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert_eq!(status, 200, "Admin should be able to list users");

    let body: serde_json::Value = response.json();
    println!("   ✓ Users listed successfully");
    println!(
        "   Response: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

    // Verify response structure
    assert!(
        body.get("users").is_some(),
        "Response should have users field"
    );

    let users = body.get("users").unwrap().as_array().unwrap();
    println!("   Found {} users", users.len());

    // Verify that the admin user is in the list
    let admin_user_found = users.iter().any(|user| {
        user.get("email")
            .and_then(|v| v.as_str())
            .map(|email| email == admin_email)
            .unwrap_or(false)
    });
    assert!(admin_user_found, "Admin user should be in the users list");
    println!("   ✓ Admin user found in the list");

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Admin can successfully list users\n");
}

#[tokio::test]
async fn test_admin_users_list_with_non_admin_account() {
    let server = create_test_server().await;

    println!("\n=== Test: List Users with Non-Admin Account ===");

    // Create a non-admin user (email domain is not admin.org)
    println!("\n0. Creating non-admin user via mock login...");
    let non_admin_email = "test_user@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;
    println!("   ✓ Non-admin user created and token obtained");

    // Test listing users as non-admin (should fail with 403)
    println!("\n1. Attempting to list users as non-admin...");
    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    println!("   Status: {status}");

    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to list users"
    );

    let body: serde_json::Value = response.json();
    println!("   ✓ Access correctly denied");
    println!(
        "   Response: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

    // Verify error message
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Non-admin correctly denied access to admin endpoint\n");
}

#[tokio::test]
async fn test_admin_users_list_pagination() {
    let server = create_test_server().await;

    println!("\n=== Test: List Users with Pagination ===");

    // Create an admin user
    println!("\n0. Creating admin user via mock login...");
    let admin_email = "test_admin_pagination@admin.org";
    let admin_token = mock_login(&server, admin_email).await;
    println!("   ✓ Admin user created and token obtained");

    // Create a few more users to test pagination
    println!("\n0.1. Creating additional users for pagination test...");
    let _user1 = mock_login(&server, "user1@example.com").await;
    let _user2 = mock_login(&server, "user2@example.com").await;
    let _user3 = mock_login(&server, "user3@example.com").await;
    println!("   ✓ Additional users created");

    // Test pagination with page=1, page_size=2
    println!("\n1. Testing pagination (page=1, page_size=2)...");
    let response = server
        .get("/v1/admin/users?page=1&page_size=2")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();

    let page = body.get("page").unwrap().as_u64().unwrap();
    let page_size = body.get("page_size").unwrap().as_u64().unwrap();
    let total = body.get("total").unwrap().as_u64().unwrap();
    let users = body.get("users").unwrap().as_array().unwrap();

    assert_eq!(page, 1);
    assert_eq!(page_size, 2);
    assert!(users.len() <= 2, "Should return at most 2 users per page");
    assert!(total >= 4, "Should have at least 4 users total");

    println!("   ✓ Pagination works correctly");
    println!(
        "   Page: {}, Page Size: {}, Total: {}, Users in page: {}",
        page,
        page_size,
        total,
        users.len()
    );

    println!("\n=== Test Complete ===");
    println!("✅ Test passed: Pagination works correctly\n");
}
