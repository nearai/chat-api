mod common;

use common::{create_test_server, mock_login};

#[tokio::test]
async fn test_admin_users_list_with_admin_account() {
    let server = create_test_server().await;

    let admin_email = "test_admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to list users");
}

#[tokio::test]
async fn test_admin_users_list_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to list users"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
async fn test_admin_users_list_pagination() {
    let server = create_test_server().await;

    let admin_email = "test_admin_pagination@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Create additional users for pagination test
    let _user1 = mock_login(&server, "user1@example.com").await;
    let _user2 = mock_login(&server, "user2@example.com").await;
    let _user3 = mock_login(&server, "user3@example.com").await;

    let response = server
        .get("/v1/admin/users?limit=2&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();

    let limit = body.get("limit").unwrap().as_u64().unwrap();
    let offset = body.get("offset").unwrap().as_u64().unwrap();
    let total = body.get("total").unwrap().as_u64().unwrap();
    let users = body.get("users").unwrap().as_array().unwrap();

    assert_eq!(limit, 2);
    assert_eq!(offset, 0);
    assert!(users.len() <= 2, "Should return at most 2 users");
    assert!(total >= 4, "Should have at least 4 users total");
}

#[tokio::test]
async fn test_revoke_vpc_credentials_with_admin_account() {
    let server = create_test_server().await;

    let admin_email = "test_admin_revoke@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .post("/v1/admin/vpc/revoke")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 204,
        "Admin should be able to revoke VPC credentials"
    );
}

#[tokio::test]
async fn test_revoke_vpc_credentials_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_revoke@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .post("/v1/admin/vpc/revoke")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to revoke VPC credentials"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}
