mod common;

use common::{create_test_server, mock_login};
use serde_json::json;
use serial_test::serial;

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

#[tokio::test]
#[serial(write_system_configs)]
async fn test_get_system_configs_admin_when_no_configs_exist() {
    let server = create_test_server().await;

    let admin_email = "test_admin_get_configs_none@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // GET configs without creating any first
    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should be able to get system configs even when none exist"
    );

    let body: serde_json::Value = response.json();
    assert!(
        body.is_null(),
        "Response should be null when no configs exist, got: {body:?}"
    );
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_get_system_configs_admin_when_configs_exist() {
    let server = create_test_server().await;

    let admin_email = "test_admin_get_configs_exist@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // First, create system configs
    let upsert_body = json!({
        "default_model": "test-model-for-get",
        "rate_limit": {
            "max_concurrent": 5,
            "max_requests_per_window": 10,
            "window_duration_seconds": 60,
            "window_limits": []
        }
    });

    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&upsert_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to upsert system configs"
    );

    // Now GET the configs via admin endpoint
    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should be able to get system configs when they exist"
    );

    let body: serde_json::Value = response.json();
    assert!(
        body.is_object(),
        "Response should be an object when configs exist, got: {body:?}"
    );
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-model-for-get")),
        "Response should contain the default_model"
    );
    assert!(
        body.get("rate_limit").is_some(),
        "Response should contain rate_limit (admin-only field)"
    );
}

#[tokio::test]
async fn test_get_system_configs_admin_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_get_configs@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should receive 403 Forbidden when trying to get system configs"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}
