mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn test_upsert_global_config_and_get() {
    let server = create_test_server().await;

    let admin_email = "test_admin_globals_upsert@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Upsert system settings with a default_model value
    let upsert_body = json!({
        "default_model": "test-default-model-1"
    });

    let response = server
        .post("/v1/admin/configs")
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
        "Admin should be able to upsert system settings"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-default-model-1")),
        "Upserted settings should contain correct default_model"
    );

    // Get system settings to verify it was persisted
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
        "Admin should be able to get system settings"
    );

    let body: serde_json::Value = response.json();
    assert!(
        body.is_object(),
        "System settings GET after upsert should return an object, got: {body:?}"
    );
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-default-model-1")),
        "Fetched system settings should contain correct default_model"
    );
}

#[tokio::test]
async fn test_update_global_config() {
    let server = create_test_server().await;

    let admin_email = "test_admin_globals_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Ensure a known initial config via upsert
    let upsert_body = json!({
        "default_model": "initial-model"
    });

    let response = server
        .post("/v1/admin/configs")
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

    println!("{}", response.text());

    assert!(
        response.status_code().is_success(),
        "Admin should be able to upsert initial system settings"
    );

    // Partially update settings (simulate PATCH behavior)
    let update_body = json!({
        "default_model": "updated-model"
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
        .json(&update_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to update system settings"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Updated system settings should contain new default_model"
    );

    // Verify via GET
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
        "Admin should be able to get updated system settings"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Fetched system settings should reflect updated default_model"
    );
}

#[tokio::test]
async fn test_global_config_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_globals@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    // Non-admin trying to GET system settings should receive 403
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
        "Non-admin should receive 403 Forbidden when accessing system settings"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}
