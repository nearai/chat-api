mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn test_upsert_system_configs_and_get() {
    let server = create_test_server().await;

    let admin_email = "test_admin_configs_upsert@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Upsert system configs with a default_model value
    let upsert_body = json!({
        "default_model": "test-default-model-1"
    });

    let response = server
        .post("/v1/admin/settings")
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

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-default-model-1")),
        "Upserted configs should contain correct default_model"
    );

    // Get system configs to verify it was persisted
    let response = server
        .get("/v1/admin/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should be able to get system configs"
    );

    let body: serde_json::Value = response.json();
    assert!(
        body.is_object(),
        "System configs GET after upsert should return an object, got: {body:?}"
    );
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-default-model-1")),
        "Fetched system configs should contain correct default_model"
    );
}

#[tokio::test]
async fn test_update_system_configs() {
    let server = create_test_server().await;

    let admin_email = "test_admin_configs_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Ensure a known initial config via upsert
    let upsert_body = json!({
        "default_model": "initial-model"
    });

    let response = server
        .post("/v1/admin/settings")
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
        "Admin should be able to upsert initial system configs"
    );

    // Partially update configs (simulate PATCH behavior)
    let update_body = json!({
        "default_model": "updated-model"
    });

    let response = server
        .patch("/v1/admin/settings")
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
        "Admin should be able to update system configs"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Updated system configs should contain new default_model"
    );

    // Verify via GET
    let response = server
        .get("/v1/admin/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should be able to get updated system configs"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Fetched system configs should reflect updated default_model"
    );
}

#[tokio::test]
async fn test_system_configs_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_configs@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    // Non-admin trying to GET system configs should receive 403
    let response = server
        .get("/v1/admin/settings")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should receive 403 Forbidden when accessing system configs"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}
