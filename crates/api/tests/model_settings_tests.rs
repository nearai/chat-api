mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn test_model_settings_get_default() {
    let server = create_test_server().await;

    // Use an admin account to access admin endpoints
    let admin_email = "test_admin_model_settings_default@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .get("/v1/admin/model_settings/test-model-1")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 200,
        "Should return default model settings when none exist"
    );

    let body: serde_json::Value = response.json();
    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("private"),
        Some(&json!(false)),
        "Default private should be false"
    );
}

#[tokio::test]
async fn test_model_settings_update_and_get() {
    let server = create_test_server().await;

    let admin_email = "test_admin_model_settings_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Update settings to private = true
    let update_body = json!({
        "private": true
    });

    let response = server
        .post("/v1/admin/model_settings/test-model-2")
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

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to update model settings");

    let body: serde_json::Value = response.json();
    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("private"),
        Some(&json!(true)),
        "Private should be true after update"
    );

    // Get settings to verify
    let response = server
        .get("/v1/admin/model_settings/test-model-2")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to get model settings");

    let body: serde_json::Value = response.json();
    let settings = body.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("private"),
        Some(&json!(true)),
        "Private should remain true when fetched"
    );
}

#[tokio::test]
async fn test_model_settings_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_model_settings@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/model_settings/test-model-3")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when accessing model settings"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}
