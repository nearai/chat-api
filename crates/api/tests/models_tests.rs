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
        settings.get("public"),
        Some(&json!(false)),
        "Default public should be false"
    );
}

#[tokio::test]
async fn test_model_settings_update_and_get() {
    let server = create_test_server().await;

    let admin_email = "test_admin_model_settings_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Update settings to public = true
    let update_body = json!({
        "public": true
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
        settings.get("public"),
        Some(&json!(true)),
        "Public should be true after update"
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
        settings.get("public"),
        Some(&json!(true)),
        "Public should remain true when fetched"
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

/// Requests with a model whose settings are non-public should be blocked with 403.
#[tokio::test]
async fn test_responses_block_non_public_model() {
    let server = create_test_server().await;

    let token = mock_login(&server, "visibility-non-public@example.com").await;

    // By default, models are non-public (public = false), so this model should be blocked.
    let body = json!({
        "model": "test-non-public-model",
        "input": "Hello"
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Requests with non-public model should be blocked with 403"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("This model is not available"),
        "Error message should indicate model is not available"
    );
}

/// Requests with a model whose settings are public should be allowed (not blocked by 403).
#[tokio::test]
async fn test_responses_allow_public_model() {
    let server = create_test_server().await;

    // Use an admin account to configure model settings
    let admin_email = "visibility-public-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Mark the model as public via admin API
    let update_body = json!({
        "public": true
    });

    let response = server
        .post("/v1/admin/model_settings/test-public-model")
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
        "Admin should be able to set model as public"
    );

    // Now send a response request using the public model
    let body = json!({
        "model": "test-public-model",
        "input": "Hello"
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // We only assert that our visibility check did not block the request with 403.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model should not be blocked by visibility check (status was {})",
        response.status_code()
    );
}

/// Requests without a `model` field should be allowed (no 403 from visibility logic).
#[tokio::test]
async fn test_responses_allow_without_model_field() {
    let server = create_test_server().await;

    let token = mock_login(&server, "visibility-no-model@example.com").await;

    // No `model` field in body
    let body = json!({
        "input": "Hello"
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "Requests without model field should not be blocked by visibility check (status was {})",
        response.status_code()
    );
}
