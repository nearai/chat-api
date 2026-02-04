mod common;

use common::{create_test_server, mock_login};
use serde_json::json;
use serial_test::serial;

#[tokio::test]
#[serial(write_system_configs)]
async fn test_upsert_system_configs_and_get() {
    let server = create_test_server().await;

    let admin_email = "test_admin_configs_upsert@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Upsert system configs with a default_model value
    let upsert_body = json!({
        "default_model": "test-default-model-1"
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

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("test-default-model-1")),
        "Upserted configs should contain correct default_model"
    );

    // Get system configs to verify it was persisted (requires user auth)
    let response = server
        .get("/v1/configs")
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
#[serial(write_system_configs)]
async fn test_update_system_configs() {
    let server = create_test_server().await;

    let admin_email = "test_admin_configs_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Ensure a known initial config via upsert
    let upsert_body = json!({
        "default_model": "initial-model"
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
        "Admin should be able to upsert initial system configs"
    );

    // Partially update configs
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
        "Admin should be able to update system configs"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Updated system configs should contain new default_model"
    );

    // Verify via public GET (only default_model is returned)
    let response = server
        .get("/v1/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should be able to get public system configs"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Public config should have default_model"
    );
    assert!(
        body.get("rate_limit").is_none(),
        "Public config should NOT have rate_limit"
    );

    // Verify via admin GET (full config including rate_limit)
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
        "Admin should be able to get full system configs"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("default_model"),
        Some(&json!("updated-model")),
        "Full config should have updated default_model"
    );
    assert!(
        body.get("rate_limit").is_some(),
        "Full config should have rate_limit"
    );
}

#[tokio::test]
async fn test_get_system_configs_requires_auth() {
    let server = create_test_server().await;

    // GET /v1/configs without authentication should return 401
    let response = server.get("/v1/configs").await;

    assert_eq!(
        response.status_code(),
        401,
        "GET /v1/configs should require user authentication"
    );
}

#[tokio::test]
async fn test_get_system_configs_allows_non_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_configs@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    // Non-admin user should be able to GET public system configs
    let response = server
        .get("/v1/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    assert!(
        response.status_code().is_success() || response.status_code() == 200,
        "Non-admin users should be able to GET public system configs"
    );

    let body: serde_json::Value = response.json();
    // Public config should NOT have rate_limit
    assert!(
        body.get("rate_limit").is_none(),
        "Non-admin should not see rate_limit in public config"
    );
}

#[tokio::test]
async fn test_get_full_configs_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_full_configs@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    // Non-admin trying to GET full configs should receive 403
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
        "Non-admin should receive 403 when accessing full configs"
    );
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_system_configs_write_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_configs@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    // Non-admin trying to PATCH system configs should receive 403
    let upsert_body = json!({
        "default_model": "test-model"
    });

    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&upsert_body)
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should receive 403 Forbidden when writing system configs"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_upsert_rate_limit_config() {
    let server = create_test_server().await;

    let admin_email = "test_admin_rate_limit@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Upsert system configs with rate_limit configuration
    let upsert_body = json!({
        "rate_limit": {
            "max_concurrent": 5,
            "max_requests_per_window": 10,
            "window_duration_seconds": 60,
            "window_limits": [
                {
                    "window_duration_seconds": 86400,
                    "limit": 1000
                },
                {
                    "window_duration_seconds": 604800,
                    "limit": 5000
                }
            ],
            "token_window_limits": [],
            "cost_window_limits": []
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
        "Admin should be able to upsert rate_limit config"
    );

    let body: serde_json::Value = response.json();
    let rate_limit = body.get("rate_limit").expect("Should have rate_limit");
    assert_eq!(
        rate_limit.get("max_concurrent"),
        Some(&json!(5)),
        "max_concurrent should match"
    );
    assert_eq!(
        rate_limit.get("max_requests_per_window"),
        Some(&json!(10)),
        "max_requests_per_window should match"
    );
    assert_eq!(
        rate_limit.get("window_duration_seconds"),
        Some(&json!(60)),
        "window_duration_seconds should match"
    );

    let window_limits = rate_limit
        .get("window_limits")
        .and_then(|v| v.as_array())
        .expect("Should have window_limits array");
    assert_eq!(window_limits.len(), 2, "Should have 2 window limits");
    assert_eq!(
        window_limits[0].get("window_duration_seconds"),
        Some(&json!(86400))
    );
    assert_eq!(window_limits[0].get("limit"), Some(&json!(1000)));

    // Verify via GET (admin endpoint to see full config including rate_limit)
    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    let rate_limit = body.get("rate_limit").expect("Should have rate_limit");

    // Verify all fields are correctly persisted
    assert_eq!(
        rate_limit.get("max_concurrent"),
        Some(&json!(5)),
        "max_concurrent should be persisted"
    );
    assert_eq!(
        rate_limit.get("max_requests_per_window"),
        Some(&json!(10)),
        "max_requests_per_window should be persisted"
    );
    assert_eq!(
        rate_limit.get("window_duration_seconds"),
        Some(&json!(60)),
        "window_duration_seconds should be persisted"
    );

    let window_limits = rate_limit
        .get("window_limits")
        .and_then(|v| v.as_array())
        .expect("Should have window_limits array");
    assert_eq!(window_limits.len(), 2, "Should have 2 window limits");

    // Verify first window limit (day)
    assert_eq!(
        window_limits[0].get("window_duration_seconds"),
        Some(&json!(86400)),
        "First window should be 1 day (86400 seconds)"
    );
    assert_eq!(
        window_limits[0].get("limit"),
        Some(&json!(1000)),
        "First window limit should be 1000"
    );

    // Verify second window limit (week)
    assert_eq!(
        window_limits[1].get("window_duration_seconds"),
        Some(&json!(604800)),
        "Second window should be 1 week (604800 seconds)"
    );
    assert_eq!(
        window_limits[1].get("limit"),
        Some(&json!(5000)),
        "Second window limit should be 5000"
    );
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_invalid_rate_limit_config_rejected() {
    let server = create_test_server().await;

    let admin_email = "test_admin_invalid_rate_limit@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Test 1: zero max_concurrent
    let invalid_body = json!({
        "rate_limit": {
            "max_concurrent": 0,
            "max_requests_per_window": 10,
            "window_duration_seconds": 60,
            "window_limits": [],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&invalid_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should reject zero max_concurrent"
    );

    // Test 2: zero window_duration_seconds
    let invalid_body = json!({
        "rate_limit": {
            "max_concurrent": 2,
            "max_requests_per_window": 10,
            "window_duration_seconds": 0,
            "window_limits": [],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&invalid_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should reject zero window_duration_seconds"
    );

    // Test 3: zero window_duration_seconds in window_limits
    let invalid_body = json!({
        "rate_limit": {
            "max_concurrent": 2,
            "max_requests_per_window": 10,
            "window_duration_seconds": 60,
            "window_limits": [
                {
                    "window_duration_seconds": 0,
                    "limit": 100
                }
            ],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&invalid_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should reject zero window_duration_seconds in window_limits"
    );
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_empty_window_limits_allowed() {
    let server = create_test_server().await;

    let admin_email = "test_admin_empty_window_limits@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Empty window_limits should be allowed (disables long-term window limiting)
    let valid_body = json!({
        "rate_limit": {
            "max_concurrent": 2,
            "max_requests_per_window": 10,
            "window_duration_seconds": 60,
            "window_limits": [],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&valid_body)
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Empty window_limits should be allowed"
    );

    let body: serde_json::Value = response.json();
    let rate_limit = body.get("rate_limit").expect("Should have rate_limit");
    let window_limits = rate_limit
        .get("window_limits")
        .and_then(|v| v.as_array())
        .expect("Should have window_limits array");
    assert_eq!(
        window_limits.len(),
        0,
        "window_limits should be empty array"
    );
}

#[tokio::test]
#[serial(write_system_configs)]
async fn test_rate_limit_config_hot_reload() {
    let server = create_test_server().await;

    let admin_email = "test_admin_hot_reload@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Step 1: Set initial rate limit config (very restrictive)
    let initial_config = json!({
        "rate_limit": {
            "max_concurrent": 1,
            "max_requests_per_window": 1,
            "window_duration_seconds": 10,
            "window_limits": [
                {
                    "window_duration_seconds": 60,
                    "limit": 2
                }
            ],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&initial_config)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should set initial config"
    );

    // Step 2: Make first request (should succeed)
    let test_user_email = "test_user_hot_reload@example.com";
    let user_token = mock_login(&server, test_user_email).await;

    let request_body = json!({
        "model": "test-model",
        "input": "First request"
    });

    let response1 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert_ne!(
        response1.status_code(),
        429,
        "First request should not be rate limited"
    );

    // Step 3: Make second request immediately (should be rate limited with restrictive config)
    let response2 = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response2.status_code(),
        429,
        "Second request should be rate limited with restrictive config"
    );

    // Step 4: Update config to be more permissive (hot reload)
    let updated_config = json!({
        "rate_limit": {
            "max_concurrent": 10,
            "max_requests_per_window": 100,
            "window_duration_seconds": 1,
            "window_limits": [
                {
                    "window_duration_seconds": 86400,
                    "limit": 10000
                }
            ],
            "token_window_limits": [],
            "cost_window_limits": []
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
        .json(&updated_config)
        .await;

    assert!(
        response.status_code().is_success(),
        "Should update config successfully"
    );

    // Step 5: Wait for window to clear (11 seconds to be safe)
    tokio::time::sleep(tokio::time::Duration::from_secs(11)).await;

    // Step 6: Make multiple requests (should NOT be rate limited with new config)
    for i in 0..3 {
        let response = server
            .post("/v1/responses")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
            )
            .json(&request_body)
            .await;

        assert_ne!(
            response.status_code(),
            429,
            "Request {} should not be rate limited after hot reload (max_requests_per_window=100)",
            i + 1
        );
    }
}
