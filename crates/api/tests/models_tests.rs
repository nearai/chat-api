mod common;

use common::{clear_default_allowed_models, create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn test_list_models_response_structure() {
    let server = create_test_server().await;

    // Use an admin account to access admin endpoints
    let admin_email = "test_admin_model_default@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Request with the maximum limit (100) to ensure we get all models in one page
    // This makes the test resilient to models created by other concurrent tests
    let response = server
        .get("/v1/admin/models?limit=100&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Should return 200 when listing models");

    let body: serde_json::Value = response.json();
    // Verify response structure (don't assert exact count as other tests may have created models)
    assert!(
        body.get("total").is_some(),
        "Response should have total field"
    );
    assert!(
        body.get("models").is_some(),
        "Response should have models array"
    );
    assert!(
        body.get("limit").is_some(),
        "Response should have limit field"
    );
    assert!(
        body.get("offset").is_some(),
        "Response should have offset field"
    );

    let models = body
        .get("models")
        .and_then(|v| v.as_array())
        .expect("Should have models array");
    let total: i64 = body
        .get("total")
        .and_then(|v| v.as_i64())
        .expect("Should have total as number");

    // Verify pagination structure is correct
    // With max allowed limit (100), all models should fit in one page at offset=0
    assert_eq!(
        models.len() as i64,
        total,
        "Models array length should equal total when requesting all models with limit=100&offset=0"
    );
}

#[tokio::test]
async fn test_model_batch_update_and_list() {
    let server = create_test_server().await;

    let admin_email = "test_admin_model_update@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Use a unique model ID to avoid conflicts with other tests
    let test_model_id = "test-model-batch-update-and-list";

    // Batch upsert model with settings.public = true
    let batch_body = json!({
        test_model_id: {
            "public": true
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to batch upsert model");

    let body: serde_json::Value = response.json();
    assert!(body.is_array(), "Response should be an array of models");
    let models = body.as_array().expect("Should be an array");
    assert_eq!(models.len(), 1, "Should return one model");
    let model = &models[0];
    assert_eq!(
        model.get("model_id"),
        Some(&json!(test_model_id)),
        "Response should include correct model_id"
    );
    let settings = model.get("settings").expect("Should have settings field");
    assert_eq!(
        settings.get("public"),
        Some(&json!(true)),
        "Public should be true after update"
    );

    // List models to verify persisted settings
    let response = server
        .get("/v1/admin/models?limit=100&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to list models");

    let body: serde_json::Value = response.json();
    let models = body
        .get("models")
        .and_then(|v| v.as_array())
        .expect("Should have models array");

    // Find our model in the list (there may be other models from other tests)
    let our_model = models
        .iter()
        .find(|m| m.get("model_id") == Some(&json!(test_model_id)))
        .expect("Should find our model in the list");

    assert_eq!(
        our_model.get("model_id"),
        Some(&json!(test_model_id)),
        "Listed model should have correct model_id"
    );
    let settings = our_model
        .get("settings")
        .expect("Should have settings field");
    assert_eq!(
        settings.get("public"),
        Some(&json!(true)),
        "Public should remain true when listed"
    );

    // Cleanup: delete the test model
    let response = server
        .delete(&format!("/v1/admin/models/{}", test_model_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;
    assert!(
        response.status_code() == 200 || response.status_code() == 204,
        "Should cleanup test model"
    );
}

#[tokio::test]
async fn test_list_models_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_model@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/models?limit=10&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when accessing model admin API"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
async fn test_delete_model_success() {
    let server = create_test_server().await;

    let admin_email = "test_admin_model_delete_success@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // First, create a model
    let batch_body = json!({
        "test-model-delete-1": {
            "public": true
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to batch upsert model before deleting"
    );

    // Then, delete the model
    let response = server
        .delete("/v1/admin/models/test-model-delete-1")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        204,
        "Deleting existing model should return 204 No Content"
    );

    // Verify the model is gone by listing models
    let response = server
        .get("/v1/admin/models?limit=10&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Listing models after deletion should return 200"
    );

    let body: serde_json::Value = response.json();
    let models = body
        .get("models")
        .and_then(|v| v.as_array())
        .expect("Should have models array");
    let model_ids: Vec<&str> = models
        .iter()
        .filter_map(|m| m.get("model_id").and_then(|v| v.as_str()))
        .collect();
    assert!(
        !model_ids.contains(&"test-model-delete-1"),
        "Deleted model should not appear in the list, got: {model_ids:?}"
    );
}

#[tokio::test]
async fn test_delete_model_not_found() {
    let server = create_test_server().await;

    let admin_email = "test_admin_model_delete_not_found@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .delete("/v1/admin/models/non-existent-model")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Deleting a non-existent model should return 404"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("message"),
        Some(&json!("Model not found")),
        "Error message should indicate model not found"
    );
}

#[tokio::test]
async fn test_delete_model_requires_admin() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_model_delete@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .delete("/v1/admin/models/test-model-delete-requires-admin")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should receive 403 Forbidden when deleting a model"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

/// Requests with a model whose settings are non-public should be blocked with 403.
#[tokio::test]
async fn test_responses_block_non_public_model() {
    let server = create_test_server().await;

    // Clear any model allowlist config from previous tests
    clear_default_allowed_models(&server).await;

    // Use an admin account to configure model settings
    let admin_email = "visibility-non-public-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Explicitly create a non-public model via admin API
    let batch_body = json!({
        "test-non-public-model": {
            "public": false
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model as non-public"
    );

    // Now send a response request using the non-public model
    let body = json!({
        "model": "test-non-public-model",
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

    // Clear any model allowlist config from previous tests
    clear_default_allowed_models(&server).await;

    // Use an admin account to configure model settings
    let admin_email = "visibility-public-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Mark the model as public via admin API
    let batch_body = json!({
        "test-public-model": {
            "public": true
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
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

/// When a public model has a system_prompt and the client does NOT send instructions,
/// the proxy should inject `instructions = system_prompt` into the forwarded request.
#[tokio::test]
async fn test_responses_injects_system_prompt_when_instructions_missing() {
    let server = create_test_server().await;

    // Clear any model allowlist config from previous tests
    clear_default_allowed_models(&server).await;

    // Use an admin account to configure model settings (public + system_prompt)
    let admin_email = "system-prompt-no-instructions-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let system_prompt = "You are a helpful assistant (model-level).";

    let batch_body = json!({
        "test-system-prompt-model-1": {
            "public": true,
            "system_prompt": system_prompt
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model with system_prompt"
    );

    // Now send a responses request WITHOUT instructions
    let user_email = "system-prompt-no-instructions-user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let body = json!({
        "model": "test-system-prompt-model-1",
        "input": "Hello"
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // We cannot directly inspect the upstream OpenAI request in this test,
    // but at minimum the proxy should not block, since the model is public.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model and system_prompt should not be blocked (status was {})",
        response.status_code()
    );
}

/// When a public model has a system_prompt and the client already sends instructions,
/// the proxy should prepend the model system_prompt with two newlines.
#[tokio::test]
async fn test_responses_prepends_system_prompt_when_instructions_present() {
    let server = create_test_server().await;

    // Clear any model allowlist config from previous tests
    clear_default_allowed_models(&server).await;

    // Use an admin account to configure model settings (public + system_prompt)
    let admin_email = "system-prompt-with-instructions-admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let system_prompt = "You are a helpful assistant (model-level, prepend).";

    let batch_body = json!({
        "test-system-prompt-model-2": {
            "public": true,
            "system_prompt": system_prompt
        }
    });

    let response = server
        .patch("/v1/admin/models")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&batch_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to set model with system_prompt"
    );

    // Now send a responses request WITH client instructions
    let user_email = "system-prompt-with-instructions-user@example.com";
    let user_token = mock_login(&server, user_email).await;

    let body = json!({
        "model": "test-system-prompt-model-2",
        "instructions": "User provided instructions.",
        "input": "Hello"
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&body)
        .await;

    // Similarly, we cannot directly assert the final contents of `instructions` here,
    // but we can at least ensure that the request is not blocked by the visibility logic.
    assert_ne!(
        response.status_code(),
        403,
        "Requests with public model and custom instructions should not be blocked (status was {})",
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
