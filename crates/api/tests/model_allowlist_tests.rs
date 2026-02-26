mod common;

use common::{
    cleanup_user_subscriptions, clear_default_allowed_models, create_test_server,
    create_test_server_and_db, insert_test_subscription_with_price, mock_login,
    set_subscription_plans, TestServerConfig,
};
use serde_json::json;
use serial_test::serial;

/// Stripe secrets must be non-empty for subscription gating; otherwise requests reach upstream (401).
fn ensure_stripe_env_for_gating() {
    std::env::set_var(
        "STRIPE_SECRET_KEY",
        std::env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| "sk_test_dummy".to_string()),
    );
    std::env::set_var(
        "STRIPE_WEBHOOK_SECRET",
        std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| "whsec_dummy".to_string()),
    );
}

// ============================================================================
// Test: Users without subscription (using default_allowed_models)
// ============================================================================

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_no_subscription_default_allowed_models_allows_listed_model() {
    ensure_stripe_env_for_gating();
    let server = create_test_server().await;

    // Clear any existing default_allowed_models from previous test runs
    clear_default_allowed_models(&server).await;

    let admin_token = mock_login(&server, "test_admin_model_allowlist@admin.org").await;

    // Configure subscription plans with default_allowed_models
    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", admin_token)).unwrap(),
        )
        .json(&json!({
            "default_allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"],
            "subscription_plans": {
                "basic": {
                    "providers": { "stripe": { "price_id": "price_basic" } },
                    "monthly_tokens": { "max": 1000000 }
                }
            }
        }))
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Failed to configure default_allowed_models"
    );

    let user_email = "no_subscription_allowed@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Try to use a model that's in the default allowlist
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should NOT be 403 (will likely be 401/502 due to no upstream, but not 403)
    assert_ne!(
        response.status_code(),
        403,
        "User should be allowed to use model in default_allowed_models"
    );

    // Cleanup: clear default_allowed_models for subsequent tests
    clear_default_allowed_models(&server).await;
}

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_no_subscription_default_allowed_models_blocks_unlisted_model() {
    ensure_stripe_env_for_gating();
    let server = create_test_server().await;

    // Configure subscription plans with default_allowed_models (admin auth required)
    let admin_token = mock_login(&server, "test_admin_model_blocked@admin.org").await;
    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", admin_token)).unwrap(),
        )
        .json(&json!({
            "default_allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"],
            "subscription_plans": {
                "basic": {
                    "providers": { "stripe": { "price_id": "price_basic" } },
                    "monthly_tokens": { "max": 1000000 }
                }
            }
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    let user_email = "no_subscription_blocked@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Try to use a model NOT in the default allowlist
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should be 403 Forbidden
    assert_eq!(
        response.status_code(),
        403,
        "User without subscription should be blocked from using model not in default_allowed_models"
    );

    let body = response.text();
    assert!(
        body.contains("gpt-4o") && body.contains("not available"),
        "Error message should mention the model and that it's not available"
    );

    // Cleanup: clear default_allowed_models for subsequent tests
    clear_default_allowed_models(&server).await;
}

// ============================================================================
// Test: Users with subscription (using plan-specific allowed_models)
// ============================================================================

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_subscription_plan_allowed_models_allows_listed_model() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure subscription plans with plan-specific allowed_models
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_basic" } },
                "monthly_tokens": { "max": 1000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"]
            },
            "pro": {
                "providers": { "stripe": { "price_id": "price_pro" } },
                "monthly_tokens": { "max": 10000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini", "gpt-4o", "gpt-4-turbo"]
            }
        }),
    )
    .await;

    let user_email = "basic_plan_allowed@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription_with_price(&server, &db, user_email, "price_basic", false).await;
    let user_token = mock_login(&server, user_email).await;

    // Try to use a model in the basic plan allowlist
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should NOT be 403
    assert_ne!(
        response.status_code(),
        403,
        "Basic plan user should be allowed to use model in their plan's allowlist"
    );
}

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_subscription_plan_allowed_models_blocks_unlisted_model() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure subscription plans
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_basic" } },
                "monthly_tokens": { "max": 1000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"]
            }
        }),
    )
    .await;

    let user_email = "basic_plan_blocked@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription_with_price(&server, &db, user_email, "price_basic", false).await;
    let user_token = mock_login(&server, user_email).await;

    // Try to use a premium model NOT in the basic plan allowlist
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should be 403 Forbidden
    assert_eq!(
        response.status_code(),
        403,
        "Basic plan user should be blocked from using premium models"
    );

    let body = response.text();
    assert!(
        body.contains("gpt-4o") && body.contains("not available"),
        "Error message should mention the model: {}",
        body
    );
}

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_pro_plan_allows_more_models() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure subscription plans
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_basic" } },
                "monthly_tokens": { "max": 1000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"]
            },
            "pro": {
                "providers": { "stripe": { "price_id": "price_pro" } },
                "monthly_tokens": { "max": 10000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini", "gpt-4o", "gpt-4-turbo"]
            }
        }),
    )
    .await;

    let user_email = "pro_plan_user@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription_with_price(&server, &db, user_email, "price_pro", false).await;
    let user_token = mock_login(&server, user_email).await;

    // Try to use a premium model (should be allowed for pro)
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should NOT be 403
    assert_ne!(
        response.status_code(),
        403,
        "Pro plan user should be allowed to use premium models"
    );
}

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_plan_without_allowlist_allows_all_models() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure subscription plan WITHOUT allowed_models (None = allow all)
    set_subscription_plans(
        &server,
        json!({
            "enterprise": {
                "providers": { "stripe": { "price_id": "price_enterprise" } },
                "monthly_tokens": { "max": 100000000 }
                // No allowed_models field
            }
        }),
    )
    .await;

    let user_email = "enterprise_plan_user@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription_with_price(&server, &db, user_email, "price_enterprise", false).await;
    let user_token = mock_login(&server, user_email).await;

    // Try to use any model (should be allowed)
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    // Should NOT be 403
    assert_ne!(
        response.status_code(),
        403,
        "Enterprise plan user without allowlist should be allowed all models"
    );
}

// ============================================================================
// Test: /v1/responses endpoint (same logic should apply)
// ============================================================================

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_responses_endpoint_respects_model_allowlist() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure subscription plans with restricted allowlist
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_basic" } },
                "monthly_tokens": { "max": 1000000 },
                "allowed_models": ["gpt-3.5-turbo"]
            }
        }),
    )
    .await;

    let user_email = "responses_restricted@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription_with_price(&server, &db, user_email, "price_basic", false).await;
    let user_token = mock_login(&server, user_email).await;

    // Try to use a model NOT in the allowlist via /v1/responses
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", user_token)).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "prompt": "Hello"
        }))
        .await;

    // Should be 403 Forbidden
    assert_eq!(
        response.status_code(),
        403,
        "Responses endpoint should also enforce model allowlist"
    );

    let body = response.text();
    assert!(
        body.contains("gpt-4o") && body.contains("not available"),
        "Error message should mention the model"
    );
}

// ============================================================================
// Test: Admin config endpoint returns allowed_models fields
// ============================================================================

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_admin_config_returns_allowed_models_fields() {
    let server = create_test_server().await;

    let admin_token = mock_login(&server, "test_admin_config_return@admin.org").await;

    // Configure with both default_allowed_models and plan-specific allowed_models
    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", admin_token)).unwrap(),
        )
        .json(&json!({
            "default_allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"],
            "subscription_plans": {
                "basic": {
                    "providers": { "stripe": { "price_id": "price_basic" } },
                    "monthly_tokens": { "max": 1000000 },
                    "allowed_models": ["gpt-3.5-turbo"]
                },
                "pro": {
                    "providers": { "stripe": { "price_id": "price_pro" } },
                    "monthly_tokens": { "max": 10000000 }
                    // No allowed_models
                }
            }
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    // Retrieve the config
    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {}", admin_token)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();

    // Verify default_allowed_models is present
    assert_eq!(
        body["default_allowed_models"],
        json!(["gpt-3.5-turbo", "gpt-4o-mini"]),
        "default_allowed_models should be returned"
    );

    // Verify plan-specific allowed_models
    assert_eq!(
        body["subscription_plans"]["basic"]["allowed_models"],
        json!(["gpt-3.5-turbo"]),
        "basic plan allowed_models should be returned"
    );

    // Verify pro plan has no allowed_models field (or null)
    assert!(
        body["subscription_plans"]["pro"]["allowed_models"].is_null()
            || !body["subscription_plans"]["pro"]
                .as_object()
                .unwrap()
                .contains_key("allowed_models"),
        "pro plan should not have allowed_models field"
    );

    // Cleanup: clear default_allowed_models for subsequent tests
    clear_default_allowed_models(&server).await;
}

// ============================================================================
// Test: GET /v1/subscriptions/plans includes allowed_models
// ============================================================================

#[tokio::test]
#[serial(model_allowlist_tests)]
async fn test_get_subscription_plans_includes_allowed_models() {
    ensure_stripe_env_for_gating();
    let server = create_test_server().await;

    // Configure subscription plans with allowed_models
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_basic" } },
                "monthly_tokens": { "max": 1000000 },
                "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"]
            },
            "pro": {
                "providers": { "stripe": { "price_id": "price_pro" } },
                "monthly_tokens": { "max": 10000000 }
                // No allowed_models
            }
        }),
    )
    .await;

    let response = server.get("/v1/subscriptions/plans").await;

    assert_eq!(
        response.status_code(),
        200,
        "Should return 200 when plans are configured"
    );

    let body: serde_json::Value = response.json();
    let plans_array = body["plans"]
        .as_array()
        .unwrap_or_else(|| panic!("Response should have 'plans' array, got: {:?}", body));

    // Find basic plan
    let basic_plan = plans_array
        .iter()
        .find(|p| p["name"] == "basic")
        .expect("Should have basic plan");

    assert_eq!(
        basic_plan["allowed_models"],
        json!(["gpt-3.5-turbo", "gpt-4o-mini"]),
        "basic plan should include allowed_models"
    );

    // Find pro plan
    let pro_plan = plans_array
        .iter()
        .find(|p| p["name"] == "pro")
        .expect("Should have pro plan");

    assert!(
        pro_plan["allowed_models"].is_null()
            || !pro_plan.as_object().unwrap().contains_key("allowed_models"),
        "pro plan should not have allowed_models field or it should be null"
    );
}
