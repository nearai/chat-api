mod common;

use api::routes::api::SUBSCRIPTION_REQUIRED_ERROR_MESSAGE;
use chrono::Duration;
use common::{
    cleanup_user_subscriptions, clear_subscription_plans, create_test_server,
    create_test_server_and_db, insert_test_agent_instances, insert_test_subscription, mock_login,
    set_subscription_plans, TestServerConfig,
};
use serde_json::json;
use serial_test::serial;
use services::system_configs::ports::RateLimitConfig;
use services::user::ports::UserRepository;
use services::user_usage::{UserUsageRepository, METRIC_KEY_LLM_TOKENS};

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

/// Permissive rate limit config for subscription proxy tests to avoid 429 interference.
fn permissive_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        max_concurrent: 100,
        max_requests_per_window: 10000,
        window_duration: Duration::seconds(60),
        window_limits: vec![],
        token_window_limits: vec![],
        cost_window_limits: vec![],
    }
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_requires_auth() {
    let server = create_test_server().await;

    // GET /v1/subscriptions without authentication should return 401
    let response = server.get("/v1/subscriptions").await;

    assert_eq!(
        response.status_code(),
        401,
        "GET /v1/subscriptions should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_not_configured() {
    let server = create_test_server().await;

    // Ensure subscriptions are not configured
    clear_subscription_plans(&server).await;

    let user_email = "test_subscription_not_configured@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Should return 503 when not configured
    assert_eq!(
        response.status_code(),
        503,
        "Should return 503 when Stripe is not configured"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_configured_returns_empty() {
    let server = create_test_server().await;

    // Configure subscription plans with Stripe provider
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_subscription_configured_empty@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Should return 200 with empty array
    assert_eq!(
        response.status_code(),
        200,
        "Should return 200 when Stripe is configured"
    );

    let body: serde_json::Value = response.json();
    let subscriptions = body
        .get("subscriptions")
        .expect("Should have subscriptions field");
    assert!(subscriptions.is_array());
    assert_eq!(subscriptions.as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_requires_auth() {
    let server = create_test_server().await;

    let request_body = json!({
        "plan": "basic"
    });

    // POST /v1/subscriptions without authentication should return 401
    let response = server.post("/v1/subscriptions").json(&request_body).await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/subscriptions should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_not_configured() {
    let server = create_test_server().await;

    // Ensure subscriptions are not configured
    clear_subscription_plans(&server).await;

    let user_email = "test_create_not_configured@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "plan": "any_plan",
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel"
    });

    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    // Should return 503 when not configured
    assert_eq!(
        response.status_code(),
        503,
        "Should return 503 when Stripe is not configured"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_invalid_provider() {
    let server = create_test_server().await;

    // Configure subscription plans with Stripe provider
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_create_invalid_provider@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "provider": "paypal",
        "plan": "basic",
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel"
    });

    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    // Should return 400 for unsupported provider
    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 for invalid/unsupported provider"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_invalid_plan() {
    let server = create_test_server().await;

    // Configure subscription plans with Stripe provider
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_create_invalid_plan@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "plan": "nonexistent_plan",
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel"
    });

    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    // Should return 400 for invalid plan
    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 for invalid plan"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_cancel_subscription_requires_auth() {
    let server = create_test_server().await;

    // POST /v1/subscriptions/cancel without authentication should return 401
    let response = server.post("/v1/subscriptions/cancel").await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/subscriptions/cancel should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_cancel_subscription_not_found() {
    let server = create_test_server().await;

    let user_email = "test_cancel_subscription@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Attempt to cancel non-existent subscription
    let response = server
        .post("/v1/subscriptions/cancel")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Should return 404 when no active subscription exists
    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when no active subscription exists"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_requires_auth() {
    let server = create_test_server().await;

    // POST /v1/subscriptions/resume without authentication should return 401
    let response = server.post("/v1/subscriptions/resume").await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/subscriptions/resume should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_not_found() {
    let server = create_test_server().await;

    let user_email = "test_resume_subscription@example.com";
    let user_token = mock_login(&server, user_email).await;

    // Attempt to resume non-existent subscription
    let response = server
        .post("/v1/subscriptions/resume")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Should return 404 when no active subscription exists
    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when no active subscription exists"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_not_scheduled_for_cancellation() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_resume_not_scheduled@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;

    let user_token = mock_login(&server, user_email).await;

    // Attempt to resume subscription that is NOT scheduled for cancellation
    let response = server
        .post("/v1/subscriptions/resume")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Should return 400 when subscription is not scheduled for cancellation
    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 when subscription is not scheduled for cancellation"
    );
}

// --- Change plan tests ---

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_requires_auth() {
    let server = create_test_server().await;

    let request_body = json!({ "plan": "pro" });

    // POST /v1/subscriptions/change without authentication should return 401
    let response = server
        .post("/v1/subscriptions/change")
        .json(&request_body)
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/subscriptions/change should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_no_active_subscription() {
    let server = create_test_server().await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_no_sub@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({ "plan": "pro" });

    let response = server
        .post("/v1/subscriptions/change")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when no active subscription exists"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_invalid_plan() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_invalid@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({ "plan": "nonexistent_plan" });

    let response = server
        .post("/v1/subscriptions/change")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 for invalid plan"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_instance_limit_exceeded() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } },
            "starter": { "providers": { "stripe": { "price_id": "price_test_starter" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_instance_limit@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;
    insert_test_agent_instances(&db, user_email, 2).await;
    let user_token = mock_login(&server, user_email).await;

    // User has 2 instances and basic plan (max 5); trying to switch to starter (max 1)
    let request_body = json!({ "plan": "starter" });

    let response = server
        .post("/v1/subscriptions/change")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 when instance count exceeds target plan limit"
    );

    let body: serde_json::Value = response.json();
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("detail").and_then(|v| v.as_str()))
        .unwrap_or("");
    assert!(
        message.contains("2") && message.contains("1"),
        "Error message should include current (2) and max (1) instance counts, got: {}",
        message
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_success_validates_before_stripe() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // User on basic (price_test_basic), changing to pro (price_test_pro)
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_success@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;
    // 0 instances - under both plans' limits
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({ "plan": "pro" });

    let response = server
        .post("/v1/subscriptions/change")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&request_body)
        .await;

    // Validation passes (auth, subscription, valid plan, instance limit).
    // Stripe API call fails with fake sub_test_* ID -> 500.
    // This confirms we reach the Stripe update step; full success would need Stripe mocking.
    let status = response.status_code();
    assert!(
        status == 200 || status == 500,
        "Should pass validation (200) or fail at Stripe (500), got {}",
        status
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_successfully() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_list_with_sub@example.com";
    // Clean up any leftover subscriptions from previous test runs for test isolation
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;

    let user_token = mock_login(&server, user_email).await;

    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should return 200 when listing subscriptions with data"
    );

    let body: serde_json::Value = response.json();
    let subscriptions = body
        .get("subscriptions")
        .expect("Should have subscriptions field")
        .as_array()
        .expect("subscriptions should be array");

    assert_eq!(
        subscriptions.len(),
        1,
        "Should have exactly one subscription"
    );

    let sub = &subscriptions[0];
    assert_eq!(sub.get("plan").and_then(|v| v.as_str()), Some("basic"));
    assert_eq!(
        sub.get("cancel_at_period_end").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_webhook_requires_signature() {
    let server = create_test_server().await;

    let webhook_payload = json!({
        "id": "evt_test",
        "type": "customer.subscription.created"
    });

    // POST /v1/subscriptions/stripe/webhook without signature should return 400
    let response = server
        .post("/v1/subscriptions/stripe/webhook")
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&webhook_payload)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Webhook should require Stripe-Signature header"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_configure_subscription_plans_as_admin() {
    let server = create_test_server().await;

    let admin_email = "test_admin_stripe@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure subscription plans
    let config_body = json!({
        "subscription_plans": {
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic_123" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro_456" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
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
        .json(&config_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Admin should be able to configure Stripe plans"
    );

    let body: serde_json::Value = response.json();
    let subscription_plans = body
        .get("subscription_plans")
        .expect("Should have subscription_plans");
    let basic = subscription_plans
        .get("basic")
        .expect("Should have basic plan");
    let pro = subscription_plans.get("pro").expect("Should have pro plan");

    assert_eq!(
        basic
            .get("providers")
            .and_then(|p| p.get("stripe"))
            .and_then(|s| s.get("price_id")),
        Some(&json!("price_test_basic_123")),
        "Should have basic plan with Stripe price_id configured"
    );
    assert_eq!(
        pro.get("providers")
            .and_then(|p| p.get("stripe"))
            .and_then(|s| s.get("price_id")),
        Some(&json!("price_test_pro_456")),
        "Should have pro plan with Stripe price_id configured"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_subscription_plans_persisted_in_database() {
    let server = create_test_server().await;

    let admin_email = "test_admin_stripe_persist@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure subscription plans
    let config_body = json!({
        "subscription_plans": {
            "basic": { "providers": { "stripe": { "price_id": "price_persist_basic" } } },
            "pro": { "providers": { "stripe": { "price_id": "price_persist_pro" } } }
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
        .json(&config_body)
        .await;

    assert!(response.status_code().is_success());

    // Verify persistence by fetching config
    let response = server
        .get("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let subscription_plans = body
        .get("subscription_plans")
        .expect("Should have subscription_plans");
    let basic_price = subscription_plans
        .get("basic")
        .and_then(|p| p.get("providers"))
        .and_then(|p| p.get("stripe"))
        .and_then(|s| s.get("price_id"));
    let pro_price = subscription_plans
        .get("pro")
        .and_then(|p| p.get("providers"))
        .and_then(|p| p.get("stripe"))
        .and_then(|s| s.get("price_id"));

    assert_eq!(
        basic_price,
        Some(&json!("price_persist_basic")),
        "Basic plan should be persisted"
    );
    assert_eq!(
        pro_price,
        Some(&json!("price_persist_pro")),
        "Pro plan should be persisted"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_plans_no_auth_required() {
    let server = create_test_server().await;

    // GET /v1/subscriptions/plans should not require authentication
    let response = server.get("/v1/subscriptions/plans").await;

    // Should return 200 or 503 (not configured), but not 401
    let status = response.status_code();
    assert_ne!(
        status, 401,
        "GET /v1/subscriptions/plans should not require authentication"
    );
    assert!(
        status == 200 || status == 503,
        "Should return 200 or 503, got {}",
        status
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_plans_returns_configured_plans() {
    let server = create_test_server().await;

    let admin_email = "test_list_plans@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure subscription plans with private_assistant_instances and monthly_tokens
    let config_body = json!({
        "subscription_plans": {
            "starter": {
                "providers": { "stripe": { "price_id": "price_starter_789" } },
                "agent_instances": { "max": 1 },
                "monthly_tokens": { "max": 500_000 }
            },
            "premium": {
                "providers": { "stripe": { "price_id": "price_premium_012" } },
                "agent_instances": { "max": 5 },
                "monthly_tokens": { "max": 5_000_000 }
            }
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
        .json(&config_body)
        .await;

    assert!(response.status_code().is_success());

    // Get available plans
    let response = server.get("/v1/subscriptions/plans").await;

    assert_eq!(
        response.status_code(),
        200,
        "Should return 200 when plans are configured"
    );

    let body: serde_json::Value = response.json();
    let plans = body.get("plans").expect("Should have plans field");

    assert!(plans.is_array(), "plans should be an array");

    let plans_array = plans.as_array().unwrap();
    assert_eq!(plans_array.len(), 2, "Should have 2 plans configured");

    // Verify plan structure
    let plan_names: Vec<String> = plans_array
        .iter()
        .map(|p| p.get("name").unwrap().as_str().unwrap().to_string())
        .collect();

    assert!(
        plan_names.contains(&"starter".to_string()),
        "Should have starter plan"
    );
    assert!(
        plan_names.contains(&"premium".to_string()),
        "Should have premium plan"
    );

    // Verify private_assistant_instances and monthly_tokens structure for each plan
    for plan in plans_array {
        assert!(plan.get("name").is_some(), "Each plan should have name");
        let name = plan.get("name").unwrap().as_str().unwrap();
        match name {
            "starter" => {
                assert_eq!(
                    plan.get("agent_instances")
                        .and_then(|d| d.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(1),
                    "Starter plan should have private_assistant_instances.max = 1"
                );
                assert_eq!(
                    plan.get("monthly_tokens")
                        .and_then(|t| t.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(500_000),
                    "Starter plan should have monthly_tokens.max = 500000"
                );
            }
            "premium" => {
                assert_eq!(
                    plan.get("agent_instances")
                        .and_then(|d| d.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(5),
                    "Premium plan should have private_assistant_instances.max = 5"
                );
                assert_eq!(
                    plan.get("monthly_tokens")
                        .and_then(|t| t.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(5_000_000),
                    "Premium plan should have monthly_tokens.max = 5000000"
                );
            }
            _ => {}
        }
    }
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_plans_includes_trial_period_days() {
    let server = create_test_server().await;

    set_subscription_plans(
        &server,
        json!({
            "starter": {
                "providers": { "stripe": { "price_id": "price_starter_trial" } },
                "trial_period_days": 14,
                "agent_instances": { "max": 1 },
                "monthly_tokens": { "max": 500_000 }
            },
            "premium": {
                "providers": { "stripe": { "price_id": "price_premium_trial" } },
                "trial_period_days": 7,
                "agent_instances": { "max": 5 },
                "monthly_tokens": { "max": 5_000_000 }
            },
            "no_trial": {
                "providers": { "stripe": { "price_id": "price_no_trial" } },
                "agent_instances": { "max": 1 },
                "monthly_tokens": { "max": 1_000_000 }
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
    let plans = body
        .get("plans")
        .expect("Should have plans field")
        .as_array()
        .unwrap();

    let starter = plans
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some("starter"));
    let premium = plans
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some("premium"));
    let no_trial = plans
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some("no_trial"));

    assert_eq!(
        starter
            .and_then(|p| p.get("trial_period_days"))
            .and_then(|v| v.as_u64()),
        Some(14),
        "Starter plan should have trial_period_days 14"
    );
    assert_eq!(
        premium
            .and_then(|p| p.get("trial_period_days"))
            .and_then(|v| v.as_u64()),
        Some(7),
        "Premium plan should have trial_period_days 7"
    );
    assert!(
        no_trial.and_then(|p| p.get("trial_period_days")).is_none(),
        "no_trial plan should not have trial_period_days (or be null)"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_plans_empty_configuration() {
    let server = create_test_server().await;

    let admin_email = "test_list_plans_empty@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure empty subscription plans
    let config_body = json!({
        "subscription_plans": {}
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
        .json(&config_body)
        .await;

    assert!(response.status_code().is_success());

    // Get plans with empty configuration
    let response = server.get("/v1/subscriptions/plans").await;

    // Should return 503 when Stripe plans are empty
    assert_eq!(
        response.status_code(),
        503,
        "Should return 503 when Stripe plans are empty"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_portal_session_requires_auth() {
    let server = create_test_server().await;

    // POST /v1/subscriptions/portal without authentication should return 401
    let response = server
        .post("/v1/subscriptions/portal")
        .json(&json!({"return_url": "https://example.com"}))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/subscriptions/portal should require authentication"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_portal_session_no_stripe_customer() {
    let server = create_test_server().await;

    // Configure Stripe plans so Stripe is considered "configured"
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_portal_no_customer@example.com";
    let user_token = mock_login(&server, user_email).await;

    // User has no Stripe customer record, should return 404
    let response = server
        .post("/v1/subscriptions/portal")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({"return_url": "https://example.com"}))
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when user has no Stripe customer"
    );
}

// --- Subscription-gated proxy/chat tests ---

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_returns_403_without_subscription_when_plans_configured() {
    ensure_stripe_env_for_gating();
    let (server, _) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_tokens": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_no_subscription@example.com";
    let user_token = mock_login(&server, user_email).await;

    // User has no subscription - falls back to "free" plan (max 0 tokens). Used 0 >= 0 -> 402 (Payment Required).
    for (path, body) in [
        (
            "/v1/chat/completions",
            json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Hello"}]
            }),
        ),
        (
            "/v1/responses",
            json!({
                "model": "gpt-4o",
                "input": "Hello"
            }),
        ),
        (
            "/v1/images/generations",
            json!({
                "prompt": "A sunset",
                "n": 1,
                "size": "1024x1024"
            }),
        ),
    ] {
        let response = server
            .post(path)
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
            )
            .json(&body)
            .await;

        // 402 Payment Required when token quota exceeded (free plan max 0); 403 when no subscription
        let status = response.status_code();
        assert!(
            status == 402 || status == 403,
            "POST {} should return 402 or 403 when user has no subscription, got {}",
            path,
            status
        );

        let body_res: serde_json::Value = response.json();
        let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            err_msg.contains("Monthly token limit exceeded")
                || err_msg == SUBSCRIPTION_REQUIRED_ERROR_MESSAGE,
            "POST {} should return token limit or subscription error, got: {}",
            path,
            err_msg
        );
    }
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_with_subscription() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_with_subscription@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    // User has active subscription - proxy should allow (may get 502 from upstream)
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "User with subscription should not get 403 (may get 502/other from upstream)"
    );
    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE),
        "User with subscription should not get subscription required error"
    );

    // Also verify /v1/responses allows with subscription
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "POST /v1/responses with subscription should not get 403 (may get 502/other from upstream)"
    );
    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE),
        "POST /v1/responses with subscription should not get subscription required error"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_when_subscription_not_configured() {
    let server = create_test_server().await;

    clear_subscription_plans(&server).await;

    let user_email = "test_proxy_no_plans@example.com";
    let user_token = mock_login(&server, user_email).await;

    // No plans configured - gating is skipped, should not get 403
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "When subscription plans not configured, should not gate proxy (may get 502/other)"
    );
    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE)
    );

    // Also verify /v1/responses allows when subscription not configured
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "input": "Hello"
        }))
        .await;

    assert_ne!(
        response.status_code(),
        403,
        "POST /v1/responses when subscription not configured should not get 403"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_blocks_when_monthly_token_limit_exceeded() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_tokens": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_token_limit@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record 150 tokens (exceeds limit of 100)
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, Some(0), None)
        .await
        .expect("record usage");

    // Proxy should return 402 Payment Required when monthly token limit exceeded
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .await;

    assert_eq!(
        response.status_code(),
        402,
        "Proxy should return 402 when monthly token limit exceeded"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Monthly token limit exceeded"),
        "Error should mention token limit, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("100"),
        "Error should include limit value, got: {}",
        err_msg
    );

    // Also verify /v1/responses returns 402 when token limit exceeded
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "input": "Hello"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        402,
        "POST /v1/responses should return 402 when monthly token limit exceeded"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Monthly token limit exceeded") && err_msg.contains("100"),
        "POST /v1/responses error should mention token limit, got: {}",
        err_msg
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_responses_returns_403_without_subscription_when_plans_configured() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_tokens": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_responses_no_subscription@example.com";
    let user_token = mock_login(&server, user_email).await;

    // User has no subscription - POST /v1/responses should return 402 or 403
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4o",
            "input": "Hello"
        }))
        .await;

    // 402 Payment Required (token quota), 403 Forbidden (no subscription)
    let status = response.status_code();
    assert!(
        status == 402 || status == 403,
        "POST /v1/responses should return 402 or 403 when user has no subscription (free plan max 0), got {}",
        status
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Monthly token limit exceeded")
            || err_msg == SUBSCRIPTION_REQUIRED_ERROR_MESSAGE,
        "POST /v1/responses should return token limit or subscription error, got: {}",
        err_msg
    );
}

// ========== ADMIN SUBSCRIPTION MANAGEMENT TESTS ==========

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_set_subscription_requires_admin() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Login as regular user (non-admin)
    let user_token = mock_login(&server, "regular_user@example.com").await;
    let fake_user_id = "00000000-0000-0000-0000-000000000000";

    let response = server
        .post(&format!("/v1/admin/users/{}/subscription", fake_user_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "provider": "stripe",
            "plan": "basic",
            "current_period_end": "2025-12-31T23:59:59Z"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should not be able to set subscriptions"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_set_subscription_requires_auth() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;
    let fake_user_id = "00000000-0000-0000-0000-000000000000";

    // No auth header
    let response = server
        .post(&format!("/v1/admin/users/{}/subscription", fake_user_id))
        .json(&json!({
            "provider": "stripe",
            "plan": "basic",
            "current_period_end": "2025-12-31T23:59:59Z"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Request without auth should be rejected"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_set_subscription_invalid_plan() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure valid plans
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } } }
        }),
    )
    .await;

    // Create a test user
    let user_email = "test_admin_set_sub_user@example.com";
    let _user_token = mock_login(&server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user should exist");
    let admin_token = mock_login(&server, "test_admin@admin.org").await;

    // Try to set subscription with invalid plan
    let response = server
        .post(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "provider": "stripe",
            "plan": "nonexistent_plan",
            "current_period_end": "2025-12-31T23:59:59Z"
        }))
        .await;

    assert_eq!(response.status_code(), 400, "Should reject invalid plan");
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_set_subscription_success() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure valid plans
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    // Create a test user
    let user_email = "test_admin_set_success@example.com";
    let _user_token = mock_login(&server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user should exist");

    let admin_token = mock_login(&server, "test_admin_set_success@admin.org").await;

    // Set subscription as admin
    let response = server
        .post(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "provider": "stripe",
            "plan": "basic",
            "current_period_end": "2025-12-31T23:59:59Z"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should successfully set subscription as admin"
    );

    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("plan").and_then(|v| v.as_str()),
        Some("basic"),
        "Response should include plan name"
    );
    assert!(
        body.get("subscription_id").is_some(),
        "Response should include subscription_id"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_cancel_subscription_requires_admin() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Login as regular user (non-admin)
    let user_token = mock_login(&server, "regular_user@example.com").await;
    let fake_user_id = "00000000-0000-0000-0000-000000000000";

    let response = server
        .delete(&format!("/v1/admin/users/{}/subscription", fake_user_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should not be able to cancel subscriptions"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_cancel_subscription_requires_auth() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;
    let fake_user_id = "00000000-0000-0000-0000-000000000000";

    // No auth header
    let response = server
        .delete(&format!("/v1/admin/users/{}/subscription", fake_user_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Request without auth should be rejected"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_cancel_subscription_success() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Configure valid plans
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } } }
        }),
    )
    .await;

    // Create a test user with a subscription
    let user_email = "test_admin_cancel@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user should exist");

    let admin_token = mock_login(&server, "test_admin_cancel@admin.org").await;

    // Verify subscription exists
    let user_token = mock_login(&server, user_email).await;
    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    let body: serde_json::Value = response.json();
    let subscriptions = body
        .get("subscriptions")
        .and_then(|v| v.as_array())
        .expect("subscriptions should be array");
    assert!(
        !subscriptions.is_empty(),
        "User should have subscriptions before cancel"
    );

    // Cancel subscription as admin
    let response = server
        .delete(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Should successfully cancel subscriptions as admin"
    );

    // Verify subscription is gone
    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    let body: serde_json::Value = response.json();
    let subscriptions = body
        .get("subscriptions")
        .and_then(|v| v.as_array())
        .expect("subscriptions should be array");
    assert!(
        subscriptions.is_empty(),
        "User should have no subscriptions after admin cancel"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_subscription_gating_full_flow() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    // Configure subscription plans: free plan with 0 tokens (requires subscription), and basic paid plan
    // Users without subscription fall back to "free" plan and hit 402 Payment Required immediately
    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_tokens": { "max": 0 }
            },
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "agent_instances": { "max": 1 },
                "monthly_tokens": { "max": 1000000 }
            }
        }),
    )
    .await;

    // Create test user
    let user_email = "test_subscription_gating@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    let user_token = mock_login(&server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user should exist");

    let admin_token = mock_login(&server, "test_gating_admin@admin.org").await;

    // Step 1: Verify user CANNOT call inference without subscription
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4",
            "messages": [
                { "role": "user", "content": "Hello" }
            ]
        }))
        .await;

    assert!(
        response.status_code() == 402 || response.status_code() == 403,
        "User without subscription should be blocked (402 or 403), got {}",
        response.status_code()
    );
    let body: serde_json::Value = response.json();
    let error_msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error_msg.contains("subscription") || error_msg.contains("limit"),
        "Error should mention subscription or limit requirement, got: {}",
        error_msg
    );

    // Step 2: Admin sets subscription for user
    let response = server
        .post(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "provider": "stripe",
            "plan": "basic",
            "current_period_end": "2099-12-31T23:59:59Z"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should successfully set subscription"
    );

    // Step 3: Verify user CAN call inference with subscription
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4",
            "messages": [
                { "role": "user", "content": "Hello" }
            ]
        }))
        .await;

    assert_ne!(
        response.status_code(),
        402,
        "User with subscription should NOT get 402 (payment required)"
    );
    assert_ne!(
        response.status_code(),
        403,
        "User with subscription should NOT get 403 (forbidden due to no subscription)"
    );
    // Note: Response may be 401 if model is not found, or other errors, but NOT 402/403 subscription errors

    // Step 4: Admin cancels subscription
    let response = server
        .delete(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Admin should successfully cancel subscription"
    );

    // Step 5: Verify user CANNOT call inference after subscription is canceled
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "model": "gpt-4",
            "messages": [
                { "role": "user", "content": "Hello" }
            ]
        }))
        .await;

    assert!(
        response.status_code() == 402 || response.status_code() == 403,
        "User without subscription (after cancellation) should be blocked (402 or 403), got {}",
        response.status_code()
    );
    let body: serde_json::Value = response.json();
    let error_msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error_msg.contains("subscription") || error_msg.contains("limit"),
        "Error should mention subscription or limit requirement, got: {}",
        error_msg
    );
}
