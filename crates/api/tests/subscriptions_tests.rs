mod common;

use api::routes::api::SUBSCRIPTION_REQUIRED_ERROR_MESSAGE;
use chrono::{Duration, TimeZone, Utc};
use common::{
    cleanup_user_agent_instances, cleanup_user_subscriptions, clear_subscription_plans,
    create_test_server, create_test_server_and_db, insert_test_agent_instances,
    insert_test_subscription, insert_test_subscription_with_price_id, mock_login,
    set_subscription_plans, TestServerConfig,
};
use hmac::Mac;
use serde_json::json;
use serial_test::serial;
use services::subscription::ports::SubscriptionRepository;
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
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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
async fn test_create_subscription_instance_limit_exceeded() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    ensure_stripe_env_for_gating();

    set_subscription_plans(
        &server,
        json!({
            "starter": { "providers": { "stripe": { "price_id": "price_test_starter" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    // User had Pro (5 instances), cancelled; instances remain. Resubscribing to Starter (max 1).
    let user_email = "test_create_instance_limit@example.com";
    let user_token = mock_login(&server, user_email).await;
    cleanup_user_subscriptions(&db, user_email).await;
    cleanup_user_agent_instances(&db, user_email).await;
    insert_test_agent_instances(&db, user_email, 3).await;

    let request_body = json!({
        "plan": "starter",
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

    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 when instance count exceeds plan limit before checkout"
    );

    let body: serde_json::Value = response.json();
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("detail").and_then(|v| v.as_str()))
        .unwrap_or("");
    assert!(
        message.contains("3") && message.contains("1"),
        "Error message should include current (3) and max (1) instance counts, got: {}",
        message
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
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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
async fn test_change_plan_downgrade_schedules_even_if_instance_limit_exceeded() {
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
    cleanup_user_agent_instances(&db, user_email).await;
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
        200,
        "Should return 200 when downgrade is scheduled"
    );

    let body: serde_json::Value = response.json();
    let result = body.get("result").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        result, "scheduled_for_period_end",
        "Should return scheduled_for_period_end for downgrade scheduling"
    );

    // Verify pending downgrade intent persisted
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");
    let client = db.pool().get().await.expect("get pool client");
    let row = client
        .query_one(
            "SELECT pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status, current_period_end
             FROM subscriptions
             WHERE user_id = $1 AND status IN ('active', 'trialing')
             ORDER BY created_at DESC
             LIMIT 1",
            &[&user.id],
        )
        .await
        .expect("select subscription");

    let target: Option<String> = row.get("pending_downgrade_target_price_id");
    let from: Option<String> = row.get("pending_downgrade_from_price_id");
    let expected_end: Option<chrono::DateTime<chrono::Utc>> =
        row.get("pending_downgrade_expected_period_end");
    let status: Option<String> = row.get("pending_downgrade_status");
    let current_end: chrono::DateTime<chrono::Utc> = row.get("current_period_end");

    assert_eq!(target.as_deref(), Some("price_test_starter"));
    assert_eq!(from.as_deref(), Some("price_test_basic"));
    assert_eq!(status.as_deref(), Some("pending"));
    assert_eq!(
        expected_end,
        Some(current_end),
        "Expected period end snapshot should match current period end"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_success_clears_pending_downgrade_before_upgrade() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_clears_pending_downgrade@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");
    let client = db.pool().get().await.expect("get pool client");
    client
        .execute(
            "UPDATE subscriptions
             SET pending_downgrade_target_price_id = 'price_test_basic',
                 pending_downgrade_from_price_id = 'price_test_basic',
                 pending_downgrade_expected_period_end = current_period_end,
                 pending_downgrade_status = 'pending'
             WHERE user_id = $1 AND status IN ('active', 'trialing')",
            &[&user.id],
        )
        .await
        .expect("seed pending downgrade");

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
        .json(&json!({ "plan": "pro" }))
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "Expected successful plan change"
    );

    let row = client
        .query_one(
            "SELECT pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status
             FROM subscriptions
             WHERE user_id = $1 AND status IN ('active', 'trialing')
             ORDER BY created_at DESC
             LIMIT 1",
            &[&user.id],
        )
        .await
        .expect("select subscription");

    let target: Option<String> = row.get("pending_downgrade_target_price_id");
    let from: Option<String> = row.get("pending_downgrade_from_price_id");
    let expected_end: Option<chrono::DateTime<chrono::Utc>> =
        row.get("pending_downgrade_expected_period_end");
    let status: Option<String> = row.get("pending_downgrade_status");

    assert_eq!(target, None);
    assert_eq!(from, None);
    assert_eq!(expected_end, None);
    assert_eq!(status, None);
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

    // Validation + Stripe update should now succeed through the internal Stripe client implementation.
    assert_eq!(
        response.status_code(),
        200,
        "Expected successful plan change"
    );
    let body: serde_json::Value = response.json();
    let result = body.get("result").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        result, "changed_immediately",
        "Successful upgrade should return changed_immediately"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_successfully() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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
async fn test_webhook_accepts_when_any_v1_signature_matches() {
    let server = create_test_server().await;

    let webhook_payload = json!({
        "id": "evt_test_multi_v1",
        "type": "customer.subscription.created",
        "data": { "object": { "id": "sub_test_multi_v1" } }
    });
    let payload = webhook_payload.to_string();
    let ts = chrono::Utc::now().timestamp();

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let signed_payload = format!("{ts}.{payload}");
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(b"whsec_dummy").unwrap();
    mac.update(signed_payload.as_bytes());
    let good_sig = hex::encode(mac.finalize().into_bytes());
    let signature_header = format!("t={ts},v1=deadbeef,v1={good_sig}");

    let response = server
        .post("/v1/subscriptions/stripe/webhook")
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .add_header(
            http::HeaderName::from_static("stripe-signature"),
            http::HeaderValue::from_str(&signature_header).unwrap(),
        )
        .text(&payload)
        .await;

    assert_ne!(
        response.status_code(),
        400,
        "Webhook should accept request when any v1 signature matches"
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
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic_123" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro_456" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
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

    // Configure subscription plans with price, agent_instances, and monthly_credits
    let config_body = json!({
        "subscription_plans": {
            "starter": {
                "providers": { "stripe": { "price_id": "price_starter_789" } },
                "price": 999,
                "agent_instances": { "max": 1 },
                "monthly_credits": { "max": 500_000 }
            },
            "premium": {
                "providers": { "stripe": { "price_id": "price_premium_012" } },
                "price": 1999,
                "agent_instances": { "max": 5 },
                "monthly_credits": { "max": 5_000_000 }
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

    // Verify agent_instances and monthly_credits structure for each plan
    for plan in plans_array {
        assert!(plan.get("name").is_some(), "Each plan should have name");
        let name = plan.get("name").unwrap().as_str().unwrap();
        match name {
            "starter" => {
                assert_eq!(
                    plan.get("price").and_then(|p| p.as_i64()),
                    Some(999),
                    "Starter plan should have price = 999 cents ($9.99)"
                );
                assert_eq!(
                    plan.get("agent_instances")
                        .and_then(|d| d.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(1),
                    "Starter plan should have agent_instances.max = 1"
                );
                assert_eq!(
                    plan.get("monthly_credits")
                        .and_then(|t| t.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(500_000),
                    "Starter plan should have monthly_credits.max = 500000"
                );
            }
            "premium" => {
                assert_eq!(
                    plan.get("price").and_then(|p| p.as_i64()),
                    Some(1999),
                    "Premium plan should have price = 1999 cents ($19.99)"
                );
                assert_eq!(
                    plan.get("agent_instances")
                        .and_then(|d| d.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(5),
                    "Premium plan should have agent_instances.max = 5"
                );
                assert_eq!(
                    plan.get("monthly_credits")
                        .and_then(|t| t.get("max"))
                        .and_then(|m| m.as_u64()),
                    Some(5_000_000),
                    "Premium plan should have monthly_credits.max = 5000000"
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
                "monthly_credits": { "max": 500_000 }
            },
            "premium": {
                "providers": { "stripe": { "price_id": "price_premium_trial" } },
                "trial_period_days": 7,
                "agent_instances": { "max": 5 },
                "monthly_credits": { "max": 5_000_000 }
            },
            "no_trial": {
                "providers": { "stripe": { "price_id": "price_no_trial" } },
                "agent_instances": { "max": 1 },
                "monthly_credits": { "max": 1_000_000 }
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
                "monthly_credits": {"max": 1000000}
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
                "monthly_credits": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_credits": {"max": 1000000}
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
            err_msg.contains("Credit limit exceeded")
                || err_msg == SUBSCRIPTION_REQUIRED_ERROR_MESSAGE,
            "POST {} should return credit limit or subscription error, got: {}",
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
                "monthly_credits": {"max": 1000000}
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

    // No plans configured - subscription gating is skipped, so this should not fail with the
    // subscription-required 403. Omit `model` to avoid unrelated model gating affecting the test.
    let response = server
        .post("/v1/chat/completions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
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

    // Also verify /v1/responses allows when subscription not configured.
    // Omit `model` to avoid unrelated model gating affecting the test.
    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
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
                "monthly_credits": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_credit_limit@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record usage with cost exceeding the credit limit of 100
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, Some(150), None)
        .await
        .expect("record usage");

    // Proxy should return 402 Payment Required when monthly credit limit exceeded
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
        "Proxy should return 402 when monthly credit limit exceeded"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Credit limit exceeded"),
        "Error should mention credit limit, got: {}",
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
        "POST /v1/responses should return 402 when monthly credit limit exceeded"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Credit limit exceeded"),
        "POST /v1/responses error should mention credit limit, got: {}",
        err_msg
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_blocks_exactly_at_plan_limit() {
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
                "monthly_credits": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_exact_limit@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record usage exactly at plan limit (100)
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 100, Some(100), None)
        .await
        .expect("record usage");

    // Proxy should return 402 when exactly at limit with no purchased credits
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
        "Proxy should return 402 when exactly at plan limit with no credits balance"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_over_plan_with_purchased_credits() {
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
                "monthly_credits": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_over_plan_with_credits@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record usage over plan (150 > 100); overage is 50.
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, Some(150), None)
        .await
        .expect("record usage");

    // Grant 100 nano-USD purchased credits. After reconcile: 50 covers overage, 50 remains.
    // (Reconcile runs on GET /v1/credits or when recording usage.)
    let admin_token = mock_login(&server, "test_credits_over_plan_admin@admin.org").await;
    let grant_response = server
        .post("/v1/admin/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "user_id": user.id,
            "amount_nano_usd": 100,
            "reason": "test over-plan with credits"
        }))
        .await;

    assert_eq!(
        grant_response.status_code(),
        200,
        "Admin grant credits should succeed"
    );

    // Trigger reconcile (GET /v1/credits). After: overage 50 charged to purchased, balance = 50 remaining.
    let credits_resp = server
        .get("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert!(
        credits_resp.status_code().is_success(),
        "GET /v1/credits should succeed to trigger reconcile"
    );

    // Proxy should allow (not 402) when over plan but has purchased credits remaining
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
        402,
        "Proxy should allow when over plan but has purchased credits (got 402)"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        !err_msg.contains("Credit limit exceeded"),
        "Should not get credit limit error when has purchased credits, got: {}",
        err_msg
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_blocks_when_all_credits_used_up() {
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
                "monthly_credits": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_all_credits_used@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record usage: 150 = 100 plan + 50 overage.
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, Some(150), None)
        .await
        .expect("record usage");

    // Grant exactly 50 purchased credits (same as overage). After reconcile, all used up.
    let admin_token = mock_login(&server, "test_credits_all_used_admin@admin.org").await;
    let grant_response = server
        .post("/v1/admin/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "user_id": user.id,
            "amount_nano_usd": 50,
            "reason": "test all credits used"
        }))
        .await;

    assert_eq!(
        grant_response.status_code(),
        200,
        "Admin grant credits should succeed"
    );

    // Trigger reconcile. Overage 50 charged to purchased; balance = 0.
    let credits_resp = server
        .get("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert!(
        credits_resp.status_code().is_success(),
        "GET /v1/credits should succeed to trigger reconcile"
    );

    // Proxy should return 402 when all credits (plan + purchased) are used up.
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
        "Proxy should return 402 when all credits (plan + purchased) are used up"
    );
    let body_res: serde_json::Value = response.json();
    let err_msg = body_res.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err_msg.contains("Credit limit exceeded"),
        "Error should mention credit limit, got: {}",
        err_msg
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_within_plan() {
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
                "monthly_credits": {"max": 100}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_within_plan@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user exists");

    // Record usage within plan (50 < 100)
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 50, Some(50), None)
        .await
        .expect("record usage");

    // Proxy should allow (not 402 or 403)
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
        402,
        "Proxy should allow when within plan (got 402)"
    );
    assert_ne!(
        response.status_code(),
        403,
        "Proxy should allow when within plan (got 403)"
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
                "monthly_credits": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "agent_instances": {"max": 1},
                "monthly_credits": {"max": 1000000}
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
        err_msg.contains("Credit limit exceeded") || err_msg == SUBSCRIPTION_REQUIRED_ERROR_MESSAGE,
        "POST /v1/responses should return credit limit or subscription error, got: {}",
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
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "monthly_credits": { "max": 1000000 }
            }
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

    // Configure subscription plans: free plan with 0 credits (requires subscription), and basic paid plan
    // Users without subscription fall back to "free" plan and hit 402 Payment Required immediately
    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_credits": { "max": 0 }
            },
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "agent_instances": { "max": 1 },
                "monthly_credits": { "max": 1000000 }
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

// --- Free-plan anchor: `last_cancelled_subscription_period_end` (Postgres + repository) ---
//
// Stripe subscription webhooks re-fetch the subscription from Stripe; these tests model the
// resulting database rows (and admin tooling) without calling Stripe.

#[tokio::test]
#[serial(subscription_tests)]
async fn last_cancelled_period_uses_most_recent_canceled_row() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_email = "test_free_anchor_max_canceled@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    let _ = mock_login(&server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .expect("user should exist");

    let client = db.pool().get().await.unwrap();
    let older_row_period_end = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    let newer_row_period_end = Utc.with_ymd_and_hms(2026, 3, 19, 8, 0, 0).unwrap();
    let older_updated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let newer_updated_at = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end, created_at, updated_at
            ) VALUES ($1, $2, 'stripe', 'cus_anchor', 'price_test_basic', 'canceled', $3, false, $4, $4)",
            &[&"sub_free_anchor_old", &user.id, &older_row_period_end, &older_updated_at],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end, created_at, updated_at
            ) VALUES ($1, $2, 'stripe', 'cus_anchor', 'price_test_basic', 'canceled', $3, false, $4, $4)",
            &[&"sub_free_anchor_new", &user.id, &newer_row_period_end, &newer_updated_at],
        )
        .await
        .unwrap();

    let got = db
        .subscription_repository()
        .last_cancelled_subscription_period_end_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(
        got,
        Some(newer_row_period_end),
        "latest canceled row (by updated_at) should win, not greatest period_end"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn last_cancelled_period_ignores_non_canceled_statuses() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_email = "test_free_anchor_ignore_non_canceled@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    let _ = mock_login(&server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .expect("user should exist");

    let client = db.pool().get().await.unwrap();
    let canceled_end = Utc.with_ymd_and_hms(2026, 3, 19, 0, 0, 0).unwrap();
    let active_end = Utc.with_ymd_and_hms(2027, 12, 31, 23, 59, 59).unwrap();
    let incomplete_end = Utc.with_ymd_and_hms(2028, 1, 1, 0, 0, 0).unwrap();
    let other_provider_canceled_end = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();

    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_x', 'price_test_basic', 'canceled', $3, false)",
            &[&"sub_only_canceled", &user.id, &canceled_end],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_x', 'price_test_basic', 'active', $3, false)",
            &[&"sub_active_later", &user.id, &active_end],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_x', 'price_test_basic', 'incomplete', $3, false)",
            &[&"sub_incomplete_later", &user.id, &incomplete_end],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'other', 'cus_x', 'price_test_basic', 'canceled', $3, false)",
            &[
                &"sub_other_provider_canceled",
                &user.id,
                &other_provider_canceled_end,
            ],
        )
        .await
        .unwrap();

    let got = db
        .subscription_repository()
        .last_cancelled_subscription_period_end_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(
        got,
        Some(other_provider_canceled_end),
        "latest canceled row should win regardless of provider"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn last_cancelled_period_none_when_no_canceled_rows() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_email = "test_free_anchor_no_canceled@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .expect("user should exist");

    let got = db
        .subscription_repository()
        .last_cancelled_subscription_period_end_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn active_to_canceled_transition_sets_free_plan_anchor() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_email = "test_free_anchor_active_to_canceled@example.com";
    cleanup_user_subscriptions(&db, user_email).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } } }
        }),
    )
    .await;

    insert_test_subscription(&server, &db, user_email, false).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .expect("user should exist");

    let subscription_id: String = {
        let client = db.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT subscription_id, current_period_end FROM subscriptions WHERE user_id = $1",
                &[&user.id],
            )
            .await
            .unwrap();
        let sid: String = row.get(0);
        let new_end = Utc.with_ymd_and_hms(2026, 3, 22, 12, 0, 0).unwrap();
        client
            .execute(
                "UPDATE subscriptions SET current_period_end = $2 WHERE subscription_id = $1",
                &[&sid, &new_end],
            )
            .await
            .unwrap();
        sid
    };

    assert_eq!(
        db.subscription_repository()
            .last_cancelled_subscription_period_end_for_user(user.id)
            .await
            .unwrap(),
        None,
        "no canceled row yet"
    );

    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "UPDATE subscriptions SET status = 'canceled' WHERE subscription_id = $1",
            &[&subscription_id],
        )
        .await
        .unwrap();

    let expected_end = Utc.with_ymd_and_hms(2026, 3, 22, 12, 0, 0).unwrap();
    let got = db
        .subscription_repository()
        .last_cancelled_subscription_period_end_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(got, Some(expected_end));
}

#[tokio::test]
#[serial(subscription_tests)]
async fn admin_cancel_deletes_rows_no_cancel_anchor() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } } }
        }),
    )
    .await;

    let user_email = "test_free_anchor_admin_delete@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .expect("user should exist");

    let admin_token = mock_login(&server, "test_free_anchor_admin@admin.org").await;

    let response = server
        .delete(&format!("/v1/admin/users/{}/subscription", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let got = db
        .subscription_repository()
        .last_cancelled_subscription_period_end_for_user(user.id)
        .await
        .unwrap();
    assert_eq!(
        got, None,
        "admin cancel removes subscription rows, so there is no canceled stripe row to anchor on"
    );
}

// Test clock tests
#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_with_test_clock_disabled() {
    // Set to "false" BEFORE creating server - dotenvy won't overwrite existing vars
    std::env::set_var("STRIPE_TEST_CLOCK_ENABLED", "false");

    let server = create_test_server().await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_clock_disabled@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "provider": "stripe",
        "plan": "basic",
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel",
        "test_clock_id": "clock_test_12345"
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

    // Should return 400 Bad Request when test_clock_id provided but feature disabled
    assert_eq!(
        response.status_code(),
        400,
        "Should return 400 when test_clock_id provided but STRIPE_TEST_CLOCK_ENABLED is false"
    );

    let body: serde_json::Value = response.json();
    let error_msg = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        error_msg.contains("Test clock feature is not enabled"),
        "Error should mention test clock not enabled, got: {}",
        error_msg
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_includes_pending_downgrade_info() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro":   { "providers": { "stripe": { "price_id": "price_test_pro"  } }, "agent_instances": { "max": 3 }, "monthly_tokens": { "max": 5000000 } }
        }),
    )
    .await;

    let user_email = "test_list_subscriptions_pending_downgrade@example.com";
    // Start user on pro
    insert_test_subscription_with_price_id(&server, &db, user_email, false, "price_test_pro").await;

    // Manually set a pending downgrade in DB
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .unwrap()
        .unwrap();
    let client = db.pool().get().await.unwrap();
    client
        .execute(
            "UPDATE subscriptions SET
                pending_downgrade_target_price_id = 'price_test_basic',
                pending_downgrade_from_price_id = 'price_test_pro',
                pending_downgrade_expected_period_end = current_period_end,
                pending_downgrade_status = 'pending'
             WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .unwrap();

    let user_token = mock_login(&server, user_email).await;
    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let sub = &body["subscriptions"][0];

    assert_eq!(
        sub["pending_downgrade_plan"].as_str(),
        Some("basic"),
        "Should include pending_downgrade_plan"
    );
    assert_eq!(
        sub["pending_downgrade_status"].as_str(),
        Some("pending"),
        "Should include pending_downgrade_status"
    );
    assert!(
        sub["pending_downgrade_period_end"].is_string(),
        "Should include pending_downgrade_period_end"
    );
}
