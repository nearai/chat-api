mod common;

use api::routes::api::SUBSCRIPTION_REQUIRED_ERROR_MESSAGE;
use chrono::{Duration, TimeZone, Timelike, Utc};
use common::{
    cleanup_user_agent_instances, cleanup_user_subscription_credits, cleanup_user_subscriptions,
    cleanup_user_usage, clear_subscription_plans, create_test_server, create_test_server_and_db,
    insert_test_agent_instances, insert_test_subscription, insert_test_subscription_with_price_id,
    insert_test_subscription_with_provider_and_price, mock_login, set_subscription_plans,
    TestServerConfig,
};
use hmac::Mac;
use serde_json::json;
use serial_test::serial;
use services::subscription::ports::{
    ChangePlanOutcome, CreateSubscriptionOutcome,
    NEAR_STAKING_SYNC_SKIPPED_REASON_UPSERT_BLOCKED_NON_HOS,
};
use services::subscription::SubscriptionRepository;
use services::system_configs::ports::RateLimitConfig;
use services::user::ports::UserRepository;
use services::user_usage::{UserUsageRepository, METRIC_KEY_LLM_TOKENS};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    let result_kind = body
        .get("result")
        .and_then(|r| r.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        result_kind, "scheduled_for_period_end",
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
async fn test_change_plan_upgrade_clears_pending_downgrade_before_stripe_update() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "agent_instances": { "max": 5 }, "monthly_tokens": { "max": 1000000 } },
            "starter": { "providers": { "stripe": { "price_id": "price_test_starter" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_change_plan_upgrade_clears_pending@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;
    let user_token = mock_login(&server, user_email).await;

    // Seed pending downgrade columns as if a prior downgrade was scheduled.
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
             SET pending_downgrade_target_price_id = $2,
                 pending_downgrade_from_price_id = $3,
                 pending_downgrade_expected_period_end = current_period_end,
                 pending_downgrade_status = 'pending',
                 pending_downgrade_updated_at = NOW()
             WHERE user_id = $1
               AND status IN ('active', 'trialing')",
            &[&user.id, &"price_test_starter", &"price_test_basic"],
        )
        .await
        .expect("seed pending downgrade");

    let _response = server
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

    let row = client
        .query_one(
            "SELECT pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status
             FROM subscriptions
             WHERE user_id = $1
               AND status IN ('active', 'trialing')
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

    assert!(
        target.is_none(),
        "pending_downgrade_target_price_id should be cleared on upgrade"
    );
    assert!(
        from.is_none(),
        "pending_downgrade_from_price_id should be cleared on upgrade"
    );
    assert!(
        expected_end.is_none(),
        "pending_downgrade_expected_period_end should be cleared on upgrade"
    );
    assert!(
        status.is_none(),
        "pending_downgrade_status should be cleared on upgrade"
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
        sub.get("price_id").and_then(|v| v.as_str()),
        Some("price_test_basic")
    );
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
    ensure_stripe_env_for_gating();
    let server = create_test_server().await;

    let webhook_payload = json!({
        "id": "evt_test_multi_v1",
        "type": "customer.subscription.created",
        "data": { "object": { "id": "sub_test_multi_v1" } }
    });
    let payload = webhook_payload.to_string();
    let ts = chrono::Utc::now().timestamp();

    let webhook_secret =
        std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| "whsec_dummy".to_string());
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let signed_payload = format!("{ts}.{payload}");
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(webhook_secret.as_bytes()).unwrap();
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
async fn test_proxy_allows_email_only_user_on_free_priced_plan() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {"stripe": {"price_id": "price_test_free"}},
                "price": 0,
                "monthly_credits": {"max": 1000000}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "price": 999,
                "agent_instances": {"max": 1},
                "monthly_credits": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_email_only_free_plan_allowed@example.com";
    insert_test_subscription_with_price_id(&server, &db, user_email, false, "price_test_free")
        .await;
    let user_token = mock_login(&server, user_email).await;

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
        "Email-only user with an active free-priced subscription should not be blocked from LLM APIs"
    );

    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE),
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_blocks_email_only_user_without_active_subscription() {
    ensure_stripe_env_for_gating();
    let (server, _db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {"stripe": {"price_id": "price_test_free"}},
                "price": 0,
                "monthly_credits": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_email_only_no_subscription_block@example.com";
    let user_token = mock_login(&server, user_email).await;

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
        403,
        "Email-only user without an active subscription should be blocked from LLM APIs"
    );

    let body_res: serde_json::Value = response.json();
    assert_eq!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE)
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_email_only_user_on_paid_plan() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig {
        rate_limit_config: Some(permissive_rate_limit_config()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {"stripe": {"price_id": "price_test_free"}},
                "price": 0,
                "monthly_credits": {"max": 1000000}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "price": 999,
                "agent_instances": {"max": 1},
                "monthly_credits": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_email_only_paid_plan_allowed@example.com";
    insert_test_subscription_with_price_id(&server, &db, user_email, false, "price_test_basic")
        .await;
    let user_token = mock_login(&server, user_email).await;

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
        "Email-only user on paid plan should not be blocked by free-plan rule"
    );

    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE),
    );
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

    let run_id = Uuid::new_v4();
    let user_email = format!("test-proxy-over-plan-{run_id}@example.com");

    // Clean up any leftover state from previous runs using the same email
    cleanup_user_subscription_credits(&db, &user_email).await;
    cleanup_user_usage(&db, &user_email).await;
    cleanup_user_subscriptions(&db, &user_email).await;

    insert_test_subscription(&server, &db, &user_email, false).await;
    let user_token = mock_login(&server, &user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(&user_email)
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

    let run_id = Uuid::new_v4();
    let user_email = format!("test-proxy-within-plan-{run_id}@example.com");

    // Clean up any leftover state from previous runs using the same email
    cleanup_user_subscription_credits(&db, &user_email).await;
    cleanup_user_usage(&db, &user_email).await;
    cleanup_user_subscriptions(&db, &user_email).await;

    insert_test_subscription(&server, &db, &user_email, false).await;
    let user_token = mock_login(&server, &user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(&user_email)
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
async fn test_admin_replace_subscription_requires_admin() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_email = "replace_sub_requires_admin@example.com";
    cleanup_user_subscriptions(&db, user_email).await;
    insert_test_subscription(&server, &db, user_email, false).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user should exist");

    let client = db.pool().get().await.expect("get pool client");
    let row = client
        .query_one(
            "SELECT subscription_id, provider, customer_id, price_id, status, current_period_end, cancel_at_period_end, created_at,
                    pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status, pending_downgrade_updated_at
             FROM subscriptions WHERE user_id = $1 LIMIT 1",
            &[&user.id],
        )
        .await
        .expect("load subscription row");

    let subscription_id: String = row.get("subscription_id");
    let current_period_end: chrono::DateTime<Utc> = row.get("current_period_end");
    let created_at: chrono::DateTime<Utc> = row.get("created_at");

    let user_token = mock_login(&server, user_email).await;
    let response = server
        .put(&format!("/v1/admin/subscriptions/{subscription_id}"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "user_id": user.id,
            "provider": row.get::<_, String>("provider"),
            "customer_id": row.get::<_, String>("customer_id"),
            "price_id": row.get::<_, String>("price_id"),
            "status": row.get::<_, String>("status"),
            "current_period_end": current_period_end,
            "cancel_at_period_end": row.get::<_, bool>("cancel_at_period_end"),
            "created_at": created_at,
            "pending_downgrade_target_price_id": row.get::<_, Option<String>>("pending_downgrade_target_price_id"),
            "pending_downgrade_from_price_id": row.get::<_, Option<String>>("pending_downgrade_from_price_id"),
            "pending_downgrade_expected_period_end": row.get::<_, Option<chrono::DateTime<Utc>>>("pending_downgrade_expected_period_end"),
            "pending_downgrade_status": row.get::<_, Option<String>>("pending_downgrade_status"),
            "pending_downgrade_updated_at": row.get::<_, Option<chrono::DateTime<Utc>>>("pending_downgrade_updated_at")
        }))
        .await;

    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_replace_subscription_requires_auth() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    let response = server
        .put("/v1/admin/subscriptions/sub_missing")
        .json(&json!({
            "user_id": services::UserId::nil(),
            "provider": "stripe",
            "customer_id": "cus_test",
            "price_id": "price_test_basic",
            "status": "active",
            "current_period_end": Utc::now(),
            "cancel_at_period_end": false,
            "created_at": Utc::now(),
            "pending_downgrade_target_price_id": null,
            "pending_downgrade_from_price_id": null,
            "pending_downgrade_expected_period_end": null,
            "pending_downgrade_status": null,
            "pending_downgrade_updated_at": null
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_replace_subscription_not_found() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;
    let admin_token = mock_login(&server, "replace_sub_not_found@admin.org").await;

    let response = server
        .put("/v1/admin/subscriptions/sub_missing")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "user_id": services::UserId::nil(),
            "provider": "stripe",
            "customer_id": "cus_test",
            "price_id": "price_test_basic",
            "status": "active",
            "current_period_end": Utc::now(),
            "cancel_at_period_end": false,
            "created_at": Utc::now(),
            "pending_downgrade_target_price_id": null,
            "pending_downgrade_from_price_id": null,
            "pending_downgrade_expected_period_end": null,
            "pending_downgrade_status": null,
            "pending_downgrade_updated_at": null
        }))
        .await;

    assert_eq!(response.status_code(), 404);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_replace_subscription_success_updates_only_target_row() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let target_email = "replace_sub_target@example.com";
    let other_email = "replace_sub_other@example.com";
    cleanup_user_subscriptions(&db, target_email).await;
    cleanup_user_subscriptions(&db, other_email).await;
    insert_test_subscription(&server, &db, target_email, false).await;
    insert_test_subscription(&server, &db, other_email, false).await;

    let target_user = db
        .user_repository()
        .get_user_by_email(target_email)
        .await
        .expect("get target user")
        .expect("target user should exist");
    let other_user = db
        .user_repository()
        .get_user_by_email(other_email)
        .await
        .expect("get other user")
        .expect("other user should exist");

    let client = db.pool().get().await.expect("get pool client");
    let target_row = client
        .query_one(
            "SELECT subscription_id, provider, customer_id, price_id, status, current_period_end, cancel_at_period_end, created_at, updated_at,
                    pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status, pending_downgrade_updated_at
             FROM subscriptions WHERE user_id = $1 LIMIT 1",
            &[&target_user.id],
        )
        .await
        .expect("load target row");
    let other_row = client
        .query_one(
            "SELECT subscription_id, price_id, status, cancel_at_period_end, updated_at
             FROM subscriptions WHERE user_id = $1 LIMIT 1",
            &[&other_user.id],
        )
        .await
        .expect("load other row");

    let subscription_id: String = target_row.get("subscription_id");
    let previous_updated_at: chrono::DateTime<Utc> = target_row.get("updated_at");
    let other_subscription_id: String = other_row.get("subscription_id");
    let other_price_id_before: String = other_row.get("price_id");
    let other_status_before: String = other_row.get("status");
    let other_cancel_before: bool = other_row.get("cancel_at_period_end");
    let other_updated_before: chrono::DateTime<Utc> = other_row.get("updated_at");

    let replacement_period_end = Utc::now() + Duration::days(30);
    let pending_updated_at = (Utc::now() - Duration::hours(3))
        .with_nanosecond(((Utc::now() - Duration::hours(3)).timestamp_subsec_micros()) * 1_000)
        .expect("valid microsecond timestamp");
    let admin_token = mock_login(&server, "replace_sub_success@admin.org").await;

    let response = server
        .put(&format!("/v1/admin/subscriptions/{subscription_id}"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "user_id": target_user.id,
            "provider": "stripe",
            "customer_id": "cus_manual_override",
            "price_id": "price_manual_override",
            "status": "past_due",
            "current_period_end": replacement_period_end,
            "cancel_at_period_end": true,
            "created_at": target_row.get::<_, chrono::DateTime<Utc>>("created_at"),
            "pending_downgrade_target_price_id": "price_manual_target",
            "pending_downgrade_from_price_id": "price_manual_from",
            "pending_downgrade_expected_period_end": replacement_period_end,
            "pending_downgrade_status": "pending",
            "pending_downgrade_updated_at": pending_updated_at
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["subscription_id"].as_str(),
        Some(subscription_id.as_str())
    );
    assert_eq!(body["customer_id"].as_str(), Some("cus_manual_override"));
    assert_eq!(body["price_id"].as_str(), Some("price_manual_override"));
    assert_eq!(body["status"].as_str(), Some("past_due"));
    assert_eq!(body["cancel_at_period_end"].as_bool(), Some(true));
    assert_eq!(body["pending_downgrade_status"].as_str(), Some("pending"));
    let response_pending_updated_at = body["pending_downgrade_updated_at"]
        .as_str()
        .expect("response should include pending_downgrade_updated_at")
        .parse::<chrono::DateTime<Utc>>()
        .expect("pending_downgrade_updated_at should be valid RFC3339");
    assert_eq!(response_pending_updated_at, pending_updated_at);

    let updated_target_row = client
        .query_one(
            "SELECT subscription_id, customer_id, price_id, status, current_period_end, cancel_at_period_end, updated_at,
                    pending_downgrade_target_price_id, pending_downgrade_from_price_id,
                    pending_downgrade_expected_period_end, pending_downgrade_status, pending_downgrade_updated_at
             FROM subscriptions WHERE subscription_id = $1",
            &[&subscription_id],
        )
        .await
        .expect("reload target row");

    assert_eq!(
        updated_target_row.get::<_, String>("customer_id"),
        "cus_manual_override"
    );
    assert_eq!(
        updated_target_row.get::<_, String>("price_id"),
        "price_manual_override"
    );
    assert_eq!(updated_target_row.get::<_, String>("status"), "past_due");
    assert!(updated_target_row.get::<_, bool>("cancel_at_period_end"));
    assert_eq!(
        updated_target_row.get::<_, Option<String>>("pending_downgrade_target_price_id"),
        Some("price_manual_target".to_string())
    );
    assert_eq!(
        updated_target_row.get::<_, Option<String>>("pending_downgrade_from_price_id"),
        Some("price_manual_from".to_string())
    );
    assert_eq!(
        updated_target_row.get::<_, Option<String>>("pending_downgrade_status"),
        Some("pending".to_string())
    );
    assert_eq!(
        updated_target_row.get::<_, Option<chrono::DateTime<Utc>>>("pending_downgrade_updated_at"),
        Some(pending_updated_at)
    );
    assert!(
        updated_target_row.get::<_, chrono::DateTime<Utc>>("updated_at") >= previous_updated_at,
        "updated_at should be set by DB trigger"
    );

    let updated_other_row = client
        .query_one(
            "SELECT subscription_id, price_id, status, cancel_at_period_end, updated_at
             FROM subscriptions WHERE subscription_id = $1",
            &[&other_subscription_id],
        )
        .await
        .expect("reload other row");

    assert_eq!(
        updated_other_row.get::<_, String>("price_id"),
        other_price_id_before
    );
    assert_eq!(
        updated_other_row.get::<_, String>("status"),
        other_status_before
    );
    assert_eq!(
        updated_other_row.get::<_, bool>("cancel_at_period_end"),
        other_cancel_before
    );
    assert_eq!(
        updated_other_row.get::<_, chrono::DateTime<Utc>>("updated_at"),
        other_updated_before
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_admin_replace_subscription_can_move_row_to_another_user() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let source_email = "replace_sub_move_source@example.com";
    let target_email = "replace_sub_move_target@example.com";
    cleanup_user_subscriptions(&db, source_email).await;
    cleanup_user_subscriptions(&db, target_email).await;
    insert_test_subscription(&server, &db, source_email, false).await;
    let _ = mock_login(&server, target_email).await;

    let source_user = db
        .user_repository()
        .get_user_by_email(source_email)
        .await
        .expect("get source user")
        .expect("source user should exist");
    let target_user = db
        .user_repository()
        .get_user_by_email(target_email)
        .await
        .expect("get target user")
        .expect("target user should exist");

    let client = db.pool().get().await.expect("get pool client");
    let row = client
        .query_one(
            "SELECT subscription_id, provider, customer_id, price_id, status, current_period_end, cancel_at_period_end, created_at
             FROM subscriptions WHERE user_id = $1 LIMIT 1",
            &[&source_user.id],
        )
        .await
        .expect("load source row");
    let subscription_id: String = row.get("subscription_id");

    let admin_token = mock_login(&server, "replace_sub_move@admin.org").await;
    let response = server
        .put(&format!("/v1/admin/subscriptions/{subscription_id}"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .json(&json!({
            "user_id": target_user.id,
            "provider": row.get::<_, String>("provider"),
            "customer_id": row.get::<_, String>("customer_id"),
            "price_id": row.get::<_, String>("price_id"),
            "status": row.get::<_, String>("status"),
            "current_period_end": row.get::<_, chrono::DateTime<Utc>>("current_period_end"),
            "cancel_at_period_end": row.get::<_, bool>("cancel_at_period_end"),
            "created_at": row.get::<_, chrono::DateTime<Utc>>("created_at"),
            "pending_downgrade_target_price_id": null,
            "pending_downgrade_from_price_id": null,
            "pending_downgrade_expected_period_end": null,
            "pending_downgrade_status": null,
            "pending_downgrade_updated_at": null
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    let moved_row = client
        .query_one(
            "SELECT user_id FROM subscriptions WHERE subscription_id = $1",
            &[&subscription_id],
        )
        .await
        .expect("reload moved row");
    assert_eq!(
        moved_row.get::<_, services::UserId>("user_id"),
        target_user.id
    );

    let source_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM subscriptions WHERE user_id = $1",
            &[&source_user.id],
        )
        .await
        .expect("count source rows")
        .get(0);
    let target_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM subscriptions WHERE user_id = $1",
            &[&target_user.id],
        )
        .await
        .expect("count target rows")
        .get(0);

    assert_eq!(source_count, 0);
    assert_eq!(target_count, 1);
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

fn clear_proxy_env_for_local_wiremock() {
    for k in [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
}

fn near_rpc_call_function_body(result_json: &serde_json::Value) -> serde_json::Value {
    let payload = serde_json::to_vec(result_json).expect("serialize view result");
    let encoded: Vec<serde_json::Value> = payload.iter().map(|b| json!(*b)).collect();
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "result": {
            "block_hash": "11111111111111111111111111111111",
            "block_height": 12345u64,
            "logs": [],
            "result": encoded
        }
    })
}

/// NEAR JSON-RPC `query` bodies use `args_base64` (not literal `price_*` in the wire payload), so
/// WireMock must decode args and branch on `method_name`.
fn near_rpc_hos_catalog_respond(
    req: &wiremock::Request,
    price_basic: &serde_json::Value,
    price_pro: &serde_json::Value,
) -> ResponseTemplate {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
    let empty = json!({});
    let params = body.get("params").unwrap_or(&empty);
    let method_name = params
        .get("method_name")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    match method_name {
        "get_subscription_for_price" => {
            let sub = json!({
                "subscription_id": "sub_chain_hos_change_plan",
                "price_id": "price_hos_basic",
                "end_ns": "2000000000000000000",
                "status": "Active",
                "cancel_at_period_end": false
            });
            ResponseTemplate::new(200).set_body_json(near_rpc_call_function_body(&sub))
        }
        "get_price" => {
            let args_b64 = params
                .get("args_base64")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let decoded = STANDARD
                .decode(args_b64)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .unwrap_or_default();
            let pid = decoded
                .get("price_id")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let price = if pid == "price_hos_pro" {
                price_pro
            } else {
                price_basic
            };
            ResponseTemplate::new(200).set_body_json(near_rpc_call_function_body(price))
        }
        _ => ResponseTemplate::new(500).set_body_json(json!({
            "error": "unexpected NEAR RPC mock",
            "method_name": method_name
        })),
    }
}

/// WireMock responder for tests that only need `get_subscription_for_price` (all other methods 500).
fn near_rpc_wiremock_hos_subscription_probe_only(
    subscription_result: serde_json::Value,
) -> impl wiremock::Respond {
    move |req: &wiremock::Request| {
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let empty = json!({});
        let params = body.get("params").unwrap_or(&empty);
        match params.get("method_name").and_then(|x| x.as_str()) {
            Some("get_subscription_for_price") => ResponseTemplate::new(200)
                .set_body_json(near_rpc_call_function_body(&subscription_result)),
            _ => ResponseTemplate::new(500).set_body_json(json!({ "error": "unmocked NEAR RPC" })),
        }
    }
}

#[test]
fn test_change_plan_outcome_serde_uses_kind_discriminant() {
    let o = ChangePlanOutcome::NearStakingUpgrade {
        new_price_id: "price_hos_pro".to_string(),
    };
    let v = serde_json::to_value(&o).expect("serialize");
    assert_eq!(
        v.get("kind").and_then(|x| x.as_str()),
        Some("near_staking_upgrade")
    );
    assert_eq!(
        v.get("new_price_id").and_then(|x| x.as_str()),
        Some("price_hos_pro")
    );
    let back: ChangePlanOutcome = serde_json::from_value(v).expect("deserialize");
    assert!(matches!(back, ChangePlanOutcome::NearStakingUpgrade { .. }));
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_house_of_stake_returns_flat_json() {
    clear_proxy_env_for_local_wiremock();
    let near_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(near_rpc_wiremock_hos_subscription_probe_only(
            serde_json::Value::Null,
        ))
        .mount(&near_mock)
        .await;

    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(near_mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        near_network_id: Some("testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let login = json!({
        "email": format!("{}@near", "hos_create_ok.testnet"),
        "name": "HoS Test",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    assert_eq!(response.status_code(), 200);
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .expect("token")
        .to_string();

    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "provider": "house-of-stake",
            "plan": "basic",
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("kind").and_then(|x| x.as_str()),
        Some("house_of_stake")
    );
    assert_eq!(
        body.get("price_id").and_then(|x| x.as_str()),
        Some("price_hos_basic")
    );
    assert_eq!(
        body.get("network_id").and_then(|x| x.as_str()),
        Some("testnet")
    );

    let parsed: CreateSubscriptionOutcome = serde_json::from_value(body).expect("parse outcome");
    assert!(matches!(
        parsed,
        CreateSubscriptionOutcome::NearStakeLock { .. }
    ));
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_house_of_stake_requires_near_wallet() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "hos_create_no_near@example.com";
    let token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "provider": "house-of-stake",
            "plan": "basic",
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_cancel_subscription_house_of_stake_returns_wallet_intent_message() {
    clear_proxy_env_for_local_wiremock();
    // Reconcile runs before cancel; RPC `null` would delete local HoS rows — return a minimal chain view.
    let chain_sub = json!({
        "subscription_id": "sub_on_chain_hos_cancel_msg",
        "price_id": "price_hos_basic",
        "end_ns": "2000000000000000000",
        "status": "Active",
        "cancel_at_period_end": false
    });
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(near_rpc_wiremock_hos_subscription_probe_only(chain_sub))
        .mount(&mock)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let near_email = "hos_cancel_msg.testnet@near";
    let login = json!({
        "email": near_email,
        "name": "HoS Cancel Msg",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    insert_test_subscription_with_provider_and_price(
        &server,
        &db,
        near_email,
        "house-of-stake",
        "price_hos_basic",
        false,
    )
    .await;

    let response = server
        .post("/v1/subscriptions/cancel")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("message").and_then(|x| x.as_str()),
        Some("Complete cancellation in your NEAR wallet")
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_house_of_stake_returns_wallet_intent_message() {
    clear_proxy_env_for_local_wiremock();
    // Reconcile runs before resume; keep `cancel_at_period_end` true so resume preconditions still hold.
    let chain_sub = json!({
        "subscription_id": "sub_on_chain_hos_resume_msg",
        "price_id": "price_hos_basic",
        "end_ns": "2000000000000000000",
        "status": "Active",
        "cancel_at_period_end": true
    });
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(near_rpc_wiremock_hos_subscription_probe_only(chain_sub))
        .mount(&mock)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let near_email = "hos_resume_msg.testnet@near";
    let login = json!({
        "email": near_email,
        "name": "HoS Resume Msg",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    insert_test_subscription_with_provider_and_price(
        &server,
        &db,
        near_email,
        "house-of-stake",
        "price_hos_basic",
        true,
    )
    .await;

    let response = server
        .post("/v1/subscriptions/resume")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("message").and_then(|x| x.as_str()),
        Some("Complete resume in your NEAR wallet")
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_staking_sync_skipped_without_contract() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some(String::new()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let login = json!({
        "email": format!("{}@near", "hos_sync_skip_contract.testnet"),
        "name": "HoS Sync",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let response = server
        .post("/v1/subscriptions/near/sync")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("skipped").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(
        body.get("deleted_house_of_stake_rows")
            .and_then(|x| x.as_u64()),
        Some(0)
    );
    assert_eq!(
        body.get("upserted_house_of_stake_row")
            .and_then(|x| x.as_bool()),
        Some(false)
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_staking_sync_skipped_without_linked_near() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let token = mock_login(&server, "hos_sync_skip_near@example.com").await;

    let response = server
        .post("/v1/subscriptions/near/sync")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("skipped").and_then(|x| x.as_bool()), Some(true));
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_staking_sync_skipped_reason_when_upsert_blocked_by_active_stripe() {
    clear_proxy_env_for_local_wiremock();
    let chain_sub = json!({
        "subscription_id": "sub_on_chain_hos",
        "price_id": "price_hos_basic",
        "end_ns": "2000000000000000000",
        "status": "Active",
        "cancel_at_period_end": false
    });
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(near_rpc_wiremock_hos_subscription_probe_only(chain_sub))
        .mount(&mock)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let near_email = "hos_sync_stripe_blocks.testnet@near";
    let login = json!({
        "email": near_email,
        "name": "HoS Stripe Block",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    insert_test_subscription(&server, &db, near_email, false).await;

    let response = server
        .post("/v1/subscriptions/near/sync")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("skipped").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(
        body.get("deleted_house_of_stake_rows")
            .and_then(|x| x.as_u64()),
        Some(0)
    );
    assert_eq!(
        body.get("upserted_house_of_stake_row")
            .and_then(|x| x.as_bool()),
        Some(false)
    );
    assert_eq!(
        body.get("skipped_reason").and_then(|x| x.as_str()),
        Some(NEAR_STAKING_SYNC_SKIPPED_REASON_UPSERT_BLOCKED_NON_HOS)
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_near_staking_sync_deletes_local_hos_when_chain_returns_null() {
    clear_proxy_env_for_local_wiremock();
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(near_rpc_call_function_body(&serde_json::Value::Null)),
        )
        .mount(&mock)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let near_email = "hos_sync_delete.testnet@near";
    let login = json!({
        "email": near_email,
        "name": "HoS Sync Delete",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    insert_test_subscription_with_provider_and_price(
        &server,
        &db,
        near_email,
        "house-of-stake",
        "price_hos_basic",
        false,
    )
    .await;

    let response = server
        .post("/v1/subscriptions/near/sync")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("skipped").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(
        body.get("deleted_house_of_stake_rows")
            .and_then(|x| x.as_u64()),
        Some(1)
    );

    let user = db
        .user_repository()
        .get_user_by_email(near_email)
        .await
        .unwrap()
        .unwrap();
    let client = db.pool().get().await.unwrap();
    let cnt: i64 = client
        .query_one(
            "SELECT COUNT(*)::bigint FROM subscriptions WHERE user_id = $1 AND provider = 'house-of-stake'",
            &[&user.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        cnt, 0,
        "HoS rows should be removed after chain reports null"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_change_plan_house_of_stake_upgrade_json_shape() {
    clear_proxy_env_for_local_wiremock();
    let mock = MockServer::start().await;
    let price_basic = json!({
        "product_id": "nearai|prod_cat",
        "amount": "1000000000000000000000000"
    });
    let price_pro = json!({
        "product_id": "nearai|prod_cat",
        "amount": "2000000000000000000000000"
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with({
            let price_basic = price_basic.clone();
            let price_pro = price_pro.clone();
            move |req: &wiremock::Request| {
                near_rpc_hos_catalog_respond(req, &price_basic, &price_pro)
            }
        })
        .mount(&mock)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        near_rpc_url: Some(mock.uri().to_string()),
        near_staking_contract_id: Some("staking.testnet".to_string()),
        ..Default::default()
    })
    .await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "house-of-stake": { "price_id": "price_hos_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } },
            "pro": { "providers": { "house-of-stake": { "price_id": "price_hos_pro" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000000 } }
        }),
    )
    .await;

    let near_email = "hos_change_plan.testnet@near";
    let login = json!({
        "email": near_email,
        "name": "HoS Change",
        "oauth_provider": "near"
    });
    let response = server.post("/v1/auth/mock-login").json(&login).await;
    let token = response.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    insert_test_subscription_with_provider_and_price(
        &server,
        &db,
        near_email,
        "house-of-stake",
        "price_hos_basic",
        false,
    )
    .await;

    let response = server
        .post("/v1/subscriptions/change")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({ "plan": "pro" }))
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    let result = &body["result"];
    assert_eq!(
        result.get("kind").and_then(|x| x.as_str()),
        Some("near_staking_upgrade")
    );
    assert_eq!(
        result.get("new_price_id").and_then(|x| x.as_str()),
        Some("price_hos_pro")
    );
}
