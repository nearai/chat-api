mod common;

use common::{clear_stripe_plans, create_test_server, mock_login, set_stripe_plans};
use serde_json::json;
use serial_test::serial;

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

    // Ensure stripe is not configured
    clear_stripe_plans(&server).await;

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

    // Configure stripe with some plans
    set_stripe_plans(
        &server,
        json!({
            "basic": "price_test_basic",
            "pro": "price_test_pro"
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

    // Ensure stripe is not configured
    clear_stripe_plans(&server).await;

    let user_email = "test_create_not_configured@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "plan": "any_plan"
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
async fn test_create_subscription_invalid_plan() {
    let server = create_test_server().await;

    // Configure stripe with some plans
    set_stripe_plans(
        &server,
        json!({
            "basic": "price_test_basic",
            "pro": "price_test_pro"
        }),
    )
    .await;

    let user_email = "test_create_invalid_plan@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "plan": "nonexistent_plan"
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
async fn test_webhook_requires_signature() {
    let server = create_test_server().await;

    let webhook_payload = json!({
        "id": "evt_test",
        "type": "customer.subscription.created"
    });

    // POST /v1/subscriptions/webhook without signature should return 400
    let response = server
        .post("/v1/subscriptions/webhook")
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
async fn test_configure_stripe_plans_as_admin() {
    let server = create_test_server().await;

    let admin_email = "test_admin_stripe@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure Stripe plans
    let config_body = json!({
        "stripe_plans": {
            "basic": "price_test_basic_123",
            "pro": "price_test_pro_456"
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
    let stripe_plans = body.get("stripe_plans").expect("Should have stripe_plans");

    assert_eq!(
        stripe_plans.get("basic"),
        Some(&json!("price_test_basic_123")),
        "Should have basic plan configured"
    );
    assert_eq!(
        stripe_plans.get("pro"),
        Some(&json!("price_test_pro_456")),
        "Should have pro plan configured"
    );
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_stripe_plans_persisted_in_database() {
    let server = create_test_server().await;

    let admin_email = "test_admin_stripe_persist@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure Stripe plans
    let config_body = json!({
        "stripe_plans": {
            "basic": "price_persist_basic",
            "pro": "price_persist_pro"
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
    let stripe_plans = body.get("stripe_plans").expect("Should have stripe_plans");

    assert_eq!(
        stripe_plans.get("basic"),
        Some(&json!("price_persist_basic")),
        "Basic plan should be persisted"
    );
    assert_eq!(
        stripe_plans.get("pro"),
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

    // Configure Stripe plans
    let config_body = json!({
        "stripe_plans": {
            "starter": "price_starter_789",
            "premium": "price_premium_012"
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

    // Verify price_id exists
    for plan in plans_array {
        assert!(
            plan.get("price_id").is_some(),
            "Each plan should have price_id"
        );
        let price_id = plan.get("price_id").unwrap().as_str().unwrap();
        assert!(
            price_id.starts_with("price_"),
            "price_id should start with 'price_'"
        );
    }
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_plans_empty_configuration() {
    let server = create_test_server().await;

    let admin_email = "test_list_plans_empty@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Configure empty Stripe plans
    let config_body = json!({
        "stripe_plans": {}
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
