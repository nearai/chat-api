mod common;

use common::{create_test_server, mock_login};
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
async fn test_list_subscriptions_returns_empty_for_new_user() {
    let server = create_test_server().await;

    let user_email = "test_subscription_list_empty@example.com";
    let user_token = mock_login(&server, user_email).await;

    // List subscriptions for a user with no subscriptions
    // Note: This may succeed or fail depending on whether stripe_plans is configured
    // If configured by previous tests, it returns 200 with empty list
    // If not configured, it returns 503
    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    // Either 200 (empty list) or 503 (not configured) are acceptable
    let status = response.status_code();
    assert!(
        status == 200 || status == 503,
        "Should return 200 or 503, got {}",
        status
    );

    if status.is_success() {
        let body: serde_json::Value = response.json();
        let subscriptions = body
            .get("subscriptions")
            .expect("Should have subscriptions field");
        assert!(subscriptions.is_array(), "subscriptions should be an array");
    }
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
async fn test_create_subscription_with_invalid_plan() {
    let server = create_test_server().await;

    let user_email = "test_create_invalid_plan@example.com";
    let user_token = mock_login(&server, user_email).await;

    let request_body = json!({
        "plan": "nonexistent_plan"
    });

    // Attempt to create subscription with invalid plan
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

    // Should return 400 (invalid plan), 500 (Stripe API error), or 503 (not configured)
    // depending on whether stripe_plans is configured in database from previous tests
    let status = response.status_code();
    assert!(
        status == 400 || status == 500 || status == 503,
        "Should return 400, 500, or 503, got {}",
        status
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
