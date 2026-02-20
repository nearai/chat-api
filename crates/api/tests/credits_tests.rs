mod common;

use common::{create_test_server, mock_login, set_credits_config, set_subscription_plans};
use serde_json::json;
use serial_test::serial;

/// Ensure Stripe env vars are set (needed for subscription/credits service to not return NotConfigured).
fn ensure_stripe_env() {
    std::env::set_var(
        "STRIPE_SECRET_KEY",
        std::env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| "sk_test_dummy".to_string()),
    );
    std::env::set_var(
        "STRIPE_WEBHOOK_SECRET",
        std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| "whsec_dummy".to_string()),
    );
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_get_credits_requires_auth() {
    let server = create_test_server().await;

    let response = server.get("/v1/credits").await;

    assert_eq!(
        response.status_code(),
        401,
        "GET /v1/credits should require authentication"
    );
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_get_credits_returns_summary() {
    ensure_stripe_env();
    let server = create_test_server().await;

    set_subscription_plans(
        &server,
        json!({
            "free": { "providers": {}, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 1000 } },
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 10000 } }
        }),
    )
    .await;

    let user_email = "test_credits_get@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .get("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        200,
        "GET /v1/credits should return 200 when configured"
    );

    let body: serde_json::Value = response.json();
    assert!(body.get("balance").is_some(), "Should have balance");
    assert!(
        body.get("used_credits").is_some(),
        "Should have used_credits"
    );
    assert!(
        body.get("effective_max_credits").is_some(),
        "Should have effective_max_credits"
    );
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_requires_auth() {
    let server = create_test_server().await;

    let response = server
        .post("/v1/credits")
        .json(&json!({
            "credits": 100,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "POST /v1/credits should require authentication"
    );
}

/// Runs before test_post_credits_checkout_invalid so credits are never set (fresh server state).
#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_01_not_configured() {
    ensure_stripe_env();
    let server = create_test_server().await;

    let user_email = "test_credits_not_configured@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 100,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        503,
        "POST /v1/credits should return 503 when credits not configured"
    );
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_02_invalid_credits_zero() {
    ensure_stripe_env();
    let server = create_test_server().await;

    set_credits_config(&server, "price_test_credit").await;

    let user_email = "test_credits_invalid@example.com";
    let user_token = mock_login(&server, user_email).await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 0,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "POST /v1/credits with credits=0 should return 400"
    );
}
