mod common;

use async_trait::async_trait;
use common::{
    clear_credits_config, create_test_server, create_test_server_and_db, mock_login,
    set_credits_config, set_hos_credits_config, set_multi_provider_credits_config,
    set_subscription_plans, TestServerConfig,
};
use serde_json::json;
use serial_test::serial;
use services::subscription::ports::{
    StripeCheckoutSessionResult, StripeClientPort, StripeCreateCreditsCheckoutParams,
    StripeCreateSubscriptionCheckoutParams, StripeCustomerRef, StripePortalSessionResult,
    StripeSubscriptionSnapshot, StripeUpdateSubscriptionParams, SubscriptionError,
};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug)]
struct MockStripeClient {
    checkout_url: String,
}

impl MockStripeClient {
    fn new(checkout_url: &str) -> Self {
        Self {
            checkout_url: checkout_url.to_string(),
        }
    }
}

#[async_trait]
impl StripeClientPort for MockStripeClient {
    async fn verify_webhook_signature(
        &self,
        _payload: &[u8],
        _signature: &str,
        _secret: &str,
    ) -> Result<(), SubscriptionError> {
        Ok(())
    }

    async fn create_customer(
        &self,
        _email: Option<&str>,
        _name: Option<&str>,
        user_id: &str,
        _test_clock_id: Option<&str>,
    ) -> Result<String, SubscriptionError> {
        Ok(format!("cus_{user_id}"))
    }

    async fn retrieve_customer(
        &self,
        customer_id: &str,
    ) -> Result<StripeCustomerRef, SubscriptionError> {
        Ok(StripeCustomerRef {
            id: customer_id.to_string(),
            metadata: HashMap::new(),
        })
    }

    async fn create_subscription_checkout_session(
        &self,
        _params: StripeCreateSubscriptionCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        Err(SubscriptionError::StripeError(
            "subscription checkout not mocked".to_string(),
        ))
    }

    async fn create_credits_checkout_session(
        &self,
        params: StripeCreateCreditsCheckoutParams,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        assert_eq!(params.price_id, "price_stripe_credits");
        assert_eq!(params.credits, 10);
        Ok(StripeCheckoutSessionResult {
            id: "cs_test_credits".to_string(),
            url: Some(self.checkout_url.clone()),
            line_items: None,
            line_items_has_more: false,
        })
    }

    async fn retrieve_checkout_session(
        &self,
        _checkout_session_id: &str,
    ) -> Result<StripeCheckoutSessionResult, SubscriptionError> {
        Err(SubscriptionError::StripeError(
            "retrieve checkout not mocked".to_string(),
        ))
    }

    async fn retrieve_subscription(
        &self,
        _subscription_id: &str,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        Err(SubscriptionError::StripeError(
            "retrieve subscription not mocked".to_string(),
        ))
    }

    async fn update_subscription(
        &self,
        _subscription_id: &str,
        _params: StripeUpdateSubscriptionParams,
    ) -> Result<StripeSubscriptionSnapshot, SubscriptionError> {
        Err(SubscriptionError::StripeError(
            "update subscription not mocked".to_string(),
        ))
    }

    async fn create_billing_portal_session(
        &self,
        _customer_id: &str,
        _return_url: &str,
    ) -> Result<StripePortalSessionResult, SubscriptionError> {
        Err(SubscriptionError::StripeError(
            "billing portal not mocked".to_string(),
        ))
    }
}

/// Ensure Stripe env vars are set (needed for subscription/credits service to not return NotConfigured).
fn ensure_stripe_env() {
    if std::env::var("STRIPE_SECRET_KEY").is_err() {
        std::env::set_var("STRIPE_SECRET_KEY", "sk_test_dummy");
    }
    if std::env::var("STRIPE_WEBHOOK_SECRET").is_err() {
        std::env::set_var("STRIPE_WEBHOOK_SECRET", "whsec_dummy");
    }
    if std::env::var("AGENT_API_TOKEN").is_err() {
        std::env::set_var("AGENT_API_TOKEN", "test_token");
    }
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

fn near_rpc_hos_credit_purchase_respond(req: &wiremock::Request) -> ResponseTemplate {
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
    match body
        .pointer("/params/method_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
    {
        "get_purchase" => {
            ResponseTemplate::new(200).set_body_json(near_rpc_call_function_body(&json!({
                "purchase_id": "pay_test",
                "account_id": "hos-credits.testnet",
                "product_id": "prod_credits",
                "price_id": "price_hos_credits",
                "quantity": "10",
                "amount_paid": "50",
                "created_ns": "1"
            })))
        }
        "get_price" => {
            ResponseTemplate::new(200).set_body_json(near_rpc_call_function_body(&json!({
                "price_id": "price_hos_credits",
                "product_id": "prod_credits",
                "amount": "5",
                "price_type": "OneOff",
                "status": "Active"
            })))
        }
        _ => ResponseTemplate::new(500).set_body_json(json!({ "error": "unmocked NEAR RPC" })),
    }
}

async fn near_login_token(server: &axum_test::TestServer, account_id: &str) -> String {
    let response = server
        .post("/v1/auth/mock-login")
        .json(&json!({
            "email": format!("{account_id}@near"),
            "name": "HoS Credits Test",
            "oauth_provider": "near"
        }))
        .await;
    assert_eq!(response.status_code(), 200);
    response.json::<serde_json::Value>()["token"]
        .as_str()
        .expect("token")
        .to_string()
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
        body.get("period_spent_credits").is_some(),
        "Should have period_spent_credits"
    );
    assert!(
        body.get("plan_credits").is_some(),
        "Should have plan_credits"
    );
    assert!(
        body.get("total_purchased_nano_usd").is_some(),
        "Should have total_purchased_nano_usd"
    );
    assert!(
        body.get("spent_purchased_nano_usd").is_some(),
        "Should have spent_purchased_nano_usd"
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
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    clear_credits_config(&db).await;

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

    let status = response.status_code();
    let body = response.text();
    assert_eq!(
        status, 503,
        "POST /v1/credits should return 503 when credits not configured, body: {}",
        body
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

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_requires_near_wallet() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some("staking.testnet".to_string()),
        near_network_id: Some("testnet".to_string()),
        ..Default::default()
    })
    .await;
    set_hos_credits_config(&server, "price_hos_credits").await;

    let token = mock_login(&server, "hos-credits-email@example.com").await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 10,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 403, "{}", response.text());
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_house_of_stake_returns_intent() {
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some("staking.testnet".to_string()),
        near_network_id: Some("testnet".to_string()),
        ..Default::default()
    })
    .await;
    set_hos_credits_config(&server, "price_hos_credits").await;

    let token = near_login_token(&server, "hos-credits.testnet").await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 10,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("kind").and_then(|v| v.as_str()),
        Some("house_of_stake")
    );
    assert_eq!(
        body.get("price_id").and_then(|v| v.as_str()),
        Some("price_hos_credits")
    );
    assert_eq!(
        body.get("network_id").and_then(|v| v.as_str()),
        Some("testnet")
    );
    assert_eq!(
        body.get("contract_id").and_then(|v| v.as_str()),
        Some("staking.testnet")
    );
    assert_eq!(body.get("quantity").and_then(|v| v.as_u64()), Some(10));
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_stripe_default_returns_checkout_url_without_near_wallet() {
    ensure_stripe_env();
    let (server, _) = create_test_server_and_db(TestServerConfig {
        stripe_client: Some(Arc::new(MockStripeClient::new(
            "https://checkout.stripe.com/c/pay/cs_test_credits",
        ))),
        ..Default::default()
    })
    .await;
    set_multi_provider_credits_config(
        &server,
        "stripe",
        "price_stripe_credits",
        "price_hos_credits",
    )
    .await;

    let token = mock_login(&server, "stripe-credits@example.com").await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 10,
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("kind").and_then(|v| v.as_str()), Some("stripe"));
    assert_eq!(
        body.get("checkout_url").and_then(|v| v.as_str()),
        Some("https://checkout.stripe.com/c/pay/cs_test_credits")
    );
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_request_provider_overrides_default_provider() {
    ensure_stripe_env();
    let (server, _) = create_test_server_and_db(TestServerConfig {
        near_staking_contract_id: Some("staking.testnet".to_string()),
        near_network_id: Some("testnet".to_string()),
        stripe_client: Some(Arc::new(MockStripeClient::new(
            "https://checkout.stripe.com/c/pay/cs_test_credits",
        ))),
        ..Default::default()
    })
    .await;
    set_multi_provider_credits_config(
        &server,
        "stripe",
        "price_stripe_credits",
        "price_hos_credits",
    )
    .await;

    let token = near_login_token(&server, "hos-credits.testnet").await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 10,
            "provider": "house-of-stake",
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 200, "{}", response.text());
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("kind").and_then(|v| v.as_str()),
        Some("house_of_stake")
    );
    assert_eq!(
        body.get("price_id").and_then(|v| v.as_str()),
        Some("price_hos_credits")
    );
    assert_eq!(
        body.get("contract_id").and_then(|v| v.as_str()),
        Some("staking.testnet")
    );
    assert_eq!(body.get("quantity").and_then(|v| v.as_u64()), Some(10));
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_post_credits_checkout_unsupported_provider_returns_400() {
    ensure_stripe_env();
    let (server, _) = create_test_server_and_db(TestServerConfig {
        stripe_client: Some(Arc::new(MockStripeClient::new(
            "https://checkout.stripe.com/c/pay/cs_test_credits",
        ))),
        ..Default::default()
    })
    .await;
    set_multi_provider_credits_config(
        &server,
        "stripe",
        "price_stripe_credits",
        "price_hos_credits",
    )
    .await;

    let token = mock_login(&server, "unsupported-credits@example.com").await;

    let response = server
        .post("/v1/credits")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&json!({
            "credits": 10,
            "provider": "paypal",
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 400, "{}", response.text());
}

#[tokio::test]
#[serial(credits_tests)]
async fn test_confirm_house_of_stake_credit_purchase_is_idempotent() {
    clear_proxy_env_for_local_wiremock();
    let near_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(near_rpc_hos_credit_purchase_respond)
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
            "free": { "providers": {}, "agent_instances": { "max": 1 }, "monthly_credits": { "max": 0 } }
        }),
    )
    .await;
    set_hos_credits_config(&server, "price_hos_credits").await;

    let token = near_login_token(&server, "hos-credits.testnet").await;
    for _ in 0..2 {
        let response = server
            .post("/v1/credits/confirm")
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            )
            .add_header(
                http::HeaderName::from_static("content-type"),
                http::HeaderValue::from_static("application/json"),
            )
            .json(&json!({
                "purchase_id": "pay_test",
                "expected_credits": 10
            }))
            .await;

        assert_eq!(response.status_code(), 200, "{}", response.text());
        let body: serde_json::Value = response.json();
        assert_eq!(
            body.get("total_purchased_nano_usd")
                .and_then(|v| v.as_i64()),
            Some(10_000_000_000)
        );
        assert_eq!(
            body.get("balance").and_then(|v| v.as_i64()),
            Some(10_000_000_000)
        );
    }
}
