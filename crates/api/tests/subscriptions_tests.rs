//! Subscription tests. Run with: `cargo test -p api --test subscriptions_tests --features test`

mod common;

use api::routes::api::SUBSCRIPTION_REQUIRED_ERROR_MESSAGE;
use common::{
    clear_subscription_plans, create_test_server, create_test_server_and_db,
    insert_test_subscription, mock_login, set_subscription_plans, TestServerConfig,
};
use serde_json::json;
use serial_test::serial;
use services::user::ports::UserRepository;
use services::user_usage::{UserUsageRepository, METRIC_KEY_LLM_TOKENS};
use uuid::Uuid;

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

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_requires_auth() {
    let server = create_test_server().await;
    let response = server.get("/v1/subscriptions").await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_not_configured() {
    let server = create_test_server().await;
    clear_subscription_plans(&server).await;

    let user_token = mock_login(&server, "test_subscription_not_configured@example.com").await;
    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 503);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_configured_returns_empty() {
    let server = create_test_server().await;
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
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

    assert_eq!(response.status_code(), 200);
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
    let response = server
        .post("/v1/subscriptions")
        .json(&json!({"plan": "basic"}))
        .await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_not_configured() {
    let server = create_test_server().await;
    clear_subscription_plans(&server).await;

    let user_token = mock_login(&server, "test_create_not_configured@example.com").await;
    let response = server
        .post("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({
            "plan": "any_plan",
            "success_url": "https://example.com/success",
            "cancel_url": "https://example.com/cancel"
        }))
        .await;

    assert_eq!(response.status_code(), 503);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_invalid_provider() {
    let server = create_test_server().await;
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
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
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_create_subscription_invalid_plan() {
    let server = create_test_server().await;
    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
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
        .json(&request_body)
        .await;

    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_cancel_subscription_requires_auth() {
    let server = create_test_server().await;
    let response = server.post("/v1/subscriptions/cancel").await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_cancel_subscription_not_found() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "test_cancel_subscription@example.com").await;
    let response = server
        .post("/v1/subscriptions/cancel")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 404);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_requires_auth() {
    let server = create_test_server().await;
    let response = server.post("/v1/subscriptions/resume").await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_not_found() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "test_resume_subscription@example.com").await;
    let response = server
        .post("/v1/subscriptions/resume")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 404);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_resume_subscription_not_scheduled_for_cancellation() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = "test_resume_not_scheduled@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;

    let user_token = mock_login(&server, user_email).await;
    let response = server
        .post("/v1/subscriptions/resume")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;
    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_list_subscriptions_successfully() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
        }),
    )
    .await;

    let user_email = format!("test_list_with_sub_{}@example.com", Uuid::new_v4());
    insert_test_subscription(&server, &db, &user_email, false).await;
    let user_token = mock_login(&server, &user_email).await;

    let response = server
        .get("/v1/subscriptions")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
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
    let response = server
        .post("/v1/subscriptions/stripe/webhook")
        .json(&json!({
            "id": "evt_test",
            "type": "customer.subscription.created"
        }))
        .await;
    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_configure_subscription_plans_as_admin() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_admin_stripe@admin.org").await;
    let config_body = json!({
        "subscription_plans": {
            "basic": { "providers": { "stripe": { "price_id": "price_test_basic_123" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } },
            "pro": { "providers": { "stripe": { "price_id": "price_test_pro_456" } }, "private_assistant_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } }
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
    let admin_token = mock_login(&server, "test_admin_stripe_persist@admin.org").await;
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
    let response = server.get("/v1/subscriptions/plans").await;
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
    clear_subscription_plans(&server).await;
    let admin_token = mock_login(&server, "test_list_plans@admin.org").await;
    let config_body = json!({
        "subscription_plans": {
            "starter": {
                "providers": { "stripe": { "price_id": "price_starter_789" } },
                "private_assistant_instances": { "max": 1 },
                "monthly_tokens": { "max": 500_000 }
            },
            "premium": {
                "providers": { "stripe": { "price_id": "price_premium_012" } },
                "private_assistant_instances": { "max": 5 },
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
    let response = server.get("/v1/subscriptions/plans").await;
    assert_eq!(response.status_code(), 200);

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
                    plan.get("private_assistant_instances")
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
                    plan.get("private_assistant_instances")
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
async fn test_list_plans_empty_configuration() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_list_plans_empty@admin.org").await;
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
    let response = server.get("/v1/subscriptions/plans").await;
    assert_eq!(response.status_code(), 503);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_portal_session_requires_auth() {
    let server = create_test_server().await;
    let response = server
        .post("/v1/subscriptions/portal")
        .json(&json!({"return_url": "https://example.com"}))
        .await;
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_portal_session_no_stripe_customer() {
    ensure_stripe_env_for_gating();
    let server = create_test_server().await;
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "private_assistant_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_portal_no_customer@example.com";
    let user_token = mock_login(&server, user_email).await;
    let response = server
        .post("/v1/subscriptions/portal")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .json(&json!({"return_url": "https://example.com"}))
        .await;
    assert_eq!(response.status_code(), 404);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_returns_403_without_subscription_when_plans_configured() {
    ensure_stripe_env_for_gating();
    let (server, _) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_tokens": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "private_assistant_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_token = mock_login(&server, "test_proxy_no_subscription@example.com").await;
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

        let status = response.status_code();
        assert!(status == 402 || status == 403, "POST {} got {}", path, status);
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
                "private_assistant_instances": {"max": 1},
                "monthly_tokens": {"max": 1000000}
            }
        }),
    )
    .await;

    let user_email = "test_proxy_with_subscription@example.com";
    insert_test_subscription(&server, &db, user_email, false).await;
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

    assert_ne!(response.status_code(), 403);
    let body_res: serde_json::Value = response.json();
    assert_ne!(
        body_res.get("error").and_then(|v| v.as_str()),
        Some(SUBSCRIPTION_REQUIRED_ERROR_MESSAGE)
    );

    // /v1/responses with subscription
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

    assert_ne!(response.status_code(), 403);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_allows_when_subscription_not_configured() {
    let server = create_test_server().await;

    clear_subscription_plans(&server).await;

    let user_token = mock_login(&server, "test_proxy_no_plans@example.com").await;
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

    assert_ne!(response.status_code(), 403);

    // /v1/responses when subscription not configured
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

    assert_ne!(response.status_code(), 403);
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_proxy_blocks_when_monthly_token_limit_exceeded() {
    ensure_stripe_env_for_gating();
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "private_assistant_instances": {"max": 1},
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

    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 150, Some(0), None)
        .await
        .expect("record usage");

    // Proxy should return 402 when monthly token limit exceeded
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

    assert_eq!(response.status_code(), 402);
    let body: serde_json::Value = response.json();
    let err_msg = body
        .get("error")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()))
        .unwrap_or("");
    assert!(err_msg.contains("Monthly token limit exceeded") && err_msg.contains("100"));

    // /v1/responses when token limit exceeded
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

    assert_eq!(response.status_code(), 402);
    let body: serde_json::Value = response.json();
    let err_msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(err_msg.contains("Monthly token limit exceeded") && err_msg.contains("100"));
}

#[tokio::test]
#[serial(subscription_tests)]
async fn test_responses_returns_403_without_subscription_when_plans_configured() {
    ensure_stripe_env_for_gating();
    let (server, _) = create_test_server_and_db(TestServerConfig::default()).await;

    set_subscription_plans(
        &server,
        json!({
            "free": {
                "providers": {},
                "monthly_tokens": {"max": 0}
            },
            "basic": {
                "providers": {"stripe": {"price_id": "price_test_basic"}},
                "private_assistant_instances": {"max": 1},
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
        .authorization_bearer(&user_token)
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
