mod common;

use common::{create_test_server_with_state, mock_login, set_subscription_plans, TestServerConfig};
use http::{header::AUTHORIZATION, HeaderValue};
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[serial_test::serial(subscription_tests)]
async fn blocks_new_subscriptions_and_preserves_existing_account_access() {
    let (server, _, _) = create_test_server_with_state(TestServerConfig::default()).await;
    set_subscription_plans(
        &server,
        json!({
            "starter": {
                "providers": { "stripe": { "price_id": "price_restrictions_test" } },
                "agent_instances": { "max": 1 },
                "monthly_credits": { "max": 1000000 }
            }
        }),
    )
    .await;
    let token = mock_login(
        &server,
        &format!("registration-{}@test.org", Uuid::new_v4()),
    )
    .await;
    let auth = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

    let checkout = json!({
        "provider": "stripe",
        "plan": "starter",
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel"
    });
    let mut near_checkout = checkout.clone();
    near_checkout["provider"] = json!("house-of-stake");
    let blocked_requests = [
        ("/v1/subscriptions", checkout.clone()),
        ("/v1/subscriptions", near_checkout),
    ];

    for (path, body) in blocked_requests {
        let response = server
            .post(path)
            .add_header(AUTHORIZATION, auth.clone())
            .json(&body)
            .await;
        response.assert_status_forbidden();
        assert_eq!(
            response.json::<Value>()["code"],
            "service_subscriptions_closed"
        );
    }

    for path in ["/v1/users/me", "/v1/agents/instances", "/v1/subscriptions"] {
        server
            .get(path)
            .add_header(AUTHORIZATION, auth.clone())
            .await
            .assert_status_ok();
    }

    let deletion = server
        .delete("/v1/users/me")
        .add_header(AUTHORIZATION, auth)
        .await;
    assert_eq!(deletion.status_code(), 202);
    assert_eq!(deletion.json::<Value>()["status"], "pending");
}

#[tokio::test]
#[serial_test::serial(subscription_tests)]
async fn existing_subscribers_can_create_agents_before_their_subscription_ends() {
    use common::insert_test_subscription_with_provider_and_price;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    for (provider, streaming) in [("stripe", false), ("house-of-stake", true)] {
        let manager = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"session_token": "test-session"})),
            )
            .mount(&manager)
            .await;
        Mock::given(method("POST"))
            .and(path("/instances"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(
                        "data: {\"name\":\"existing-subscriber-agent\"}\n\ndata: [DONE]\n\n",
                    ),
            )
            .expect(1)
            .mount(&manager)
            .await;
        Mock::given(method("GET"))
            .and(path("/instances/existing-subscriber-agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "existing-subscriber-agent", "status": "running"
            })))
            .mount(&manager)
            .await;
        let (server, db, _) = create_test_server_with_state(TestServerConfig {
            agent_managers: Some(vec![config::AgentManager {
                url: manager.uri(),
                token: "test-manager".into(),
            }]),
            ..Default::default()
        })
        .await;
        set_subscription_plans(
            &server,
            json!({
                "starter": {
                    "providers": {
                        "stripe": { "price_id": "price_existing" },
                        "house-of-stake": { "price_id": "price_existing" }
                    },
                    "agent_instances": { "max": 1 },
                    "monthly_credits": { "max": 1000000 }
                }
            }),
        )
        .await;
        let email = format!("existing-subscriber-{}@test.org", Uuid::new_v4());
        let token = mock_login(&server, &email).await;
        // Cancellation at period end must not remove an existing subscriber's rights early.
        insert_test_subscription_with_provider_and_price(
            &server,
            &db,
            &email,
            provider,
            "price_existing",
            true,
        )
        .await;
        let auth = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
        let response = server.post("/v1/agents/instances")
            .add_header(AUTHORIZATION, auth.clone())
            .add_header(http::header::ACCEPT, HeaderValue::from_static(if streaming { "text/event-stream" } else { "application/json" }))
            .json(&json!({"name": "existing-subscriber-agent", "image": "test-agent:local", "service_type": "ironclaw"}))
            .await;
        assert!(
            response.status_code().is_success(),
            "{provider}: {}",
            response.text()
        );
        let instances = server
            .get("/v1/agents/instances")
            .add_header(AUTHORIZATION, auth)
            .await;
        instances.assert_status_ok();
        assert_eq!(
            instances.json::<Value>()["items"][0]["name"],
            "existing-subscriber-agent"
        );
        manager.verify().await;
    }
}
