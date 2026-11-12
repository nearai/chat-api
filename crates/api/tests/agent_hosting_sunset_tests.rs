mod common;

use api::create_router_with_cors;
use axum_test::TestServer;
use common::{create_test_server_with_state, mock_login, set_subscription_plans, TestServerConfig};
use http::{header::AUTHORIZATION, HeaderValue};
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn sunset_blocks_new_activity_and_preserves_existing_account_access() {
    let (server, _, mut state) = create_test_server_with_state(TestServerConfig::default()).await;
    set_subscription_plans(
        &server,
        json!({
            "starter": {
                "providers": { "stripe": { "price_id": "price_sunset_test" } },
                "agent_instances": { "max": 1 },
                "monthly_credits": { "max": 1000000 }
            }
        }),
    )
    .await;
    let token = mock_login(&server, &format!("sunset-{}@test.org", Uuid::new_v4())).await;
    let auth = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

    let checkout = json!({
        "provider": "stripe",
        "plan": "starter",
        "credits": 10,
        "success_url": "https://example.com/success",
        "cancel_url": "https://example.com/cancel"
    });
    let mut near_checkout = checkout.clone();
    near_checkout["provider"] = json!("house-of-stake");
    let blocked_requests = [
        ("/v1/agents/instances", json!({"service_type": "ironclaw"})),
        ("/v1/subscriptions", checkout.clone()),
        ("/v1/credits", checkout.clone()),
        ("/v1/subscriptions", near_checkout.clone()),
        ("/v1/credits", near_checkout),
    ];

    let mut schedule = json!({
        "cutoff_at": "2098-01-01T00:00:00Z",
        "export_deadline_at": "2099-01-01T00:00:00Z",
        "shutdown_at": "2099-01-02T00:00:00Z",
        "export_url": "https://example.com/export",
        "support_url": "https://example.com/support",
        "close_signups": true
    });
    state.agent_hosting_sunset = Some(serde_json::from_value(schedule.clone()).unwrap());
    let before_cutoff =
        TestServer::new(create_router_with_cors(state.clone(), Default::default())).unwrap();
    // No agent is provisioned: validation still runs before the cutoff.
    let invalid_instance = before_cutoff
        .post("/v1/agents/instances")
        .add_header(AUTHORIZATION, auth.clone())
        .json(&json!({"service_type": "invalid"}))
        .await;
    invalid_instance.assert_status_bad_request();

    schedule["cutoff_at"] = json!("2000-01-01T00:00:00Z");
    state.agent_hosting_sunset = Some(serde_json::from_value(schedule.clone()).unwrap());
    let after_cutoff = TestServer::new(create_router_with_cors(state, Default::default())).unwrap();
    let notice = after_cutoff.get("/v1/agent-hosting/sunset").await;
    notice.assert_status_ok();
    assert_eq!(notice.json::<Value>()["schedule"], schedule);

    for (path, body) in blocked_requests {
        let response = after_cutoff
            .post(path)
            .add_header(AUTHORIZATION, auth.clone())
            .json(&body)
            .await;
        response.assert_status_forbidden();
        assert_eq!(response.json::<Value>()["code"], "agent_hosting_closed");
    }

    for path in ["/v1/users/me", "/v1/agents/instances", "/v1/subscriptions"] {
        after_cutoff
            .get(path)
            .add_header(AUTHORIZATION, auth.clone())
            .await
            .assert_status_ok();
    }

    let deletion = after_cutoff
        .delete("/v1/users/me")
        .add_header(AUTHORIZATION, auth)
        .await;
    assert_eq!(deletion.status_code(), 202);
    assert_eq!(deletion.json::<Value>()["status"], "pending");
}
