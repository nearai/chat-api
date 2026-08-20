mod common;

use common::{
    create_test_server_and_db, insert_test_subscription, mock_login, set_subscription_plans,
    TestServerConfig,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn responses_rejects_conversation_state_locally() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "monthly_credits": { "max": 1_000_000_000 }
            }
        }),
    )
    .await;
    let email = format!("stateless-permissions-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    insert_test_subscription(&server, &db, &email, false).await;

    // The stateless proxy must reject a conversation reference before it can
    // invoke Cloud API or the legacy conversation-access service.
    let request_body = json!({
        "conversation": "conv_no_write_access",
        "model": "gpt-4o",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": "hello"
            }
        ]
    });

    let response = server
        .post("/v1/responses")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&request_body)
        .await;

    assert_eq!(
        response.status_code(),
        400,
        "Stateful conversation requests must fail locally"
    );
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some("The stateless Responses API does not support conversation.")
    );
}
