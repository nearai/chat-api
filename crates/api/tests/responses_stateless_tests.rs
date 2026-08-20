mod common;

use common::{
    create_test_server_and_db, insert_test_subscription, mock_login, set_subscription_plans,
    TestServerConfig,
};
use http::{HeaderName, HeaderValue};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bearer(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header"),
    )
}

#[tokio::test]
async fn responses_forwards_store_false_without_author_metadata() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "resp_stateless_test",
            "object": "response",
            "model": "gpt-test",
            "output": [],
            "usage": {
                "input_tokens": 1,
                "output_tokens": 1,
                "total_tokens": 2
            }
        })))
        .expect(1)
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        ..Default::default()
    })
    .await;

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

    let email = format!("stateless-responses-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    insert_test_subscription(&server, &db, &email, false).await;

    let auth = bearer(&token);
    let response = server
        .post("/v1/responses")
        .add_header(auth.0, auth.1)
        .json(&json!({
            "model": "gpt-test",
            "metadata": { "client_key": "client_value" },
            "input": "hello"
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let requests = mock_upstream
        .received_requests()
        .await
        .expect("mock upstream should record the request");
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("forwarded body should be JSON");

    assert_eq!(forwarded.get("store"), Some(&json!(false)));
    assert_eq!(
        forwarded.get("metadata"),
        Some(&json!({ "client_key": "client_value" }))
    );
    assert!(
        forwarded
            .get("metadata")
            .and_then(|metadata| metadata.get("author_id"))
            .is_none(),
        "Chat API must not inject stateful author metadata"
    );
    assert!(
        forwarded
            .get("metadata")
            .and_then(|metadata| metadata.get("author_name"))
            .is_none(),
        "Chat API must not inject stateful author metadata"
    );
}
