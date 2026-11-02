mod common;

use bytes::Bytes;
use common::{
    create_test_server_and_db, insert_test_subscription, mock_login, set_subscription_plans,
    TestServerConfig,
};
use flate2::{write::GzEncoder, Compression};
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;
use std::io::Write;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bearer(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header"),
    )
}

fn gzip_json(value: &serde_json::Value) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serde_json::to_vec(value).expect("test JSON should serialize"))
        .expect("gzip test body should be writable");
    encoder.finish().expect("gzip test body should finish")
}

fn assert_stateless_bad_request(response: axum_test::TestResponse, expected_error: &str) {
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
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
        Some(expected_error)
    );
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
        .add_header(http::header::CONTENT_ENCODING, "identity")
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

#[tokio::test]
async fn responses_forwards_client_managed_function_replay() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "resp_function_replay",
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

    let email = format!("stateless-function-replay-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    insert_test_subscription(&server, &db, &email, false).await;

    let request = json!({
        "model": "gpt-test",
        "input": [
            { "role": "user", "content": "What is the weather in Shanghai?" },
            {
                "type": "function_call",
                "call_id": "call_weather",
                "name": "get_weather",
                "arguments": "{\"location\":\"Shanghai\"}"
            },
            {
                "type": "function_call_output",
                "call_id": "call_weather",
                "output": "{\"temperature_c\":22}"
            }
        ],
        "tools": [{
            "type": "function",
            "name": "get_weather",
            "parameters": {
                "type": "object",
                "properties": { "location": { "type": "string" } },
                "required": ["location"]
            }
        }]
    });

    let auth = bearer(&token);
    let response = server
        .post("/v1/responses")
        .add_header(auth.0, auth.1)
        .json(&request)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
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
    assert_eq!(forwarded.get("tools"), request.get("tools"));
    assert_eq!(forwarded.get("input"), request.get("input"));
}

#[tokio::test]
async fn responses_forwards_builtin_tool_shapes_to_cloud_for_validation() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/responses"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({ "error": "unsupported tool from Cloud API" })),
        )
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

    let email = format!("stateless-builtin-forward-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    insert_test_subscription(&server, &db, &email, false).await;

    let request = json!({
        "model": "gpt-test",
        "input": "hello",
        "tools": [{ "type": "code_interpreter" }]
    });

    let auth = bearer(&token);
    let response = server
        .post("/v1/responses")
        .add_header(auth.0, auth.1)
        .json(&request)
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({ "error": "unsupported tool from Cloud API" })
    );

    let requests = mock_upstream
        .received_requests()
        .await
        .expect("mock upstream should record the request");
    assert_eq!(requests.len(), 1);
    let forwarded: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("forwarded body should be JSON");
    assert_eq!(forwarded.get("tools"), request.get("tools"));
    assert_eq!(forwarded.get("store"), Some(&json!(false)));
}

#[tokio::test]
async fn responses_rejects_encoded_or_non_object_bodies_without_forwarding() {
    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/responses"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
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

    let email = format!("stateless-invalid-body-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    insert_test_subscription(&server, &db, &email, false).await;
    let auth = bearer(&token);

    let gzip_body = gzip_json(&json!({
        "model": "gpt-test",
        "store": true,
        "conversation": "conv_legacy"
    }));
    assert_stateless_bad_request(
        server
            .post("/v1/responses")
            .add_header(auth.0.clone(), auth.1.clone())
            .add_header(http::header::CONTENT_ENCODING, "gzip")
            .content_type("application/json")
            .bytes(Bytes::from(gzip_body))
            .await,
        "The stateless Responses API requires an uncompressed JSON object body.",
    );

    assert_stateless_bad_request(
        server
            .post("/v1/responses")
            .add_header(auth.0.clone(), auth.1.clone())
            .content_type("application/json")
            .bytes(Bytes::from_static(b"{\"model\":"))
            .await,
        "The stateless Responses API requires an uncompressed JSON object body.",
    );

    assert_stateless_bad_request(
        server
            .post("/v1/responses")
            .add_header(auth.0, auth.1)
            .json(&json!(["not", "an", "object"]))
            .await,
        "The stateless Responses API requires a JSON object body.",
    );

    assert!(
        mock_upstream
            .received_requests()
            .await
            .expect("mock upstream should record requests")
            .is_empty(),
        "invalid stateless requests must not reach Cloud API"
    );
}
