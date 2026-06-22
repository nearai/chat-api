mod common;

use http::{HeaderName, HeaderValue};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const ORG_ID: HeaderName = HeaderName::from_static("x-org-id");
const WORKSPACE_ID: HeaderName = HeaderName::from_static("x-workspace-id");

fn bearer_header(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header is valid")
}

fn header_value<'a>(response: &'a axum_test::TestResponse, name: &HeaderName) -> &'a str {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("response should include requested header")
}

fn assert_uuid_header(response: &axum_test::TestResponse) -> String {
    let request_id = header_value(response, &REQUEST_ID);
    Uuid::parse_str(request_id).expect("x-request-id should be UUID shaped");
    request_id.to_string()
}

async fn authenticated_proxy_fixture() -> (axum_test::TestServer, database::Database, MockServer) {
    authenticated_proxy_fixture_with_response(ResponseTemplate::new(200).set_body_json(json!({
        "id": "chatcmpl-request-id-test",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-test",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": ""},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })))
    .await
}

async fn authenticated_proxy_fixture_with_response(
    response: ResponseTemplate,
) -> (axum_test::TestServer, database::Database, MockServer) {
    std::env::set_var("AGENT_API_TOKEN", "request-id-contract-test-token");

    let mock_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(response)
        .mount(&mock_upstream)
        .await;

    let (server, db) = common::create_test_server_and_db(common::TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        ..Default::default()
    })
    .await;

    common::set_subscription_plans(
        &server,
        json!({
            "basic": {
                "providers": { "stripe": { "price_id": "price_test_basic" } },
                "monthly_credits": { "max": 1_000_000_000 }
            }
        }),
    )
    .await;

    (server, db, mock_upstream)
}

#[tokio::test]
async fn request_id_contract_baseline_keeps_client_auth_and_host_out_of_upstream_proxy() {
    let (server, db, mock_upstream) = authenticated_proxy_fixture().await;
    let email = format!("request-id-baseline-{}@example.com", Uuid::new_v4());
    let token = common::mock_login(&server, &email).await;
    common::insert_test_subscription(&server, &db, &email, false).await;

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            HeaderName::from_static("authorization"),
            bearer_header(&token),
        )
        .add_header(
            HeaderName::from_static("host"),
            HeaderValue::from_static("spoofed.example"),
        )
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": ""}]
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    let received = mock_upstream
        .received_requests()
        .await
        .expect("mock upstream should record requests");
    assert_eq!(received.len(), 1);
    let forwarded_headers = &received[0].headers;

    assert_eq!(
        forwarded_headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer mock-api-key")
    );
    assert_ne!(
        forwarded_headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some("spoofed.example")
    );
}

#[tokio::test]
async fn request_id_contract_inserts_selected_uuid_and_strips_public_tenant_headers_for_proxy() {
    let (server, db, mock_upstream) = authenticated_proxy_fixture().await;
    let email = format!("request-id-proxy-{}@example.com", Uuid::new_v4());
    let token = common::mock_login(&server, &email).await;
    common::insert_test_subscription(&server, &db, &email, false).await;

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            HeaderName::from_static("authorization"),
            bearer_header(&token),
        )
        .add_header(
            REQUEST_ID.clone(),
            HeaderValue::from_static("invalid-public-id"),
        )
        .add_header(ORG_ID.clone(), HeaderValue::from_static("spoofed-org"))
        .add_header(
            WORKSPACE_ID.clone(),
            HeaderValue::from_static("spoofed-workspace"),
        )
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": ""}]
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let selected_request_id = assert_uuid_header(&response);
    assert_ne!(selected_request_id, "invalid-public-id");

    let received = mock_upstream
        .received_requests()
        .await
        .expect("mock upstream should record requests");
    assert_eq!(received.len(), 1);
    let forwarded_headers = &received[0].headers;
    assert_eq!(
        forwarded_headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(selected_request_id.as_str())
    );
    assert!(forwarded_headers.get("x-org-id").is_none());
    assert!(forwarded_headers.get("x-workspace-id").is_none());
    println!(
        "request_id_contract proxy status={} x-request-id={} tenant_headers_absent=true",
        response.status_code(),
        selected_request_id
    );
}

#[tokio::test]
async fn request_id_contract_preserves_valid_uuid_for_proxy_and_streaming_response() {
    let inbound = Uuid::new_v4().to_string();
    let stream_response = ResponseTemplate::new(200)
        .append_header("content-type", "text/event-stream")
        .set_body_string("data: [DONE]\n\n");
    let (server, db, mock_upstream) =
        authenticated_proxy_fixture_with_response(stream_response).await;
    let email = format!("request-id-stream-{}@example.com", Uuid::new_v4());
    let token = common::mock_login(&server, &email).await;
    common::insert_test_subscription(&server, &db, &email, false).await;

    let response = server
        .post("/v1/chat/completions")
        .add_header(
            HeaderName::from_static("authorization"),
            bearer_header(&token),
        )
        .add_header(
            REQUEST_ID.clone(),
            HeaderValue::from_str(&inbound).expect("uuid header is valid"),
        )
        .json(&json!({
            "model": "gpt-test",
            "stream": true,
            "messages": [{"role": "user", "content": ""}]
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    assert_eq!(header_value(&response, &REQUEST_ID), inbound);

    let received = mock_upstream
        .received_requests()
        .await
        .expect("mock upstream should record requests");
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0]
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(inbound.as_str())
    );
    println!(
        "request_id_contract streaming headers observed before body chunks status={} x-request-id={} forwarded=true",
        response.status_code(),
        inbound
    );
    let body = response.text();
    assert!(
        body.contains("[DONE]"),
        "stream body should remain readable after header assertion"
    );
}
