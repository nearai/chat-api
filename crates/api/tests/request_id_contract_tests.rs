mod common;

#[path = "request_id_contract/support.rs"]
mod support;

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use serde_json::json;
use support::{
    assert_uuid_header, bearer_header, create_request_id_test_server, header_value, REQUEST_ID,
};
use uuid::Uuid;

#[tokio::test]
async fn request_id_contract_reuses_valid_inbound_id_on_success_and_static_fallback() {
    let server = create_request_id_test_server().await;
    let inbound = Uuid::new_v4().to_string();

    let health_response = server
        .get("/health")
        .add_header(
            REQUEST_ID.clone(),
            HeaderValue::from_str(&inbound).expect("uuid header is valid"),
        )
        .await;
    assert_eq!(health_response.status_code(), 200);
    assert_eq!(header_value(&health_response, &REQUEST_ID), inbound);
    println!(
        "request_id_contract valid reuse status={} x-request-id={}",
        health_response.status_code(),
        inbound
    );

    let fallback_response = server
        .get("/definitely-not-a-real-static-file")
        .add_header(
            REQUEST_ID.clone(),
            HeaderValue::from_str(&inbound).expect("uuid header is valid"),
        )
        .await;
    let fallback_request_id = header_value(&fallback_response, &REQUEST_ID);
    assert_eq!(fallback_request_id, inbound);
    println!(
        "request_id_contract static fallback status={} x-request-id={}",
        fallback_response.status_code(),
        fallback_request_id
    );
}

#[tokio::test]
async fn request_id_contract_replaces_invalid_and_missing_ids_on_error_surfaces() {
    let server = create_request_id_test_server().await;

    let invalid_response = server
        .get("/health")
        .add_header(REQUEST_ID.clone(), HeaderValue::from_static("not-a-uuid"))
        .await;
    assert_eq!(invalid_response.status_code(), 200);
    let replacement_id = assert_uuid_header(&invalid_response);
    assert_ne!(replacement_id, "not-a-uuid");
    println!(
        "request_id_contract invalid replacement status={} x-request-id={}",
        invalid_response.status_code(),
        replacement_id
    );

    let auth_failure = server
        .post("/v1/chat/completions")
        .json(&json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": ""}]
        }))
        .await;
    assert_eq!(auth_failure.status_code(), 401);
    let auth_request_id = assert_uuid_header(&auth_failure);
    println!(
        "request_id_contract auth failure status={} x-request-id={}",
        auth_failure.status_code(),
        auth_request_id
    );
}

#[tokio::test]
async fn request_id_contract_replaces_invalid_id_on_json_extractor_failure() {
    let server = create_request_id_test_server().await;
    let email = format!("request-id-validation-{}@example.com", Uuid::new_v4());
    let token = common::mock_login(&server, &email).await;

    let response = server
        .post("/v1/users/me/settings")
        .add_header(
            HeaderName::from_static("authorization"),
            bearer_header(&token),
        )
        .add_header(
            REQUEST_ID.clone(),
            HeaderValue::from_static("invalid-public-id"),
        )
        .add_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        )
        .bytes(Bytes::from_static(b"{"))
        .await;

    assert_eq!(response.status_code(), 400);
    let replacement_id = assert_uuid_header(&response);
    assert_ne!(replacement_id, "invalid-public-id");
    println!(
        "request_id_contract validation/extractor failure status={} x-request-id={}",
        response.status_code(),
        replacement_id
    );
}

#[tokio::test]
async fn request_id_contract_allows_and_exposes_header_through_cors() {
    let server = create_request_id_test_server().await;

    let preflight = server
        .method(http::Method::OPTIONS, "/v1/chat/completions")
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("http://localhost:3000"),
        )
        .add_header(
            HeaderName::from_static("access-control-request-method"),
            HeaderValue::from_static("POST"),
        )
        .add_header(
            HeaderName::from_static("access-control-request-headers"),
            HeaderValue::from_static("authorization,content-type,x-request-id"),
        )
        .await;
    assert_eq!(preflight.status_code(), 200);
    assert_uuid_header(&preflight);
    assert_header_csv_contains(&preflight, "access-control-allow-headers", "x-request-id");
    println!(
        "request_id_contract CORS preflight status={} access-control-allow-headers={}",
        preflight.status_code(),
        header_value_by_name(&preflight, "access-control-allow-headers")
    );

    let actual = server
        .get("/health")
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("http://localhost:3000"),
        )
        .await;
    assert_eq!(actual.status_code(), 200);
    assert_uuid_header(&actual);
    assert_header_csv_contains(&actual, "access-control-expose-headers", "x-request-id");
    println!(
        "request_id_contract CORS actual status={} access-control-expose-headers={}",
        actual.status_code(),
        header_value_by_name(&actual, "access-control-expose-headers")
    );
}

fn assert_header_csv_contains(response: &axum_test::TestResponse, name: &str, expected: &str) {
    let header = header_value_by_name(response, name);
    assert!(
        header
            .split(',')
            .map(str::trim)
            .any(|part| part.eq_ignore_ascii_case(expected)),
        "{name} should include {expected}; actual value: {header}"
    );
}

fn header_value_by_name(response: &axum_test::TestResponse, name: &str) -> String {
    let header = response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("response should include expected header");
    header.to_string()
}
