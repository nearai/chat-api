mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bearer(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header"),
    )
}

async fn signature_fixture(chat_id: &str) -> (axum_test::TestServer, MockServer, String) {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/signature/{chat_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "request_hash:response_hash",
            "signature": "0xsignature",
            "signing_address": "0xaddress",
            "signing_algo": "ed25519"
        })))
        .mount(&upstream)
        .await;

    let (server, _db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(upstream.uri()),
        ..Default::default()
    })
    .await;
    let email = format!("signature-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    (server, upstream, token)
}

/// Query pairs of every upstream signature request, in order.
async fn upstream_signature_queries(upstream: &MockServer) -> Vec<Vec<(String, String)>> {
    upstream
        .received_requests()
        .await
        .expect("mock upstream should record requests")
        .into_iter()
        .filter(|request| request.url.path().starts_with("/signature/"))
        .map(|request| {
            request
                .url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn signature_forwards_model_and_signing_algo_to_cloud_api() {
    let chat_id = format!("chatcmpl-{}", Uuid::new_v4());
    let (server, upstream, token) = signature_fixture(&chat_id).await;
    let auth = bearer(&token);

    let response = server
        .get(&format!(
            "/v1/signature/{chat_id}?model=zai-org%2FGLM-5-FP8&signing_algo=ed25519&unknown=1"
        ))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["signing_algo"], "ed25519");

    // Without parameters the upstream path stays bare.
    let response = server
        .get(&format!("/v1/signature/{chat_id}"))
        .add_header(auth.0, auth.1)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    assert_eq!(
        upstream_signature_queries(&upstream).await,
        vec![
            vec![
                ("model".to_string(), "zai-org/GLM-5-FP8".to_string()),
                ("signing_algo".to_string(), "ed25519".to_string()),
            ],
            vec![],
        ]
    );
}

#[tokio::test]
async fn signature_rejects_unknown_signing_algo() {
    let chat_id = format!("chatcmpl-{}", Uuid::new_v4());
    let (server, upstream, token) = signature_fixture(&chat_id).await;
    let auth = bearer(&token);

    let response = server
        .get(&format!("/v1/signature/{chat_id}?signing_algo=rsa"))
        .add_header(auth.0, auth.1)
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("Invalid signing_algo parameter. Must be 'ecdsa' or 'ed25519'")
    );

    assert!(
        upstream_signature_queries(&upstream).await.is_empty(),
        "invalid queries must not reach Cloud API"
    );
}
