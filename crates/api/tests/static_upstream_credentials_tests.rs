mod common;

use http::{HeaderName, HeaderValue};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn llm_and_mcp_ignore_persisted_vpc_credentials_after_restart() {
    let (_, db) = common::create_test_server_and_db(Default::default()).await;
    let repository = db.app_config_repository();
    repository
        .set("vpc_organization_id", "legacy-organization")
        .await
        .unwrap();
    repository
        .set("vpc_api_key", "disabled-legacy-key")
        .await
        .unwrap();

    let upstream = MockServer::start().await;
    for route in ["/chat/completions", "/mcp"] {
        Mock::given(method("POST"))
            .and(path(route))
            .and(header("authorization", "Bearer configured-static-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": {}})))
            .expect(1)
            .mount(&upstream)
            .await;
    }

    // Rebuild API state against the same database with the old key already present.
    let (server, _) = common::create_test_server_and_db(common::TestServerConfig {
        cloud_api_api_key: Some("configured-static-key".into()),
        cloud_api_base_url: upstream.uri(),
        proxy_base_url: Some(upstream.uri()),
        ..Default::default()
    })
    .await;
    common::clear_subscription_plans(&server).await;

    let email = format!("static-upstream-{}@example.com", Uuid::new_v4());
    let token = common::mock_login(&server, &email).await;
    let authorization = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

    for (route, body) in [
        (
            "/v1/chat/completions",
            json!({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}]
            }),
        ),
        (
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ),
    ] {
        let response = server
            .post(route)
            .add_header(
                HeaderName::from_static("authorization"),
                authorization.clone(),
            )
            .json(&body)
            .await;

        assert_eq!(response.status_code(), 200, "{route}: {}", response.text());
    }

    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
    assert_eq!(
        repository.get("vpc_api_key").await.unwrap().as_deref(),
        Some("disabled-legacy-key")
    );
    assert_eq!(
        repository
            .get("vpc_organization_id")
            .await
            .unwrap()
            .as_deref(),
        Some("legacy-organization")
    );
}
