mod common;

use common::{
    clear_subscription_plans, create_test_server_with_state, mock_login, TestServerConfig,
};
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
#[serial_test::serial]
async fn model_visibility_preserves_long_ids_without_caching_them() {
    let upstream = MockServer::start().await;
    for endpoint in [
        "images/generations",
        "images/edits",
        "chat/completions",
        "responses",
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
            .expect(4)
            .mount(&upstream)
            .await;
    }
    let (server, _, state) = create_test_server_with_state(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", upstream.uri())),
        cloud_api_base_url: upstream.uri(),
        ..Default::default()
    })
    .await;
    clear_subscription_plans(&server).await;
    // The config update above restores production rate limits; this matrix tests visibility.
    state
        .rate_limit_state
        .update_config(services::system_configs::ports::RateLimitConfig {
            max_concurrent: 10,
            max_requests_per_window: 100,
            window_duration: chrono::Duration::seconds(1),
            window_limits: vec![],
            token_window_limits: vec![],
            cost_window_limits: vec![],
        })
        .await;
    let admin = mock_login(&server, "visibility-non-public-admin@admin.org").await;
    for (long, public) in [
        (false, Some(false)),
        (false, Some(true)),
        (false, None),
        (true, Some(false)),
        (true, Some(true)),
        (true, None),
    ] {
        let model = format!(
            "test-model-{}-{}",
            if long { "x".repeat(257) } else { String::new() },
            Uuid::new_v4()
        );
        let token = mock_login(
            &server,
            &format!("visibility-{}@example.com", Uuid::new_v4()),
        )
        .await;
        if let Some(public) = public {
            server
                .patch("/v1/admin/models")
                .add_header("authorization", format!("Bearer {admin}"))
                .json(&json!({model.clone(): {"public": public}}))
                .await
                .assert_status_ok();
        }
        for endpoint in [
            "images/generations",
            "images/edits",
            "chat/completions",
            "responses",
        ] {
            // Repeat hidden requests: short IDs use cached denial; long IDs must recheck the DB.
            for _ in 0..if public == Some(false) { 2 } else { 1 } {
                let request = server
                    .post(&format!("/v1/{endpoint}"))
                    .add_header("authorization", format!("Bearer {token}"));
                let response = if endpoint != "images/edits" {
                    let body = match endpoint {
                        "chat/completions" => {
                            json!({"model": model, "messages": [{"role": "user", "content": "test"}]})
                        }
                        "responses" => json!({"model": model, "input": "test"}),
                        _ => json!({"model": model, "prompt": "test image"}),
                    };
                    request.json(&body).await
                } else {
                    let boundary = "imageVisibilityBoundary";
                    let body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"input.png\"\r\nContent-Type: image/png\r\n\r\ntest-image\r\n--{boundary}--\r\n");
                    request
                        .add_header(
                            "content-type",
                            format!("multipart/form-data; boundary={boundary}"),
                        )
                        .bytes(bytes::Bytes::from(body))
                        .await
                };
                if public == Some(false) {
                    response.assert_status_forbidden();
                    assert_eq!(
                        response.json::<serde_json::Value>()["error"],
                        "This model is not available"
                    );
                } else {
                    response.assert_status_ok();
                }
            }
        }
        if long {
            assert!(!state.model_settings_cache.read().await.contains_key(&model));
        }
    }
    upstream.verify().await;
}
