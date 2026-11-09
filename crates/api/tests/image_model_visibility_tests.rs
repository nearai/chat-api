mod common;

use common::{clear_subscription_plans, create_test_server_and_db, mock_login, TestServerConfig};
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
#[serial_test::serial]
async fn image_routes_reject_hidden_models_before_forwarding_and_preserve_public_defaults() {
    let upstream = MockServer::start().await;
    for endpoint in ["generations", "edits"] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/images/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
            .expect(2)
            .mount(&upstream)
            .await;
    }
    let (server, _) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", upstream.uri())),
        cloud_api_base_url: upstream.uri(),
        ..Default::default()
    })
    .await;
    clear_subscription_plans(&server).await;
    let admin = mock_login(&server, "visibility-non-public-admin@admin.org").await;
    for public in [Some(false), Some(true), None] {
        let model = format!("test-image-{}", Uuid::new_v4());
        let token = mock_login(&server, &format!("{model}@example.com")).await;
        if let Some(public) = public {
            server
                .patch("/v1/admin/models")
                .add_header("authorization", format!("Bearer {admin}"))
                .json(&json!({model.clone(): {"public": public}}))
                .await
                .assert_status_ok();
        }
        for endpoint in ["generations", "edits"] {
            // Repeat hidden requests to cover both service lookup and cached denial.
            for _ in 0..if public == Some(false) { 2 } else { 1 } {
                let request = server
                    .post(&format!("/v1/images/{endpoint}"))
                    .add_header("authorization", format!("Bearer {token}"));
                let response = if endpoint == "generations" {
                    request
                        .json(&json!({"model": model, "prompt": "test image"}))
                        .await
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
    }
}
