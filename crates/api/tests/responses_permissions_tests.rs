mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn responses_rejects_conversation_state_locally() {
    let server = create_test_server().await;
    let token = mock_login(&server, "no-write@test.com").await;

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
