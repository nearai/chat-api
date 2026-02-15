mod common;

use common::{create_test_server, mock_login};
use serde_json::json;

#[tokio::test]
async fn responses_requires_write_access_when_conversation_is_provided() {
    let server = create_test_server().await;
    let token = mock_login(&server, "no-write@test.com").await;

    // Use a conversation id the user does not own and is not shared with.
    // The handler should reject with 403 BEFORE attempting any OpenAI call.
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
        403,
        "Should require write access for existing conversations"
    );
}
