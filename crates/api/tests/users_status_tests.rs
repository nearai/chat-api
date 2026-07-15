mod common;

use common::{create_test_server, mock_login};

fn auth_header(token: &str) -> (http::HeaderName, http::HeaderValue) {
    (
        http::HeaderName::from_static("authorization"),
        http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

#[tokio::test]
async fn test_user_status_requires_auth() {
    let server = create_test_server().await;

    let response = server.get("/v1/users/status").await;

    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn test_user_status_returns_minimal_ok_response() {
    let server = create_test_server().await;
    let token = mock_login(&server, "user-status-ok@example.com").await;
    let (name, value) = auth_header(&token);

    let response = server.get("/v1/users/status").add_header(name, value).await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}
