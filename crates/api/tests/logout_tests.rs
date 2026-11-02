mod common;

use common::{create_test_server, mock_login};
use serde_json::json;
use uuid::Uuid;

fn auth_header(token: &str) -> (http::HeaderName, http::HeaderValue) {
    (
        http::HeaderName::from_static("authorization"),
        http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

fn configure_test_environment() {
    std::env::set_var("AGENT_API_TOKEN", "logout-integration-test-token");
}

#[tokio::test]
async fn logout_without_session_id_revokes_the_authenticated_session() {
    configure_test_environment();
    let server = create_test_server().await;
    let token = mock_login(&server, "logout-token-only@example.com").await;
    let (name, value) = auth_header(&token);

    let logout = server.post("/v1/auth/logout").add_header(name, value).await;

    assert_eq!(logout.status_code(), 204);

    let (name, value) = auth_header(&token);
    let after_logout = server.get("/v1/users/status").add_header(name, value).await;
    assert_eq!(after_logout.status_code(), 401);
}

#[tokio::test]
async fn logout_ignores_legacy_session_id_and_preserves_other_sessions() {
    configure_test_environment();
    let server = create_test_server().await;
    let email = "logout-multi-session@example.com";
    let current_token = mock_login(&server, email).await;
    let other_token = mock_login(&server, email).await;
    let (name, value) = auth_header(&current_token);

    let logout = server
        .post("/v1/auth/logout")
        .add_header(name, value)
        .json(&json!({ "session_id": Uuid::new_v4().to_string() }))
        .await;

    assert_eq!(logout.status_code(), 204);

    let (name, value) = auth_header(&current_token);
    let current_after_logout = server.get("/v1/users/status").add_header(name, value).await;
    assert_eq!(current_after_logout.status_code(), 401);

    let (name, value) = auth_header(&other_token);
    let other_after_logout = server.get("/v1/users/status").add_header(name, value).await;
    assert_eq!(other_after_logout.status_code(), 200);
}

#[tokio::test]
async fn logout_requires_a_valid_bearer_token() {
    configure_test_environment();
    let server = create_test_server().await;

    let without_token = server.post("/v1/auth/logout").await;
    assert_eq!(without_token.status_code(), 401);

    let invalid_token = server
        .post("/v1/auth/logout")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_static("Bearer sess_invalid"),
        )
        .await;
    assert_eq!(invalid_token.status_code(), 401);
}
