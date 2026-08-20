mod common;

use api::routes::api::STATEFUL_API_RETIRED_MESSAGE;
use axum_test::TestResponse;
use common::{create_test_server, mock_login};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde_json::Value;

fn bearer(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header"),
    )
}

fn assert_retired(response: TestResponse) {
    assert_eq!(response.status_code(), StatusCode::GONE);
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body: Value = response.json();
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some(STATEFUL_API_RETIRED_MESSAGE)
    );
}

#[tokio::test]
async fn retired_conversation_routes_return_the_migration_response() {
    let server = create_test_server().await;
    let token = mock_login(&server, "retired-conversations@example.com").await;

    // Publicly shared conversation reads remain optional-auth, but never expose
    // the legacy resource now that the API is retired.
    assert_retired(server.get("/v1/conversations/conv_legacy").await);
    assert_retired(server.get("/v1/conversations/conv_legacy/items").await);

    // Unknown descendants remain protected by the original session boundary.
    assert_eq!(
        server
            .get("/v1/conversations/conv_legacy/unknown-child")
            .await
            .status_code(),
        StatusCode::UNAUTHORIZED
    );

    // Mutating conversation routes retain the old session-auth boundary.
    assert_eq!(
        server.post("/v1/conversations").await.status_code(),
        StatusCode::UNAUTHORIZED
    );

    let auth = bearer(&token);
    for (method, path) in [
        // Every method that was previously supported by the session-auth API.
        (Method::POST, "/v1/conversations"),
        (Method::GET, "/v1/conversations"),
        (Method::POST, "/v1/conversations/conv_legacy"),
        (Method::DELETE, "/v1/conversations/conv_legacy"),
        (Method::POST, "/v1/conversations/conv_legacy/items"),
        (Method::POST, "/v1/conversations/conv_legacy/shares"),
        (Method::GET, "/v1/conversations/conv_legacy/shares"),
        (
            Method::DELETE,
            "/v1/conversations/conv_legacy/shares/share_legacy",
        ),
        (Method::POST, "/v1/conversations/conv_legacy/pin"),
        (Method::DELETE, "/v1/conversations/conv_legacy/pin"),
        (Method::POST, "/v1/conversations/conv_legacy/archive"),
        (Method::DELETE, "/v1/conversations/conv_legacy/archive"),
        (Method::POST, "/v1/conversations/conv_legacy/clone"),
        (Method::GET, "/v1/conversations/"),
        // Exact known routes and unknown descendants also use the migration
        // response for methods that were never part of the old contract.
        (Method::PATCH, "/v1/conversations/conv_legacy"),
        (Method::PATCH, "/v1/conversations/conv_legacy/unknown-child"),
    ] {
        assert_retired(
            server
                .method(method, path)
                .add_header(auth.0.clone(), auth.1.clone())
                .await,
        );
    }
}
