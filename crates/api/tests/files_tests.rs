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
async fn retired_file_and_sharing_routes_return_the_migration_response() {
    let server = create_test_server().await;
    let token = mock_login(&server, "retired-files@example.com").await;
    let auth = bearer(&token);

    // Files and sharing routes remain session-auth only, even though they no
    // longer call their stateful services after authentication succeeds.
    assert_eq!(
        server.get("/v1/files").await.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .get("/v1/files/file_legacy/unknown-child")
            .await
            .status_code(),
        StatusCode::UNAUTHORIZED
    );

    for (method, path) in [
        // Every method that was previously supported by the session-auth API.
        (Method::POST, "/v1/files"),
        (Method::GET, "/v1/files"),
        (Method::GET, "/v1/files/file_legacy"),
        (Method::DELETE, "/v1/files/file_legacy"),
        (Method::GET, "/v1/files/file_legacy/content"),
        (Method::GET, "/v1/files/"),
        (Method::POST, "/v1/share-groups"),
        (Method::GET, "/v1/share-groups"),
        (Method::GET, "/v1/share-groups/"),
        (Method::PATCH, "/v1/share-groups/group_legacy"),
        (Method::DELETE, "/v1/share-groups/group_legacy"),
        (Method::GET, "/v1/shared-with-me"),
        // Exact known routes and unknown descendants also use the migration
        // response for methods that were never part of the old contract.
        (Method::PATCH, "/v1/files/file_legacy"),
        (Method::PATCH, "/v1/files/file_legacy/unknown-child"),
        (Method::PATCH, "/v1/share-groups/group_legacy/unknown-child"),
        (Method::POST, "/v1/shared-with-me"),
        (Method::GET, "/v1/shared-with-me/unknown-child"),
    ] {
        assert_retired(
            server
                .method(method, path)
                .add_header(auth.0.clone(), auth.1.clone())
                .await,
        );
    }
}
