mod common;

use api::routes::api::STATEFUL_API_RETIRED_MESSAGE;
use axum_test::{TestResponse, TestServer};
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde_json::Value;
use services::user::ports::UserRepository;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bearer(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).expect("test token header"),
    )
}

fn assert_no_store(response: &TestResponse) {
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

fn assert_retired_mutation(response: TestResponse) {
    assert_eq!(response.status_code(), StatusCode::GONE);
    assert_no_store(&response);
    let body: Value = response.json();
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some(STATEFUL_API_RETIRED_MESSAGE)
    );
}

async fn stage_one_fixture() -> (TestServer, MockServer, String, String) {
    let upstream = MockServer::start().await;
    let file_id = format!("file_stage1_{}", Uuid::new_v4());
    Mock::given(method("GET"))
        .and(path(format!("/files/{file_id}/content")))
        .respond_with(ResponseTemplate::new(200).set_body_string("temporary file content"))
        .mount(&upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(upstream.uri()),
        ..Default::default()
    })
    .await;
    let email = format!("stage-one-files-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");
    db.pool()
        .get()
        .await
        .expect("db client")
        .execute(
            "INSERT INTO files (id, user_id, bytes, file_created_at, filename, purpose)
             VALUES ($1, $2, 25, 123, 'temporary-export.txt', 'assistants')",
            &[&file_id, &user.id],
        )
        .await
        .expect("insert file");

    (server, upstream, token, file_id)
}

#[tokio::test]
async fn stage_one_file_views_remain_readable() {
    let (server, _upstream, token, file_id) = stage_one_fixture().await;
    let auth = bearer(&token);

    let response = server
        .get("/v1/files")
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_no_store(&response);
    let list: Value = response.json();
    assert_eq!(list["data"][0]["id"], file_id);

    let response = server
        .get(&format!("/v1/files/{file_id}"))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_no_store(&response);
    let file: Value = response.json();
    assert_eq!(file["id"], file_id);

    let response = server
        .get(&format!("/v1/files/{file_id}/content"))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_no_store(&response);
    assert_eq!(response.text(), "temporary file content");

    let unauthenticated = server.get("/v1/files").await;
    assert_eq!(unauthenticated.status_code(), StatusCode::UNAUTHORIZED);
    assert_no_store(&unauthenticated);

    let unauthenticated_unknown = server
        .get(&format!("/v1/files/{file_id}/unknown-child"))
        .await;
    assert_eq!(
        unauthenticated_unknown.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_no_store(&unauthenticated_unknown);

    let unauthenticated_trailing_slash = server.get("/v1/files/").await;
    assert_eq!(
        unauthenticated_trailing_slash.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_no_store(&unauthenticated_trailing_slash);
}

#[tokio::test]
async fn stage_one_file_mutations_and_fallbacks_are_gone() {
    let (server, _upstream, token, file_id) = stage_one_fixture().await;
    let auth = bearer(&token);

    for (method, path) in [
        (Method::POST, "/v1/files".to_string()),
        (Method::DELETE, format!("/v1/files/{file_id}")),
        // Unsupported methods on retained views and unlisted descendants must
        // remain inside the authenticated migration namespace.
        (Method::PATCH, format!("/v1/files/{file_id}")),
        (Method::POST, format!("/v1/files/{file_id}/content")),
        (Method::GET, format!("/v1/files/{file_id}/unknown-child")),
        (Method::GET, "/v1/files/".to_string()),
    ] {
        assert_retired_mutation(
            server
                .method(method, &path)
                .add_header(auth.0.clone(), auth.1.clone())
                .await,
        );
    }
}
