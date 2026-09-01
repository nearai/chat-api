mod common;

use api::routes::api::STATEFUL_API_RETIRED_MESSAGE;
use axum_test::{TestResponse, TestServer};
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};
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
    let conversation_id = format!("conv_stage1_{}", Uuid::new_v4());

    Mock::given(method("POST"))
        .and(path("/conversations/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": conversation_id.clone(), "object": "conversation"}],
            "missing_ids": []
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/conversations/{conversation_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": conversation_id.clone(),
            "object": "conversation",
            "metadata": {"title": "temporary export view"}
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/conversations/{conversation_id}/items")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [],
            "first_id": null,
            "last_id": null,
            "has_more": false
        })))
        .mount(&upstream)
        .await;
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(upstream.uri()),
        ..Default::default()
    })
    .await;
    let email = format!("stage-one-views-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");
    let client = db.pool().get().await.expect("db client");

    client
        .execute(
            "INSERT INTO conversations (id, user_id) VALUES ($1, $2)",
            &[&conversation_id, &user.id],
        )
        .await
        .expect("insert conversation");
    (server, upstream, token, conversation_id)
}

#[tokio::test]
async fn stage_one_owner_conversation_views_remain_readable() {
    let (server, _upstream, token, conversation_id) = stage_one_fixture().await;
    let auth = bearer(&token);

    let response = server
        .get("/v1/conversations")
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_no_store(&response);
    let conversations: Vec<Value> = response.json();
    assert_eq!(conversations[0]["id"], conversation_id);

    for path in [
        format!("/v1/conversations/{conversation_id}"),
        format!("/v1/conversations/{conversation_id}/items"),
    ] {
        let response = server
            .get(&path)
            .add_header(auth.0.clone(), auth.1.clone())
            .await;
        assert_eq!(response.status_code(), StatusCode::OK, "GET {path}");
        assert_no_store(&response);
    }

    let unauthenticated = server
        .get(&format!("/v1/conversations/{conversation_id}"))
        .await;
    assert_eq!(unauthenticated.status_code(), StatusCode::UNAUTHORIZED);
    assert_no_store(&unauthenticated);
}

#[tokio::test]
async fn conversation_detail_and_items_are_owner_only() {
    let (server, _upstream, _owner_token, conversation_id) = stage_one_fixture().await;
    let other_email = format!("stage-one-non-owner-{}@example.com", Uuid::new_v4());
    let other_token = mock_login(&server, &other_email).await;
    let auth = bearer(&other_token);

    for path in [
        format!("/v1/conversations/{conversation_id}"),
        format!("/v1/conversations/{conversation_id}/items"),
    ] {
        let response = server
            .get(&path)
            .add_header(auth.0.clone(), auth.1.clone())
            .await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND, "GET {path}");
        assert_no_store(&response);
    }
}

#[tokio::test]
async fn anonymous_conversation_reads_require_session_auth() {
    let (server, _upstream, _token, conversation_id) = stage_one_fixture().await;

    for path in [
        format!("/v1/conversations/{conversation_id}"),
        format!("/v1/conversations/{conversation_id}/items"),
        format!("/v1/conversations/{conversation_id}/unknown-child"),
        format!("/v1/conversations/{conversation_id}/shares"),
        "/v1/conversations/".to_string(),
        "/v1/share-groups".to_string(),
        "/v1/shared-with-me".to_string(),
    ] {
        let response = server.get(&path).await;
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "GET {path}"
        );
        assert_no_store(&response);
    }
}

#[tokio::test]
async fn stage_one_stateful_conversation_and_sharing_surfaces_are_gone() {
    let (server, _upstream, token, conversation_id) = stage_one_fixture().await;
    let auth = bearer(&token);

    for (method, path) in [
        (Method::POST, "/v1/conversations".to_string()),
        (Method::POST, format!("/v1/conversations/{conversation_id}")),
        (
            Method::DELETE,
            format!("/v1/conversations/{conversation_id}"),
        ),
        (
            Method::POST,
            format!("/v1/conversations/{conversation_id}/items"),
        ),
        (
            Method::POST,
            format!("/v1/conversations/{conversation_id}/shares"),
        ),
        (
            Method::GET,
            format!("/v1/conversations/{conversation_id}/shares"),
        ),
        (
            Method::DELETE,
            format!(
                "/v1/conversations/{conversation_id}/shares/{}",
                Uuid::new_v4()
            ),
        ),
        (
            Method::POST,
            format!("/v1/conversations/{conversation_id}/pin"),
        ),
        (
            Method::DELETE,
            format!("/v1/conversations/{conversation_id}/pin"),
        ),
        (
            Method::POST,
            format!("/v1/conversations/{conversation_id}/archive"),
        ),
        (
            Method::DELETE,
            format!("/v1/conversations/{conversation_id}/archive"),
        ),
        (
            Method::POST,
            format!("/v1/conversations/{conversation_id}/clone"),
        ),
        (Method::POST, "/v1/share-groups".to_string()),
        (Method::GET, "/v1/share-groups".to_string()),
        (
            Method::PATCH,
            format!("/v1/share-groups/{}", Uuid::new_v4()),
        ),
        (
            Method::DELETE,
            format!("/v1/share-groups/{}", Uuid::new_v4()),
        ),
        // Unsupported methods on a retained read view and unlisted legacy
        // descendants remain within the authenticated migration namespace.
        (
            Method::PATCH,
            format!("/v1/conversations/{conversation_id}"),
        ),
        (
            Method::GET,
            format!("/v1/conversations/{conversation_id}/unknown-child"),
        ),
        (
            Method::GET,
            format!(
                "/v1/conversations/{conversation_id}/shares/{}",
                Uuid::new_v4()
            ),
        ),
        (
            Method::GET,
            format!("/v1/share-groups/{}/unknown-child", Uuid::new_v4()),
        ),
        (Method::POST, "/v1/shared-with-me".to_string()),
        (Method::GET, "/v1/shared-with-me".to_string()),
        (Method::GET, "/v1/shared-with-me/unknown-child".to_string()),
        // Axum nesting does not cover the trailing-slash prefix, so those
        // exact legacy namespace paths are explicitly reserved too.
        (Method::GET, "/v1/conversations/".to_string()),
        (Method::GET, "/v1/share-groups/".to_string()),
        (Method::GET, "/v1/shared-with-me/".to_string()),
        // `batch` is used only for Chat API's internal Cloud list request and
        // is never a public view or a conversation ID.
        (Method::GET, "/v1/conversations/batch".to_string()),
        (Method::POST, "/v1/conversations/batch".to_string()),
        (Method::PATCH, "/v1/conversations/batch".to_string()),
    ] {
        assert_retired_mutation(
            server
                .method(method, &path)
                .add_header(auth.0.clone(), auth.1.clone())
                .await,
        );
    }
}
