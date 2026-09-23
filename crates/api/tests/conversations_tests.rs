mod common;

use api::routes::api::STATEFUL_API_RETIRED_MESSAGE;
use axum_test::{TestResponse, TestServer};
use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};
use services::conversation::ports::{
    ConversationShareRepository, NewConversationShare, SharePermission, ShareRecipient,
    ShareRecipientKind, ShareType,
};
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

async fn stage_one_fixture_with_db() -> (
    TestServer,
    MockServer,
    database::Database,
    String,
    String,
    services::UserId,
) {
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
    Mock::given(method("DELETE"))
        .and(path(format!("/conversations/{conversation_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": conversation_id.clone(),
            "deleted": true
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
    (server, upstream, db, token, conversation_id, user.id)
}

async fn stage_one_fixture() -> (TestServer, MockServer, String, String) {
    let (server, upstream, _db, token, conversation_id, _owner_user_id) =
        stage_one_fixture_with_db().await;
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
async fn stage_one_retired_conversation_and_sharing_surfaces_are_gone() {
    let (server, _upstream, token, conversation_id) = stage_one_fixture().await;
    let auth = bearer(&token);

    for (method, path) in [
        (Method::POST, "/v1/conversations".to_string()),
        (Method::POST, format!("/v1/conversations/{conversation_id}")),
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

#[tokio::test]
async fn stage_one_established_delete_operations_remain_available() {
    let (server, _upstream, db, token, conversation_id, owner_user_id) =
        stage_one_fixture_with_db().await;
    let auth = bearer(&token);

    let shares = db.conversation_share_repository();
    let direct_share = shares
        .create_share(NewConversationShare {
            conversation_id: conversation_id.clone(),
            owner_user_id,
            share_type: ShareType::Direct,
            permission: SharePermission::Read,
            recipient: Some(ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: format!("stage-one-share-{}@example.com", Uuid::new_v4()),
            }),
            group_id: None,
            org_email_pattern: None,
        })
        .await
        .expect("seed direct share");
    let group = shares
        .create_group(
            owner_user_id,
            &format!("stage-one-group-{}", Uuid::new_v4()),
            &[ShareRecipient {
                kind: ShareRecipientKind::Email,
                value: format!("stage-one-member-{}@example.com", Uuid::new_v4()),
            }],
        )
        .await
        .expect("seed share group");
    let group_share = shares
        .create_share(NewConversationShare {
            conversation_id: conversation_id.clone(),
            owner_user_id,
            share_type: ShareType::Group,
            permission: SharePermission::Read,
            recipient: None,
            group_id: Some(group.id),
            org_email_pattern: None,
        })
        .await
        .expect("seed group share");

    let response = server
        .delete(&format!(
            "/v1/conversations/{conversation_id}/shares/{}",
            direct_share.id
        ))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);
    assert_no_store(&response);

    let response = server
        .delete(&format!("/v1/share-groups/{}", group.id))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);
    assert_no_store(&response);

    let client = db.pool().get().await.expect("db client");
    for (table, column, id) in [
        ("conversation_shares", "id", direct_share.id),
        ("conversation_share_groups", "id", group.id),
        ("conversation_share_group_members", "group_id", group.id),
        ("conversation_shares", "id", group_share.id),
    ] {
        let query = format!("SELECT 1 FROM {table} WHERE {column} = $1");
        assert!(
            client
                .query_opt(&query, &[&id])
                .await
                .expect("query deleted share state")
                .is_none(),
            "{table}.{column} should be removed"
        );
    }

    let missing_share = server
        .delete(&format!(
            "/v1/conversations/{conversation_id}/shares/{}",
            Uuid::new_v4()
        ))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(missing_share.status_code(), StatusCode::NOT_FOUND);
    assert_no_store(&missing_share);

    let missing_group = server
        .delete(&format!("/v1/share-groups/{}", Uuid::new_v4()))
        .add_header(auth.0.clone(), auth.1.clone())
        .await;
    assert_eq!(missing_group.status_code(), StatusCode::NOT_FOUND);
    assert_no_store(&missing_group);

    let response = server
        .delete(&format!("/v1/conversations/{conversation_id}"))
        .add_header(auth.0, auth.1)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_no_store(&response);
    let body: Value = response.json();
    assert_eq!(body["id"], conversation_id);
    assert_eq!(body["deleted"], true);
}
