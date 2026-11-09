mod common;
mod retired_stateful;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::StatusCode;
use services::user::ports::UserRepository;
use uuid::Uuid;
use wiremock::MockServer;

#[tokio::test]
async fn conversation_and_sharing_endpoints_are_retired_without_accessing_data() {
    let upstream = MockServer::start().await;
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(upstream.uri()),
        ..TestServerConfig::default()
    })
    .await;
    let email = format!("retired-{}@example.com", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let owner = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .unwrap()
        .unwrap();
    let conversation_id = format!("conv_{}", Uuid::new_v4());
    let client = db.pool().get().await.unwrap();

    client
        .execute(
            "INSERT INTO conversations (id, user_id) VALUES ($1, $2)",
            &[&conversation_id, &owner.id],
        )
        .await
        .unwrap();

    client
        .execute(
            "INSERT INTO conversation_shares (
                id, conversation_id, owner_user_id, share_type, permission
             ) VALUES ($1, $2, $3, 'public', 'read')",
            &[&Uuid::new_v4(), &conversation_id, &owner.id],
        )
        .await
        .unwrap();

    let mut paths = vec![
        "/v1/conversations".to_string(),
        "/v1/conversations/".to_string(),
        "/v1/conversations/batch".to_string(),
        "/v1/conversations/missing".to_string(),
    ];

    for suffix in [
        "",
        "/items",
        "/shares",
        "/shares/missing",
        "/pin",
        "/archive",
        "/clone",
        "/unknown/child",
    ] {
        paths.push(format!("/v1/conversations/{conversation_id}{suffix}"));
    }

    for namespace in ["/v1/share-groups", "/v1/shared-with-me"] {
        for suffix in ["", "/", "/missing", "/missing/child"] {
            paths.push(format!("{namespace}{suffix}"));
        }
    }

    retired_stateful::assert_retired_paths(&server, &paths, &token).await;

    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM conversations WHERE id = $1",
            &[&conversation_id],
        )
        .await
        .unwrap()
        .get(0);

    assert_eq!(count, 1, "retirement must not delete stored conversations");
    assert!(upstream.received_requests().await.unwrap().is_empty());
    assert_eq!(server.get("/health").await.status_code(), StatusCode::OK);
    assert_eq!(
        server.get("/v1/users/me").await.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.post("/v1/responses").await.status_code(),
        StatusCode::UNAUTHORIZED
    );
}
