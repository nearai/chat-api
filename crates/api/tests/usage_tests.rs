mod common;

use common::{create_test_server, create_test_server_and_db, mock_login, TestServerConfig};
use services::user::ports::UserRepository;
use services::user_usage::{UserUsageRepository, METRIC_KEY_IMAGE_EDIT, METRIC_KEY_LLM_TOKENS};

// ---- GET /v1/users/me/usage ----

#[tokio::test]
async fn test_my_usage_requires_auth() {
    let server = create_test_server().await;

    let response = server.get("/v1/users/me/usage").await;

    assert_eq!(response.status_code(), 401, "Should require authentication");
}

#[tokio::test]
async fn test_my_usage_returns_404_when_no_usage() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test_my_usage_no_usage@example.com").await;

    let response = server
        .get("/v1/users/me/usage")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when user has no usage records"
    );
    let body: serde_json::Value = response.json();
    assert!(
        body.get("message")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("usage"))
            .unwrap_or(false),
        "Error message should mention usage"
    );
}

#[tokio::test]
async fn test_my_usage_returns_200_with_correct_body() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("test_my_usage_{}@example.com", uuid::Uuid::new_v4());
    let token = mock_login(&server, &email).await;

    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user created by mock_login");

    db.user_usage_repository()
        .record_usage_event(
            user.id,
            METRIC_KEY_LLM_TOKENS,
            100,
            Some(500),
            Some("gpt-4"),
        )
        .await
        .expect("record usage");
    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_IMAGE_EDIT, 1, Some(200), None)
        .await
        .expect("record image usage");

    let response = server
        .get("/v1/users/me/usage")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body.get("user_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        Some(user.id.to_string())
    );
    assert_eq!(body.get("token_sum").and_then(|v| v.as_i64()), Some(100));
    assert_eq!(body.get("image_num").and_then(|v| v.as_i64()), Some(1));
    assert_eq!(
        body.get("cost_nano_usd").and_then(|v| v.as_i64()),
        Some(700)
    );
}

// ---- GET /v1/admin/usage/users/{user_id} ----

#[tokio::test]
async fn test_admin_usage_by_user_id_requires_admin() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test_user_usage@no-admin.org").await;

    // Use a placeholder UUID; endpoint will return 404 (no usage) or 403 (admin check first)
    let response = server
        .get("/v1/admin/usage/users/00000000-0000-0000-0000-000000000001")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 403, "Non-admin should get 403");
}

#[tokio::test]
async fn test_admin_usage_by_user_id_returns_404_when_no_usage() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = "test_admin_usage_no_usage@example.com";
    let _ = mock_login(&server, email).await;

    let admin_token = mock_login(&server, "test_admin_usage_admin@admin.org").await;
    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user exists");
    let user_id = user.id;

    let response = server
        .get(&format!("/v1/admin/usage/users/{user_id}"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 when user has no usage"
    );
}

#[tokio::test]
async fn test_admin_usage_by_user_id_returns_200_with_usage() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("test_admin_usage_{}@example.com", uuid::Uuid::new_v4());
    let _ = mock_login(&server, &email).await;

    let admin_token = mock_login(&server, "test_admin_usage_admin2@admin.org").await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user exists");

    db.user_usage_repository()
        .record_usage_event(user.id, METRIC_KEY_LLM_TOKENS, 200, Some(1000), None)
        .await
        .expect("record usage");

    let response = server
        .get(&format!("/v1/admin/usage/users/{}", user.id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("token_sum").and_then(|v| v.as_i64()), Some(200));
    assert_eq!(body.get("image_num").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(
        body.get("cost_nano_usd").and_then(|v| v.as_i64()),
        Some(1000)
    );
}

// ---- GET /v1/admin/usage/top ----

#[tokio::test]
async fn test_admin_usage_top_requires_admin() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test_user_top@no-admin.org").await;

    let response = server
        .get("/v1/admin/usage/top")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
async fn test_admin_usage_top_returns_200() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_admin_top@admin.org").await;

    let response = server
        .get("/v1/admin/usage/top")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert!(body.get("users").is_some(), "Should have users array");
    assert_eq!(body.get("rank_by").and_then(|v| v.as_str()), Some("token"));
}

#[tokio::test]
async fn test_admin_usage_top_rank_by_cost() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_admin_top_cost@admin.org").await;

    let response = server
        .get("/v1/admin/usage/top?rank_by=cost")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body.get("rank_by").and_then(|v| v.as_str()), Some("cost"));
}

#[tokio::test]
async fn test_admin_usage_top_invalid_rank_by() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_admin_top_invalid@admin.org").await;

    let response = server
        .get("/v1/admin/usage/top?rank_by=invalid")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 400);
}

#[tokio::test]
async fn test_admin_usage_top_limit_validation() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "test_admin_top_limit@admin.org").await;

    let response = server
        .get("/v1/admin/usage/top?limit=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 400);

    let response = server
        .get("/v1/admin/usage/top?limit=101")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 400);
}
