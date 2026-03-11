mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use services::user::ports::UserRepository;
use services::UserId;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn wait_for_web_search_usage_count(
    db: &database::Database,
    user_id: UserId,
    expected: i64,
) -> i64 {
    let client = db.pool().get().await.expect("db client");
    for _ in 0..20 {
        let row = client
            .query_one(
                "SELECT COUNT(*)::bigint
                 FROM user_usage_event
                 WHERE user_id = $1 AND metric_key = 'service.web_search'",
                &[&user_id],
            )
            .await
            .expect("count usage");
        let count: i64 = row.get(0);
        if count == expected {
            return count;
        }
        sleep(Duration::from_millis(50)).await;
    }

    client
        .query_one(
            "SELECT COUNT(*)::bigint
             FROM user_usage_event
             WHERE user_id = $1 AND metric_key = 'service.web_search'",
            &[&user_id],
        )
        .await
        .expect("final count")
        .get(0)
}

async fn create_agent_api_key(
    server: &axum_test::TestServer,
    db: &database::Database,
    user_email: &str,
) -> (UserId, Uuid, String) {
    let token = mock_login(server, user_email).await;
    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("db")
        .expect("user");

    let instance_id = Uuid::new_v4();
    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, instance_url, instance_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())",
            &[
                &instance_id,
                &user.id,
                &format!("inst_test_{}", Uuid::new_v4().simple()),
                &"web-search-instance",
                &"http://test-instance.local",
                &"tok_test_instance_secret",
            ],
        )
        .await
        .expect("insert instance");

    let api_key_response = server
        .post(&format!("/v1/agents/instances/{instance_id}/keys"))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&serde_json::json!({
            "name": "web-search-key",
            "spend_limit": null,
            "expires_at": null
        }))
        .await;

    assert_eq!(api_key_response.status_code(), 201);
    let api_key_body: serde_json::Value = api_key_response.json();
    let api_key = api_key_body["api_key"]
        .as_str()
        .expect("api key")
        .to_string();

    (user.id, instance_id, api_key)
}

#[tokio::test]
async fn web_search_requires_authentication() {
    let mock_upstream = MockServer::start().await;

    let (server, _db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", mock_upstream.uri())),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let response = server.get("/v1/web/search?q=rust").await;

    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn web_search_records_usage_only_on_success() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(r#"{"results":[{"title":"Rust"}]}"#, "application/json"),
        )
        .mount(&mock_upstream)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/services/web_search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(r#"{"costPerUnit":123}"#, "application/json"),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", mock_upstream.uri())),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let email = "test_web_search_success@example.com";
    let token = mock_login(&server, email).await;
    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user");

    let response = server
        .get("/v1/web/search?q=rust")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body["results"][0]["title"], "Rust");

    let count = wait_for_web_search_usage_count(&db, user.id, 1).await;
    assert_eq!(
        count, 1,
        "successful web search should record one usage event"
    );

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT quantity, cost_nano_usd, details->>'request_type'
             FROM user_usage_event
             WHERE user_id = $1 AND metric_key = 'service.web_search'
             ORDER BY created_at DESC
             LIMIT 1",
            &[&user.id],
        )
        .await
        .expect("usage row");

    let quantity: i64 = row.get(0);
    let cost_nano_usd: Option<i64> = row.get(1);
    let request_type: Option<String> = row.get(2);

    assert_eq!(quantity, 1);
    assert_eq!(cost_nano_usd, Some(123));
    assert_eq!(request_type.as_deref(), Some("web_search"));
}

#[tokio::test]
async fn web_search_does_not_record_usage_for_failed_agent_request() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("content-type", "application/json")
                .set_body_raw(r#"{"error":"rate limited"}"#, "application/json"),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", mock_upstream.uri())),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let (user_id, instance_id, api_key) =
        create_agent_api_key(&server, &db, "test_web_search_failed_agent@example.com").await;

    let response = server
        .get("/v1/web/search?q=rust")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 429);

    let count = wait_for_web_search_usage_count(&db, user_id, 0).await;
    assert_eq!(count, 0, "failed web search should not record usage");

    let client = db.pool().get().await.expect("db client");
    let row = client
        .query_one(
            "SELECT total_spent, total_requests
             FROM agent_balance
             WHERE instance_id = $1",
            &[&instance_id],
        )
        .await
        .expect("agent balance");

    let total_spent: i64 = row.get(0);
    let total_requests: i64 = row.get(1);

    assert_eq!(total_spent, 0);
    assert_eq!(total_requests, 0);
}

#[tokio::test]
async fn web_search_records_usage_for_successful_agent_request() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(
                    r#"{"results":[{"title":"Agent search"}]}"#,
                    "application/json",
                ),
        )
        .mount(&mock_upstream)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/services/web_search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(r#"{"costPerUnit":456}"#, "application/json"),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(format!("{}/v1", mock_upstream.uri())),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let (user_id, instance_id, api_key) =
        create_agent_api_key(&server, &db, "test_web_search_success_agent@example.com").await;

    let response = server
        .get("/v1/web/search?q=rust")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body["results"][0]["title"], "Agent search");

    let count = wait_for_web_search_usage_count(&db, user_id, 1).await;
    assert_eq!(count, 1, "successful agent web search should record usage");

    let client = db.pool().get().await.expect("db client");
    let usage_row = client
        .query_one(
            "SELECT quantity, cost_nano_usd, instance_id, details->>'request_type'
             FROM user_usage_event
             WHERE user_id = $1 AND metric_key = 'service.web_search'
             ORDER BY created_at DESC
             LIMIT 1",
            &[&user_id],
        )
        .await
        .expect("usage row");

    let quantity: i64 = usage_row.get(0);
    let cost_nano_usd: Option<i64> = usage_row.get(1);
    let recorded_instance_id: Option<Uuid> = usage_row.get(2);
    let request_type: Option<String> = usage_row.get(3);

    assert_eq!(quantity, 1);
    assert_eq!(cost_nano_usd, Some(456));
    assert_eq!(recorded_instance_id, Some(instance_id));
    assert_eq!(request_type.as_deref(), Some("web_search"));

    let balance_row = client
        .query_one(
            "SELECT total_spent, total_requests
             FROM agent_balance
             WHERE instance_id = $1",
            &[&instance_id],
        )
        .await
        .expect("agent balance");

    let total_spent: i64 = balance_row.get(0);
    let total_requests: i64 = balance_row.get(1);

    assert_eq!(total_spent, 456);
    assert_eq!(total_requests, 1);
}
