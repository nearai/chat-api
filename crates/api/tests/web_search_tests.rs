mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use serde_json::json;
use services::agent::ports::AgentRepository;
use services::user::ports::UserRepository;
use services::UserId;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use wiremock::matchers::{body_partial_json, method, path};
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
        .json(&json!({
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

fn web_search_tool_call(query: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "web_search",
            "arguments": {
                "query": query
            }
        }
    })
}

fn other_tool_call() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "other_tool",
            "arguments": {
                "query": "ignored"
            }
        }
    })
}

#[tokio::test]
async fn web_search_requires_authentication() {
    let mock_upstream = MockServer::start().await;

    let (server, _db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let response = server
        .post("/mcp")
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn web_search_records_usage_only_on_success() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": { "name": "web_search" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "{\"query\":\"rust\",\"result_count\":1,\"results\":[{\"title\":\"Rust\"}]}"
                        }],
                        "structuredContent": {
                            "query": "rust",
                            "result_count": 1,
                            "results": [{ "title": "Rust" }]
                        },
                        "isError": false
                    }
                })),
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
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let email = format!(
        "test_web_search_success_{}@example.com",
        Uuid::new_v4().simple()
    );
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["result"]["structuredContent"]["results"][0]["title"],
        "Rust"
    );

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
    assert_eq!(request_type.as_deref(), Some("mcp.web_search"));
}

#[tokio::test]
async fn web_search_does_not_record_usage_when_is_error_flag_is_missing() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": { "name": "web_search" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "{\"query\":\"rust\",\"result_count\":1}"
                        }],
                        "structuredContent": {
                            "query": "rust",
                            "result_count": 1
                        }
                    }
                })),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let email = format!(
        "test_web_search_missing_flag_{}@example.com",
        Uuid::new_v4().simple()
    );
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 200);

    let count = wait_for_web_search_usage_count(&db, user.id, 0).await;
    assert_eq!(count, 0, "missing isError should not record usage");
}

#[tokio::test]
async fn web_search_does_not_record_usage_for_failed_agent_request() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {
                        "code": -32003,
                        "message": "rate limited"
                    }
                })),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let failed_agent_email = format!(
        "test_web_search_failed_agent_{}@example.com",
        Uuid::new_v4().simple()
    );
    let (user_id, instance_id, api_key) =
        create_agent_api_key(&server, &db, &failed_agent_email).await;

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"]["code"], -32003);

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
async fn non_web_search_mcp_call_does_not_record_usage() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "ok"
                        }],
                        "structuredContent": {
                            "status": "ok"
                        },
                        "isError": false
                    }
                })),
        )
        .mount(&mock_upstream)
        .await;

    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let email = format!(
        "test_mcp_other_tool_{}@example.com",
        Uuid::new_v4().simple()
    );
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&other_tool_call())
        .await;

    assert_eq!(response.status_code(), 200);

    let count = wait_for_web_search_usage_count(&db, user.id, 0).await;
    assert_eq!(count, 0, "non-web_search MCP calls should not record usage");
}

#[tokio::test]
async fn web_search_records_usage_for_successful_agent_request() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": { "name": "web_search" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "{\"query\":\"rust\",\"result_count\":1,\"results\":[{\"title\":\"Agent search\"}]}"
                        }],
                        "structuredContent": {
                            "query": "rust",
                            "result_count": 1,
                            "results": [{ "title": "Agent search" }]
                        },
                        "isError": false
                    }
                })),
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
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url: mock_upstream.uri(),
        ..Default::default()
    })
    .await;

    let success_agent_email = format!(
        "test_web_search_success_agent_{}@example.com",
        Uuid::new_v4().simple()
    );
    let (user_id, instance_id, api_key) =
        create_agent_api_key(&server, &db, &success_agent_email).await;

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
        )
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["result"]["structuredContent"]["results"][0]["title"],
        "Agent search"
    );

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
    assert_eq!(request_type.as_deref(), Some("mcp.web_search"));

    let balance_row = client
        .query_one(
            "SELECT total_spent, total_requests, total_tokens
             FROM agent_balance
             WHERE instance_id = $1",
            &[&instance_id],
        )
        .await
        .expect("agent balance");

    let total_spent: i64 = balance_row.get(0);
    let total_requests: i64 = balance_row.get(1);
    let total_tokens: i64 = balance_row.get(2);

    assert_eq!(total_spent, 456);
    assert_eq!(total_requests, 1);
    assert_eq!(total_tokens, 0);

    let agent_repo = db.agent_repository();
    let (usage_entries, usage_total) = agent_repo
        .get_instance_usage(instance_id, None, None, 10, 0)
        .await
        .expect("usage entries");

    assert_eq!(usage_total, 1);
    let item = &usage_entries[0];
    assert_eq!(item.request_type, "mcp.web_search");
    assert_eq!(item.model_id, "");
    assert_eq!(item.input_tokens, 0);
    assert_eq!(item.output_tokens, 0);
    assert_eq!(item.total_tokens, 0);
    assert_eq!(item.total_cost, 456);

    let balance = agent_repo
        .get_instance_balance(instance_id)
        .await
        .expect("balance lookup")
        .expect("instance balance");
    assert_eq!(balance.total_requests, 1);
    assert_eq!(balance.total_tokens, 0);
}

#[tokio::test]
async fn web_search_supports_cloud_api_base_url_with_v1_suffix() {
    let mock_upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({
            "method": "tools/call",
            "params": { "name": "web_search" }
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "{\"query\":\"rust\",\"result_count\":1,\"results\":[{\"title\":\"Rust via v1 base\"}]}"
                        }],
                        "structuredContent": {
                            "query": "rust",
                            "result_count": 1,
                            "results": [{ "title": "Rust via v1 base" }]
                        },
                        "isError": false
                    }
                })),
        )
        .mount(&mock_upstream)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/services/web_search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_raw(r#"{"costPerUnit":789}"#, "application/json"),
        )
        .mount(&mock_upstream)
        .await;

    let cloud_api_base_url = format!("{}/v1", mock_upstream.uri());
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_upstream.uri()),
        cloud_api_base_url,
        ..Default::default()
    })
    .await;

    let email = format!(
        "test_web_search_v1_base_url_{}@example.com",
        Uuid::new_v4().simple()
    );
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("db")
        .expect("user");

    let response = server
        .post("/mcp")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .json(&web_search_tool_call("rust"))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["result"]["structuredContent"]["results"][0]["title"],
        "Rust via v1 base"
    );

    let count = wait_for_web_search_usage_count(&db, user.id, 1).await;
    assert_eq!(count, 1, "web search should record usage with /v1 base URL");
}
