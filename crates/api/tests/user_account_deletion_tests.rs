mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue};
use services::user::ports::UserRepository;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn auth_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

#[tokio::test]
async fn delete_account_blocks_active_subscription() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!(
        "delete_account_active_subscription_{}@test.org",
        Uuid::new_v4()
    );
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
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_delete_active', 'price_test', 'active', NOW() + INTERVAL '1 day', false)",
            &[&format!("sub_delete_active_{}", Uuid::new_v4()), &user.id],
        )
        .await
        .expect("insert active subscription");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;

    assert_eq!(response.status_code(), 409);
    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get user after blocked delete")
        .is_some());
}

#[tokio::test]
async fn delete_account_blocks_non_stopped_instance() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("delete_account_active_instance_{}@test.org", Uuid::new_v4());
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
            "INSERT INTO agent_instances (user_id, instance_id, name, type, status)
             VALUES ($1, $2, 'active delete blocker', 'openclaw', 'active')",
            &[&user.id, &format!("inst_delete_active_{}", Uuid::new_v4())],
        )
        .await
        .expect("insert active instance");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;

    assert_eq!(response.status_code(), 409);
    let body: serde_json::Value = response.json();
    assert!(body
        .get("details")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .contains("active"));
}

#[tokio::test]
async fn delete_account_removes_pii_and_preserves_audit_rows() {
    let mock_cloud_api = MockServer::start().await;
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_cloud_api.uri()),
        ..TestServerConfig::default()
    })
    .await;
    let email = format!("delete_account_success_{}@test.org", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");

    let client = db.pool().get().await.expect("db client");
    let instance_pk = Uuid::new_v4();
    let instance_id = format!("inst_delete_success_{}", Uuid::new_v4());
    let subscription_id = format!("sub_delete_success_{}", Uuid::new_v4());
    let conversation_id = format!("conv_delete_success_{}", Uuid::new_v4());

    Mock::given(method("DELETE"))
        .and(path(format!("/conversations/{conversation_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": conversation_id,
            "deleted": true
        })))
        .mount(&mock_cloud_api)
        .await;

    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, 'stripe', 'cus_delete_success', 'price_test', 'canceled', NOW() - INTERVAL '1 day', false)",
            &[&subscription_id, &user.id],
        )
        .await
        .expect("insert canceled subscription");

    client
        .execute(
            "INSERT INTO user_usage_event (user_id, metric_key, quantity, cost_nano_usd, model_id)
             VALUES ($1, 'llm.tokens', 42, 1000, 'test-model')",
            &[&user.id],
        )
        .await
        .expect("insert usage");

    client
        .execute(
            "INSERT INTO user_settings (user_id, content)
             VALUES ($1, '{\"web_search\": true}'::jsonb)
             ON CONFLICT (user_id) DO UPDATE SET content = EXCLUDED.content",
            &[&user.id],
        )
        .await
        .expect("insert settings");

    client
        .execute(
            "INSERT INTO conversations (id, user_id) VALUES ($1, $2)",
            &[&conversation_id, &user.id],
        )
        .await
        .expect("insert conversation");

    client
        .execute(
            "INSERT INTO agent_instances (
                id, user_id, instance_id, name, type, public_ssh_key, instance_url,
                instance_token, dashboard_url, agent_api_base_url, status
            ) VALUES ($1, $2, $3, 'delete success instance', 'openclaw', 'ssh-rsa AAA',
                'https://instance.internal', 'secret-token', 'https://dash.internal?token=secret',
                'https://manager.internal', 'stopped')",
            &[&instance_pk, &user.id, &instance_id],
        )
        .await
        .expect("insert stopped instance");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;
    assert_eq!(response.status_code(), 204);

    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get deleted user")
        .is_none());

    let subscription_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM subscriptions WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count subscriptions")
        .get(0);
    assert_eq!(subscription_count, 1);

    let usage_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM user_usage_event WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count usage")
        .get(0);
    assert_eq!(usage_count, 1);

    let settings_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM user_settings WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count settings")
        .get(0);
    assert_eq!(settings_count, 0);

    let conversation_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM conversations WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count conversations")
        .get(0);
    assert_eq!(conversation_count, 0);

    let instance = client
        .query_one(
            "SELECT status, public_ssh_key, instance_token, dashboard_url, agent_api_base_url
             FROM agent_instances WHERE id = $1",
            &[&instance_pk],
        )
        .await
        .expect("get retained instance");
    assert_eq!(instance.get::<_, String>("status"), "deleted");
    assert!(instance
        .get::<_, Option<String>>("public_ssh_key")
        .is_none());
    assert!(instance
        .get::<_, Option<String>>("instance_token")
        .is_none());
    assert!(instance.get::<_, Option<String>>("dashboard_url").is_none());
    assert!(instance
        .get::<_, Option<String>>("agent_api_base_url")
        .is_none());
}

#[tokio::test]
async fn delete_account_blocks_when_cloud_conversation_delete_fails() {
    let mock_cloud_api = MockServer::start().await;
    let (server, db) = create_test_server_and_db(TestServerConfig {
        proxy_base_url: Some(mock_cloud_api.uri()),
        ..TestServerConfig::default()
    })
    .await;
    let email = format!("delete_account_cloud_failure_{}@test.org", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");
    let conversation_id = format!("conv_delete_failure_{}", Uuid::new_v4());

    Mock::given(method("DELETE"))
        .and(path(format!("/conversations/{conversation_id}")))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "upstream failure"
        })))
        .mount(&mock_cloud_api)
        .await;

    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO conversations (id, user_id) VALUES ($1, $2)",
            &[&conversation_id, &user.id],
        )
        .await
        .expect("insert conversation");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;
    assert_eq!(response.status_code(), 502);

    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get user after cloud failure")
        .is_some());

    let conversation_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM conversations WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count conversations after cloud failure")
        .get(0);
    assert_eq!(conversation_count, 1);
}
