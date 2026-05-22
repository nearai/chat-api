mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use http::{HeaderName, HeaderValue};
use services::user::ports::{AccountDeletionError, UserRepository};
use uuid::Uuid;

fn auth_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

#[tokio::test]
async fn delete_account_blocks_non_terminal_subscription_statuses() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let client = db.pool().get().await.expect("db client");

    for status in [
        "active",
        "trialing",
        "past_due",
        "unpaid",
        "incomplete",
        "paused",
    ] {
        let email = format!(
            "delete_account_{}_subscription_{}@test.org",
            status,
            Uuid::new_v4()
        );
        let token = mock_login(&server, &email).await;
        let user = db
            .user_repository()
            .get_user_by_email(&email)
            .await
            .expect("get user")
            .expect("user exists");
        let subscription_id = format!("sub_delete_{}_{}", status, Uuid::new_v4());
        let customer_id = format!("cus_delete_{}_{}", status, Uuid::new_v4());

        client
            .execute(
                "INSERT INTO subscriptions (
                    subscription_id, user_id, provider, customer_id, price_id, status,
                    current_period_end, cancel_at_period_end
                ) VALUES ($1, $2, 'stripe', $3, 'price_test', $4, NOW() + INTERVAL '1 day', false)",
                &[&subscription_id, &user.id, &customer_id, &status],
            )
            .await
            .expect("insert non-terminal subscription");

        let (name, value) = auth_header(&token);
        let response = server.delete("/v1/users/me").add_header(name, value).await;

        assert_eq!(
            response.status_code(),
            409,
            "{status} subscription should block account deletion"
        );
        let body: serde_json::Value = response.json();
        assert!(body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("non-terminal subscription"));
        assert!(db
            .user_repository()
            .get_user(user.id)
            .await
            .expect("get user after blocked delete")
            .is_some());
    }
}

#[tokio::test]
async fn delete_account_allows_terminal_subscription_statuses() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let client = db.pool().get().await.expect("db client");

    for status in ["canceled", "incomplete_expired"] {
        let email = format!(
            "delete_account_{}_subscription_{}@test.org",
            status,
            Uuid::new_v4()
        );
        let token = mock_login(&server, &email).await;
        let user = db
            .user_repository()
            .get_user_by_email(&email)
            .await
            .expect("get user")
            .expect("user exists");
        let subscription_id = format!("sub_delete_{}_{}", status, Uuid::new_v4());
        let customer_id = format!("cus_delete_{}_{}", status, Uuid::new_v4());

        client
            .execute(
                "INSERT INTO subscriptions (
                    subscription_id, user_id, provider, customer_id, price_id, status,
                    current_period_end, cancel_at_period_end
                ) VALUES ($1, $2, 'stripe', $3, 'price_test', $4, NOW() - INTERVAL '1 day', false)",
                &[&subscription_id, &user.id, &customer_id, &status],
            )
            .await
            .expect("insert terminal subscription");

        let (name, value) = auth_header(&token);
        let response = server.delete("/v1/users/me").add_header(name, value).await;
        assert_eq!(
            response.status_code(),
            202,
            "{status} subscription should allow account deletion"
        );
    }
}

#[tokio::test]
async fn delete_account_blocks_non_deleted_instance() {
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
async fn delete_account_request_creates_pending_state_and_blocks_access() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
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
            ) VALUES ($1, $2, $3, 'delete success instance', 'openclaw', NULL,
                NULL, NULL, NULL, NULL, 'deleted')",
            &[&instance_pk, &user.id, &instance_id],
        )
        .await
        .expect("insert deleted instance");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;
    assert_eq!(response.status_code(), 202);

    let body: serde_json::Value = response.json();
    assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("pending"));

    let deletion = db
        .user_repository()
        .get_account_deletion_by_user_id(user.id)
        .await
        .expect("get deletion")
        .expect("deletion exists");
    assert_eq!(deletion.status.as_str(), "pending");

    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get pending deletion user")
        .is_some());

    let (name, value) = auth_header(&token);
    let profile_response = server.get("/v1/users/me").add_header(name, value).await;
    assert_eq!(profile_response.status_code(), 403);

    db.user_repository()
        .delete_user_account(user.id, std::slice::from_ref(&conversation_id), &[])
        .await
        .expect("finalize delete account");
    db.user_repository()
        .mark_account_deletion_completed(deletion.id)
        .await
        .expect("mark completed");

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
async fn pending_delete_account_request_can_be_retried() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("delete_account_retry_{}@test.org", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");

    let (name, value) = auth_header(&token);
    let response = server.delete("/v1/users/me").add_header(name, value).await;
    assert_eq!(response.status_code(), 202);

    let (name, value) = auth_header(&token);
    let retry_response = server.delete("/v1/users/me").add_header(name, value).await;
    assert_eq!(retry_response.status_code(), 202);

    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get user after pending delete retry")
        .is_some());

    let deletion_count: i64 = db
        .pool()
        .get()
        .await
        .expect("db client")
        .query_one(
            "SELECT COUNT(*) FROM user_account_deletions WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .expect("count deletion requests")
        .get(0);
    assert_eq!(deletion_count, 1);
}

#[tokio::test]
async fn account_deletion_request_reports_insert_vs_existing() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("delete_account_insert_flag_{}@test.org", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    drop(token);
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");

    let first = db
        .user_repository()
        .create_account_deletion_request(user.id)
        .await
        .expect("create first deletion request");
    assert!(first.was_inserted);

    let second = db
        .user_repository()
        .create_account_deletion_request(user.id)
        .await
        .expect("return existing deletion request");
    assert!(!second.was_inserted);
    assert_eq!(first.deletion.id, second.deletion.id);
}

#[tokio::test]
async fn delete_account_requires_cloud_file_cleanup() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let email = format!("delete_account_file_guard_{}@test.org", Uuid::new_v4());
    let token = mock_login(&server, &email).await;
    drop(token);
    let user = db
        .user_repository()
        .get_user_by_email(&email)
        .await
        .expect("get user")
        .expect("user exists");
    let file_id = format!("file-delete-guard-{}", Uuid::new_v4());

    let client = db.pool().get().await.expect("db client");
    client
        .execute(
            "INSERT INTO files (id, user_id, bytes, file_created_at, filename, purpose)
             VALUES ($1, $2, 10, 123, 'delete-guard.txt', 'assistants')",
            &[&file_id, &user.id],
        )
        .await
        .expect("insert file");

    let err = db
        .user_repository()
        .delete_user_account(user.id, &[], &[])
        .await
        .expect_err("file guard should block finalization");
    match err {
        AccountDeletionError::FileCleanupIncomplete { file_ids } => {
            assert_eq!(file_ids, vec![file_id.clone()]);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(db
        .user_repository()
        .get_user(user.id)
        .await
        .expect("get user after blocked finalization")
        .is_some());

    db.user_repository()
        .delete_user_account(user.id, &[], std::slice::from_ref(&file_id))
        .await
        .expect("finalize after file provider cleanup");

    let file_count: i64 = client
        .query_one("SELECT COUNT(*) FROM files WHERE id = $1", &[&file_id])
        .await
        .expect("count file")
        .get(0);
    assert_eq!(file_count, 0);
}

#[tokio::test]
async fn delete_account_removes_shared_recipient_identifiers() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;
    let deleted_email = format!("delete_account_share_recipient_{}@test.org", Uuid::new_v4());
    let owner_email = format!("delete_account_share_owner_{}@test.org", Uuid::new_v4());
    let deleted_token = mock_login(&server, &deleted_email).await;
    let owner_token = mock_login(&server, &owner_email).await;
    drop((deleted_token, owner_token));

    let deleted_user = db
        .user_repository()
        .get_user_by_email(&deleted_email)
        .await
        .expect("get deleted user")
        .expect("deleted user exists");
    let owner_user = db
        .user_repository()
        .get_user_by_email(&owner_email)
        .await
        .expect("get owner user")
        .expect("owner user exists");

    let client = db.pool().get().await.expect("db client");
    let near_account = format!("{}.near", Uuid::new_v4());
    let conversation_id = format!("conv-share-recipient-{}", Uuid::new_v4());
    let group_id = Uuid::new_v4();

    client
        .execute(
            "INSERT INTO oauth_accounts (user_id, provider, provider_user_id)
             VALUES ($1, 'near', $2)",
            &[&deleted_user.id, &near_account],
        )
        .await
        .expect("insert near account");
    client
        .execute(
            "INSERT INTO conversations (id, user_id) VALUES ($1, $2)",
            &[&conversation_id, &owner_user.id],
        )
        .await
        .expect("insert owner conversation");
    client
        .execute(
            "INSERT INTO conversation_share_groups (id, owner_user_id, name)
             VALUES ($1, $2, 'shared group')",
            &[&group_id, &owner_user.id],
        )
        .await
        .expect("insert share group");
    client
        .execute(
            "INSERT INTO conversation_shares (
                 conversation_id, owner_user_id, share_type, permission, recipient_type, recipient_value
             ) VALUES ($1, $2, 'direct', 'read', 'email', $3)",
            &[&conversation_id, &owner_user.id, &deleted_email],
        )
        .await
        .expect("insert direct email share");
    client
        .execute(
            "INSERT INTO conversation_shares (
                 conversation_id, owner_user_id, share_type, permission, recipient_type, recipient_value
             ) VALUES ($1, $2, 'direct', 'read', 'near', $3)",
            &[&conversation_id, &owner_user.id, &near_account],
        )
        .await
        .expect("insert direct near share");
    client
        .execute(
            "INSERT INTO conversation_share_group_members (group_id, member_type, member_value)
             VALUES ($1, 'email', $2), ($1, 'near', $3)",
            &[&group_id, &deleted_email, &near_account],
        )
        .await
        .expect("insert group members");

    db.user_repository()
        .delete_user_account(deleted_user.id, &[], &[])
        .await
        .expect("delete account");

    let direct_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM conversation_shares
             WHERE recipient_value = $1 OR recipient_value = $2",
            &[&deleted_email, &near_account],
        )
        .await
        .expect("count direct shares")
        .get(0);
    assert_eq!(direct_count, 0);

    let member_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM conversation_share_group_members
             WHERE member_value = $1 OR member_value = $2",
            &[&deleted_email, &near_account],
        )
        .await
        .expect("count group members")
        .get(0);
    assert_eq!(member_count, 0);
}
