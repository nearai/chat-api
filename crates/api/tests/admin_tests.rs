mod common;

use common::{create_test_server, create_test_server_and_db, mock_login};
use uuid::Uuid;

#[tokio::test]
async fn test_admin_users_list_with_admin_account() {
    let server = create_test_server().await;

    let admin_email = "test_admin@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to list users");
}

#[tokio::test]
async fn test_admin_users_list_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/users")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to list users"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
async fn test_admin_users_list_pagination() {
    let server = create_test_server().await;

    let admin_email = "test_admin_pagination@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    // Create additional users for pagination test
    let _user1 = mock_login(&server, "user1@example.com").await;
    let _user2 = mock_login(&server, "user2@example.com").await;
    let _user3 = mock_login(&server, "user3@example.com").await;

    let response = server
        .get("/v1/admin/users?limit=2&offset=0")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);
    let body: serde_json::Value = response.json();

    let limit = body.get("limit").unwrap().as_u64().unwrap();
    let offset = body.get("offset").unwrap().as_u64().unwrap();
    let total = body.get("total").unwrap().as_u64().unwrap();
    let users = body.get("users").unwrap().as_array().unwrap();

    assert_eq!(limit, 2);
    assert_eq!(offset, 0);
    assert!(users.len() <= 2, "Should return at most 2 users");
    assert!(total >= 4, "Should have at least 4 users total");
}

#[tokio::test]
async fn test_revoke_vpc_credentials_with_admin_account() {
    let server = create_test_server().await;

    let admin_email = "test_admin_revoke@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .post("/v1/admin/vpc/revoke")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 204,
        "Admin should be able to revoke VPC credentials"
    );
}

#[tokio::test]
async fn test_revoke_vpc_credentials_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_revoke@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .post("/v1/admin/vpc/revoke")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to revoke VPC credentials"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

/// Admin list instances sanitizes dashboard_url by stripping query params (token etc) to avoid leaking agent info.
#[tokio::test]
async fn test_admin_agents_instances_sanitizes_dashboard_url() {
    let (server, db) = create_test_server_and_db(Default::default()).await;

    let admin_token = mock_login(&server, "test_admin_agents@admin.org").await;

    // Get user ID for seeding
    let user = db
        .user_repository()
        .get_user_by_email("test_admin_agents@admin.org")
        .await
        .unwrap()
        .unwrap();

    // Seed instance with dashboard_url that has token in query (would leak if exposed)
    let inst_id = Uuid::new_v4();
    let client = db.pool().get().await.expect("get pool client");
    let dashboard_with_token =
        "https://internal-agent.example.com/dashboard?token=secret123&other=param";
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, type, status, dashboard_url)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &inst_id,
                &user.id.0,
                &format!("admin-test-{}", Uuid::new_v4()),
                &"Admin Test Instance",
                &"openclaw",
                &"active",
                &dashboard_with_token,
            ],
        )
        .await
        .expect("insert test instance");

    let response = server
        .get("/v1/admin/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200, "Admin should list instances");

    let body: serde_json::Value = response.json();
    let items = body.get("items").unwrap().as_array().unwrap();

    // Find our instance - dashboard_url must be present but sanitized (no query params)
    let our_item = items
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(&inst_id.to_string()));
    let dashboard_url = our_item
        .and_then(|i| i.get("dashboard_url"))
        .and_then(|v| v.as_str());

    assert!(
        dashboard_url.is_some(),
        "Admin list should include dashboard_url (root path)"
    );
    let url = dashboard_url.unwrap();
    assert!(
        !url.contains('?'),
        "Dashboard URL must not expose query params (token): {}",
        url
    );
    assert_eq!(
        url, "https://internal-agent.example.com/dashboard",
        "Should keep only scheme + host + path"
    );

    // Cleanup
    let _ = client
        .execute("DELETE FROM agent_instances WHERE id = $1", &[&inst_id])
        .await;
}
