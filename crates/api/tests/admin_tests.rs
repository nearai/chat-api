mod common;

use common::{create_test_server, create_test_server_and_db, mock_login};
use services::user::ports::UserRepository;
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

/// Admin list instances sanitizes dashboard_url by stripping query params, fragment, and userinfo.
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

    let client = db.pool().get().await.expect("get pool client");

    // Seed instance 1: query params (token) - would leak if exposed
    let inst1_id = Uuid::new_v4();
    let dashboard_with_token =
        "https://internal-agent.example.com/dashboard?token=secret123&other=param";
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, type, status, dashboard_url)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &inst1_id,
                &user.id.0,
                &format!("admin-test-{}", Uuid::new_v4()),
                &"Admin Test Instance 1",
                &"openclaw",
                &"active",
                &dashboard_with_token,
            ],
        )
        .await
        .expect("insert test instance 1");

    // Seed instance 2: userinfo (user:pass@) - would leak credentials if exposed
    let inst2_id = Uuid::new_v4();
    let dashboard_with_userinfo =
        "https://admin:secret@internal-agent.example.com/dashboard#section";
    client
        .execute(
            "INSERT INTO agent_instances (id, user_id, instance_id, name, type, status, dashboard_url)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &inst2_id,
                &user.id.0,
                &format!("admin-test-{}", Uuid::new_v4()),
                &"Admin Test Instance 2",
                &"openclaw",
                &"active",
                &dashboard_with_userinfo,
            ],
        )
        .await
        .expect("insert test instance 2");

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

    // Instance 1: no query params, no fragment
    let item1 = items
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(&inst1_id.to_string()));
    let url1 = item1
        .and_then(|i| i.get("dashboard_url"))
        .and_then(|v| v.as_str());
    assert!(url1.is_some(), "Instance 1 should have dashboard_url");
    let url1 = url1.unwrap();
    assert!(
        !url1.contains('?'),
        "Dashboard URL must not expose query params: {}",
        url1
    );
    assert_eq!(url1, "https://internal-agent.example.com/dashboard");

    // Instance 2: no userinfo, no fragment
    let item2 = items
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(&inst2_id.to_string()));
    let url2 = item2
        .and_then(|i| i.get("dashboard_url"))
        .and_then(|v| v.as_str());
    assert!(url2.is_some(), "Instance 2 should have dashboard_url");
    let url2 = url2.unwrap();
    assert!(
        !url2.contains("admin:secret@"),
        "Dashboard URL must not expose userinfo (credentials): {}",
        url2
    );
    assert!(
        !url2.contains('#'),
        "Dashboard URL must not expose fragment: {}",
        url2
    );
    assert_eq!(url2, "https://internal-agent.example.com/dashboard");

    // Cleanup
    let _ = client
        .execute("DELETE FROM agent_instances WHERE id = $1", &[&inst1_id])
        .await;
    let _ = client
        .execute("DELETE FROM agent_instances WHERE id = $1", &[&inst2_id])
        .await;
}
