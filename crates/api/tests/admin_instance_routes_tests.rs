mod common;

use common::{
    cleanup_user_agent_instances, create_test_server_and_db, mock_login, TestServerConfig,
};
use http::{HeaderName, HeaderValue};
use serde_json::json;
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "admin-instance-routes@admin.org";

#[tokio::test]
#[serial]
async fn admin_instance_patch_is_not_supported() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    let user_id = UserId(Uuid::new_v4());
    let user_email = format!("{user_id}@example.com");
    db.pool()
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &user_email],
        )
        .await
        .unwrap();
    let instance = db
        .agent_repository()
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: Uuid::new_v4().to_string(),
            name: "admin-instance-routes".into(),
            public_ssh_key: None,
            instance_url: Some("https://agent.example.com".into()),
            instance_token: Some("instance-secret".into()),
            dashboard_url: Some("https://dashboard.example.com".into()),
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();

    let token = mock_login(&server, ADMIN_EMAIL).await;
    let auth = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

    let response = server
        .patch(&format!("/v1/admin/agents/instances/{}", instance.id))
        .add_header(HeaderName::from_static("authorization"), auth.clone())
        .json(&json!({
            "agent_api_base_url": "https://manager.example.com",
            "instance_url": "https://other.example.com",
            "instance_token": "replacement-token",
            "dashboard_url": "https://other-dashboard.example.com",
        }))
        .await;
    assert_eq!(
        response.status_code(),
        405,
        "PATCH on an admin instance must not be routed"
    );

    let stored = db
        .agent_repository()
        .get_instance(instance.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.instance_url.as_deref(),
        Some("https://agent.example.com")
    );
    assert_eq!(stored.instance_token.as_deref(), Some("instance-secret"));
    assert_eq!(
        stored.dashboard_url.as_deref(),
        Some("https://dashboard.example.com")
    );
    assert_eq!(stored.agent_api_base_url, None);

    // DELETE on the same path is still routed.
    let response = server
        .delete(&format!("/v1/admin/agents/instances/{}", Uuid::new_v4()))
        .add_header(HeaderName::from_static("authorization"), auth)
        .await;
    assert_eq!(response.status_code(), 404);

    cleanup_user_agent_instances(&db, &user_email).await;
    db.pool()
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .await
        .unwrap();
}
