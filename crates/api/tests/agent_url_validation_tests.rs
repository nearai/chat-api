mod common;

use common::{
    cleanup_user_agent_instances, create_test_server_with_state, mock_login, TestServerConfig,
};
use http::{HeaderName, HeaderValue};
use serde_json::json;
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::UserId;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "agent-url-validation@admin.org";

async fn create_instance(db: &database::Database) -> (UserId, Uuid) {
    let user_id = UserId(Uuid::new_v4());
    db.pool()
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO users(id,email) VALUES($1,$2)",
            &[&user_id, &format!("{user_id}@example.com")],
        )
        .await
        .unwrap();
    let instance = db
        .agent_repository()
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: Uuid::new_v4().to_string(),
            name: "url-validation".into(),
            public_ssh_key: None,
            instance_url: Some("https://agent.example.com".into()),
            instance_token: Some("instance-secret".into()),
            dashboard_url: Some("https://dashboard.example.com".into()),
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .unwrap();
    (user_id, instance.id)
}

async fn cleanup(db: &database::Database, user_id: UserId) {
    cleanup_user_agent_instances(db, &format!("{user_id}@example.com")).await;
    db.pool()
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn admin_patch_instance_validates_urls() {
    let (server, db, state) = create_test_server_with_state(TestServerConfig::default()).await;
    let (user_id, instance_id) = create_instance(&db).await;
    let token = mock_login(&server, ADMIN_EMAIL).await;
    let auth = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    let path = format!("/v1/admin/agents/instances/{instance_id}");

    let rejected = [
        json!({"instance_url": "http://127.0.0.1:8443/"}),
        json!({"instance_url": "http://localhost:8000"}),
        json!({"instance_url": "http://[::1]/"}),
        json!({"instance_url": "file:///etc/passwd"}),
        json!({"dashboard_url": "http://169.254.169.254/"}),
        json!({"agent_api_base_url": "https://unconfigured-manager.example.com"}),
    ];
    for body in rejected {
        let response = server
            .patch(&path)
            .add_header(HeaderName::from_static("authorization"), auth.clone())
            .json(&body)
            .await;
        assert_eq!(response.status_code(), 400, "expected rejection for {body}");
    }

    // Rejected requests leave the stored values unchanged.
    let unchanged = db
        .agent_repository()
        .get_instance(instance_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unchanged.instance_url.as_deref(),
        Some("https://agent.example.com")
    );
    assert_eq!(
        unchanged.dashboard_url.as_deref(),
        Some("https://dashboard.example.com")
    );
    assert_eq!(unchanged.agent_api_base_url, None);

    // A configured manager and regular URLs are accepted.
    let manager_url = state
        .agent_service
        .manager_urls()
        .into_iter()
        .next()
        .expect("at least one agent manager is configured");
    let response = server
        .patch(&path)
        .add_header(HeaderName::from_static("authorization"), auth.clone())
        .json(&json!({
            "agent_api_base_url": manager_url,
            "instance_url": "https://agent2.example.com/?token=abc",
            "dashboard_url": "https://dashboard2.example.com",
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    let updated = db
        .agent_repository()
        .get_instance(instance_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.agent_api_base_url.as_deref(),
        Some(manager_url.as_str())
    );
    assert_eq!(
        updated.instance_url.as_deref(),
        Some("https://agent2.example.com/?token=abc")
    );
    assert_eq!(
        updated.dashboard_url.as_deref(),
        Some("https://dashboard2.example.com")
    );

    cleanup(&db, user_id).await;
}
