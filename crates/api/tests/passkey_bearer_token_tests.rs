mod common;

use common::{create_test_server_and_db, mock_login};
use serial_test::serial;
use services::agent::ports::{AgentRepository, CreateInstanceParams};
use services::user::ports::UserRepository;
use uuid::Uuid;

#[tokio::test]
#[serial]
async fn test_passkey_credentials_stored_and_retrievable() {
    let (server, db) = create_test_server_and_db(Default::default()).await;
    let user_email = format!("passkey-credentials-{}@example.com", Uuid::new_v4());
    mock_login(&server, &user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(&user_email)
        .await
        .expect("User lookup should succeed")
        .expect("User should exist");
    let agent_repo = db.agent_repository();
    let auth_secret = "test-auth-secret";
    let backup_passphrase = "test-backup-passphrase";

    agent_repo
        .upsert_user_passkey_credentials(user.id, auth_secret, backup_passphrase)
        .await
        .expect("Passkey credentials should be stored");

    let stored = agent_repo
        .get_user_passkey_credentials(user.id)
        .await
        .expect("Passkey credential lookup should succeed")
        .expect("Passkey credentials should exist");

    assert_eq!(stored, (auth_secret.into(), backup_passphrase.into()));
}

#[tokio::test]
#[serial]
async fn test_list_instances_returns_correct_structure() {
    let (server, db) = create_test_server_and_db(Default::default()).await;
    let user_email = format!("passkey-instance-list-{}@example.com", Uuid::new_v4());
    let user_token = mock_login(&server, &user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(&user_email)
        .await
        .expect("User lookup should succeed")
        .expect("User should exist");
    let instance = db
        .agent_repository()
        .create_instance(CreateInstanceParams {
            user_id: user.id,
            instance_id: Uuid::new_v4().to_string(),
            name: "passkey-instance-list".into(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
        })
        .await
        .expect("Instance fixture should be created");

    let response = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), 200);

    let body: serde_json::Value = response.json();
    let items = body["items"]
        .as_array()
        .expect("Response should contain items");

    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], instance.id.to_string());
    assert_eq!(items[0]["name"], instance.name);
    assert!(items[0].get("instance_token").is_none());
    assert!(items[0].get("auth_secret").is_none());
    assert!(items[0].get("backup_passphrase").is_none());
}
