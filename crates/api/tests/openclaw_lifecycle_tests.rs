mod common;

use common::{create_test_server, mock_login};
use uuid::Uuid;

/// Test that starting an instance requires authentication
#[tokio::test]
async fn test_start_instance_requires_auth() {
    let server = create_test_server().await;
    let fake_id = Uuid::new_v4();

    let response = server
        .post(&format!("/v1/agents/instances/{}/start", fake_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to start instance"
    );
}

/// Test that stopping an instance requires authentication
#[tokio::test]
async fn test_stop_instance_requires_auth() {
    let server = create_test_server().await;
    let fake_id = Uuid::new_v4();

    let response = server
        .post(&format!("/v1/agents/instances/{}/stop", fake_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to stop instance"
    );
}

/// Test that restarting an instance requires authentication
#[tokio::test]
async fn test_restart_instance_requires_auth() {
    let server = create_test_server().await;
    let fake_id = Uuid::new_v4();

    let response = server
        .post(&format!("/v1/agents/instances/{}/restart", fake_id))
        .await;

    assert_eq!(
        response.status_code(),
        401,
        "Should require authentication to restart instance"
    );
}

/// Test that starting a non-existent instance returns 404
#[tokio::test]
async fn test_start_instance_not_found() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "user@example.com").await;
    let fake_id = Uuid::new_v4();

    let response = server
        .post(&format!("/v1/agents/instances/{}/start", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 for non-existent instance"
    );
}

/// Test that creating a backup requires admin authentication
#[tokio::test]
async fn test_create_backup_requires_admin() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "user@example.com").await;
    let fake_id = Uuid::new_v4();

    let response = server
        .post(&format!("/v1/admin/agents/instances/{}/backup", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should get forbidden when creating backup"
    );
}

/// Test that listing backups requires admin authentication
#[tokio::test]
async fn test_list_backups_requires_admin() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "user@example.com").await;
    let fake_id = Uuid::new_v4();

    let response = server
        .get(&format!("/v1/admin/agents/instances/{}/backups", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should get forbidden when listing backups"
    );
}

/// Test that getting a backup requires admin authentication
#[tokio::test]
async fn test_get_backup_requires_admin() {
    let server = create_test_server().await;
    let user_token = mock_login(&server, "user@example.com").await;
    let fake_id = Uuid::new_v4();
    let fake_backup_id = Uuid::new_v4();

    let response = server
        .get(&format!(
            "/v1/admin/agents/instances/{}/backups/{}",
            fake_id, fake_backup_id
        ))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response.status_code(),
        403,
        "Non-admin should get forbidden when getting backup"
    );
}

/// Test that listing backups as admin returns 404 for non-existent instance
#[tokio::test]
async fn test_list_backups_not_found() {
    let server = create_test_server().await;
    let admin_token = mock_login(&server, "admin@admin.org").await;
    let fake_id = Uuid::new_v4();

    let response = server
        .get(&format!("/v1/admin/agents/instances/{}/backups", fake_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    // Should fail because instance doesn't exist
    assert_eq!(
        response.status_code(),
        404,
        "Should return 404 for non-existent instance"
    );
}
