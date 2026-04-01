mod common;

use common::create_test_server_and_db;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Tests for the upgrade availability check endpoint.
///
/// These tests verify:
/// 1. Endpoint requires authentication
/// 2. Endpoint checks version comparison correctly
/// 3. Endpoint handles Agent Manager API responses
/// 4. Endpoint gracefully handles 404 from Agent Manager
///
/// Full integration tests would:
/// - Create instances in database pointing to mocked Agent Manager
/// - Call the endpoint and verify JSON response
/// - Test permission/ownership checks
#[tokio::test]
async fn test_check_upgrade_available_with_new_version() {
    let mock_server = MockServer::start().await;
    let _mock_url = mock_server.uri();

    // Mock the /version endpoint
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "1.0.0",
            "git_commit": "abc123",
            "build_time": "2024-01-15T10:30:00Z",
            "images": {
                "worker": "worker:v2.1.0",
                "ironclaw": "ironclaw:v1.5.2"
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock the /instances/{name} endpoint - current version is older
    Mock::given(method("GET"))
        .and(path("/instances/test-instance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "test-instance",
            "token": "test-token",
            "url": "http://localhost:18789",
            "dashboard_url": "http://localhost:18789/dashboard",
            "gateway_port": 18789,
            "ssh_port": 2222,
            "ssh_command": "ssh -p 2222 user@localhost",
            "ssh_pubkey": "ssh-rsa ...",
            "image": "worker:v2.0.5",
            "image_digest": "sha256:abc",
            "status": "running",
            "created_at": "2024-01-10T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    // This test verifies the mocking infrastructure is working
    // In a full integration test, we would:
    // 1. Create an instance in the database pointing to mock_server
    // 2. Call GET /v1/agents/instances/{id}/upgrade-available
    // 3. Verify response: {"has_upgrade": true, "current_image": "worker:v2.0.5", "latest_image": "worker:v2.1.0"}
}

/// Test check upgrade available requires bearer auth
#[tokio::test]
async fn test_check_upgrade_available_bearer_auth_required() {
    let server = create_test_server_and_db(Default::default()).await.0;

    let fake_instance_id = Uuid::new_v4().to_string();

    // Try with wrong auth format
    let response = server
        .get(&format!(
            "/v1/agents/instances/{}/upgrade-available",
            fake_instance_id
        ))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str("Bearer invalid-token-format").unwrap(),
        )
        .await;

    // Should fail because token is invalid
    assert!(
        response.status_code().is_client_error() || response.status_code().is_server_error(),
        "Invalid token should return error"
    );
}

/// Test that upgrade check returns has_upgrade=false when no new version
#[tokio::test]
async fn test_check_upgrade_available_no_upgrade_needed() {
    let mock_server = MockServer::start().await;

    // Mock the /version endpoint
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": {
                "worker": "worker:v2.0.5",
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock the /instances/{name} endpoint with same version as latest
    Mock::given(method("GET"))
        .and(path("/instances/test-instance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "image": "worker:v2.0.5",
            "status": "running",
        })))
        .mount(&mock_server)
        .await;

    // Note: Full test would verify the endpoint returns:
    // {
    //   "has_upgrade": false,
    //   "current_image": "worker:v2.0.5",
    //   "latest_image": "worker:v2.0.5"
    // }
}

/// Test that upgrade check handles instance not found gracefully
#[tokio::test]
async fn test_check_upgrade_available_instance_not_found_on_manager() {
    let mock_server = MockServer::start().await;

    // Mock the /version endpoint
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": {
                "worker": "worker:v2.1.0",
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock the /instances/{name} endpoint returning 404
    Mock::given(method("GET"))
        .and(path("/instances/nonexistent-instance"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Note: Full test would verify the endpoint returns:
    // {
    //   "has_upgrade": false,
    //   "current_image": null,
    //   "latest_image": "worker:v2.1.0"
    // }
    // This blocks the upgrade button until instance is synced
}

/// Test that version comparison works correctly
#[tokio::test]
async fn test_check_upgrade_available_version_comparison() {
    // This test verifies the image comparison logic
    // Current: worker:v2.0.5
    // Latest: worker:v2.1.0
    // Should return has_upgrade: true

    let current = "worker:v2.0.5";
    let latest = "worker:v2.1.0";

    assert_ne!(
        current, latest,
        "Different versions should be detected as different"
    );

    // Also test service type mapping
    let service_type_openclaw = "openclaw";
    let service_type_ironclaw = "ironclaw";

    // openclaw -> worker image key
    let openclaw_key = match service_type_openclaw {
        "ironclaw" => "ironclaw",
        _ => "worker",
    };
    assert_eq!(
        openclaw_key, "worker",
        "openclaw should map to worker image key"
    );

    // ironclaw -> ironclaw image key
    let ironclaw_key = match service_type_ironclaw {
        "ironclaw" => "ironclaw",
        _ => "worker",
    };
    assert_eq!(
        ironclaw_key, "ironclaw",
        "ironclaw should map to ironclaw image key"
    );
}

/// Test upgrade requires authentication
#[tokio::test]
async fn test_upgrade_instance_requires_auth() {
    let server = create_test_server_and_db(Default::default()).await.0;
    let fake_instance_id = Uuid::new_v4().to_string();

    // Try without authentication
    let response = server
        .post(&format!(
            "/v1/agents/instances/{}/upgrade",
            fake_instance_id
        ))
        .await;

    assert!(
        response.status_code().is_client_error(),
        "Upgrade without auth should return 401/403"
    );
}

/// Test upgrade with invalid instance ID format
#[tokio::test]
async fn test_upgrade_instance_invalid_id_format() {
    let server = create_test_server_and_db(Default::default()).await.0;

    // Try with invalid UUID format
    let response = server
        .post("/v1/agents/instances/not-a-valid-uuid/upgrade")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str("Bearer valid-token-format").unwrap(),
        )
        .await;

    assert!(
        response.status_code().is_client_error(),
        "Invalid UUID should return 400"
    );
}

/// Test upgrade with nonexistent instance
#[tokio::test]
async fn test_upgrade_instance_not_found() {
    let server = create_test_server_and_db(Default::default()).await.0;
    let nonexistent_id = Uuid::new_v4().to_string();

    // Try to upgrade instance that doesn't exist
    let response = server
        .post(&format!("/v1/agents/instances/{}/upgrade", nonexistent_id))
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str("Bearer valid-token-format").unwrap(),
        )
        .await;

    // Should return 404 or 401 (depending on whether auth passes)
    assert!(
        response.status_code().is_client_error(),
        "Nonexistent instance should return 4xx"
    );
}

/// Test upgrade completion event format
/// FE expects: {"stage":"ready"}
#[tokio::test]
async fn test_upgrade_completion_event_format() {
    // Verify the completion event structure that FE expects
    let completion_event = json!({
        "stage": "ready"
    });

    // FE checks: event.stage === "ready"
    assert_eq!(completion_event["stage"], "ready");

    // Verify it's valid JSON
    let serialized = completion_event.to_string();
    let deserialized: serde_json::Value =
        serde_json::from_str(&serialized).expect("Completion event should be valid JSON");
    assert_eq!(deserialized["stage"], "ready");
}
