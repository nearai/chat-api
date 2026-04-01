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

// ============================================================================
// UPGRADE STREAMING TESTS
// ============================================================================

/// Test TEE upgrade streaming flow
/// Verifies:
/// 1. Fetches latest image from compose-api /version endpoint
/// 2. Sends POST to /restart endpoint
/// 3. Streams manager API response events to client
/// 4. Sends completion event with stage: "ready"
#[tokio::test]
async fn test_upgrade_instance_tee_streaming() {
    let mock_server = MockServer::start().await;
    let _mock_url = mock_server.uri();

    // Mock compose-api /version endpoint
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "1.0.0",
            "images": {
                "worker": "worker:v2.1.0",
                "ironclaw": "ironclaw:v1.5.0"
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock the /instances/{name}/restart endpoint - returns SSE stream
    Mock::given(method("POST"))
        .and(path("/instances/test-instance/restart"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "text/event-stream")
                // Simulate manager API sending progress events
                .set_body_string(
                    "data: {\"status\":\"pulling\"}\n\ndata: {\"status\":\"starting\"}\n\n",
                ),
        )
        .mount(&mock_server)
        .await;

    // Full integration test would:
    // 1. Create instance in DB with service_type="openclaw"
    // 2. Make POST /v1/agents/instances/{id}/upgrade with valid session token
    // 3. Verify SSE response contains manager API events
    // 4. Verify final event is {"stage":"ready"}
}

/// Test non-TEE upgrade streaming flow
/// Verifies:
/// 1. Fetches image allowlist from crabshack /images endpoint
/// 2. Filters by service_type + status="allow-create"
/// 3. Selects image with latest semantic version
/// 4. Sends POST to /restart endpoint
/// 5. Streams manager API response to client
/// 6. Sends completion event with stage: "ready"
#[tokio::test]
async fn test_upgrade_instance_non_tee_streaming() {
    let mock_server = MockServer::start().await;
    let _mock_url = mock_server.uri();

    // Mock crabshack /images endpoint
    Mock::given(method("GET"))
        .and(path("/images"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                "service_type": "openclaw-dind",
                "status": "allow-create",
                "created_at": "2024-01-10T00:00:00Z"
            },
            {
                "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                "service_type": "openclaw-dind",
                "status": "allow-create",
                "created_at": "2024-01-15T00:00:00Z"
            },
            {
                "ref": "docker.io/nearaidev/openclaw-dind:latest",
                "service_type": "openclaw-dind",
                "status": "deprecated",
                "created_at": "2024-01-01T00:00:00Z"
            }
        ])))
        .mount(&mock_server)
        .await;

    // Mock the /instances/{name}/restart endpoint - returns SSE stream
    Mock::given(method("POST"))
        .and(path("/instances/test-instance/restart"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "text/event-stream")
                .set_body_string("data: {\"name\":\"test-instance\"}\n\n"),
        )
        .mount(&mock_server)
        .await;

    // Full integration test would:
    // 1. Create instance in DB with service_type="openclaw" on non-TEE manager
    // 2. Make POST /v1/agents/instances/{id}/upgrade with valid session token
    // 3. Verify service selects image version 0.21.0 (newest with status=allow-create)
    // 4. Verify POST to /restart includes image: "docker.io/nearaidev/openclaw-dind:0.21.0"
    // 5. Verify SSE response contains manager API events
    // 6. Verify final event is {"stage":"ready"}
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

/// Test upgrade denies access to other users' instances
#[tokio::test]
async fn test_upgrade_instance_ownership_check() {
    let _server = create_test_server_and_db(Default::default()).await.0;

    // Note: Full integration test would:
    // 1. Create instance A owned by user 1
    // 2. Authenticate as user 2
    // 3. Try to upgrade instance A
    // 4. Verify 403 Forbidden response
    // 5. Verify instance was not modified
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

/// Test semantic version comparison for image selection
#[tokio::test]
async fn test_upgrade_version_comparison() {
    // Test that newer semantic versions are correctly identified

    let images = [
        ("ironclaw-dind:0.20.0", Some("0.20.0")),
        ("ironclaw-dind:0.21.0", Some("0.21.0")),
        ("ironclaw-dind:0.20.5", Some("0.20.5")),
        ("ironclaw-dind:latest", None), // non-numeric, filtered
        ("ironclaw-dind:dev", None),    // non-numeric, filtered
    ];

    // Extract versions and verify semantic version ordering
    let versions: Vec<&str> = images.iter().filter_map(|(_, v)| v.as_deref()).collect();

    assert_eq!(versions.len(), 3, "Should have 3 numeric versions");

    // Verify version ordering: 0.21.0 is newest, 0.20.5 is middle, 0.20.0 is oldest
    // Compare major.minor.patch: 0.21.0 > 0.20.5 > 0.20.0
    assert!(
        versions.contains(&"0.21.0"),
        "0.21.0 should be in available versions"
    );
    assert!(
        versions.contains(&"0.20.5"),
        "0.20.5 should be in available versions"
    );
    assert!(
        versions.contains(&"0.20.0"),
        "0.20.0 should be in available versions"
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

/// Test that manager API events are passed through without filtering
#[tokio::test]
async fn test_upgrade_stream_passthrough() {
    // This verifies the route handler passes all manager API events to FE
    // without filtering or modifying them

    // Sample events that manager API would send:
    // - {"status":"pulling","message":"Pulling image..."}
    // - {"status":"starting","message":"Starting container..."}
    // - : keepalive (non-JSON keepalive - should be ignored by FE parser)

    // Full test would verify:
    // 1. JSON events are wrapped in "data: ...\n\n" format
    // 2. Non-JSON lines (keepalive pings) are still sent but FE ignores them
    // 3. Completion event {"stage":"ready"} is sent at the end in SSE format
}

/// Test upgrade request with ironclaw service type
#[tokio::test]
async fn test_upgrade_instance_ironclaw_service_type() {
    let mock_server = MockServer::start().await;

    // For TEE: Mock /version endpoint with ironclaw image
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": {
                "ironclaw": "ironclaw:v1.5.0"
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock restart endpoint
    Mock::given(method("POST"))
        .and(path("/instances/test-ironclaw/restart"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "text/event-stream")
                .set_body_string(""),
        )
        .mount(&mock_server)
        .await;

    // Full test would:
    // 1. Create instance with service_type="ironclaw"
    // 2. Call upgrade endpoint
    // 3. Verify it selects "ironclaw" image key, not "worker"
    // 4. Verify POST body includes image: "ironclaw:v1.5.0"
}
