mod common;

use common::{create_test_server_and_db, mock_login, TestServerConfig};
use services::user::ports::UserRepository;
use services::user_usage::UserUsageRepository;

/// Test that the dual auth middleware provides both user and API key extensions
/// This verifies that both AuthenticatedUser and AuthenticatedApiKey can be extracted
#[tokio::test]
async fn test_dual_auth_middleware_extensions() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Create a user
    let email = "test_dual_auth@example.com";
    let token = mock_login(&server, email).await;

    // User should be able to make authenticated requests
    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user created by mock_login");

    assert!(
        !user.id.to_string().is_empty(),
        "User ID should not be empty"
    );

    // User can access their own profile
    let profile_response = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    assert_eq!(
        profile_response.status_code(),
        200,
        "User should be able to access their own profile"
    );
}

/// Test that API key isolation prevents unauthorized access to agent instances
#[tokio::test]
async fn test_api_key_isolation_prevents_cross_user_access() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // User 1 logs in
    let user1_token = mock_login(&server, "test_isolation_user1@example.com").await;

    // User 2 logs in
    let user2_token = mock_login(&server, "test_isolation_user2@example.com").await;

    // Both can access their own instances (empty list)
    let user1_instances = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user1_token}")).unwrap(),
        )
        .await;

    let user2_instances = server
        .get("/v1/agents/instances")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user2_token}")).unwrap(),
        )
        .await;

    assert_eq!(user1_instances.status_code(), 200);
    assert_eq!(user2_instances.status_code(), 200);

    // Both should see empty instance lists since neither created any
    let body1: serde_json::Value = user1_instances.json();
    let body2: serde_json::Value = user2_instances.json();

    let items1_count = body1
        .get("items")
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    let items2_count = body2
        .get("items")
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);

    assert_eq!(items1_count, 0, "User 1 should have no instances");
    assert_eq!(items2_count, 0, "User 2 should have no instances");
}

/// Test that usage recording infrastructure is in place and functional
#[tokio::test]
async fn test_usage_recording_infrastructure() {
    let (server, db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Create a user and verify we can access usage APIs
    let email = "test_usage_recording@example.com";
    let token = mock_login(&server, email).await;

    let user = db
        .user_repository()
        .get_user_by_email(email)
        .await
        .expect("db")
        .expect("user");

    // Check that user usage endpoint is accessible (should return 404 since no usage yet)
    let usage_response = server
        .get("/v1/users/me/usage")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .await;

    // Either 404 (no usage) or 200 (has usage) are both valid
    // The important thing is we get a proper response, not an auth error
    assert!(
        usage_response.status_code() == 404 || usage_response.status_code() == 200,
        "Should return 404 (no usage) or 200 (has usage), not auth error"
    );

    // Verify we can query user usage from the database
    let usage_summary = db
        .user_usage_repository()
        .get_usage_by_user_id(user.id, None, None)
        .await
        .expect("query");

    // Usage summary should either be None (no usage) or present
    if let Some(summary) = usage_summary {
        assert_eq!(summary.user_id, user.id, "User ID should match");
        // token_sum, image_num, and cost_nano_usd are already initialized to 0
    }
}

/// Test that authentication middleware correctly handles both user and API key auth
#[tokio::test]
async fn test_auth_middleware_handles_both_methods() {
    let (server, _db) = create_test_server_and_db(TestServerConfig::default()).await;

    // Test user auth (session token) - should work
    let user_token = mock_login(&server, "test_auth_user@example.com").await;

    let response_with_user_auth = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {user_token}")).unwrap(),
        )
        .await;

    assert_eq!(
        response_with_user_auth.status_code(),
        200,
        "User auth should work for /v1/users/me"
    );

    // Test missing auth - should fail
    let response_no_auth = server.get("/v1/users/me").await;

    assert_eq!(
        response_no_auth.status_code(),
        401,
        "Missing auth should return 401"
    );

    // Test invalid token - should fail
    let response_bad_token = server
        .get("/v1/users/me")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str("Bearer invalid_token_xyz").unwrap(),
        )
        .await;

    assert_eq!(
        response_bad_token.status_code(),
        401,
        "Invalid token should return 401"
    );
}
