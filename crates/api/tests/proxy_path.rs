mod common;

use common::{create_test_server, mock_login};

/// Test that allowed proxy paths are accepted
#[tokio::test]
async fn test_allowed_proxy_paths() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test-proxy@example.com").await;

    // Test all allowed paths from ALLOWED_PROXY_PATHS
    let allowed_paths = vec!["models", "model/list"];

    for path in allowed_paths {
        let response = server
            .get(&format!("/v1/{}", path))
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_ne!(response.status_code(), 500);

        // Allowed paths should not return 403 Forbidden
        // They might fail for other reasons (e.g., OpenAI API not available in tests),
        // but they should not be blocked by the whitelist
        assert_ne!(
            response.status_code(),
            403,
            "Path '{}' should be allowed, but got 403 Forbidden",
            path
        );
    }
}

/// Test that allowed paths with sub-paths are accepted
#[tokio::test]
async fn test_allowed_proxy_paths_with_subpaths() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test-proxy@example.com").await;

    // Test sub-paths of allowed paths
    let allowed_subpaths = vec!["files/123", "files/abc/download"];

    for path in allowed_subpaths {
        let response = server
            .get(&format!("/v1/{}", path))
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_ne!(response.status_code(), 500);

        // Sub-paths of allowed paths should not return 403 Forbidden
        assert_ne!(
            response.status_code(),
            403,
            "Sub-path '{}' should be allowed, but got 403 Forbidden",
            path
        );
    }
}

/// Test that disallowed proxy paths are rejected with 403
#[tokio::test]
async fn test_disallowed_proxy_paths() {
    let server = create_test_server().await;
    let token = mock_login(&server, "test@example.com").await;

    // Test paths that are NOT in the whitelist
    let disallowed_paths = vec!["admin", "v1/models", "random/path"];

    for path in disallowed_paths {
        let response = server
            .get(&format!("/v1/{}", path))
            .add_header(
                http::HeaderName::from_static("authorization"),
                http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            )
            .await;

        // Disallowed paths should return 403 Forbidden
        assert_eq!(
            response.status_code(),
            403,
            "Path '{}' should be rejected with 403 Forbidden, but got {}",
            path,
            response.status_code()
        );

        // Verify error message
        let body: serde_json::Value = response.json();
        assert!(
            body.get("error").is_some(),
            "Error response should contain 'error' field for path '{}'",
            path
        );

        let error_msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            error_msg.contains("not allowed"),
            "Error message should indicate path is not allowed for path '{}', got: {}",
            path,
            error_msg
        );
    }
}
