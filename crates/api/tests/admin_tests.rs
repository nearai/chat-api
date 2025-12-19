mod common;

use common::{create_test_server, create_test_server_with_config, mock_login, TestServerConfig};
use services::vpc::VpcCredentials;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
async fn test_get_system_prompt_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_prompt@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .get("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to get system prompt"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
async fn test_set_system_prompt_with_non_admin_account() {
    let server = create_test_server().await;

    let non_admin_email = "test_user_set_prompt@no-admin.org";
    let non_admin_token = mock_login(&server, non_admin_email).await;

    let response = server
        .post("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {non_admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&serde_json::json!({
            "system_prompt": "You are a helpful assistant."
        }))
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 403,
        "Non-admin should receive 403 Forbidden when trying to set system prompt"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Admin access required"));
}

#[tokio::test]
async fn test_get_system_prompt_with_admin_success() {
    let mock_cloud_api = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/organizations/test-org-123/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "settings": {
                "system_prompt": "You are a helpful AI assistant."
            }
        })))
        .mount(&mock_cloud_api)
        .await;

    let vpc_credentials = VpcCredentials {
        access_token: "test-access-token".to_string(),
        organization_id: "test-org-123".to_string(),
        api_key: "test-api-key".to_string(),
    };

    let server = create_test_server_with_config(TestServerConfig {
        vpc_credentials: Some(vpc_credentials),
        cloud_api_base_url: mock_cloud_api.uri(),
    })
    .await;

    let admin_email = "test_admin_get_prompt_success@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .get("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to get system prompt");

    let body: serde_json::Value = response.json();
    let system_prompt = body.get("system_prompt").and_then(|v| v.as_str());
    assert_eq!(system_prompt, Some("You are a helpful AI assistant."));
}

#[tokio::test]
async fn test_set_system_prompt_with_admin_success() {
    let mock_cloud_api = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/organizations/test-org-456/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "settings": {
                "system_prompt": "You are a helpful assistant."
            }
        })))
        .mount(&mock_cloud_api)
        .await;

    let vpc_credentials = VpcCredentials {
        access_token: "test-access-token".to_string(),
        organization_id: "test-org-456".to_string(),
        api_key: "test-api-key".to_string(),
    };

    let server = create_test_server_with_config(TestServerConfig {
        vpc_credentials: Some(vpc_credentials),
        cloud_api_base_url: mock_cloud_api.uri(),
    })
    .await;

    let admin_email = "test_admin_set_prompt_success@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .post("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&serde_json::json!({
            "system_prompt": "You are a helpful assistant."
        }))
        .await;

    let status = response.status_code();
    assert_eq!(status, 200, "Admin should be able to set system prompt");

    let body: serde_json::Value = response.json();
    let system_prompt = body.get("system_prompt").and_then(|v| v.as_str());
    assert_eq!(system_prompt, Some("You are a helpful assistant."));
}

#[tokio::test]
async fn test_get_system_prompt_with_admin_but_vpc_not_configured() {
    let server = create_test_server().await;

    let admin_email = "test_admin_get_prompt@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .get("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 500,
        "Admin should receive 500 Internal Server Error when VPC is not configured"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Cloud API not configured"));
}

#[tokio::test]
async fn test_set_system_prompt_with_admin_but_vpc_not_configured() {
    let server = create_test_server().await;

    let admin_email = "test_admin_set_prompt@admin.org";
    let admin_token = mock_login(&server, admin_email).await;

    let response = server
        .post("/v1/admin/system_prompt")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&serde_json::json!({
            "system_prompt": "You are a helpful assistant."
        }))
        .await;

    let status = response.status_code();
    assert_eq!(
        status, 500,
        "Admin should receive 500 Internal Server Error when VPC is not configured"
    );

    let body: serde_json::Value = response.json();
    let error = body.get("message").and_then(|v| v.as_str());
    assert_eq!(error, Some("Cloud API not configured"));
}
