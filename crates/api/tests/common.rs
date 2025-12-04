#![allow(dead_code)]

use api::{create_router, AppState};
use axum_test::TestServer;
use serde_json::json;
use services::file::service::FileServiceImpl;
use services::vpc::test_helpers::MockVpcCredentialsService;
use services::vpc::VpcCredentials;
use std::sync::Arc;
use tokio::sync::OnceCell;

// Global once cell to ensure migrations only run once across all tests
static MIGRATIONS_INITIALIZED: OnceCell<()> = OnceCell::const_new();

/// Configuration for test server with Cloud API mocking
pub struct TestServerConfig {
    pub vpc_credentials: Option<VpcCredentials>,
    pub cloud_api_base_url: String,
    pub near_expected_recipient: Option<String>,
    pub near_rpc_url: Option<String>,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            vpc_credentials: None,
            cloud_api_base_url: String::new(),
            near_expected_recipient: Some("localhost".to_string()),
            near_rpc_url: Some("https://rpc.testnet.near.org".to_string()),
        }
    }
}

/// Create a test server with all services initialized (VPC not configured)
pub async fn create_test_server() -> TestServer {
    create_test_server_with_config(TestServerConfig::default()).await
}

/// Create a test server with custom configuration
pub async fn create_test_server_with_config(test_config: TestServerConfig) -> TestServer {
    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let mut config = config::Config::from_env();

    config.near.expected_recipient = test_config
        .near_expected_recipient
        .clone()
        .unwrap_or(config.near.expected_recipient);

    if let Some(rpc_url) = test_config.near_rpc_url.clone() {
        config.near.rpc_url = rpc_url;
    }

    // Create database connection
    let db = database::Database::from_config(&config.database)
        .await
        .expect("Failed to connect to database");

    // Run migrations only once, even when tests run in parallel
    MIGRATIONS_INITIALIZED
        .get_or_init(|| async {
            db.run_migrations()
                .await
                .expect("Failed to run database migrations");
        })
        .await;

    // Get repositories
    let user_repo = db.user_repository();
    let session_repo = db.session_repository();
    let oauth_repo = db.oauth_repository();
    let conversation_repo = db.conversation_repository();
    let file_repo = db.file_repository();
    let user_settings_repo = db.user_settings_repository();
    let near_nonce_repo = db.near_nonce_repository();

    // Create services
    let oauth_service = Arc::new(services::auth::OAuthServiceImpl::new(
        oauth_repo.clone(),
        session_repo.clone(),
        user_repo.clone(),
        near_nonce_repo,
        config.near.expected_recipient.clone(),
        config.near.rpc_url.clone(),
        config.oauth.google_client_id.clone(),
        config.oauth.google_client_secret.clone(),
        config.oauth.github_client_id.clone(),
        config.oauth.github_client_secret.clone(),
        config.oauth.redirect_uri.clone(),
    ));

    let user_service = Arc::new(services::user::UserServiceImpl::new(user_repo.clone()));

    let user_settings_service = Arc::new(services::user::UserSettingsServiceImpl::new(
        user_settings_repo as Arc<dyn services::user::ports::UserSettingsRepository>,
    ));

    // Create VPC credentials service based on provided credentials
    let vpc_credentials_service: Arc<dyn services::vpc::VpcCredentialsService> =
        match test_config.vpc_credentials {
            Some(creds) => Arc::new(MockVpcCredentialsService::with_credentials(creds)),
            None => Arc::new(MockVpcCredentialsService::not_configured()),
        };

    // Initialize OpenAI proxy service
    let mut proxy_service =
        services::response::service::OpenAIProxy::new(vpc_credentials_service.clone());
    if let Some(base_url) = config.openai.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let proxy_service = Arc::new(proxy_service);

    // Initialize conversation service
    let conversation_service = Arc::new(
        services::conversation::service::ConversationServiceImpl::new(
            conversation_repo,
            proxy_service.clone(),
        ),
    );

    let mut admin_domains = config.admin.admin_domains;

    // Add `admin.org` as test admin domain
    admin_domains.push("admin.org".to_string());

    let file_service = Arc::new(FileServiceImpl::new(file_repo, proxy_service.clone()));

    // Create application state
    let app_state = AppState {
        vpc_credentials_service,
        oauth_service,
        user_service,
        user_settings_service,
        session_repository: session_repo,
        user_repository: user_repo,
        proxy_service,
        conversation_service,
        file_service,
        redirect_uri: config.oauth.redirect_uri,
        admin_domains: Arc::new(admin_domains),
        cloud_api_base_url: test_config.cloud_api_base_url.clone(),
    };

    // Create router
    let app = create_router(app_state);

    // Create test server
    TestServer::new(app).expect("Failed to create test server")
}

/// Helper function to get/create a user and get a session token via mock login.
///
/// To use this function, you need to enable test feature: `cargo test --features test`
pub async fn mock_login(server: &TestServer, email: &str) -> String {
    let login_request = json!({
        "email": email,
        "name": format!("Test User {}", email),
    });

    let response = server
        .post("/v1/auth/mock-login")
        .json(&login_request)
        .await;

    assert_eq!(response.status_code(), 200, "Mock login should succeed");

    let body: serde_json::Value = response.json();
    body.get("token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .expect("Response should contain token")
}
