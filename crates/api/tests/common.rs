#![allow(dead_code)]

use api::middleware::RateLimitState;
use api::{create_router_with_cors, AppState};
use axum_test::TestServer;
use chrono::Duration;
use serde_json::json;
use services::analytics::AnalyticsServiceImpl;
use services::conversation::share_service::ConversationShareServiceImpl;
use services::file::service::FileServiceImpl;
use services::metrics::MockMetricsService;
use services::system_configs::ports::RateLimitConfig;
use services::user::ports::UserRepository;
use services::vpc::test_helpers::MockVpcCredentialsService;
use services::vpc::VpcCredentials;
use std::sync::Arc;
use tokio::sync::OnceCell;
use uuid::Uuid;

// Global once cell to ensure migrations only run once across all tests
static MIGRATIONS_INITIALIZED: OnceCell<()> = OnceCell::const_new();

/// Configuration for test server with Cloud API mocking
#[derive(Default)]
pub struct TestServerConfig {
    pub vpc_credentials: Option<VpcCredentials>,
    pub cloud_api_base_url: String,
    /// Override for the LLM proxy's upstream base URL (e.g. WireMock for tests).
    /// When set, proxy forwards to this URL instead of config.openai.base_url.
    pub proxy_base_url: Option<String>,
    /// Optional override for `/v1/responses` rate limiting in tests.
    ///
    /// If not set, tests use a permissive default to avoid unrelated flakiness.
    pub rate_limit_config: Option<RateLimitConfig>,
}

/// Restrictive rate limit config for rate limit tests.
/// Use this when tests need to trigger 429 responses (e.g. test_rate_limit_blocks_rapid_requests).
pub fn restrictive_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        max_concurrent: 2,
        max_requests_per_window: 1,
        window_duration: Duration::seconds(1),
        window_limits: vec![],
        token_window_limits: vec![],
        cost_window_limits: vec![],
    }
}

/// Create a test server with all services initialized (VPC not configured)
pub async fn create_test_server() -> TestServer {
    create_test_server_with_config(TestServerConfig::default()).await
}

/// Create a test server with custom configuration
pub async fn create_test_server_with_config(test_config: TestServerConfig) -> TestServer {
    let (server, _) = create_test_server_and_db(test_config).await;
    server
}

/// Create a test server and database for tests that need to pre-populate DB (e.g. token/cost rate limit).
pub async fn create_test_server_and_db(
    test_config: TestServerConfig,
) -> (TestServer, database::Database) {
    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let config = config::Config::from_env();

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
    let conversation_share_repo = db.conversation_share_repository();
    let file_repo = db.file_repository();
    let user_settings_repo = db.user_settings_repository();
    let model_repo = db.model_repository();
    let system_configs_repo = db.system_configs_repository();
    let near_nonce_repo = db.near_nonce_repository();

    // Create services
    let oauth_service = Arc::new(services::auth::OAuthServiceImpl::new(
        oauth_repo.clone(),
        session_repo.clone(),
        user_repo.clone(),
        near_nonce_repo,
        config.oauth.google_client_id.clone(),
        config.oauth.google_client_secret.clone(),
        config.oauth.github_client_id.clone(),
        config.oauth.github_client_secret.clone(),
        config.oauth.redirect_uri.clone(),
        config.near.rpc_url.clone(),
    ));

    let user_service = Arc::new(services::user::UserServiceImpl::new(user_repo.clone()));

    let user_settings_service = Arc::new(services::user::UserSettingsServiceImpl::new(
        user_settings_repo,
    ));

    let model_service = Arc::new(services::model::service::ModelServiceImpl::new(model_repo));

    let system_configs_service = Arc::new(
        services::system_configs::service::SystemConfigsServiceImpl::new(
            system_configs_repo
                as Arc<dyn services::system_configs::ports::SystemConfigsRepository>,
        ),
    );

    // Initialize subscription service for testing
    let subscription_service = Arc::new(services::subscription::SubscriptionServiceImpl::new(
        services::subscription::SubscriptionServiceConfig {
            db_pool: db.pool().clone(),
            stripe_customer_repo: db.stripe_customer_repository()
                as Arc<dyn services::subscription::ports::StripeCustomerRepository>,
            subscription_repo: db.subscription_repository()
                as Arc<dyn services::subscription::ports::SubscriptionRepository>,
            webhook_repo: db.payment_webhook_repository()
                as Arc<dyn services::subscription::ports::PaymentWebhookRepository>,
            system_configs_service: system_configs_service.clone()
                as Arc<dyn services::system_configs::ports::SystemConfigsService>,
            user_repository: user_repo.clone(),
            user_usage_repo: db.user_usage_repository()
                as Arc<dyn services::user_usage::UserUsageRepository>,
            stripe_secret_key: config.stripe.secret_key.clone(),
            stripe_webhook_secret: config.stripe.webhook_secret.clone(),
        },
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
    let proxy_base_url = test_config
        .proxy_base_url
        .clone()
        .or_else(|| config.openai.base_url.clone());
    if let Some(base_url) = proxy_base_url {
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

    let conversation_share_service = Arc::new(ConversationShareServiceImpl::new(
        db.conversation_repository(),
        conversation_share_repo,
        user_repo.clone(),
    ));

    let mut admin_domains = config.admin.admin_domains;

    // Add `admin.org` as test admin domain
    admin_domains.push("admin.org".to_string());

    let file_service = Arc::new(FileServiceImpl::new(file_repo, proxy_service.clone()));

    // Create metrics service (mock for tests)
    let metrics_service: Arc<dyn services::metrics::MetricsServiceTrait> =
        Arc::new(MockMetricsService);

    // Create analytics service
    let analytics_repo = db.analytics_repository();
    let analytics_service: Arc<dyn services::analytics::AnalyticsServiceTrait> =
        Arc::new(AnalyticsServiceImpl::new(
            analytics_repo.clone() as Arc<dyn services::analytics::AnalyticsRepository>
        ));

    // Create user usage service
    let user_usage_repo =
        db.user_usage_repository() as Arc<dyn services::user_usage::UserUsageRepository>;
    let user_usage_service: Arc<dyn services::user_usage::UserUsageService> = Arc::new(
        services::user_usage::UserUsageServiceImpl::new(user_usage_repo),
    );

    // Create rate limit state for testing
    // Use a permissive default to avoid unrelated rate-limit interference.
    // Individual rate limit tests can override via `TestServerConfig.rate_limit_config`.
    let default_rate_limit_config = RateLimitConfig {
        max_concurrent: 2,
        max_requests_per_window: 100,
        window_duration: Duration::seconds(60),
        window_limits: vec![],
        token_window_limits: vec![],
        cost_window_limits: vec![],
    };
    let rate_limit_state = RateLimitState::with_config(
        test_config
            .rate_limit_config
            .unwrap_or(default_rate_limit_config),
        analytics_service.clone(),
        user_usage_service.clone(),
    );

    // Create agent service for testing
    let agent_repo = db.agent_repository();
    let agent_service = Arc::new(services::agent::AgentServiceImpl::new(
        agent_repo.clone(),
        config.agent.managers.clone(),
        config.agent.nearai_api_url.clone(),
        system_configs_service.clone()
            as Arc<dyn services::system_configs::ports::SystemConfigsService>,
    ));

    // Create agent proxy service for testing
    let agent_proxy_service: Arc<dyn services::agent::AgentProxyService> =
        Arc::new(services::agent::proxy::AgentProxy::new());

    // Create BI metrics service
    let bi_metrics_repo = db.bi_metrics_repository();
    let bi_metrics_service: Arc<dyn services::bi_metrics::BiMetricsService> =
        Arc::new(services::bi_metrics::BiMetricsServiceImpl::new(
            bi_metrics_repo as Arc<dyn services::bi_metrics::BiMetricsRepository>,
        ));

    // Create application state
    let app_state = AppState {
        oauth_service,
        user_service,
        user_settings_service,
        model_service,
        system_configs_service,
        subscription_service,
        session_repository: session_repo,
        vpc_credentials_service,
        user_repository: user_repo,
        proxy_service,
        conversation_service,
        conversation_share_service,
        file_service,
        agent_service,
        agent_repository: agent_repo,
        agent_proxy_service,
        redirect_uri: config.oauth.redirect_uri,
        admin_domains: Arc::new(admin_domains),
        cloud_api_base_url: test_config.cloud_api_base_url.clone(),
        metrics_service,
        analytics_service,
        user_usage_service,
        near_rpc_url: config.near.rpc_url.clone(),
        near_balance_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        model_settings_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        model_pricing_cache: api::model_pricing::ModelPricingCache::new(
            test_config.cloud_api_base_url.clone(),
        ),
        system_configs_cache: Arc::new(tokio::sync::RwLock::new(None)),
        rate_limit_state,
        bi_metrics_service,
    };

    // Create router
    let app = create_router_with_cors(app_state, config::CorsConfig::default());

    // Create test server
    let server = TestServer::new(app).expect("Failed to create test server");
    (server, db)
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

/// Clear subscription_plans configuration from system_configs
/// Sets subscription_plans to an empty map, which is treated as "not configured"
pub async fn clear_subscription_plans(server: &TestServer) {
    let admin_email = "test_cleanup_admin@admin.org";
    let admin_token = mock_login(server, admin_email).await;

    // Set subscription_plans to empty object {} (empty HashMap)
    // This is treated as "not configured" by get_plans_for_provider()
    let config_body = json!({
        "subscription_plans": {}
    });

    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&config_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Failed to clear subscription_plans: {}",
        response.status_code()
    );
}

/// Insert a test subscription directly into the database for testing.
/// Requires the user to exist (call mock_login first). The subscription uses a fake Stripe
/// subscription_id; cancel/resume will fail at the Stripe API call, but list and
/// "not scheduled for cancellation" checks work.
pub async fn insert_test_subscription(
    server: &TestServer,
    db: &database::Database,
    user_email: &str,
    cancel_at_period_end: bool,
) {
    let _token = mock_login(server, user_email).await;

    let user = db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
        .expect("user created by mock_login");

    // Use now+1day so "now" falls within [period_start, period_end) for usage queries.
    let period_end = chrono::Utc::now() + chrono::Duration::days(1);
    let sub_id = format!("sub_test_{}", Uuid::new_v4());

    let client = db.pool().get().await.expect("get pool client");
    client
        .execute(
            "INSERT INTO subscriptions (
                subscription_id, user_id, provider, customer_id, price_id, status,
                current_period_end, cancel_at_period_end
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (subscription_id) DO UPDATE SET
                cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                updated_at = NOW()",
            &[
                &sub_id,
                &user.id,
                &"stripe",
                &"cus_test",
                &"price_test_basic",
                &"active",
                &period_end,
                &cancel_at_period_end,
            ],
        )
        .await
        .expect("insert subscription");
}

/// Clean up all subscriptions for a user (by email).
/// Useful for test isolation to ensure no leftover data from previous test runs.
pub async fn cleanup_user_subscriptions(db: &database::Database, user_email: &str) {
    let user = match db
        .user_repository()
        .get_user_by_email(user_email)
        .await
        .expect("get user")
    {
        Some(u) => u,
        None => return, // User doesn't exist, nothing to clean
    };

    let client = db.pool().get().await.expect("get pool client");
    client
        .execute("DELETE FROM subscriptions WHERE user_id = $1", &[&user.id])
        .await
        .expect("delete subscriptions");
}

/// Set subscription_plans configuration
/// plans should be in format: { "plan_name": { "providers": { "stripe": { "price_id": "price_xxx" } }, "agent_instances": { "max": 1 }, "monthly_tokens": { "max": 1000000 } } }
pub async fn set_subscription_plans(server: &TestServer, plans: serde_json::Value) {
    let admin_email = "test_setup_admin@admin.org";
    let admin_token = mock_login(server, admin_email).await;

    let config_body = json!({
        "subscription_plans": plans
    });

    let response = server
        .patch("/v1/admin/configs")
        .add_header(
            http::HeaderName::from_static("authorization"),
            http::HeaderValue::from_str(&format!("Bearer {admin_token}")).unwrap(),
        )
        .add_header(
            http::HeaderName::from_static("content-type"),
            http::HeaderValue::from_static("application/json"),
        )
        .json(&config_body)
        .await;

    assert!(
        response.status_code().is_success(),
        "Failed to set subscription_plans: {}",
        response.status_code()
    );
}
