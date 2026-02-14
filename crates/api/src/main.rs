use api::middleware::RateLimitState;
use api::{create_router_with_cors, ApiDoc, AppState};
use config::LoggingConfig;
use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{PeriodicReader, SdkMeterProvider},
    Resource,
};
use services::{
    analytics::AnalyticsServiceImpl,
    auth::OAuthServiceImpl,
    conversation::service::ConversationServiceImpl,
    conversation::share_service::ConversationShareServiceImpl,
    file::service::FileServiceImpl,
    metrics::{MockMetricsService, OtlpMetricsService},
    model::service::ModelServiceImpl,
    response::service::OpenAIProxy,
    system_configs::ports::SystemConfigsService,
    user::UserServiceImpl,
    user::UserSettingsServiceImpl,
    vpc::{initialize_vpc_credentials, VpcAuthConfig},
};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if it exists
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {e}");
        eprintln!("Continuing with environment variables...");
    }

    // Load configuration from environment
    let config = config::Config::from_env();

    // Initialize tracing based on configuration
    init_tracing(&config.logging);

    tracing::info!("Starting API server...");

    tracing::info!(
        "Database: {}:{}/{}",
        config
            .database
            .host
            .as_deref()
            .unwrap_or(if !config.database.primary_app_id.is_empty() {
                &config.database.primary_app_id
            } else {
                "localhost"
            }),
        config.database.port,
        config.database.database
    );
    tracing::info!("Server: {}:{}", config.server.host, config.server.port);

    // Create database and run migrations
    tracing::info!("Connecting to database...");
    let db = database::Database::from_config(&config.database).await?;

    tracing::info!("Running migrations...");
    db.run_migrations().await?;

    // Get repositories
    let user_repo = db.user_repository();
    let session_repo = db.session_repository();
    let oauth_repo = db.oauth_repository();
    let conversation_repo = db.conversation_repository();
    let conversation_share_repo = db.conversation_share_repository();
    let file_repo = db.file_repository();
    let user_settings_repo = db.user_settings_repository();
    let app_config_repo = db.app_config_repository();
    let near_nonce_repo = db.near_nonce_repository();
    let analytics_repo = db.analytics_repository();
    let system_configs_repo = db.system_configs_repository();
    let model_repo = db.model_repository();

    // Create services
    tracing::info!("Initializing services...");
    let oauth_service = Arc::new(OAuthServiceImpl::new(
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

    let user_service = Arc::new(UserServiceImpl::new(user_repo.clone()));

    let user_settings_service = Arc::new(UserSettingsServiceImpl::new(user_settings_repo));

    let model_service = Arc::new(ModelServiceImpl::new(model_repo));

    // Initialize VPC credentials service and get API key
    let vpc_auth_config = if config.vpc_auth.is_configured() {
        let base_url = config.openai.base_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("OPENAI_BASE_URL is required when using VPC authentication")
        })?;

        let shared_secret = config
            .vpc_auth
            .read_shared_secret()
            .ok_or_else(|| anyhow::anyhow!("Failed to read VPC shared secret"))?;

        Some(VpcAuthConfig {
            client_id: config.vpc_auth.client_id.clone(),
            shared_secret,
            base_url: base_url.clone(),
        })
    } else {
        None
    };

    let static_api_key = if vpc_auth_config.is_none() {
        tracing::info!("Using API key from environment");
        Some(config.openai.api_key.clone())
    } else {
        None
    };

    tracing::info!("Initializing VPC credentials service...");
    let vpc_credentials_service = initialize_vpc_credentials(
        vpc_auth_config,
        app_config_repo.clone() as Arc<dyn services::vpc::VpcCredentialsRepository>,
        static_api_key,
    )
    .await?;

    // Initialize OpenAI proxy service
    let mut proxy_service = OpenAIProxy::new(vpc_credentials_service.clone());
    if let Some(base_url) = config.openai.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let proxy_service = Arc::new(proxy_service);

    // Initialize conversation service
    let conversation_service = Arc::new(ConversationServiceImpl::new(
        conversation_repo,
        proxy_service.clone(),
    ));

    let conversation_share_service = Arc::new(ConversationShareServiceImpl::new(
        db.conversation_repository(),
        conversation_share_repo,
        user_repo.clone(),
    ));

    // Initialize file service
    let file_service = Arc::new(FileServiceImpl::new(file_repo, proxy_service.clone()));

    // Initialize analytics and user usage services
    tracing::info!("Initializing analytics service...");
    let analytics_service = Arc::new(AnalyticsServiceImpl::new(analytics_repo.clone()));

    tracing::info!("Initializing user usage service...");
    let user_usage_repo = db.user_usage_repository();
    let user_usage_service: Arc<dyn services::user_usage::UserUsageService> =
        Arc::new(services::user_usage::UserUsageServiceImpl::new(
            user_usage_repo as Arc<dyn services::user_usage::UserUsageRepository>,
        ));

    // Initialize system configs service
    tracing::info!("Initializing system configs service...");
    let system_configs_service = Arc::new(
        services::system_configs::service::SystemConfigsServiceImpl::new(
            system_configs_repo
                as Arc<dyn services::system_configs::ports::SystemConfigsRepository>,
        ),
    );

    // Initialize subscription service
    tracing::info!("Initializing subscription service...");
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

    // Initialize metrics service
    tracing::info!("Initializing metrics service...");
    let metrics_service: Arc<dyn services::metrics::MetricsServiceTrait> =
        if let Some(otlp_endpoint) = &config.telemetry.otlp_endpoint {
            tracing::info!(
                "Initializing OpenTelemetry OTLP metrics export to {}",
                otlp_endpoint
            );

            // Build OTLP metrics exporter
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint(otlp_endpoint)
                .build()
                .expect("Failed to build OTLP metrics exporter");

            // Create periodic reader to export metrics
            let reader = PeriodicReader::builder(exporter).build();

            // Get environment for resource tags
            let environment =
                std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

            // Build meter provider with resource attributes
            let meter_provider = SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(
                    Resource::builder()
                        .with_attributes([
                            opentelemetry::KeyValue::new(
                                "service.name",
                                config.telemetry.service_name.clone(),
                            ),
                            opentelemetry::KeyValue::new("environment", environment.clone()),
                        ])
                        .build(),
                )
                .build();

            tracing::info!(
                "OpenTelemetry metrics initialized for service '{}' in environment '{}'",
                config.telemetry.service_name,
                environment
            );

            // Set as global meter provider
            global::set_meter_provider(meter_provider.clone());

            Arc::new(OtlpMetricsService::new(&meter_provider))
        } else {
            tracing::info!("OTLP endpoint not configured, using mock metrics service");
            Arc::new(MockMetricsService)
        };

    // Load rate limit config from system configs
    let rate_limit_config = system_configs_service
        .get_configs()
        .await?
        .unwrap_or_default()
        .rate_limit;

    // Create rate limit state
    let rate_limit_state = RateLimitState::with_config(
        rate_limit_config,
        analytics_service.clone(),
        user_usage_service.clone(),
    );

    // Create application state
    let app_state = AppState {
        oauth_service,
        user_service,
        user_settings_service,
        model_service,
        system_configs_service: system_configs_service.clone(),
        subscription_service,
        session_repository: session_repo,
        proxy_service,
        conversation_service,
        conversation_share_service,
        file_service,
        redirect_uri: config.oauth.redirect_uri,
        admin_domains: Arc::new(config.admin.admin_domains),
        user_repository: user_repo.clone(),
        vpc_credentials_service,
        cloud_api_base_url: config.openai.base_url.clone().unwrap_or_default(),
        metrics_service,
        analytics_service,
        user_usage_service,
        near_rpc_url: config.near.rpc_url.clone(),
        near_balance_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        model_settings_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        model_pricing_cache: api::model_pricing::ModelPricingCache::new(
            config.openai.base_url.clone().unwrap_or_default(),
        ),
        rate_limit_state,
    };

    // Create router with CORS support
    let app = create_router_with_cors(app_state, config.cors.clone())
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("🚀 Server listening on http://{}", addr);
    tracing::info!("📚 Swagger UI available at http://{}/docs", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing(logging_config: &LoggingConfig) {
    let mut filter = logging_config.level.clone();
    for (module, level) in &logging_config.modules {
        filter.push_str(&format!(",{module}={level}"));
    }

    let env_filter = EnvFilter::try_new(&filter).unwrap_or_else(|err| {
        eprintln!(
            "Invalid log filter '{}': {}. Falling back to 'info'.",
            filter, err
        );
        EnvFilter::new("info")
    });

    match logging_config.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_current_span(false)
                .with_span_list(false)
                .init();
        }
        "compact" => {
            tracing_subscriber::fmt()
                .compact()
                .with_env_filter(env_filter)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .init();
        }
        "pretty" => {
            tracing_subscriber::fmt()
                .pretty()
                .with_env_filter(env_filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_current_span(false)
                .with_span_list(false)
                .init();
        }
    }
}
