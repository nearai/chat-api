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
    audit::service::AuditServiceImpl,
    auth::OAuthServiceImpl,
    conversation::service::ConversationServiceImpl,
    domain::service::DomainVerificationServiceImpl,
    file::service::FileServiceImpl,
    metrics::{MockMetricsService, OtlpMetricsService},
    model::service::ModelServiceImpl,
    organization::service::OrganizationServiceImpl,
    rbac::service::{PermissionServiceImpl, RoleServiceImpl},
    response::service::OpenAIProxy,
    saml::service::SamlServiceImpl,
    user::UserServiceImpl,
    user::UserSettingsServiceImpl,
    vpc::{initialize_vpc_credentials, VpcAuthConfig},
    workspace::service::WorkspaceServiceImpl,
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
    let file_repo = db.file_repository();
    let user_settings_repo = db.user_settings_repository();
    let app_config_repo = db.app_config_repository();
    let near_nonce_repo = db.near_nonce_repository();
    let analytics_repo = db.analytics_repository();
    let system_configs_repo = db.system_configs_repository();
    let model_repo = db.model_repository();

    // Enterprise repositories
    let organization_repo = db.organization_repository();
    let workspace_repo = db.workspace_repository();
    let permission_repo = db.permission_repository();
    let role_repo = db.role_repository();
    let audit_repo = db.audit_repository();
    let saml_idp_config_repo = db.saml_idp_config_repository();
    let saml_auth_state_repo = db.saml_auth_state_repository();
    let domain_repo = db.domain_repository();

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

    // Initialize file service
    let file_service = Arc::new(FileServiceImpl::new(file_repo, proxy_service.clone()));

    // Initialize analytics service
    tracing::info!("Initializing analytics service...");
    let analytics_service = Arc::new(AnalyticsServiceImpl::new(analytics_repo));

    // Initialize enterprise services
    tracing::info!("Initializing enterprise services...");

    let organization_service = Arc::new(OrganizationServiceImpl::new(
        organization_repo.clone(),
        workspace_repo.clone(),
    ));

    let workspace_service = Arc::new(WorkspaceServiceImpl::new(
        workspace_repo.clone(),
    ));

    let permission_service = Arc::new(PermissionServiceImpl::new(
        permission_repo.clone(),
        role_repo.clone(),
    ));

    let role_service = Arc::new(RoleServiceImpl::new(
        role_repo.clone(),
        permission_repo.clone(),
    ));

    let audit_service = Arc::new(AuditServiceImpl::new(audit_repo.clone()));

    let domain_service = Arc::new(DomainVerificationServiceImpl::new(domain_repo));

    // SAML service is optional - only initialize if SAML is enabled
    let saml_service: Option<Arc<dyn services::saml::ports::SamlService>> = if config.saml.enabled {
        tracing::info!("Initializing SAML SSO service...");
        tracing::info!(
            "SAML SP Base URL: {}, Entity ID: {}",
            config.saml.sp_base_url,
            config.saml.get_sp_entity_id()
        );
        Some(Arc::new(SamlServiceImpl::new(
            saml_idp_config_repo,
            saml_auth_state_repo,
            config.saml.sp_base_url.clone(),
        )))
    } else {
        tracing::info!("SAML SSO is disabled (set SAML_ENABLED=true to enable)");
        let _ = (saml_idp_config_repo, saml_auth_state_repo); // Suppress unused warnings
        None
    };

    // Initialize system configs service
    tracing::info!("Initializing system configs service...");
    let system_configs_service = Arc::new(
        services::system_configs::service::SystemConfigsServiceImpl::new(
            system_configs_repo
                as Arc<dyn services::system_configs::ports::SystemConfigsRepository>,
        ),
    );

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

    // Create application state
    let app_state = AppState {
        oauth_service,
        user_service,
        user_settings_service,
        model_service,
        system_configs_service,
        session_repository: session_repo,
        proxy_service,
        conversation_service,
        file_service,
        redirect_uri: config.oauth.redirect_uri,
        admin_domains: Arc::new(config.admin.admin_domains),
        user_repository: user_repo.clone(),
        vpc_credentials_service,
        cloud_api_base_url: config.openai.base_url.clone().unwrap_or_default(),
        metrics_service,
        analytics_service,
        near_rpc_url: config.near.rpc_url.clone(),
        near_balance_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        model_settings_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        // Enterprise services
        organization_service,
        organization_repository: organization_repo,
        workspace_service,
        workspace_repository: workspace_repo,
        permission_service,
        role_service,
        role_repository: role_repo,
        audit_service,
        saml_service,
        domain_service,
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
