use api::{create_router_with_cors, ApiDoc, AppState};
use services::{
    auth::OAuthServiceImpl, conversation::service::ConversationServiceImpl,
    response::service::CloudAPIProxy, user::UserServiceImpl, user::UserSettingsServiceImpl,
};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if it exists
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {e}");
        eprintln!("Continuing with environment variables...");
    }

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,api=debug,services=debug,database=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting API server...");

    // Load configuration from environment
    let config = config::Config::from_env();

    tracing::info!(
        "Database: {}:{}/{}",
        config.database.host,
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
    let user_settings_repo = db.user_settings_repository();

    // Create services
    tracing::info!("Initializing services...");
    let oauth_service = Arc::new(OAuthServiceImpl::new(
        oauth_repo.clone(),
        session_repo.clone(),
        user_repo.clone(),
        config.oauth.google_client_id.clone(),
        config.oauth.google_client_secret.clone(),
        config.oauth.github_client_id.clone(),
        config.oauth.github_client_secret.clone(),
        config.oauth.redirect_uri.clone(),
    ));

    let user_service = Arc::new(UserServiceImpl::new(user_repo));

    let user_settings_service = Arc::new(UserSettingsServiceImpl::new(
        user_settings_repo as Arc<dyn services::user::ports::UserSettingsRepository>,
    ));

    // Initialize Cloud API proxy service
    let mut proxy_service = CloudAPIProxy::new(config.cloud_api.api_key.clone());
    if let Some(base_url) = config.cloud_api.base_url.clone() {
        proxy_service = proxy_service.with_base_url(base_url);
    }
    let proxy_service = Arc::new(proxy_service);

    // Initialize conversation service
    let conversation_service = Arc::new(ConversationServiceImpl::new(
        conversation_repo,
        proxy_service.clone(),
    ));

    // Create application state
    let app_state = AppState {
        oauth_service: oauth_service as Arc<dyn services::auth::ports::OAuthService>,
        user_service: user_service as Arc<dyn services::user::ports::UserService>,
        user_settings_service: user_settings_service
            as Arc<dyn services::user::ports::UserSettingsService>,
        session_repository: session_repo,
        proxy_service: proxy_service as Arc<dyn services::response::ports::CloudAPIProxyService>,
        conversation_service: conversation_service
            as Arc<dyn services::conversation::ports::ConversationService>,
        redirect_uri: config.oauth.redirect_uri.clone(),
    };

    // Create router with CORS support
    let app = create_router_with_cors(app_state, config.cors.allowed_origins.clone())
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("🚀 Server listening on http://{}", addr);
    tracing::info!("📚 Swagger UI available at http://{}/docs", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
