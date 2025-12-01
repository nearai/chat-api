use api::{create_router_with_cors, ApiDoc, AppState};
use hmac::{Hmac, Mac};
use services::{
    auth::OAuthServiceImpl, conversation::service::ConversationServiceImpl,
    file::service::FileServiceImpl, response::service::OpenAIProxy, user::UserServiceImpl,
    user::UserSettingsServiceImpl,
};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

type HmacSha256 = Hmac<Sha256>;

/// Response from VPC login endpoint
#[derive(serde::Deserialize)]
struct VpcLoginResponse {
    api_key: String,
}

/// Performs VPC authentication to obtain an API key
async fn vpc_authenticate(
    config: &config::VpcAuthConfig,
    base_url: &str,
) -> anyhow::Result<String> {
    let shared_secret = config
        .read_shared_secret()
        .ok_or_else(|| anyhow::anyhow!("Failed to read VPC shared secret"))?;

    // Generate timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Generate HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(shared_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(timestamp.to_string().as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    tracing::info!(
        "Performing VPC authentication with client_id: {}",
        config.client_id
    );
    tracing::debug!("VPC auth timestamp: {}", timestamp);

    // Build the auth URL
    let auth_url = format!("{}/v1/auth/vpc/login", base_url.trim_end_matches('/'));

    // Make authentication request
    let client = reqwest::Client::new();
    let response = client
        .post(&auth_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "timestamp": timestamp,
            "signature": signature,
            "client_id": config.client_id
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("VPC authentication failed with status {}: {}", status, body);
    }

    let login_response: VpcLoginResponse = response.json().await?;
    tracing::info!("VPC authentication successful");

    Ok(login_response.api_key)
}

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

    let user_service = Arc::new(UserServiceImpl::new(user_repo.clone()));

    let user_settings_service = Arc::new(UserSettingsServiceImpl::new(
        user_settings_repo as Arc<dyn services::user::ports::UserSettingsRepository>,
    ));

    // Get OpenAI API key - check database first, then VPC auth, then config
    const VPC_API_KEY_CONFIG_KEY: &str = "vpc_api_key";

    let api_key = if config.vpc_auth.is_configured() {
        let base_url = config.openai.base_url.as_ref().ok_or_else(|| {
            anyhow::anyhow!("OPENAI_BASE_URL is required when using VPC authentication")
        })?;

        // Check if we have a cached API key in the database
        match app_config_repo.get(VPC_API_KEY_CONFIG_KEY).await {
            Ok(Some(cached_key)) => {
                tracing::info!("Using cached VPC API key from database");
                cached_key
            }
            Ok(None) => {
                tracing::info!("No cached API key found, performing VPC authentication...");
                let new_key = vpc_authenticate(&config.vpc_auth, base_url).await?;

                // Store the new key in the database
                if let Err(e) = app_config_repo.set(VPC_API_KEY_CONFIG_KEY, &new_key).await {
                    tracing::warn!("Failed to cache VPC API key in database: {}", e);
                } else {
                    tracing::info!("VPC API key cached in database");
                }

                new_key
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to check for cached API key: {}, performing VPC auth...",
                    e
                );
                vpc_authenticate(&config.vpc_auth, base_url).await?
            }
        }
    } else {
        tracing::info!("Using API key from environment");
        config.openai.api_key.clone()
    };

    // Initialize OpenAI proxy service
    let mut proxy_service = OpenAIProxy::new(api_key);
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

    // Create application state
    let app_state = AppState {
        oauth_service,
        user_service,
        user_settings_service,
        session_repository: session_repo,
        proxy_service,
        conversation_service,
        file_service,
        redirect_uri: config.oauth.redirect_uri,
        admin_domains: Arc::new(config.admin.admin_domains),
        user_repository: user_repo.clone(),
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
