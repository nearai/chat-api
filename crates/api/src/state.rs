use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub oauth_service: Arc<dyn services::auth::ports::OAuthService>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub user_settings_service: Arc<dyn services::user::ports::UserSettingsService>,
    pub model_service: Arc<dyn services::model::ports::ModelService>,
    pub session_repository: Arc<dyn services::auth::ports::SessionRepository>,
    pub user_repository: Arc<dyn services::user::ports::UserRepository>,
    pub proxy_service: Arc<dyn services::response::ports::OpenAIProxyService>,
    pub conversation_service: Arc<dyn services::conversation::ports::ConversationService>,
    pub file_service: Arc<dyn services::file::ports::FileService>,
    pub redirect_uri: String,
    pub admin_domains: Arc<Vec<String>>,
    pub vpc_credentials_service: Arc<dyn services::vpc::VpcCredentialsService>,
    /// Base URL for Cloud API calls (same as OpenAI base URL when using VPC)
    pub cloud_api_base_url: String,
    /// Metrics service for recording usage metrics
    pub metrics_service: Arc<dyn services::metrics::MetricsServiceTrait>,
    /// Analytics service for database-backed analytics
    pub analytics_service: Arc<dyn services::analytics::AnalyticsServiceTrait>,
}
