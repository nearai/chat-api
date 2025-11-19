use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub oauth_service: Arc<dyn services::auth::ports::OAuthService>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub user_settings_service: Arc<dyn services::user::ports::UserSettingsService>,
    pub session_repository: Arc<dyn services::auth::ports::SessionRepository>,
    pub proxy_service: Arc<dyn services::response::ports::OpenAIProxyService>,
    pub conversation_service: Arc<dyn services::conversation::ports::ConversationService>,
    pub redirect_uri: String,
}
