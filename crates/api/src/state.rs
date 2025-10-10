use std::sync::Arc;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub oauth_service: Arc<dyn services::auth::ports::OAuthService>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub session_repository: Arc<dyn services::auth::ports::SessionRepository>,
    pub redirect_uri: String,
}
