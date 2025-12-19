use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// Cached NEAR balance entry for a given account
#[derive(Debug, Clone)]
pub struct NearBalanceCacheEntry {
    pub last_checked_at: DateTime<Utc>,
    pub balance: u128,
}

/// Type alias for NEAR balance cache (per-account)
pub type NearBalanceCache = Arc<RwLock<HashMap<String, NearBalanceCacheEntry>>>;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub oauth_service: Arc<dyn services::auth::ports::OAuthService>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub user_settings_service: Arc<dyn services::user::ports::UserSettingsService>,
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
    /// NEAR RPC URL used for on-chain balance checks (if configured)
    pub near_rpc_url: Url,
    /// In-memory cache for NEAR account balances to avoid frequent RPC calls
    pub near_balance_cache: NearBalanceCache,
}
