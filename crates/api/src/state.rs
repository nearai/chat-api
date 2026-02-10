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

/// Cached model settings entry for a given model_id
#[derive(Debug, Clone)]
pub struct ModelSettingsCacheEntry {
    pub last_checked_at: DateTime<Utc>,
    /// Whether the model exists in the admin models table
    pub exists: bool,
    /// Whether this model is public (visible/usable in responses)
    pub public: bool,
    /// Optional system-level system prompt for this model
    pub system_prompt: Option<String>,
}

/// Type alias for model settings cache (per-model)
pub type ModelSettingsCache = Arc<RwLock<HashMap<String, ModelSettingsCacheEntry>>>;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub oauth_service: Arc<dyn services::auth::ports::OAuthService>,
    pub user_service: Arc<dyn services::user::ports::UserService>,
    pub user_settings_service: Arc<dyn services::user::ports::UserSettingsService>,
    pub model_service: Arc<dyn services::model::ports::ModelService>,
    pub system_configs_service: Arc<dyn services::system_configs::ports::SystemConfigsService>,
    pub subscription_service: Arc<dyn services::subscription::ports::SubscriptionService>,
    pub session_repository: Arc<dyn services::auth::ports::SessionRepository>,
    pub user_repository: Arc<dyn services::user::ports::UserRepository>,
    pub proxy_service: Arc<dyn services::response::ports::OpenAIProxyService>,
    pub conversation_service: Arc<dyn services::conversation::ports::ConversationService>,
    pub conversation_share_service:
        Arc<dyn services::conversation::ports::ConversationShareService>,
    pub file_service: Arc<dyn services::file::ports::FileService>,
    pub redirect_uri: String,
    pub admin_domains: Arc<Vec<String>>,
    pub vpc_credentials_service: Arc<dyn services::vpc::VpcCredentialsService>,
    /// Base URL for Cloud API calls (same as OpenAI base URL when using VPC)
    pub cloud_api_base_url: String,
    /// Metrics service for recording usage metrics
    pub metrics_service: Arc<dyn services::metrics::MetricsServiceTrait>,
    /// Analytics service for database-backed analytics and rate limiting
    pub analytics_service: Arc<dyn services::analytics::AnalyticsServiceTrait>,
    /// NEAR RPC URL used for on-chain balance checks (if configured)
    pub near_rpc_url: Url,
    /// In-memory cache for NEAR account balances to avoid frequent RPC calls
    pub near_balance_cache: NearBalanceCache,
    /// In-memory cache for model settings needed by /v1/responses (public + system_prompt)
    pub model_settings_cache: ModelSettingsCache,
    /// Rate limit state for hot-reloadable rate limit configuration
    pub rate_limit_state: crate::middleware::RateLimitState,
}
