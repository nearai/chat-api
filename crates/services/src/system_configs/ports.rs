use async_trait::async_trait;
use chrono::Duration;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

/// Helper module for serializing/deserializing Duration as seconds
mod serde_duration_seconds {
    use super::*;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let seconds = duration.num_seconds();
        serializer.serialize_i64(seconds)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = i64::deserialize(deserializer)?;
        Ok(Duration::seconds(seconds))
    }
}

/// Key for `system_configs` table entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemKey {
    /// Application-wide configuration
    Config,
}

impl fmt::Display for SystemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemKey::Config => write!(f, "config"),
        }
    }
}

/// Configuration for a single time window limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowLimit {
    /// Duration of the time window for the limit
    #[serde(with = "serde_duration_seconds")]
    pub window_duration: Duration,
    /// Maximum number of requests allowed in this window
    pub limit: usize,
}

/// Rate limit configuration stored in system configs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of concurrent requests per user
    pub max_concurrent: usize,
    /// Maximum number of requests per time window per user
    pub max_requests_per_window: usize,
    /// Duration of the short-term rate limit window
    #[serde(with = "serde_duration_seconds")]
    pub window_duration: Duration,
    /// Sliding window limits based on activity logs
    /// Each limit applies independently
    pub window_limits: Vec<WindowLimit>,
    /// Token usage limits per window (limit = max tokens in window)
    /// Use `#[serde(default)]` for old config data compatibility
    #[serde(default)]
    pub token_window_limits: Vec<WindowLimit>,
    /// Cost usage limits per window (limit = max nano-dollars in window)
    /// Use `#[serde(default)]` for old config data compatibility
    #[serde(default)]
    pub cost_window_limits: Vec<WindowLimit>,
}

/// Provider-specific price configuration (e.g. Stripe price_id)
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProviderConfig {
    pub price_id: String,
}

/// Limit configuration for a plan (e.g. max deployments, max monthly tokens)
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanLimitConfig {
    pub max: u64,
}

/// Subscription plan configuration with provider-specific pricing and limits
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPlanConfig {
    /// Provider-specific configs (e.g. "stripe" -> { "price_id": "price_xxx" })
    pub providers: HashMap<String, PaymentProviderConfig>,
    /// Deployment limits (e.g. { "max": 1 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployments: Option<PlanLimitConfig>,
    /// Monthly token limits (e.g. { "max": 1000000 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_tokens: Option<PlanLimitConfig>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            max_requests_per_window: 1,
            window_duration: Duration::seconds(1),
            window_limits: vec![WindowLimit {
                window_duration: Duration::days(1),
                limit: 1500,
            }],
            token_window_limits: vec![],
            cost_window_limits: vec![],
        }
    }
}

/// Application-wide configuration stored in `system_configs` table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigs {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
    /// Subscription plan configurations (plan name -> config with providers, deployments, monthly_tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialSystemConfigs {
    pub default_model: Option<String>,
    pub rate_limit: Option<RateLimitConfig>,
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
}

#[allow(clippy::derivable_impls)]
impl Default for SystemConfigs {
    fn default() -> Self {
        Self {
            default_model: None,
            rate_limit: RateLimitConfig::default(),
            subscription_plans: None,
        }
    }
}

impl SystemConfigs {
    pub fn into_updated(self, partial: PartialSystemConfigs) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
            rate_limit: partial.rate_limit.unwrap_or(self.rate_limit),
            subscription_plans: partial.subscription_plans.or(self.subscription_plans),
        }
    }
}

/// Repository trait for accessing system configs
#[async_trait]
pub trait SystemConfigsRepository: Send + Sync {
    /// Get system configs (if exists)
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>>;

    /// Create or update system configs (full replace)
    async fn upsert_configs(&self, configs: SystemConfigs) -> anyhow::Result<SystemConfigs>;

    /// Partially update system configs
    async fn update_configs(&self, configs: PartialSystemConfigs) -> anyhow::Result<SystemConfigs>;
}

/// Service trait for system configs
#[async_trait]
pub trait SystemConfigsService: Send + Sync {
    /// Get system configs (if exists)
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>>;

    /// Fully create or replace system configs (upsert)
    async fn upsert_configs(&self, configs: SystemConfigs) -> anyhow::Result<SystemConfigs>;

    /// Partially update system configs
    async fn update_configs(&self, configs: PartialSystemConfigs) -> anyhow::Result<SystemConfigs>;
}
