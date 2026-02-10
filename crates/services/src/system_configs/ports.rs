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
    /// Stripe plan configurations mapping plan names to Stripe price IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripe_plans: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialSystemConfigs {
    pub default_model: Option<String>,
    pub rate_limit: Option<RateLimitConfig>,
    pub stripe_plans: Option<HashMap<String, String>>,
}

#[allow(clippy::derivable_impls)]
impl Default for SystemConfigs {
    fn default() -> Self {
        Self {
            default_model: None,
            rate_limit: RateLimitConfig::default(),
            stripe_plans: None,
        }
    }
}

impl SystemConfigs {
    pub fn into_updated(self, partial: PartialSystemConfigs) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
            rate_limit: partial.rate_limit.unwrap_or(self.rate_limit),
            stripe_plans: partial.stripe_plans.or(self.stripe_plans),
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
