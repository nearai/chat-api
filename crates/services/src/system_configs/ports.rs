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

/// Limit configuration for a plan (e.g. max agent instances, max monthly tokens)
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
    /// Free trial period in days before first charge (Stripe max 730)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_period_days: Option<u32>,
    /// Agent instance limits (e.g. { "max": 1 })
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_instances: Option<PlanLimitConfig>,
    /// Monthly token limits (e.g. { "max": 1000000 }). Kept for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_tokens: Option<PlanLimitConfig>,
    /// Monthly credit limits in nano-USD (e.g. { "max": 1000000000 } = $1). Used for quota enforcement.
    /// When set, takes precedence over monthly_tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_credits: Option<PlanLimitConfig>,
}

/// Configuration for credit purchase (Stripe Price ID for 1 credit)
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditsConfig {
    /// Stripe Price ID for 1 credit (unit amount defined in Stripe)
    pub credit_price_id: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 5,
            max_requests_per_window: 5,
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

/// Auto-routing configuration for `model: "auto"` chat completion requests
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRouteConfig {
    /// Target model to substitute for "auto"
    pub model: String,
    /// Default temperature (injected when client doesn't provide one; omitted if None)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Default top_p (injected when client doesn't provide one; omitted if None)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Default max_tokens (injected when client doesn't provide one; omitted if None)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
}

/// Application-wide configuration stored in `system_configs` table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigs {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
    /// Subscription plan configurations (plan name -> config with providers, agent_instances, monthly_credits)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
    /// Maximum number of agent instances per manager. When a manager reaches this limit,
    /// round-robin skips it. If all managers are full, instance creation is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instances_per_manager: Option<u64>,
    /// Credit purchase configuration (Stripe Price ID for buying credits)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credits: Option<CreditsConfig>,
    /// Per-manager URL limits (agent manager URL -> max instances). Overrides max_instances_per_manager
    /// when set for a specific URL. Use normalized URLs matching AGENT_MANAGER_URLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instances_by_manager_url: Option<HashMap<String, u64>>,
    /// Auto-routing configuration for `model: "auto"` requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_route: Option<AutoRouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialSystemConfigs {
    pub default_model: Option<String>,
    pub rate_limit: Option<RateLimitConfig>,
    pub subscription_plans: Option<HashMap<String, SubscriptionPlanConfig>>,
    pub max_instances_per_manager: Option<u64>,
    pub credits: Option<CreditsConfig>,
    pub max_instances_by_manager_url: Option<HashMap<String, u64>>,
    pub auto_route: Option<AutoRouteConfig>,
}

#[allow(clippy::derivable_impls)]
impl Default for SystemConfigs {
    fn default() -> Self {
        Self {
            default_model: None,
            rate_limit: RateLimitConfig::default(),
            subscription_plans: None,
            max_instances_per_manager: Some(200),
            credits: None,
            max_instances_by_manager_url: None,
            auto_route: None,
        }
    }
}

impl SystemConfigs {
    pub fn into_updated(self, partial: PartialSystemConfigs) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
            rate_limit: partial.rate_limit.unwrap_or(self.rate_limit),
            subscription_plans: partial.subscription_plans.or(self.subscription_plans),
            max_instances_per_manager: partial
                .max_instances_per_manager
                .or(self.max_instances_per_manager),
            credits: partial.credits.or(self.credits),
            max_instances_by_manager_url: partial
                .max_instances_by_manager_url
                .or(self.max_instances_by_manager_url),
            auto_route: partial.auto_route.or(self.auto_route),
        }
    }

    /// Returns the max instances limit for a given agent manager URL.
    /// Checks URL-specific limits first (match by exact or normalized URL without trailing slash),
    /// then falls back to the global max_instances_per_manager.
    pub fn max_instances_for_manager(&self, manager_url: &str) -> Option<u64> {
        if let Some(ref per_url) = self.max_instances_by_manager_url {
            if let Some(&v) = per_url.get(manager_url) {
                return Some(v);
            }

            let normalized = manager_url.trim_end_matches('/');
            if normalized != manager_url {
                if let Some(&v) = per_url.get(normalized) {
                    return Some(v);
                }
            } else {
                let with_slash = format!("{}/", manager_url);
                if let Some(&v) = per_url.get(&with_slash) {
                    return Some(v);
                }
            }
        }
        self.max_instances_per_manager
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

#[cfg(test)]
mod tests {
    use super::*;

    fn configs_with_per_url(entries: Vec<(&str, u64)>, global: Option<u64>) -> SystemConfigs {
        let mut per_url = std::collections::HashMap::new();
        for (url, limit) in entries {
            per_url.insert(url.to_string(), limit);
        }
        SystemConfigs {
            max_instances_per_manager: global,
            max_instances_by_manager_url: Some(per_url),
            ..Default::default()
        }
    }

    #[test]
    fn test_max_instances_exact_match() {
        let c = configs_with_per_url(vec![("https://mgr.example.com", 10)], Some(200));
        assert_eq!(
            c.max_instances_for_manager("https://mgr.example.com"),
            Some(10)
        );
    }

    #[test]
    fn test_max_instances_trailing_slash_in_query() {
        let c = configs_with_per_url(vec![("https://mgr.example.com", 10)], Some(200));
        assert_eq!(
            c.max_instances_for_manager("https://mgr.example.com/"),
            Some(10)
        );
    }

    #[test]
    fn test_max_instances_trailing_slash_in_config() {
        let c = configs_with_per_url(vec![("https://mgr.example.com/", 10)], Some(200));
        assert_eq!(
            c.max_instances_for_manager("https://mgr.example.com"),
            Some(10)
        );
    }

    #[test]
    fn test_max_instances_falls_back_to_global() {
        let c = configs_with_per_url(vec![("https://other.example.com", 10)], Some(200));
        assert_eq!(
            c.max_instances_for_manager("https://mgr.example.com"),
            Some(200)
        );
    }

    #[test]
    fn test_max_instances_falls_back_to_global_default() {
        let c = SystemConfigs::default();
        assert_eq!(
            c.max_instances_for_manager("https://mgr.example.com"),
            Some(200)
        );
    }

    #[test]
    fn test_max_instances_no_global_no_per_url() {
        let c = SystemConfigs {
            max_instances_per_manager: None,
            max_instances_by_manager_url: None,
            ..Default::default()
        };
        assert_eq!(c.max_instances_for_manager("https://mgr.example.com"), None);
    }
}
