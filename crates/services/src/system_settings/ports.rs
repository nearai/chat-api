use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Key for `system_settings` table entries
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

/// Application-wide configuration stored in `system_settings` table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettings {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialSystemSettings {
    pub default_model: Option<String>,
}

#[allow(clippy::derivable_impls)]
impl Default for SystemSettings {
    fn default() -> Self {
        Self {
            default_model: None,
        }
    }
}

impl SystemSettings {
    pub fn into_updated(self, partial: PartialSystemSettings) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
        }
    }
}

/// Repository trait for accessing system settings
#[async_trait]
pub trait SystemSettingsRepository: Send + Sync {
    /// Get system settings (if exists)
    async fn get_config(&self) -> anyhow::Result<Option<SystemSettings>>;

    /// Create or update system settings (full replace)
    async fn upsert_config(&self, config: SystemSettings) -> anyhow::Result<SystemSettings>;

    /// Partially update system settings
    async fn update_config(&self, config: PartialSystemSettings) -> anyhow::Result<SystemSettings>;
}

/// Service trait for system settings
#[async_trait]
pub trait SystemSettingsService: Send + Sync {
    /// Get system settings (if exists)
    async fn get_config(&self) -> anyhow::Result<Option<SystemSettings>>;

    /// Fully create or replace system settings (upsert)
    async fn upsert_config(&self, config: SystemSettings) -> anyhow::Result<SystemSettings>;

    /// Partially update system settings
    async fn update_config(&self, config: PartialSystemSettings) -> anyhow::Result<SystemSettings>;
}

