use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

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

/// Application-wide configuration stored in `system_configs` table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigs {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialSystemConfigs {
    pub default_model: Option<String>,
}

#[allow(clippy::derivable_impls)]
impl Default for SystemConfigs {
    fn default() -> Self {
        Self {
            default_model: None,
        }
    }
}

impl SystemConfigs {
    pub fn into_updated(self, partial: PartialSystemConfigs) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
        }
    }
}

/// Repository trait for accessing system configs
#[async_trait]
pub trait SystemConfigsRepository: Send + Sync {
    /// Get system configs (if exists)
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>>;

    /// Create or update system configs (full replace)
    async fn upsert_configs(&self, config: SystemConfigs) -> anyhow::Result<SystemConfigs>;

    /// Partially update system configs
    async fn update_configs(&self, config: PartialSystemConfigs) -> anyhow::Result<SystemConfigs>;
}

/// Service trait for system configs
#[async_trait]
pub trait SystemConfigsService: Send + Sync {
    /// Get system configs (if exists)
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>>;

    /// Fully create or replace system configs (upsert)
    async fn upsert_configs(&self, config: SystemConfigs) -> anyhow::Result<SystemConfigs>;

    /// Partially update system configs
    async fn update_configs(&self, config: PartialSystemConfigs) -> anyhow::Result<SystemConfigs>;
}
