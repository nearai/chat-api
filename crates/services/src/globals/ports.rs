use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Key for globals table entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GlobalKey {
    /// Application-wide configuration
    Config,
}

impl fmt::Display for GlobalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlobalKey::Config => write!(f, "config"),
        }
    }
}

/// Application-wide configuration stored in globals table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Default model identifier to use when not specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialGlobalConfig {
    pub default_model: Option<String>,
}

#[allow(clippy::derivable_impls)]
impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            default_model: None,
        }
    }
}

impl GlobalConfig {
    pub fn into_updated(self, partial: PartialGlobalConfig) -> Self {
        Self {
            default_model: partial.default_model.or(self.default_model),
        }
    }
}

/// Repository trait for accessing globals
#[async_trait]
pub trait GlobalsRepository: Send + Sync {
    /// Get global config (if exists)
    async fn get_config(&self) -> anyhow::Result<Option<GlobalConfig>>;

    /// Create or update global config (full replace)
    async fn upsert_config(&self, config: GlobalConfig) -> anyhow::Result<GlobalConfig>;

    /// Partially update global config
    async fn update_config(&self, config: PartialGlobalConfig) -> anyhow::Result<GlobalConfig>;
}

/// Service trait for globals
#[async_trait]
pub trait GlobalsService: Send + Sync {
    /// Get global config (if exists)
    async fn get_config(&self) -> anyhow::Result<Option<GlobalConfig>>;

    /// Fully create or replace global config (upsert)
    async fn upsert_config(&self, config: GlobalConfig) -> anyhow::Result<GlobalConfig>;

    /// Partially update global config
    async fn update_config(&self, config: PartialGlobalConfig) -> anyhow::Result<GlobalConfig>;
}
