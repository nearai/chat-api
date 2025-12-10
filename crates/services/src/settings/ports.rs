use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Model settings content structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelSettingsContent {
    /// Whether models are private (not publicly visible)
    pub private: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialModelSettingsContent {
    pub private: Option<bool>,
}

impl Default for ModelSettingsContent {
    /// Default model settings.
    ///
    /// By default, models are **not** public (private = false as per requirement).
    fn default() -> Self {
        Self { private: false }
    }
}

impl ModelSettingsContent {
    pub fn into_updated(self, content: PartialModelSettingsContent) -> Self {
        Self {
            private: content.private.unwrap_or(self.private),
        }
    }
}

/// Model settings stored as JSONB in the database
#[derive(Debug, Clone)]
pub struct ModelSettings {
    pub id: uuid::Uuid,
    pub content: ModelSettingsContent,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository trait for model settings operations
#[async_trait]
pub trait ModelSettingsRepository: Send + Sync {
    /// Get global model settings.
    /// Returns `Ok(None)` if no settings exist yet.
    async fn get_settings(&self) -> anyhow::Result<Option<ModelSettings>>;

    /// Create or update global model settings.
    async fn upsert_settings(&self, content: ModelSettingsContent)
        -> anyhow::Result<ModelSettings>;
}

/// Service trait for model settings operations
#[async_trait]
pub trait ModelSettingsService: Send + Sync {
    /// Get model settings (returns default when none exist).
    async fn get_settings(&self) -> anyhow::Result<ModelSettingsContent>;

    /// Fully update model settings.
    async fn update_settings(
        &self,
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent>;

    /// Partially update model settings.
    async fn update_settings_partially(
        &self,
        content: PartialModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent>;
}
