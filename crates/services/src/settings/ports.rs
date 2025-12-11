use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Model settings content structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelSettingsContent {
    /// Whether models are public (visible/usable in responses)
    pub public: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialModelSettingsContent {
    pub public: Option<bool>,
}

impl Default for ModelSettingsContent {
    /// Default model settings.
    ///
    /// By default, models are **not** public (public = false).
    fn default() -> Self {
        Self { public: false }
    }
}

impl ModelSettingsContent {
    pub fn into_updated(self, content: PartialModelSettingsContent) -> Self {
        Self {
            public: content.public.unwrap_or(self.public),
        }
    }
}

/// Model settings stored as JSONB in the database
#[derive(Debug, Clone)]
pub struct ModelSettings {
    pub id: uuid::Uuid,
    pub model_id: String,
    pub content: ModelSettingsContent,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository trait for model settings operations
#[async_trait]
pub trait ModelSettingsRepository: Send + Sync {
    /// Get settings for a specific model.
    /// Returns `Ok(None)` if no settings exist yet for that model.
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<Option<ModelSettings>>;

    /// Create or update settings for a specific model.
    async fn upsert_settings(
        &self,
        model_id: &str,
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettings>;
}

/// Service trait for model settings operations
#[async_trait]
pub trait ModelSettingsService: Send + Sync {
    /// Get model settings for a specific model (returns default when none exist).
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<ModelSettingsContent>;

    /// Fully update model settings for a specific model.
    async fn update_settings(
        &self,
        model_id: &str,
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent>;

    /// Partially update model settings for a specific model.
    async fn update_settings_partially(
        &self,
        model_id: &str,
        content: PartialModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent>;
}
