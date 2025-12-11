use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Model settings content structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelSettings {
    /// Whether models are public (visible/usable in responses)
    pub public: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialModelSettings {
    pub public: Option<bool>,
}

impl Default for ModelSettings {
    /// Default model settings.
    ///
    /// By default, models are **not** public (public = false).
    fn default() -> Self {
        Self { public: false }
    }
}

impl ModelSettings {
    pub fn into_updated(self, settings: PartialModelSettings) -> Self {
        Self {
            public: settings.public.unwrap_or(self.public),
        }
    }
}

/// Model settings stored as JSONB in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Model {
    pub id: uuid::Uuid,
    pub model_id: String,
    pub settings: ModelSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpsertModelParams {
    pub model_id: String,
    pub settings: ModelSettings,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateModelParams {
    pub model_id: String,
    pub settings: Option<PartialModelSettings>,
}

/// Repository trait for model settings operations
#[async_trait]
pub trait ModelsRepository: Send + Sync {
    /// Get settings for a specific model.
    /// Returns `Ok(None)` if no settings exist yet for that model.
    async fn get_model(&self, model_id: &str) -> anyhow::Result<Option<Model>>;

    /// Batch get full model records for multiple model IDs.
    /// Returns a map from model_id to resolved `ModelSettings`.
    async fn get_models_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, Model>>;

    /// Create or update a specific model with settings.
    async fn upsert_model(&self, params: UpsertModelParams) -> anyhow::Result<Model>;

    /// Partially update an existing model (model_id + optional partial settings).
    async fn update_model(&self, params: UpdateModelParams) -> anyhow::Result<Model>;

    /// Delete a specific model by its identifier.
    ///
    /// Returns `Ok(true)` if a model was deleted, or `Ok(false)` if no model
    /// with the given `model_id` existed.
    async fn delete_model(&self, model_id: &str) -> anyhow::Result<bool>;
}

/// Service trait for model settings operations
#[async_trait]
pub trait ModelService: Send + Sync {
    /// Get model
    async fn get_model(&self, model_id: &str) -> anyhow::Result<Option<Model>>;

    /// Batch get settings content for multiple models.
    /// Missing models will not appear in the map; callers should fall back to defaults.
    async fn get_models_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, Model>>;

    /// Fully update model
    async fn upsert_model(&self, params: UpsertModelParams) -> anyhow::Result<Model>;

    /// Partially update model settings for a specific model.
    async fn update_model(&self, params: UpdateModelParams) -> anyhow::Result<Model>;

    /// Delete a specific model by its identifier.
    ///
    /// Returns `Ok(true)` if a model was deleted, or `Ok(false)` if no model
    /// with the given `model_id` existed.
    async fn delete_model(&self, model_id: &str) -> anyhow::Result<bool>;
}
