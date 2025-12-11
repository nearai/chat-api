use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{ModelService, ModelSettings, ModelsRepository, PartialModelSettings};

pub struct ModelSettingsServiceImpl {
    repository: Arc<dyn ModelsRepository>,
}

impl ModelSettingsServiceImpl {
    pub fn new(repository: Arc<dyn ModelsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl ModelService for ModelSettingsServiceImpl {
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<ModelSettings> {
        tracing::info!("Getting model settings for model_id={}", model_id);

        let settings = self
            .repository
            .get_model(model_id)
            .await?
            .map(|model| model.settings)
            .unwrap_or_else(ModelSettings::default);

        Ok(settings)
    }

    async fn update_settings(
        &self,
        model_id: &str,
        settings: ModelSettings,
    ) -> anyhow::Result<ModelSettings> {
        tracing::info!(
            "Updating model settings for model_id={}: {:?}",
            model_id,
            settings
        );

        let model = self.repository.upsert_settings(model_id, settings).await?;

        tracing::info!(
            "Model settings updated successfully for model_id={}",
            model_id
        );

        Ok(model.settings)
    }

    async fn update_settings_partially(
        &self,
        model_id: &str,
        partial: PartialModelSettings,
    ) -> anyhow::Result<ModelSettings> {
        let old_content = self.get_settings(model_id).await?;
        self.update_settings(model_id, old_content.into_updated(partial))
            .await
    }

    async fn get_settings_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, ModelSettings>> {
        self.repository.get_settings_by_ids(model_ids).await
    }
}
