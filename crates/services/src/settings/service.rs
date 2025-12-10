use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    ModelSettingsContent, ModelSettingsRepository, ModelSettingsService,
    PartialModelSettingsContent,
};

pub struct ModelSettingsServiceImpl {
    repository: Arc<dyn ModelSettingsRepository>,
}

impl ModelSettingsServiceImpl {
    pub fn new(repository: Arc<dyn ModelSettingsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl ModelSettingsService for ModelSettingsServiceImpl {
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<ModelSettingsContent> {
        tracing::info!("Getting model settings for model_id={}", model_id);

        let content = self
            .repository
            .get_settings(model_id)
            .await?
            .map(|settings| settings.content)
            .unwrap_or_else(ModelSettingsContent::default);

        Ok(content)
    }

    async fn update_settings(
        &self,
        model_id: &str,
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent> {
        tracing::info!(
            "Updating model settings for model_id={}: {:?}",
            model_id,
            content
        );

        let settings = self.repository.upsert_settings(model_id, content).await?;

        tracing::info!(
            "Model settings updated successfully for model_id={}",
            model_id
        );

        Ok(settings.content)
    }

    async fn update_settings_partially(
        &self,
        model_id: &str,
        content: PartialModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent> {
        let old_content = self.get_settings(model_id).await?;
        self.update_settings(model_id, old_content.into_updated(content))
            .await
    }
}
