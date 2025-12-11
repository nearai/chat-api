use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    ModelService, ModelSettingsContent, ModelsRepository, PartialModelSettingsContent,
};

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
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<ModelSettingsContent> {
        tracing::info!("Getting model settings for model_id={}", model_id);

        let content = self
            .repository
            .get_model(model_id)
            .await?
            .map(|settings| settings.settings)
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

        let model = self.repository.upsert_settings(model_id, content).await?;

        tracing::info!(
            "Model settings updated successfully for model_id={}",
            model_id
        );

        Ok(model.settings)
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

    async fn get_settings_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, ModelSettingsContent>> {
        self.repository.get_settings_by_ids(model_ids).await
    }
}
