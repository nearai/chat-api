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
    async fn get_settings(&self) -> anyhow::Result<ModelSettingsContent> {
        tracing::info!("Getting global model settings");

        let content = self
            .repository
            .get_settings()
            .await?
            .map(|settings| settings.content)
            .unwrap_or_else(ModelSettingsContent::default);

        Ok(content)
    }

    async fn update_settings(
        &self,
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent> {
        tracing::info!("Updating global model settings: {:?}", content);

        let settings = self.repository.upsert_settings(content).await?;

        tracing::info!("Global model settings updated successfully");

        Ok(settings.content)
    }

    async fn update_settings_partially(
        &self,
        content: PartialModelSettingsContent,
    ) -> anyhow::Result<ModelSettingsContent> {
        let old_content = self.get_settings().await?;
        self.update_settings(old_content.into_updated(content))
            .await
    }
}
