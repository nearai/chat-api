use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    SystemSettings, SystemSettingsRepository, SystemSettingsService, PartialSystemSettings,
};

pub struct SystemSettingsServiceImpl {
    repository: Arc<dyn SystemSettingsRepository>,
}

impl SystemSettingsServiceImpl {
    pub fn new(repository: Arc<dyn SystemSettingsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl SystemSettingsService for SystemSettingsServiceImpl {
    async fn get_config(&self) -> anyhow::Result<Option<SystemSettings>> {
        tracing::info!("Getting system settings");

        self.repository.get_config().await
    }

    async fn upsert_config(&self, config: SystemSettings) -> anyhow::Result<SystemSettings> {
        tracing::info!("Upserting system settings: {:?}", config);

        self.repository.upsert_config(config).await
    }

    async fn update_config(&self, config: PartialSystemSettings) -> anyhow::Result<SystemSettings> {
        tracing::info!("Partially updating system settings: {:?}", config);

        self.repository.update_config(config).await
    }
}

