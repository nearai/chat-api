use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    PartialSystemConfigs, SystemConfigs, SystemConfigsRepository, SystemConfigsService,
};

pub struct SystemConfigsServiceImpl {
    repository: Arc<dyn SystemConfigsRepository>,
}

impl SystemConfigsServiceImpl {
    pub fn new(repository: Arc<dyn SystemConfigsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl SystemConfigsService for SystemConfigsServiceImpl {
    async fn get_config(&self) -> anyhow::Result<Option<SystemConfigs>> {
        tracing::info!("Getting system configs");

        self.repository.get_config().await
    }

    async fn upsert_config(&self, config: SystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Upserting system configs: {:?}", config);

        self.repository.upsert_config(config).await
    }

    async fn update_config(&self, config: PartialSystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Partially updating system configs: {:?}", config);

        self.repository.update_config(config).await
    }
}
