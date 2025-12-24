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
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>> {
        tracing::info!("Getting system configs");

        self.repository.get_configs().await
    }

    async fn upsert_configs(&self, config: SystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Upserting system configs");

        self.repository.upsert_configs(config).await
    }

    async fn update_configs(&self, config: PartialSystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Partially updating system configs");

        self.repository.update_configs(config).await
    }
}
