use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{GlobalConfig, GlobalsRepository, GlobalsService, PartialGlobalConfig};

pub struct GlobalsServiceImpl {
    repository: Arc<dyn GlobalsRepository>,
}

impl GlobalsServiceImpl {
    pub fn new(repository: Arc<dyn GlobalsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl GlobalsService for GlobalsServiceImpl {
    async fn get_config(&self) -> anyhow::Result<Option<GlobalConfig>> {
        tracing::info!("Getting global config");

        self.repository.get_config().await
    }

    async fn upsert_config(&self, config: GlobalConfig) -> anyhow::Result<GlobalConfig> {
        tracing::info!("Upserting global config: {:?}", config);

        self.repository.upsert_config(config).await
    }

    async fn update_config(&self, config: PartialGlobalConfig) -> anyhow::Result<GlobalConfig> {
        tracing::info!("Partially updating global config: {:?}", config);

        self.repository.update_config(config).await
    }
}
