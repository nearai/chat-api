use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{Model, ModelService, ModelsRepository, UpdateModelParams, UpsertModelParams};

pub struct ModelServiceImpl {
    repository: Arc<dyn ModelsRepository>,
}

impl ModelServiceImpl {
    pub fn new(repository: Arc<dyn ModelsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl ModelService for ModelServiceImpl {
    async fn get_model(&self, model_id: &str) -> anyhow::Result<Option<Model>> {
        tracing::info!("Getting model settings for model_id={}", model_id);

        self.repository.get_model(model_id).await
    }

    async fn get_models_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, Model>> {
        self.repository.get_models_by_ids(model_ids).await
    }

    async fn upsert_model(&self, params: UpsertModelParams) -> anyhow::Result<Model> {
        tracing::info!(
            "Upserting model for model_id={}: {:?}",
            params.model_id,
            params
        );

        self.repository.upsert_model(params).await
    }

    async fn update_model(&self, params: UpdateModelParams) -> anyhow::Result<Model> {
        tracing::info!(
            "Updating model for model_id={}: {:?}",
            params.model_id,
            params
        );

        self.repository.update_model(params).await
    }
}
