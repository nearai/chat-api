use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{Model, ModelService, ModelsRepository, UpdateModelRequest, UpsertModelRequest};

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

    async fn upsert_model(&self, model: UpsertModelRequest) -> anyhow::Result<Model> {
        tracing::info!(
            "Upserting model for model_id={}: {:?}",
            model.model_id,
            model
        );

        self.repository.upsert_model(model).await
    }

    async fn update_model(&self, model: UpdateModelRequest) -> anyhow::Result<Model> {
        tracing::info!(
            "Updating model for model_id={}: {:?}",
            model.model_id,
            model
        );

        self.repository.update_model(model).await
    }

    async fn get_models_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, Model>> {
        self.repository.get_models_by_ids(model_ids).await
    }
}
