use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use services::model::ports::{Model, ModelSettings, ModelsRepository, PartialModelSettings, UpsertModelRequest};

pub struct PostgresModelRepository {
    pool: DbPool,
}

impl PostgresModelRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ModelsRepository for PostgresModelRepository {
    async fn get_model(&self, model_id: &str) -> anyhow::Result<Option<Model>> {
        tracing::debug!(
            "Repository: Fetching model settings for model_id={}",
            model_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, model_id, settings, created_at, updated_at 
                 FROM models 
                 WHERE model_id = $1",
                &[&model_id],
            )
            .await?;

        if let Some(row) = row {
            let settings_json: serde_json::Value = row.get("settings");

            let default_settings = ModelSettings::default();
            // Missing fields will be filled from default settings values
            let settings_delta = serde_json::from_value::<PartialModelSettings>(settings_json)?;
            let settings = default_settings.into_updated(settings_delta);

            Ok(Some(Model {
                id: row.get("id"),
                model_id: row.get("model_id"),
                settings,
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }

    async fn upsert_model(&self, model: UpsertModelRequest) -> anyhow::Result<Model> {
        tracing::info!(
            "Repository: Upserting model for model_id={}",
            model.model_id
        );

        let client = self.pool.get().await?;

        // Insert or update by model_id
        let row = client
            .query_one(
                "INSERT INTO models (model_id, settings)
                 VALUES ($1, $2)
                 ON CONFLICT (model_id)
                 DO UPDATE SET settings = EXCLUDED.settings
                 RETURNING *",
                &[&model.model_id, &model.settings],
            )
            .await?;
        
        let model_id = model.model_id;

        let settings = Model {
            id: row.get("id"),
            model_id: model_id.clone(),
            settings: model.settings,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        tracing::info!(
            "Repository: Model settings upserted successfully for model_id={}",
            model_id
        );

        Ok(settings)
    }

    async fn get_models_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, Model>> {
        tracing::debug!(
            "Repository: Fetching models for {} model_ids",
            model_ids.len()
        );

        if model_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, model_id, settings, created_at, updated_at
                 FROM models
                 WHERE model_id = ANY($1)",
                &[&model_ids],
            )
            .await?;

        let mut map = std::collections::HashMap::new();

        for row in rows {
            let id: Uuid = row.get("id");
            let model_id: String = row.get("model_id");
            let settings_json: serde_json::Value = row.get("settings");
            let created_at: DateTime<Utc> = row.get("created_at");
            let updated_at: DateTime<Utc> = row.get("updated_at");

            let default_settings = ModelSettings::default();
            let partial_settings = serde_json::from_value::<PartialModelSettings>(settings_json)?;
            let settings = default_settings.into_updated(partial_settings);
            
            let model = Model {
                id,
                model_id: model_id.clone(),
                settings,
                created_at,
                updated_at
            };

            map.insert(model_id, model);
        }

        Ok(map)
    }
}
