use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::model::ports::{
    Model, ModelSettings, ModelsRepository, PartialModelSettings, UpdateModelParams,
    UpsertModelParams,
};
use tokio_postgres::Row;
use uuid::Uuid;

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
            let created_at: DateTime<Utc> = row.get("created_at");
            let updated_at: DateTime<Utc> = row.get("updated_at");

            let settings = load_settings_from_row(&row)?;

            let model = Model {
                id,
                model_id: model_id.clone(),
                settings,
                created_at,
                updated_at,
            };

            map.insert(model_id, model);
        }

        Ok(map)
    }

    async fn upsert_model(&self, params: UpsertModelParams) -> anyhow::Result<Model> {
        tracing::info!(
            "Repository: Upserting model for model_id={}",
            params.model_id
        );

        let client = self.pool.get().await?;

        let settings = serde_json::to_value(params.settings.clone())?;

        // Insert or update by model_id
        let row = client
            .query_one(
                "INSERT INTO models (model_id, settings)
                 VALUES ($1, $2)
                 ON CONFLICT (model_id)
                 DO UPDATE SET settings = EXCLUDED.settings
                 RETURNING *",
                &[&params.model_id, &settings],
            )
            .await?;

        let model_id = params.model_id;

        let settings = Model {
            id: row.get("id"),
            model_id: model_id.clone(),
            settings: params.settings,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        tracing::info!(
            "Repository: Model settings upserted successfully for model_id={}",
            model_id
        );

        Ok(settings)
    }

    async fn update_model(&self, params: UpdateModelParams) -> anyhow::Result<Model> {
        tracing::info!(
            "Repository: Updating model for model_id={}",
            params.model_id
        );

        let client = self.pool.get().await?;

        // Use atomic JSONB merge to prevent lost writes from concurrent updates
        let row = if let Some(delta) = params.settings {
            // Build JSON object with only fields that should be updated (skip None values)
            let mut delta_json = serde_json::Map::new();
            if let Some(public) = delta.public {
                delta_json.insert("public".to_string(), serde_json::Value::Bool(public));
            }
            if let Some(ref system_prompt) = delta.system_prompt {
                delta_json.insert(
                    "system_prompt".to_string(),
                    serde_json::Value::String(system_prompt.clone()),
                );
            }

            let delta_value = serde_json::Value::Object(delta_json);

            // Atomic merge: COALESCE handles NULL, || merges JSONB objects
            // This ensures concurrent updates don't lose data
            client
                .query_one(
                    "UPDATE models
                     SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb,
                         updated_at = NOW()
                     WHERE model_id = $2
                     RETURNING id, model_id, settings, created_at, updated_at",
                    &[&delta_value, &params.model_id],
                )
                .await?
        } else {
            // No settings to update, just refresh updated_at
            client
                .query_one(
                    "UPDATE models
                     SET updated_at = NOW()
                     WHERE model_id = $1
                     RETURNING id, model_id, settings, created_at, updated_at",
                    &[&params.model_id],
                )
                .await?
        };

        // Deserialize the merged settings from database
        // query_one will return an error if no rows found, so no need to check
        let settings_json: serde_json::Value = row.get("settings");
        let settings: ModelSettings = serde_json::from_value(settings_json)?;

        Ok(Model {
            id: row.get("id"),
            model_id: row.get("model_id"),
            settings,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn delete_model(&self, model_id: &str) -> anyhow::Result<bool> {
        tracing::info!("Repository: Deleting model for model_id={}", model_id);

        let client = self.pool.get().await?;

        let rows_affected = client
            .execute(
                "DELETE FROM models
                 WHERE model_id = $1",
                &[&model_id],
            )
            .await?;

        Ok(rows_affected > 0)
    }
}

fn load_settings_from_row(row: &Row) -> anyhow::Result<ModelSettings> {
    let settings_json: serde_json::Value = row.get("settings");
    let default_settings = ModelSettings::default();
    let partial_settings = serde_json::from_value::<PartialModelSettings>(settings_json)?;
    let settings = default_settings.into_updated(partial_settings);
    Ok(settings)
}
