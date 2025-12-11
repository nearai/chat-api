use crate::pool::DbPool;
use async_trait::async_trait;
use services::settings::ports::{
    Model, ModelSettingsContent, ModelsRepository, PartialModelSettingsContent,
};

pub struct PostgresModelSettingsRepository {
    pool: DbPool,
}

impl PostgresModelSettingsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ModelsRepository for PostgresModelSettingsRepository {
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
            let content_json: serde_json::Value = row.get("settings");

            let default_content = ModelSettingsContent::default();
            // Missing fields will be filled from default settings content
            let partial_content =
                serde_json::from_value::<PartialModelSettingsContent>(content_json)?;
            let settings = default_content.into_updated(partial_content);

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

    async fn upsert_settings(
        &self,
        model_id: &str,
        settings: ModelSettingsContent,
    ) -> anyhow::Result<Model> {
        tracing::info!(
            "Repository: Upserting model settings for model_id={}",
            model_id
        );

        let client = self.pool.get().await?;

        let content_json = serde_json::to_value(&settings)?;

        // Insert or update by model_id
        let row = client
            .query_one(
                "INSERT INTO models (model_id, settings)
                 VALUES ($1, $2)
                 ON CONFLICT (model_id)
                 DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()
                 RETURNING id, model_id, created_at, updated_at",
                &[&model_id, &content_json],
            )
            .await?;

        let settings = Model {
            id: row.get("id"),
            model_id: row.get("model_id"),
            settings,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        tracing::info!(
            "Repository: Model settings upserted successfully for model_id={}",
            model_id
        );

        Ok(settings)
    }

    async fn get_settings_by_ids(
        &self,
        model_ids: &[&str],
    ) -> anyhow::Result<std::collections::HashMap<String, ModelSettingsContent>> {
        tracing::debug!(
            "Repository: Fetching model settings for {} model_ids",
            model_ids.len()
        );

        if model_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT model_id, settings
                 FROM models
                 WHERE model_id = ANY($1)",
                &[&model_ids],
            )
            .await?;

        let mut map = std::collections::HashMap::new();

        for row in rows {
            let model_id: String = row.get("model_id");
            let content_json: serde_json::Value = row.get("settings");

            let default_content = ModelSettingsContent::default();
            let partial = serde_json::from_value::<PartialModelSettingsContent>(content_json)
                .unwrap_or(PartialModelSettingsContent {
                    public: Some(default_content.public),
                });
            let settings = default_content.into_updated(partial);

            map.insert(model_id, settings);
        }

        Ok(map)
    }
}
