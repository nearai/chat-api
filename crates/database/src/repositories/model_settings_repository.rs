use crate::pool::DbPool;
use async_trait::async_trait;
use services::settings::ports::{
    ModelSettings, ModelSettingsContent, ModelSettingsRepository, PartialModelSettingsContent,
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
impl ModelSettingsRepository for PostgresModelSettingsRepository {
    async fn get_settings(&self, model_id: &str) -> anyhow::Result<Option<ModelSettings>> {
        tracing::debug!(
            "Repository: Fetching model settings for model_id={}",
            model_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, model_id, content, created_at, updated_at 
                 FROM model_settings 
                 WHERE model_id = $1",
                &[&model_id],
            )
            .await?;

        if let Some(row) = row {
            let content_json: serde_json::Value = row.get("content");

            let default_content = ModelSettingsContent::default();
            // Missing fields will be filled from default settings content
            let partial_content =
                serde_json::from_value::<PartialModelSettingsContent>(content_json)?;
            let content = default_content.into_updated(partial_content);

            Ok(Some(ModelSettings {
                id: row.get("id"),
                model_id: row.get("model_id"),
                content,
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
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettings> {
        tracing::info!(
            "Repository: Upserting model settings for model_id={}",
            model_id
        );

        let client = self.pool.get().await?;

        let content_json = serde_json::to_value(&content)?;

        // Insert or update by model_id
        let row = client
            .query_one(
                "INSERT INTO model_settings (model_id, content)
                 VALUES ($1, $2)
                 ON CONFLICT (model_id)
                 DO UPDATE SET content = EXCLUDED.content, updated_at = NOW()
                 RETURNING id, model_id, created_at, updated_at",
                &[&model_id, &content_json],
            )
            .await?;

        let settings = ModelSettings {
            id: row.get("id"),
            model_id: row.get("model_id"),
            content,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        tracing::info!(
            "Repository: Model settings upserted successfully for model_id={}",
            model_id
        );

        Ok(settings)
    }

    async fn get_settings_for_models(
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
                "SELECT model_id, content
                 FROM model_settings
                 WHERE model_id = ANY($1)",
                &[&model_ids],
            )
            .await?;

        let mut map = std::collections::HashMap::new();

        for row in rows {
            let model_id: String = row.get("model_id");
            let content_json: serde_json::Value = row.get("content");

            let default_content = ModelSettingsContent::default();
            let partial = serde_json::from_value::<PartialModelSettingsContent>(content_json)
                .unwrap_or(PartialModelSettingsContent {
                    public: Some(default_content.public),
                });
            let content = default_content.into_updated(partial);

            map.insert(model_id, content);
        }

        Ok(map)
    }
}
