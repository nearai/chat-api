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
    async fn get_settings(&self) -> anyhow::Result<Option<ModelSettings>> {
        tracing::debug!("Repository: Fetching global model settings");

        let client = self.pool.get().await?;

        // We keep at most one logical row; if multiple exist, take the latest one.
        let row = client
            .query_opt(
                "SELECT id, content, created_at, updated_at 
                 FROM model_settings 
                 ORDER BY created_at DESC 
                 LIMIT 1",
                &[],
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
        content: ModelSettingsContent,
    ) -> anyhow::Result<ModelSettings> {
        tracing::info!("Repository: Upserting global model settings");

        let client = self.pool.get().await?;

        let content_json = serde_json::to_value(&content)?;

        // Try to update the latest row; if none exists, insert a new one.
        let row = client
            .query_opt(
                "WITH latest AS (
                     SELECT id 
                     FROM model_settings 
                     ORDER BY created_at DESC 
                     LIMIT 1
                 )
                 UPDATE model_settings
                 SET content = $1, updated_at = NOW()
                 WHERE id IN (SELECT id FROM latest)
                 RETURNING id, created_at, updated_at",
                &[&content_json],
            )
            .await?;

        let row = if let Some(row) = row {
            row
        } else {
            client
                .query_one(
                    "INSERT INTO model_settings (content)
                     VALUES ($1)
                     RETURNING id, created_at, updated_at",
                    &[&content_json],
                )
                .await?
        };

        let settings = ModelSettings {
            id: row.get("id"),
            content,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        tracing::info!("Repository: Global model settings upserted successfully");

        Ok(settings)
    }
}
