use crate::pool::DbPool;
use async_trait::async_trait;
use services::system_configs::ports::{
    PartialSystemConfigs, SystemConfigs, SystemConfigsRepository, SystemKey,
};

pub struct PostgresSystemConfigsRepository {
    pool: DbPool,
}

impl PostgresSystemConfigsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SystemConfigsRepository for PostgresSystemConfigsRepository {
    async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>> {
        tracing::debug!("Repository: Fetching system configs");

        let client = self.pool.get().await?;
        let key = SystemKey::Config.to_string();

        let row = client
            .query_opt("SELECT value FROM system_configs WHERE key = $1", &[&key])
            .await?;

        if let Some(row) = row {
            let value_json: serde_json::Value = row.get("value");

            let default_config = SystemConfigs::default();
            // Missing fields will be filled from default config values
            let partial =
                serde_json::from_value::<PartialSystemConfigs>(value_json).unwrap_or_default();
            let config = default_config.into_updated(partial);

            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    async fn upsert_configs(&self, configs: SystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Repository: Upserting system configs");

        let client = self.pool.get().await?;
        let key = SystemKey::Config.to_string();
        let value_json = serde_json::to_value(&configs)?;

        client
            .execute(
                "INSERT INTO system_configs (key, value)
                 VALUES ($1, $2)
                 ON CONFLICT (key)
                 DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value_json],
            )
            .await?;

        tracing::info!("Repository: System configs upserted successfully");

        Ok(configs)
    }

    async fn update_configs(&self, configs: PartialSystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Repository: Updating system configs");

        let client = self.pool.get().await?;
        let key = SystemKey::Config.to_string();

        // Build JSON object with only fields that should be updated (skip None values)
        let mut delta_json = serde_json::Map::new();
        if let Some(ref default_model) = configs.default_model {
            delta_json.insert(
                "default_model".to_string(),
                serde_json::Value::String(default_model.clone()),
            );
        }

        let delta_value = serde_json::Value::Object(delta_json);

        // Use atomic JSONB merge to prevent lost writes from concurrent updates
        // COALESCE handles NULL, || merges JSONB objects atomically
        let rows_affected = client
            .execute(
                "UPDATE system_configs
                 SET value = COALESCE(value, '{}'::jsonb) || $1::jsonb,
                     updated_at = NOW()
                 WHERE key = $2",
                &[&delta_value, &key],
            )
            .await?;

        if rows_affected == 0 {
            anyhow::bail!("System configs not found for key: {}", SystemKey::Config);
        }

        // Fetch the merged result to return
        self.get_configs()
            .await?
            .ok_or_else(|| anyhow::anyhow!("System configs not found after update"))
    }
}
