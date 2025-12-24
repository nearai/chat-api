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

    async fn upsert_configs(&self, config: SystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Repository: Upserting system configs");

        let client = self.pool.get().await?;
        let key = SystemKey::Config.to_string();
        let value_json = serde_json::to_value(&config)?;

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

        Ok(config)
    }

    async fn update_configs(&self, config: PartialSystemConfigs) -> anyhow::Result<SystemConfigs> {
        tracing::info!("Repository: Updating system configs");

        // Load existing config, then merge with incoming partial
        let existing = self.get_configs().await?;
        let Some(existing) = existing else {
            anyhow::bail!("System configs not found for key: {}", SystemKey::Config);
        };

        let merged = existing.into_updated(config);

        // Reuse upsert logic to persist merged result
        self.upsert_configs(merged).await
    }
}
