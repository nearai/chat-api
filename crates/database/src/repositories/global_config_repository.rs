use crate::pool::DbPool;
use async_trait::async_trait;
use services::global_config::ports::{
    GlobalConfig, GlobalConfigRepository, GlobalKey, PartialGlobalConfig,
};

pub struct PostgresGlobalConfigRepository {
    pool: DbPool,
}

impl PostgresGlobalConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GlobalConfigRepository for PostgresGlobalConfigRepository {
    async fn get_config(&self) -> anyhow::Result<Option<GlobalConfig>> {
        tracing::debug!("Repository: Fetching global config");

        let client = self.pool.get().await?;
        let key = GlobalKey::Config.to_string();

        let row = client
            .query_opt("SELECT value FROM global_configs WHERE key = $1", &[&key])
            .await?;

        if let Some(row) = row {
            let value_json: serde_json::Value = row.get("value");

            let default_config = GlobalConfig::default();
            // Missing fields will be filled from default config values
            let partial =
                serde_json::from_value::<PartialGlobalConfig>(value_json).unwrap_or_default();
            let config = default_config.into_updated(partial);

            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    async fn upsert_config(&self, config: GlobalConfig) -> anyhow::Result<GlobalConfig> {
        tracing::info!("Repository: Upserting global config");

        let client = self.pool.get().await?;
        let key = GlobalKey::Config.to_string();
        let value_json = serde_json::to_value(&config)?;

        client
            .execute(
                "INSERT INTO global_configs (key, value)
                 VALUES ($1, $2)
                 ON CONFLICT (key)
                 DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value_json],
            )
            .await?;

        tracing::info!("Repository: Global config upserted successfully");

        Ok(config)
    }

    async fn update_config(&self, config: PartialGlobalConfig) -> anyhow::Result<GlobalConfig> {
        tracing::info!("Repository: Updating global config");

        // Load existing config, then merge with incoming partial
        let existing = self.get_config().await?;
        let Some(existing) = existing else {
            anyhow::bail!("Global config not found for key: {}", GlobalKey::Config);
        };

        let merged = existing.into_updated(config);

        // Reuse upsert logic to persist merged result
        self.upsert_config(merged).await
    }
}
