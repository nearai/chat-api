use crate::pool::DbPool;
use async_trait::async_trait;
use services::vpc::VpcCredentialsRepository;

pub struct PostgresAppConfigRepository {
    pool: DbPool,
}

impl PostgresAppConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Get a config value by key
    pub async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt("SELECT value FROM app_config WHERE key = $1", &[&key])
            .await?;

        Ok(row.map(|r| r.get("value")))
    }

    /// Set a config value (upsert)
    pub async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "INSERT INTO app_config (key, value) 
                 VALUES ($1, $2) 
                 ON CONFLICT (key) 
                 DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value],
            )
            .await?;

        Ok(())
    }
}

#[async_trait]
impl VpcCredentialsRepository for PostgresAppConfigRepository {
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        PostgresAppConfigRepository::get(self, key).await
    }

    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        PostgresAppConfigRepository::set(self, key, value).await
    }
}
