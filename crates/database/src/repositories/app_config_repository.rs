use crate::pool::DbPool;
use async_trait::async_trait;
use services::vpc::VpcCredentialsRepository;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Stable row identity for field-encryption AAD, derived from the immutable key.
/// Keep this in sync with the encryption registry's SQL projection.
pub fn app_config_encryption_id(key: &str) -> Uuid {
    let hash = Sha256::digest(key.as_bytes());
    Uuid::from_slice(&hash[..16]).expect("SHA-256 prefix is a UUID-sized byte array")
}

pub struct PostgresAppConfigRepository {
    pool: DbPool,
}

impl PostgresAppConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn encode(&self, key: &str, value: &str) -> anyhow::Result<String> {
        let config = self.pool.field_encryption().ok_or_else(|| {
            anyhow::anyhow!("field encryption configuration is required for app config")
        })?;
        // Credentials must never fall back to plaintext writes, even while the
        // general backfill write gate is disabled.
        crate::field_encryption::encrypt(
            config.ring().write_key(),
            config.ring().write_id(),
            "app_config",
            "value",
            app_config_encryption_id(key),
            value,
        )
    }

    /// Read encrypted and legacy plaintext values. Upgrade legacy rows on read.
    pub async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt("SELECT value FROM app_config WHERE key = $1", &[&key])
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored: String = row.get("value");
        let config = self.pool.field_encryption().ok_or_else(|| {
            anyhow::anyhow!("field encryption configuration is required for app config")
        })?;
        let plaintext = crate::field_encryption::decrypt_if_encrypted_with_ring(
            stored.clone(),
            config.ring(),
            "app_config",
            "value",
            app_config_encryption_id(key),
        )?;
        if stored == plaintext {
            let encrypted = self.encode(key, &plaintext)?;
            // Do not overwrite a concurrent credential refresh or backfill.
            client
                .execute(
                    "UPDATE app_config SET value=$2, updated_at=NOW() WHERE key=$1 AND value=$3",
                    &[&key, &encrypted, &stored],
                )
                .await?;
        }
        Ok(Some(plaintext))
    }

    /// Encrypt values before upserting them. The config key remains queryable.
    pub async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let encrypted = self.encode(key, value)?;
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO app_config (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &encrypted],
            )
            .await?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("DELETE FROM app_config WHERE key = $1", &[&key])
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
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        PostgresAppConfigRepository::delete(self, key).await
    }
}
