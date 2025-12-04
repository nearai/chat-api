use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use services::auth::NearNonceRepository;

pub struct PostgresNearNonceRepository {
    pool: DbPool,
}

impl PostgresNearNonceRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl NearNonceRepository for PostgresNearNonceRepository {
    async fn consume_nonce(&self, nonce_hash: &str) -> anyhow::Result<bool> {
        tracing::debug!("Repository: Attempting to consume nonce: {}", nonce_hash);

        let client = self.pool.get().await?;

        // Try to insert the nonce. If it already exists, the insert will fail
        // due to the PRIMARY KEY constraint, and we return false.
        let result = client
            .execute(
                "INSERT INTO near_used_nonces (nonce_hash) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&nonce_hash],
            )
            .await?;

        let consumed = result > 0;

        if consumed {
            tracing::debug!("Repository: Nonce consumed successfully: {}", nonce_hash);
        } else {
            tracing::warn!(
                "Repository: Nonce already used (replay attempt): {}",
                nonce_hash
            );
        }

        Ok(consumed)
    }

    async fn cleanup_expired_nonces(&self) -> anyhow::Result<u64> {
        tracing::debug!("Repository: Cleaning up expired nonces");

        let client = self.pool.get().await?;

        // Delete nonces older than 10 minutes (they can't be valid anymore)
        let cutoff = Utc::now() - Duration::minutes(10);

        let deleted = client
            .execute(
                "DELETE FROM near_used_nonces WHERE used_at < $1",
                &[&cutoff],
            )
            .await?;

        tracing::info!("Repository: Cleaned up {} expired nonces", deleted);

        Ok(deleted)
    }
}
