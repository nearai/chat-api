use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use services::auth::passkey::{PasskeyChallengeRecord, PasskeyRecord, PasskeyRepository};
use services::types::UserId;
use uuid::Uuid;

pub struct PostgresPasskeyRepository {
    pool: DbPool,
}

impl PostgresPasskeyRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn map_passkey_row(row: tokio_postgres::Row) -> PasskeyRecord {
        PasskeyRecord {
            id: row.get(0),
            user_id: row.get(1),
            credential_id: row.get(2),
            public_key: row.get(3),
            user_handle: row.get(4),
            algorithm: row.get(5),
            friendly_name: row.get(6),
            transports: row.get(7),
            sign_count: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
            last_used_at: row.get(11),
        }
    }
}

#[async_trait]
impl PasskeyRepository for PostgresPasskeyRepository {
    async fn create_passkey(&self, passkey: PasskeyRecord) -> anyhow::Result<PasskeyRecord> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO passkeys (id, user_id, credential_id, public_key, user_handle, algorithm, friendly_name, transports, sign_count, created_at, updated_at, last_used_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 RETURNING id, user_id, credential_id, public_key, user_handle, algorithm, friendly_name, transports, sign_count, created_at, updated_at, last_used_at",
                &[
                    &passkey.id,
                    &passkey.user_id,
                    &passkey.credential_id,
                    &passkey.public_key,
                    &passkey.user_handle,
                    &passkey.algorithm,
                    &passkey.friendly_name,
                    &passkey.transports,
                    &passkey.sign_count,
                    &passkey.created_at,
                    &passkey.updated_at,
                    &passkey.last_used_at,
                ],
            )
            .await?;

        Ok(Self::map_passkey_row(row))
    }

    async fn get_passkeys_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeyRecord>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT id, user_id, credential_id, public_key, user_handle, algorithm, friendly_name, transports, sign_count, created_at, updated_at, last_used_at
                 FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows.into_iter().map(Self::map_passkey_row).collect())
    }

    async fn find_passkey_by_credential(
        &self,
        credential_id: &str,
    ) -> anyhow::Result<Option<PasskeyRecord>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, credential_id, public_key, user_handle, algorithm, friendly_name, transports, sign_count, created_at, updated_at, last_used_at
                 FROM passkeys WHERE credential_id = $1",
                &[&credential_id],
            )
            .await?;

        Ok(row.map(Self::map_passkey_row))
    }

    async fn update_passkey_usage(
        &self,
        credential_id: &str,
        new_sign_count: i64,
        last_used_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute(
                "UPDATE passkeys SET sign_count = $1, last_used_at = $2 WHERE credential_id = $3",
                &[&new_sign_count, &last_used_at, &credential_id],
            )
            .await?;

        Ok(())
    }

    async fn delete_passkey(&self, credential_id: &str) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM passkeys WHERE credential_id = $1",
                &[&credential_id],
            )
            .await?;
        Ok(())
    }

    async fn store_challenge(
        &self,
        challenge: String,
        purpose: &str,
        user_id: Option<UserId>,
        metadata: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO passkey_challenges (id, challenge, purpose, user_id, metadata, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[&Uuid::new_v4(), &challenge, &purpose, &user_id, &metadata, &expires_at],
            )
            .await?;
        Ok(())
    }

    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> anyhow::Result<Option<PasskeyChallengeRecord>> {
        let mut client = self.pool.get().await?;

        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT id, challenge, purpose, user_id, metadata, expires_at, created_at
                 FROM passkey_challenges WHERE challenge = $1",
                &[&challenge],
            )
            .await?;

        let result = if let Some(row) = row {
            transaction
                .execute(
                    "DELETE FROM passkey_challenges WHERE challenge = $1",
                    &[&challenge],
                )
                .await?;

            Some(PasskeyChallengeRecord {
                id: row.get(0),
                challenge: row.get(1),
                purpose: row.get(2),
                user_id: row.get(3),
                metadata: row.get(4),
                expires_at: row.get(5),
                created_at: row.get(6),
            })
        } else {
            None
        };

        transaction.commit().await?;
        Ok(result)
    }

    async fn cleanup_expired_challenges(&self) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let cutoff = Utc::now() - Duration::minutes(10);
        let deleted = client
            .execute(
                "DELETE FROM passkey_challenges WHERE expires_at < $1",
                &[&cutoff],
            )
            .await?;
        Ok(deleted)
    }
}
