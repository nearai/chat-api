use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::auth::ports::{
    PasskeyChallenge, PasskeyChallengeKind, PasskeyChallengeRepository, PasskeyRecord,
    PasskeyRepository,
};
use services::{PasskeyChallengeId, PasskeyId, UserId};

pub struct PostgresPasskeyRepository {
    pool: DbPool,
}

impl PostgresPasskeyRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasskeyRepository for PostgresPasskeyRepository {
    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeyRecord>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                SELECT id, user_id, credential_id, passkey, nickname, created_at, last_used_at
                FROM passkeys
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#,
                &[&user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| PasskeyRecord {
                id: r.get(0),
                user_id: r.get(1),
                credential_id: r.get(2),
                passkey: r.get(3),
                nickname: r.get(4),
                created_at: r.get(5),
                last_used_at: r.get(6),
            })
            .collect())
    }

    async fn get_by_id(&self, id: PasskeyId) -> anyhow::Result<Option<PasskeyRecord>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT id, user_id, credential_id, passkey, nickname, created_at, last_used_at
                FROM passkeys
                WHERE id = $1
                "#,
                &[&id],
            )
            .await?;

        Ok(row.map(|r| PasskeyRecord {
            id: r.get(0),
            user_id: r.get(1),
            credential_id: r.get(2),
            passkey: r.get(3),
            nickname: r.get(4),
            created_at: r.get(5),
            last_used_at: r.get(6),
        }))
    }

    async fn get_by_credential_id(
        &self,
        credential_id: &str,
    ) -> anyhow::Result<Option<PasskeyRecord>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT id, user_id, credential_id, passkey, nickname, created_at, last_used_at
                FROM passkeys
                WHERE credential_id = $1
                "#,
                &[&credential_id],
            )
            .await?;

        Ok(row.map(|r| PasskeyRecord {
            id: r.get(0),
            user_id: r.get(1),
            credential_id: r.get(2),
            passkey: r.get(3),
            nickname: r.get(4),
            created_at: r.get(5),
            last_used_at: r.get(6),
        }))
    }

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: String,
        passkey: serde_json::Value,
        nickname: Option<String>,
    ) -> anyhow::Result<PasskeyId> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                r#"
                INSERT INTO passkeys (user_id, credential_id, passkey, nickname)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
                &[&user_id, &credential_id, &passkey, &nickname],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn update_passkey_and_last_used_at(
        &self,
        id: PasskeyId,
        passkey: serde_json::Value,
        last_used_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
                UPDATE passkeys
                SET passkey = $2, last_used_at = $3
                WHERE id = $1
                "#,
                &[&id, &passkey, &last_used_at],
            )
            .await?;
        Ok(())
    }

    async fn delete_passkey(&self, user_id: UserId, id: PasskeyId) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let rows = client
            .execute(
                r#"
                DELETE FROM passkeys
                WHERE id = $1 AND user_id = $2
                "#,
                &[&id, &user_id],
            )
            .await?;
        Ok(rows > 0)
    }
}

pub struct PostgresPasskeyChallengeRepository {
    pool: DbPool,
}

impl PostgresPasskeyChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn parse_kind(kind: &str) -> anyhow::Result<PasskeyChallengeKind> {
        match kind {
            "registration" => Ok(PasskeyChallengeKind::Registration),
            "authentication" => Ok(PasskeyChallengeKind::Authentication),
            "discoverable_authentication" => Ok(PasskeyChallengeKind::DiscoverableAuthentication),
            _ => Err(anyhow::anyhow!("Unknown passkey challenge kind")),
        }
    }
}

#[async_trait]
impl PasskeyChallengeRepository for PostgresPasskeyChallengeRepository {
    async fn create_challenge(
        &self,
        kind: PasskeyChallengeKind,
        user_id: Option<UserId>,
        state: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<PasskeyChallengeId> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                r#"
                INSERT INTO passkey_challenges (kind, user_id, state, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
                &[&kind.as_str(), &user_id, &state, &expires_at],
            )
            .await?;
        Ok(row.get(0))
    }

    async fn consume_challenge(
        &self,
        id: PasskeyChallengeId,
    ) -> anyhow::Result<Option<PasskeyChallenge>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                DELETE FROM passkey_challenges
                WHERE id = $1
                RETURNING id, kind, user_id, state, created_at, expires_at
                "#,
                &[&id],
            )
            .await?;

        let Some(r) = row else {
            return Ok(None);
        };

        let kind_str: String = r.get(1);
        let kind = Self::parse_kind(&kind_str)?;

        Ok(Some(PasskeyChallenge {
            id: r.get(0),
            kind,
            user_id: r.get(2),
            state: r.get(3),
            created_at: r.get(4),
            expires_at: r.get(5),
        }))
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let rows = client
            .execute(
                r#"
                DELETE FROM passkey_challenges
                WHERE expires_at < $1
                "#,
                &[&now],
            )
            .await?;
        Ok(rows)
    }
}
