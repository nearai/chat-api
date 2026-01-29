use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use postgres_types::Json;
use services::auth::ports::{
    Passkey, PasskeyAuthentication, PasskeyChallenge, PasskeyChallengeKind,
    PasskeyChallengeRepository, PasskeyChallengeState, PasskeyRecord, PasskeyRegistration,
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
                SELECT id, user_id, credential_id, passkey, label, created_at, last_used_at
                FROM passkeys
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#,
                &[&user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let Json(passkey): Json<Passkey> = r.get(3);
                PasskeyRecord {
                    id: r.get(0),
                    user_id: r.get(1),
                    credential_id: r.get(2),
                    passkey,
                    label: r.get(4),
                    created_at: r.get(5),
                    last_used_at: r.get(6),
                }
            })
            .collect())
    }

    async fn get_by_id(&self, id: PasskeyId) -> anyhow::Result<Option<PasskeyRecord>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                SELECT id, user_id, credential_id, passkey, label, created_at, last_used_at
                FROM passkeys
                WHERE id = $1
                "#,
                &[&id],
            )
            .await?;

        Ok(row.map(|r| {
            let Json(passkey): Json<Passkey> = r.get(3);
            PasskeyRecord {
                id: r.get(0),
                user_id: r.get(1),
                credential_id: r.get(2),
                passkey,
                label: r.get(4),
                created_at: r.get(5),
                last_used_at: r.get(6),
            }
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
                SELECT id, user_id, credential_id, passkey, label, created_at, last_used_at
                FROM passkeys
                WHERE credential_id = $1
                "#,
                &[&credential_id],
            )
            .await?;

        Ok(row.map(|r| {
            let Json(passkey): Json<Passkey> = r.get(3);
            PasskeyRecord {
                id: r.get(0),
                user_id: r.get(1),
                credential_id: r.get(2),
                passkey,
                label: r.get(4),
                created_at: r.get(5),
                last_used_at: r.get(6),
            }
        }))
    }

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: String,
        passkey: Passkey,
        label: Option<String>,
    ) -> anyhow::Result<PasskeyId> {
        let client = self.pool.get().await?;
        let passkey_json = Json(&passkey);
        let row = client
            .query_one(
                r#"
                INSERT INTO passkeys (user_id, credential_id, passkey, label)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
                &[&user_id, &credential_id, &passkey_json, &label],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn update_passkey_and_last_used_at(
        &self,
        id: PasskeyId,
        passkey: Passkey,
        last_used_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        let passkey_json = Json(&passkey);
        client
            .execute(
                r#"
                UPDATE passkeys
                SET passkey = $2, last_used_at = $3
                WHERE id = $1
                "#,
                &[&id, &passkey_json, &last_used_at],
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
            _ => Err(anyhow::anyhow!("Unknown passkey challenge kind")),
        }
    }
}

#[async_trait]
impl PasskeyChallengeRepository for PostgresPasskeyChallengeRepository {
    async fn create_challenge(
        &self,
        user_id: Option<UserId>,
        state: PasskeyChallengeState,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<PasskeyChallengeId> {
        let client = self.pool.get().await?;

        match state {
            PasskeyChallengeState::Registration(s) => {
                let state_json = Json(&s);
                let row = client
                    .query_one(
                        r#"
                        INSERT INTO passkey_challenges (kind, user_id, state, expires_at)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id
                        "#,
                        &[
                            &PasskeyChallengeKind::Registration.as_str(),
                            &user_id,
                            &state_json,
                            &expires_at,
                        ],
                    )
                    .await?;
                Ok(row.get(0))
            }
            PasskeyChallengeState::Authentication(s) => {
                let state_json = Json(&s);
                let row = client
                    .query_one(
                        r#"
                        INSERT INTO passkey_challenges (kind, user_id, state, expires_at)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id
                        "#,
                        &[
                            &PasskeyChallengeKind::Authentication.as_str(),
                            &user_id,
                            &state_json,
                            &expires_at,
                        ],
                    )
                    .await?;
                Ok(row.get(0))
            }
        }
    }

    async fn consume_challenge(
        &self,
        id: PasskeyChallengeId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<PasskeyChallenge>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
                DELETE FROM passkey_challenges
                WHERE id = $1 AND expires_at >= $2
                RETURNING id, kind, user_id, state, created_at, expires_at
                "#,
                &[&id, &now],
            )
            .await?;

        let Some(r) = row else {
            return Ok(None);
        };

        let kind_str: String = r.get(1);
        let kind = Self::parse_kind(&kind_str)?;

        let state = match kind {
            PasskeyChallengeKind::Registration => {
                let Json(state): Json<PasskeyRegistration> = r.get(3);
                PasskeyChallengeState::Registration(state)
            }
            PasskeyChallengeKind::Authentication => {
                let Json(state): Json<PasskeyAuthentication> = r.get(3);
                PasskeyChallengeState::Authentication(state)
            }
        };

        Ok(Some(PasskeyChallenge {
            id: r.get(0),
            kind,
            user_id: r.get(2),
            state,
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
