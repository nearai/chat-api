use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use services::{
    auth::ports::{SessionRepository, UserSession},
    SessionId, UserId,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct PostgresSessionRepository {
    pool: DbPool,
}

pub(crate) fn generate_session_token() -> String {
    format!("sess_{}", Uuid::new_v4().to_string().replace("-", ""))
}

pub(crate) fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl PostgresSessionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create_session(&self, user_id: UserId) -> anyhow::Result<UserSession> {
        tracing::info!("Creating session for user_id={}", user_id);

        let client = self.pool.get().await?;

        let created_at = Utc::now();
        // During rollout, legacy consumers retain their existing lifetime.
        let expires_at = created_at
            + if config::enforce_short_sessions() {
                Duration::minutes(15)
            } else {
                Duration::days(30)
            };

        tracing::debug!("Session expiry set to: {}", expires_at);

        // Generate token and hash it
        let token = generate_session_token();
        let token_hash = hash_session_token(&token);

        tracing::debug!("Generated session token and hash for user_id={}", user_id);

        let row = client
            .query_one(
                "INSERT INTO sessions (user_id, created_at, expires_at, token_hash) 
                 VALUES ($1, $2, $3, $4) 
                 RETURNING id, user_id, created_at, expires_at",
                &[&user_id, &created_at, &expires_at, &token_hash],
            )
            .await?;

        let session = UserSession {
            session_id: row.get(0),
            user_id: row.get(1),
            created_at: row.get(2),
            expires_at: row.get(3),
            token: Some(token), // Return the unhashed token only on creation
        };

        tracing::info!(
            "Session created successfully: session_id={}, user_id={}, expires_at={}",
            session.session_id,
            session.user_id,
            session.expires_at
        );

        Ok(session)
    }

    async fn get_session_by_token_hash(
        &self,
        token_hash: String,
    ) -> anyhow::Result<Option<UserSession>> {
        tracing::debug!("Looking up session by token hash");

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT s.id, s.user_id, s.created_at,
                        CASE WHEN $2 THEN LEAST(s.expires_at, s.created_at + INTERVAL '15 minutes')
                             ELSE s.expires_at END AS expires_at
                 FROM sessions s
                 WHERE s.token_hash = $1
                 UNION ALL
                 SELECT s.id, s.user_id, s.created_at,
                        LEAST(a.expires_at, s.expires_at, b.idle_expires_at)
                 FROM browser_access_tokens a
                 JOIN sessions s ON s.id = a.session_id
                 JOIN browser_sessions b ON b.session_id = s.id
                 WHERE a.token_hash = $1",
                &[&token_hash, &config::enforce_short_sessions()],
            )
            .await
            .inspect_err(|e| {
                tracing::error!(
                    sqlstate = e.code().map(|code| code.code()),
                    is_closed = e.is_closed(),
                    "Session lookup query failed"
                );
            })?;

        let result = row.map(|r| UserSession {
            session_id: r.get(0),
            user_id: r.get(1),
            created_at: r.get(2),
            expires_at: r.get(3),
            token: None, // Never return the token on retrieval
        });

        if let Some(ref session) = result {
            tracing::debug!(
                "Session found: session_id={}, user_id={}",
                session.session_id,
                session.user_id
            );
        } else {
            tracing::debug!("No session found for provided token_hash");
        }

        Ok(result)
    }

    async fn get_session_by_id(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<Option<UserSession>> {
        tracing::debug!("Looking up session by session_id: {}", session_id);

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, created_at, expires_at 
                 FROM sessions 
                 WHERE id = $1",
                &[&session_id],
            )
            .await?;

        let result = row.map(|r| UserSession {
            session_id: r.get(0),
            user_id: r.get(1),
            created_at: r.get(2),
            expires_at: r.get(3),
            token: None, // Never return the token on retrieval
        });

        if let Some(ref session) = result {
            tracing::debug!(
                "Session found: session_id={}, user_id={}",
                session.session_id,
                session.user_id
            );
        } else {
            tracing::debug!("No session found for session_id: {}", session_id);
        }

        Ok(result)
    }

    async fn browser_session_client(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<Option<String>> {
        let client = self.pool.get().await?;
        // A missing root is an authentication failure, not a legacy session.
        // query_one fails closed if logout/replay deleted it after token lookup.
        let row = client
            .query_one(
                "SELECT b.client FROM sessions s
                 LEFT JOIN browser_sessions b ON b.session_id = s.id
                 WHERE s.id = $1",
                &[&session_id],
            )
            .await?;

        Ok(row.get(0))
    }

    async fn delete_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        tracing::info!("Deleting session: session_id={}", session_id);

        let client = self.pool.get().await?;

        let rows_affected = client
            .execute("DELETE FROM sessions WHERE id = $1", &[&session_id])
            .await?;

        if rows_affected > 0 {
            tracing::info!("Session deleted successfully: session_id={}", session_id);
        } else {
            tracing::warn!("No session found to delete: session_id={}", session_id);
        }

        Ok(())
    }
}
