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

impl PostgresSessionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Generate a new session token
    fn generate_session_token() -> String {
        format!("sess_{}", Uuid::new_v4().to_string().replace("-", ""))
    }

    /// Hash a session token for storage
    fn hash_session_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create_session(&self, user_id: UserId) -> anyhow::Result<UserSession> {
        tracing::info!("Creating session for user_id={}", user_id);

        let client = self.pool.get().await?;

        let created_at = Utc::now();
        // Sessions expire after 30 days
        let expires_at = created_at + Duration::days(30);

        tracing::debug!("Session expiry set to: {} (30 days from now)", expires_at);

        // Generate token and hash it
        let token = Self::generate_session_token();
        let token_hash = Self::hash_session_token(&token);

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
        tracing::debug!(
            "Looking up session by token_hash: {}...",
            &token_hash.chars().take(16).collect::<String>()
        );

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, created_at, expires_at 
                 FROM sessions 
                 WHERE token_hash = $1",
                &[&token_hash],
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
