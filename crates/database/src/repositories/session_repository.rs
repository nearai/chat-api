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
        let client = self.pool.get().await?;

        let created_at = Utc::now();
        // Sessions expire after 30 days
        let expires_at = created_at + Duration::days(30);

        // Generate token and hash it
        let token = Self::generate_session_token();
        let token_hash = Self::hash_session_token(&token);

        let row = client
            .query_one(
                "INSERT INTO sessions (user_id, created_at, expires_at, token_hash) 
                 VALUES ($1, $2, $3, $4) 
                 RETURNING id, user_id, created_at, expires_at",
                &[&user_id, &created_at, &expires_at, &token_hash],
            )
            .await?;

        Ok(UserSession {
            session_id: row.get(0),
            user_id: row.get(1),
            created_at: row.get(2),
            expires_at: row.get(3),
            token: Some(token), // Return the unhashed token only on creation
        })
    }

    async fn get_session_by_token_hash(&self, token_hash: String) -> anyhow::Result<Option<UserSession>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, created_at, expires_at 
                 FROM sessions 
                 WHERE token_hash = $1",
                &[&token_hash],
            )
            .await?;

        Ok(row.map(|r| UserSession {
            session_id: r.get(0),
            user_id: r.get(1),
            created_at: r.get(2),
            expires_at: r.get(3),
            token: None, // Never return the token on retrieval
        }))
    }

    async fn delete_session(&self, session_id: SessionId) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute("DELETE FROM sessions WHERE id = $1", &[&session_id])
            .await?;

        Ok(())
    }
}
