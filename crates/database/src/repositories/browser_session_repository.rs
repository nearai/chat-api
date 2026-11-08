use crate::{
    pool::DbPool,
    repositories::session_repository::{generate_session_token, hash_session_token},
};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use services::{auth::ports::UserSession, SessionId};

// Intentionally not Debug: this value contains plaintext credentials.
pub struct BrowserCredentials {
    pub token: String,
    pub refresh_token: String,
    pub session_id: SessionId,
    pub expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

fn refresh_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn idle_duration(client: &str) -> Duration {
    if client == "admin" {
        Duration::minutes(30)
    } else {
        Duration::days(7)
    }
}

pub struct BrowserSessionRepository(pub DbPool);

impl BrowserSessionRepository {
    /// Called only directly after a successful login/code exchange, never with
    /// an arbitrary bearer credential. Replace the initial credential atomically.
    pub async fn establish(
        &self,
        session: &UserSession,
        client_kind: &str,
        origin: &str,
    ) -> anyhow::Result<BrowserCredentials> {
        anyhow::ensure!(matches!(client_kind, "user" | "admin"), "Invalid client");
        let mut client = self.0.get().await?;
        let tx = client.transaction().await?;
        let now = Utc::now();
        let absolute = now
            + if client_kind == "admin" {
                Duration::hours(8)
            } else {
                Duration::days(30)
            };
        let idle = now + idle_duration(client_kind);
        let expires = now + Duration::minutes(15);
        let token = generate_session_token();
        let refresh = refresh_secret();
        let initial_hash = hash_session_token(
            session
                .token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Missing login credential"))?,
        );

        let changed = tx
            .execute(
                "UPDATE sessions SET token_hash = '', expires_at = $3
                 WHERE id = $1 AND token_hash = $2 AND expires_at > NOW()",
                &[&session.session_id, &initial_hash, &absolute],
            )
            .await?;
        anyhow::ensure!(
            changed == 1,
            "Login session was revoked or already exchanged"
        );

        tx.execute(
            "INSERT INTO browser_sessions (session_id, client, origin, idle_expires_at)
             VALUES ($1, $2, $3, $4)",
            &[&session.session_id, &client_kind, &origin, &idle],
        )
        .await?;
        tx.execute(
            "INSERT INTO browser_access_tokens (token_hash, session_id, expires_at)
             VALUES ($1, $2, $3)",
            &[&hash_session_token(&token), &session.session_id, &expires],
        )
        .await?;
        tx.execute(
            "INSERT INTO browser_refresh_tokens (token_hash, session_id)
             VALUES ($1, $2)",
            &[&hash_session_token(&refresh), &session.session_id],
        )
        .await?;
        tx.commit().await?;

        Ok(BrowserCredentials {
            token,
            refresh_token: refresh,
            session_id: session.session_id,
            expires_at: expires,
            absolute_expires_at: absolute,
        })
    }

    /// Lock the revocation root first, serializing rotation with logout/replay.
    /// Retain consumed hashes until the family is deleted to detect replay.
    pub async fn refresh(
        &self,
        secret: &str,
        client_kind: &str,
        origin: &str,
        active: bool,
    ) -> anyhow::Result<Option<BrowserCredentials>> {
        let mut client = self.0.get().await?;
        let tx = client.transaction().await?;
        let hash = hash_session_token(secret);
        let row = tx
            .query_opt(
                "SELECT s.id, s.expires_at, b.idle_expires_at
                 FROM sessions s JOIN browser_sessions b ON b.session_id = s.id
                 JOIN browser_refresh_tokens r ON r.session_id = s.id
                 WHERE r.token_hash = $1 AND b.client = $2 AND b.origin = $3
                 FOR UPDATE OF s",
                &[&hash, &client_kind, &origin],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: SessionId = row.get(0);
        let absolute: DateTime<Utc> = row.get(1);
        let idle: DateTime<Utc> = row.get(2);
        let now = Utc::now();
        let consumed: bool = tx
            .query_one(
                "SELECT consumed FROM browser_refresh_tokens WHERE token_hash = $1",
                &[&hash],
            )
            .await?
            .get(0);

        if consumed || absolute <= now || idle <= now {
            tx.execute("DELETE FROM sessions WHERE id = $1", &[&id])
                .await?;
            tx.commit().await?;
            return Ok(None);
        }

        let idle = if active {
            (now + idle_duration(client_kind)).min(absolute)
        } else {
            idle
        };
        let expires = (now + Duration::minutes(15)).min(idle).min(absolute);
        let token = generate_session_token();
        let refresh = refresh_secret();

        tx.execute(
            "UPDATE browser_refresh_tokens SET consumed = TRUE WHERE token_hash = $1",
            &[&hash],
        )
        .await?;
        tx.execute(
            "UPDATE browser_sessions SET idle_expires_at = $2 WHERE session_id = $1",
            &[&id, &idle],
        )
        .await?;
        tx.execute(
            "DELETE FROM browser_access_tokens WHERE session_id = $1 AND expires_at <= NOW()",
            &[&id],
        )
        .await?;
        tx.execute(
            "INSERT INTO browser_access_tokens (token_hash, session_id, expires_at)
             VALUES ($1, $2, $3)",
            &[&hash_session_token(&token), &id, &expires],
        )
        .await?;
        tx.execute(
            "INSERT INTO browser_refresh_tokens (token_hash, session_id)
             VALUES ($1, $2)",
            &[&hash_session_token(&refresh), &id],
        )
        .await?;
        tx.commit().await?;

        Ok(Some(BrowserCredentials {
            token,
            refresh_token: refresh,
            session_id: id,
            expires_at: expires,
            absolute_expires_at: absolute,
        }))
    }

    /// Delete only expired browser roots, retaining all replay evidence for live
    /// families. SKIP LOCKED lets multiple API replicas run bounded cleanup safely
    /// without waiting for a concurrent refresh/logout transaction.
    pub async fn cleanup_expired(&self, batch_size: i64) -> anyhow::Result<u64> {
        anyhow::ensure!(
            (1..=500).contains(&batch_size),
            "Invalid cleanup batch size"
        );
        let client = self.0.get().await?;
        let deleted = client
            .execute(
                "WITH candidates AS (
                    SELECT s.id FROM sessions s
                    JOIN browser_sessions b ON b.session_id = s.id
                    WHERE s.expires_at <= NOW()
                    UNION
                    SELECT b.session_id FROM browser_sessions b
                    WHERE b.idle_expires_at <= NOW()
                 ), expired AS (
                    SELECT s.id FROM sessions s
                    JOIN candidates c ON c.id = s.id
                    ORDER BY s.id
                    LIMIT $1
                    FOR UPDATE OF s SKIP LOCKED
                 )
                 DELETE FROM sessions s USING expired e WHERE s.id = e.id",
                &[&batch_size],
            )
            .await?;

        Ok(deleted)
    }

    /// Accept consumed refresh credentials too: logout must win against a refresh
    /// that committed while the browser was sending its logout request.
    pub async fn logout(
        &self,
        secret: &str,
        client_kind: &str,
        origin: &str,
    ) -> anyhow::Result<()> {
        let client = self.0.get().await?;
        client
            .execute(
                "DELETE FROM sessions WHERE id IN (
                    SELECT b.session_id FROM browser_sessions b
                    JOIN browser_refresh_tokens r ON r.session_id = b.session_id
                    WHERE r.token_hash = $1 AND b.client = $2 AND b.origin = $3
                 )",
                &[&hash_session_token(secret), &client_kind, &origin],
            )
            .await?;

        Ok(())
    }
}
