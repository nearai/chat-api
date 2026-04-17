use crate::pool::DbPool;
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::auth::ports::{
    EmailVerificationChallenge, EmailVerificationChallengeRepository,
    EmailVerificationChallengeStatus,
};
use std::net::IpAddr;
use tokio_postgres::Row;
use uuid::Uuid;

pub struct PostgresEmailVerificationChallengeRepository {
    pool: DbPool,
}

impl PostgresEmailVerificationChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn status_from_str(value: &str) -> anyhow::Result<EmailVerificationChallengeStatus> {
    match value {
        "pending" => Ok(EmailVerificationChallengeStatus::Pending),
        "sent" => Ok(EmailVerificationChallengeStatus::Sent),
        "failed" => Ok(EmailVerificationChallengeStatus::Failed),
        "consumed" => Ok(EmailVerificationChallengeStatus::Consumed),
        "invalidated" => Ok(EmailVerificationChallengeStatus::Invalidated),
        _ => Err(anyhow::anyhow!(
            "unexpected email verification challenge status from DB: {}",
            value
        )),
    }
}

fn challenge_from_row(row: Row) -> anyhow::Result<EmailVerificationChallenge> {
    let status = row.get::<_, String>("status");

    Ok(EmailVerificationChallenge {
        id: row.get("id"),
        email: row.get("email"),
        code_mac: row.get("code_mac"),
        status: status_from_str(status.as_str())?,
        attempt_count: row.get("attempt_count"),
        provider_message_id: row.get("provider_message_id"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
    })
}

#[async_trait]
impl EmailVerificationChallengeRepository for PostgresEmailVerificationChallengeRepository {
    async fn create_pending_challenge(
        &self,
        challenge_id: Uuid,
        email: &str,
        code_mac: &str,
        ip_address: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<EmailVerificationChallenge> {
        let parsed_ip: IpAddr = ip_address.parse()?;
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        transaction
            .execute(
                "UPDATE email_verification_challenges
                 SET status = 'invalidated'
                 WHERE email = $1
                   AND status IN ('pending', 'sent')
                   AND expires_at > NOW()",
                &[&email],
            )
            .await?;

        let row = transaction
            .query_one(
                "INSERT INTO email_verification_challenges (id, email, code_mac, ip_address, status, expires_at)
                 VALUES ($1, $2, $3, $4, 'pending', $5)
                 RETURNING id, email, code_mac, status, attempt_count, provider_message_id, created_at, expires_at",
                &[&challenge_id, &email, &code_mac, &parsed_ip, &expires_at],
            )
            .await?;

        transaction.commit().await?;

        challenge_from_row(row)
    }

    async fn mark_challenge_sent(
        &self,
        challenge_id: Uuid,
        provider_message_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        let updated_rows = client
            .execute(
                "UPDATE email_verification_challenges
                 SET status = 'sent', provider_message_id = $2
                 WHERE id = $1 AND status = 'pending'",
                &[&challenge_id, &provider_message_id],
            )
            .await?;
        if updated_rows == 0 {
            tracing::warn!(
                challenge_id = %challenge_id,
                "mark_challenge_sent updated no rows; challenge likely changed state concurrently"
            );
        }
        Ok(())
    }

    async fn mark_challenge_failed(&self, challenge_id: Uuid) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        let updated_rows = client
            .execute(
                "UPDATE email_verification_challenges
                 SET status = 'failed'
                 WHERE id = $1 AND status = 'pending'",
                &[&challenge_id],
            )
            .await?;
        if updated_rows == 0 {
            tracing::warn!(
                challenge_id = %challenge_id,
                "mark_challenge_failed updated no rows; challenge likely changed state concurrently"
            );
        }
        Ok(())
    }

    async fn count_recent_challenges_for_email(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*)::bigint
                 FROM email_verification_challenges
                 WHERE email = $1
                   AND created_at >= $2
                   AND status <> 'failed'",
                &[&email, &since],
            )
            .await?;
        let count: i64 = row.get(0);
        Ok(count as u64)
    }

    async fn count_recent_challenges_for_ip(
        &self,
        ip_address: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let parsed_ip: IpAddr = ip_address.parse()?;
        let row = client
            .query_one(
                "SELECT COUNT(*)::bigint
                 FROM email_verification_challenges
                 WHERE ip_address = $1
                   AND created_at >= $2
                   AND status <> 'failed'",
                &[&parsed_ip, &since],
            )
            .await?;
        let count: i64 = row.get(0);
        Ok(count as u64)
    }

    async fn count_recent_failed_verifications_for_email(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "SELECT COALESCE(SUM(attempt_count), 0)::bigint
                 FROM email_verification_challenges
                 WHERE email = $1 AND created_at >= $2",
                &[&email, &since],
            )
            .await?;
        let count: i64 = row.get(0);
        Ok(count as u64)
    }

    async fn count_recent_failed_verifications_for_ip(
        &self,
        ip_address: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        let parsed_ip: IpAddr = ip_address.parse()?;
        let row = client
            .query_one(
                "SELECT COALESCE(SUM(attempt_count), 0)::bigint
                 FROM email_verification_challenges
                 WHERE ip_address = $1 AND created_at >= $2",
                &[&parsed_ip, &since],
            )
            .await?;
        let count: i64 = row.get(0);
        Ok(count as u64)
    }

    async fn get_latest_active_sent_challenge(
        &self,
        email: &str,
    ) -> anyhow::Result<Option<EmailVerificationChallenge>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT id, email, code_mac, status, attempt_count, provider_message_id, created_at, expires_at
                 FROM email_verification_challenges
                 WHERE email = $1
                   AND status = 'sent'
                   AND expires_at > NOW()
                 ORDER BY created_at DESC
                 LIMIT 1",
                &[&email],
            )
            .await?;

        row.map(challenge_from_row).transpose()
    }

    /// Atomically look up the latest 'sent' challenge for an email and attempt verification.
    /// Uses FOR UPDATE SKIP LOCKED to avoid blocking concurrent requests on different challenges.
    /// Returns Some(true) if the code matched (challenge consumed), Some(false) if the code
    /// did not match (attempt counted, may be invalidated), None if no active challenge found.
    async fn verify_email_code(
        &self,
        email: &str,
        code_mac: &str,
        max_attempts: i32,
    ) -> anyhow::Result<Option<bool>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "WITH active_challenge AS (
                    SELECT id, code_mac, attempt_count
                    FROM email_verification_challenges
                    WHERE email = $1
                      AND status = 'sent'
                      AND expires_at > NOW()
                    ORDER BY created_at DESC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE email_verification_challenges
                SET
                    attempt_count = CASE WHEN active_challenge.code_mac = $2 THEN active_challenge.attempt_count ELSE active_challenge.attempt_count + 1 END,
                    status = CASE
                        WHEN active_challenge.code_mac = $2 THEN 'consumed'
                        WHEN active_challenge.attempt_count + 1 >= $3 THEN 'invalidated'
                        ELSE status
                    END
                FROM active_challenge
                WHERE email_verification_challenges.id = active_challenge.id
                  AND email_verification_challenges.status = 'sent'
                RETURNING active_challenge.code_mac = $2 AS matched",
                &[&email, &code_mac, &max_attempts],
            )
            .await
            .context("Failed to atomically verify email code")?;

        Ok(row.map(|r| r.get(0)))
    }
}
