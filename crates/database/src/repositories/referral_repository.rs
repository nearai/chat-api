use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::referral::ports::{NewReferral, Referral, ReferralListItem, ReferralRepository};
use services::system_configs::ports::ReferralRewardTrigger;
use services::UserId;
use uuid::Uuid;

pub struct PostgresReferralRepository {
    pool: DbPool,
}

impl PostgresReferralRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn row_to_referral(row: &tokio_postgres::Row) -> anyhow::Result<Referral> {
    let trigger: String = row.get("reward_trigger_policy");
    let reward_trigger_policy = ReferralRewardTrigger::parse_db_value(&trigger)
        .ok_or_else(|| anyhow::anyhow!("invalid referral trigger policy: {trigger}"))?;

    Ok(Referral {
        id: row.get("id"),
        inviter_user_id: row.get("inviter_user_id"),
        invitee_user_id: row.get("invitee_user_id"),
        referral_code_used: row.get("referral_code_used"),
        reward_trigger_policy,
        invitee_reward_amount_nano_usd: row.get("invitee_reward_amount_nano_usd"),
        invitee_reward_credit_transaction_id: row.get("invitee_reward_credit_transaction_id"),
        invitee_reward_granted_at: row.get("invitee_reward_granted_at"),
        inviter_reward_amount_nano_usd: row.get("inviter_reward_amount_nano_usd"),
        inviter_reward_credit_transaction_id: row.get("inviter_reward_credit_transaction_id"),
        inviter_reward_granted_at: row.get("inviter_reward_granted_at"),
        created_at: row.get("created_at"),
    })
}

const REFERRAL_COLUMNS: &str = "id, inviter_user_id, invitee_user_id, referral_code_used,
    reward_trigger_policy, invitee_reward_amount_nano_usd,
    invitee_reward_credit_transaction_id, invitee_reward_granted_at,
    inviter_reward_amount_nano_usd, inviter_reward_credit_transaction_id,
    inviter_reward_granted_at, created_at";

#[async_trait]
impl ReferralRepository for PostgresReferralRepository {
    async fn get_referral_code(&self, user_id: UserId) -> anyhow::Result<Option<String>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt("SELECT referral_code FROM users WHERE id = $1", &[&user_id])
            .await?;
        Ok(row.and_then(|r| r.get("referral_code")))
    }

    async fn try_assign_referral_code(&self, user_id: UserId, code: &str) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;
        let result = client
            .execute(
                "UPDATE users
                 SET referral_code = $2
                 WHERE id = $1 AND referral_code IS NULL",
                &[&user_id, &code],
            )
            .await;

        match result {
            Ok(updated) => Ok(updated == 1),
            Err(e) => {
                if let Some(db_err) = e.code() {
                    if *db_err == tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                        return Ok(false);
                    }
                }
                Err(e.into())
            }
        }
    }

    async fn find_user_by_referral_code(&self, code: &str) -> anyhow::Result<Option<UserId>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt("SELECT id FROM users WHERE referral_code = $1", &[&code])
            .await?;
        Ok(row.map(|r| r.get("id")))
    }

    async fn create_referral(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral: NewReferral,
    ) -> anyhow::Result<Option<Referral>> {
        let trigger = referral.reward_trigger_policy.as_str();
        let row = txn
            .query_opt(
                &format!(
                    "INSERT INTO referrals (
                        inviter_user_id, invitee_user_id, referral_code_used,
                        reward_trigger_policy, invitee_reward_amount_nano_usd,
                        inviter_reward_amount_nano_usd
                     )
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (invitee_user_id) DO NOTHING
                     RETURNING {REFERRAL_COLUMNS}"
                ),
                &[
                    &referral.inviter_user_id,
                    &referral.invitee_user_id,
                    &referral.referral_code_used,
                    &trigger,
                    &referral.invitee_reward_amount_nano_usd,
                    &referral.inviter_reward_amount_nano_usd,
                ],
            )
            .await?;

        row.as_ref().map(row_to_referral).transpose()
    }

    async fn get_referral_by_invitee_for_update(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        invitee_user_id: UserId,
    ) -> anyhow::Result<Option<Referral>> {
        let row = txn
            .query_opt(
                &format!(
                    "SELECT {REFERRAL_COLUMNS}
                     FROM referrals
                     WHERE invitee_user_id = $1
                     FOR UPDATE"
                ),
                &[&invitee_user_id],
            )
            .await?;

        row.as_ref().map(row_to_referral).transpose()
    }

    async fn mark_invitee_reward_granted(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral_id: Uuid,
        transaction_id: Uuid,
    ) -> anyhow::Result<()> {
        txn.execute(
            "UPDATE referrals
             SET invitee_reward_credit_transaction_id = $2,
                 invitee_reward_granted_at = COALESCE(invitee_reward_granted_at, NOW())
             WHERE id = $1 AND invitee_reward_credit_transaction_id IS NULL",
            &[&referral_id, &transaction_id],
        )
        .await?;
        Ok(())
    }

    async fn mark_inviter_reward_granted(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral_id: Uuid,
        transaction_id: Uuid,
    ) -> anyhow::Result<()> {
        txn.execute(
            "UPDATE referrals
             SET inviter_reward_credit_transaction_id = $2,
                 inviter_reward_granted_at = COALESCE(inviter_reward_granted_at, NOW())
             WHERE id = $1 AND inviter_reward_credit_transaction_id IS NULL",
            &[&referral_id, &transaction_id],
        )
        .await?;
        Ok(())
    }

    async fn list_referrals_for_inviter(
        &self,
        inviter_user_id: UserId,
    ) -> anyhow::Result<Vec<ReferralListItem>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                SELECT
                    r.invitee_user_id,
                    u.email AS invitee_email,
                    u.created_at AS registered_at,
                    r.reward_trigger_policy,
                    r.invitee_reward_amount_nano_usd,
                    r.invitee_reward_credit_transaction_id IS NOT NULL AS invitee_reward_granted,
                    r.invitee_reward_granted_at,
                    sub.status AS subscription_status,
                    r.inviter_reward_amount_nano_usd,
                    r.inviter_reward_credit_transaction_id IS NOT NULL AS inviter_reward_granted,
                    r.inviter_reward_granted_at,
                    r.created_at
                FROM referrals r
                JOIN users u ON u.id = r.invitee_user_id
                LEFT JOIN LATERAL (
                    SELECT status
                    FROM subscriptions
                    WHERE user_id = r.invitee_user_id
                    ORDER BY
                        CASE WHEN status = 'active' THEN 0 WHEN status = 'trialing' THEN 1 ELSE 2 END,
                        updated_at DESC
                    LIMIT 1
                ) sub ON true
                WHERE r.inviter_user_id = $1
                ORDER BY r.created_at DESC
                "#,
                &[&inviter_user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| ReferralListItem {
                invitee_user_id: r.get("invitee_user_id"),
                invitee_email: r.get("invitee_email"),
                registered_at: r.get::<_, DateTime<Utc>>("registered_at"),
                reward_trigger_policy: r.get("reward_trigger_policy"),
                invitee_reward_amount_nano_usd: r.get("invitee_reward_amount_nano_usd"),
                invitee_reward_granted: r.get("invitee_reward_granted"),
                invitee_reward_granted_at: r.get("invitee_reward_granted_at"),
                subscription_status: r.get("subscription_status"),
                inviter_reward_amount_nano_usd: r.get("inviter_reward_amount_nano_usd"),
                inviter_reward_granted: r.get("inviter_reward_granted"),
                inviter_reward_granted_at: r.get("inviter_reward_granted_at"),
            })
            .collect())
    }
}
