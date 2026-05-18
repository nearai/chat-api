use super::ports::{
    NewReferral, Referral, ReferralDashboard, ReferralError, ReferralRepository, ReferralService,
};
use crate::subscription::ports::CreditsRepository;
use crate::system_configs::ports::{ReferralConfig, ReferralRewardTrigger, SystemConfigsService};
use crate::UserId;
use async_trait::async_trait;
use rand::Rng;
use serde_json::json;
use std::sync::Arc;

const REFERRAL_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const REFERRAL_CODE_LEN: usize = 8;
const REFERRAL_CODE_RETRIES: usize = 10;
const NANO_USD_PER_CREDIT: u64 = 1_000_000_000;
const DEFAULT_SIGNUP_URL_BASE: &str = "https://agent.near.ai/signup";
const SOURCE_INVITEE_REWARD: &str = "referral_invitee_reward";
const SOURCE_INVITER_REWARD: &str = "referral_inviter_reward";

pub struct ReferralServiceImpl {
    db_pool: deadpool_postgres::Pool,
    referral_repo: Arc<dyn ReferralRepository>,
    credits_repo: Arc<dyn CreditsRepository>,
    system_configs_service: Arc<dyn SystemConfigsService>,
}

impl ReferralServiceImpl {
    pub fn new(
        db_pool: deadpool_postgres::Pool,
        referral_repo: Arc<dyn ReferralRepository>,
        credits_repo: Arc<dyn CreditsRepository>,
        system_configs_service: Arc<dyn SystemConfigsService>,
    ) -> Self {
        Self {
            db_pool,
            referral_repo,
            credits_repo,
            system_configs_service,
        }
    }

    pub fn normalize_referral_code(raw: &str) -> Option<String> {
        let code: String = raw
            .trim()
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if code.is_empty() {
            return None;
        }

        if code.len() != REFERRAL_CODE_LEN
            || !code.bytes().all(|b| REFERRAL_CODE_ALPHABET.contains(&b))
        {
            return None;
        }

        Some(code)
    }

    pub fn display_referral_code(code: &str) -> String {
        if code.len() == REFERRAL_CODE_LEN {
            format!("{}-{}", &code[..4], &code[4..])
        } else {
            code.to_string()
        }
    }

    fn generate_referral_code() -> String {
        let mut rng = rand::rng();
        (0..REFERRAL_CODE_LEN)
            .map(|_| {
                let idx = rng.random_range(0..REFERRAL_CODE_ALPHABET.len());
                REFERRAL_CODE_ALPHABET[idx] as char
            })
            .collect()
    }

    async fn referral_config(&self) -> Result<ReferralConfig, ReferralError> {
        Ok(self
            .system_configs_service
            .get_configs()
            .await
            .map_err(ReferralError::Database)?
            .and_then(|c| c.referrals)
            .unwrap_or_default())
    }

    fn credits_to_nano_usd(credits: u64) -> Result<i64, ReferralError> {
        let amount = credits
            .checked_mul(NANO_USD_PER_CREDIT)
            .ok_or_else(|| ReferralError::InvalidConfig("reward credits overflow".to_string()))?;
        i64::try_from(amount)
            .map_err(|_| ReferralError::InvalidConfig("reward credits exceed i64".to_string()))
    }

    fn referral_link(signup_url_base: Option<String>, code: &str) -> String {
        let base = signup_url_base.unwrap_or_else(|| DEFAULT_SIGNUP_URL_BASE.to_string());
        let separator = if base.contains('?') { '&' } else { '?' };
        format!("{base}{separator}ref={code}")
    }

    async fn apply_referral_rewards(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral: &Referral,
    ) -> Result<(), ReferralError> {
        let reference_id = referral.id.to_string();

        if referral.invitee_reward_credit_transaction_id.is_none() {
            let metadata = json!({
                "referral_id": referral.id,
                "role": "invitee",
                "inviter_user_id": referral.inviter_user_id,
                "invitee_user_id": referral.invitee_user_id,
                "reward_trigger_policy": referral.reward_trigger_policy.as_str(),
                "reward_amount_nano_usd": referral.invitee_reward_amount_nano_usd,
            });
            let (transaction_id, inserted) = self
                .credits_repo
                .record_source_grant_once(
                    txn,
                    referral.invitee_user_id,
                    referral.invitee_reward_amount_nano_usd,
                    SOURCE_INVITEE_REWARD,
                    &reference_id,
                    metadata,
                )
                .await
                .map_err(ReferralError::Database)?;

            if inserted {
                self.credits_repo
                    .add_credits(
                        txn,
                        referral.invitee_user_id,
                        referral.invitee_reward_amount_nano_usd,
                    )
                    .await
                    .map_err(ReferralError::Database)?;
            }

            self.referral_repo
                .mark_invitee_reward_granted(txn, referral.id, transaction_id)
                .await
                .map_err(ReferralError::Database)?;
        }

        if referral.inviter_reward_credit_transaction_id.is_none() {
            let metadata = json!({
                "referral_id": referral.id,
                "role": "inviter",
                "inviter_user_id": referral.inviter_user_id,
                "invitee_user_id": referral.invitee_user_id,
                "reward_trigger_policy": referral.reward_trigger_policy.as_str(),
                "reward_amount_nano_usd": referral.inviter_reward_amount_nano_usd,
            });
            let (transaction_id, inserted) = self
                .credits_repo
                .record_source_grant_once(
                    txn,
                    referral.inviter_user_id,
                    referral.inviter_reward_amount_nano_usd,
                    SOURCE_INVITER_REWARD,
                    &reference_id,
                    metadata,
                )
                .await
                .map_err(ReferralError::Database)?;

            if inserted {
                self.credits_repo
                    .add_credits(
                        txn,
                        referral.inviter_user_id,
                        referral.inviter_reward_amount_nano_usd,
                    )
                    .await
                    .map_err(ReferralError::Database)?;
            }

            self.referral_repo
                .mark_inviter_reward_granted(txn, referral.id, transaction_id)
                .await
                .map_err(ReferralError::Database)?;
        }

        Ok(())
    }
}

#[async_trait]
impl ReferralService for ReferralServiceImpl {
    async fn get_or_create_referral_code(&self, user_id: UserId) -> Result<String, ReferralError> {
        if let Some(code) = self
            .referral_repo
            .get_referral_code(user_id)
            .await
            .map_err(ReferralError::Database)?
        {
            return Ok(code);
        }

        for _ in 0..REFERRAL_CODE_RETRIES {
            let candidate = Self::generate_referral_code();
            let assigned = self
                .referral_repo
                .try_assign_referral_code(user_id, &candidate)
                .await
                .map_err(ReferralError::Database)?;
            if assigned {
                return Ok(candidate);
            }

            if let Some(code) = self
                .referral_repo
                .get_referral_code(user_id)
                .await
                .map_err(ReferralError::Database)?
            {
                return Ok(code);
            }
        }

        Err(ReferralError::InvalidConfig(
            "failed to generate a unique referral code".to_string(),
        ))
    }

    async fn validate_referral_code(&self, code: &str) -> Result<(), ReferralError> {
        let code = Self::normalize_referral_code(code).ok_or(ReferralError::InvalidReferralCode)?;
        let inviter = self
            .referral_repo
            .find_user_by_referral_code(&code)
            .await
            .map_err(ReferralError::Database)?;
        if inviter.is_some() {
            Ok(())
        } else {
            Err(ReferralError::InvalidReferralCode)
        }
    }

    async fn bind_referral_for_new_user(
        &self,
        invitee_user_id: UserId,
        referral_code: Option<String>,
    ) -> Result<(), ReferralError> {
        let Some(raw_code) = referral_code else {
            return Ok(());
        };
        let Some(code) = Self::normalize_referral_code(&raw_code) else {
            return Ok(());
        };

        let inviter_user_id = self
            .referral_repo
            .find_user_by_referral_code(&code)
            .await
            .map_err(ReferralError::Database)?
            .ok_or(ReferralError::InvalidReferralCode)?;

        if inviter_user_id == invitee_user_id {
            return Err(ReferralError::SelfReferral);
        }

        let config = self.referral_config().await?;
        if config.invitee_reward_credits == 0 || config.inviter_reward_credits == 0 {
            return Err(ReferralError::InvalidConfig(
                "referral reward credits must be positive".to_string(),
            ));
        }

        let mut client = self.db_pool.get().await.map_err(|e| {
            ReferralError::Database(anyhow::anyhow!("failed to get DB connection: {e}"))
        })?;
        let txn = client.transaction().await.map_err(|e| {
            ReferralError::Database(anyhow::anyhow!("failed to start transaction: {e}"))
        })?;

        let referral = self
            .referral_repo
            .create_referral(
                &txn,
                NewReferral {
                    inviter_user_id,
                    invitee_user_id,
                    referral_code_used: code,
                    reward_trigger_policy: config.reward_trigger,
                    invitee_reward_amount_nano_usd: Self::credits_to_nano_usd(
                        config.invitee_reward_credits,
                    )?,
                    inviter_reward_amount_nano_usd: Self::credits_to_nano_usd(
                        config.inviter_reward_credits,
                    )?,
                },
            )
            .await
            .map_err(ReferralError::Database)?;

        if let Some(referral) = referral {
            if referral.reward_trigger_policy == ReferralRewardTrigger::InviteeRegistered {
                self.apply_referral_rewards(&txn, &referral).await?;
            }
        }

        txn.commit().await.map_err(|e| {
            ReferralError::Database(anyhow::anyhow!("failed to commit transaction: {e}"))
        })?;

        Ok(())
    }

    async fn apply_rewards_for_invitee_active_in_txn(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        invitee_user_id: UserId,
    ) -> Result<(), ReferralError> {
        let Some(referral) = self
            .referral_repo
            .get_referral_by_invitee_for_update(txn, invitee_user_id)
            .await
            .map_err(ReferralError::Database)?
        else {
            return Ok(());
        };

        if referral.reward_trigger_policy == ReferralRewardTrigger::InviteeFirstActiveSubscription {
            self.apply_referral_rewards(txn, &referral).await?;
        }

        Ok(())
    }

    async fn get_dashboard(&self, user_id: UserId) -> Result<ReferralDashboard, ReferralError> {
        let referral_code = self.get_or_create_referral_code(user_id).await?;
        let config = self.referral_config().await?;
        let invites = self
            .referral_repo
            .list_referrals_for_inviter(user_id)
            .await
            .map_err(ReferralError::Database)?;
        let total_invites = invites.len() as i64;
        let total_earned_credits_nano_usd = invites
            .iter()
            .filter(|i| i.inviter_reward_granted)
            .map(|i| i.inviter_reward_amount_nano_usd)
            .sum();

        Ok(ReferralDashboard {
            referral_link: Self::referral_link(config.signup_url_base, &referral_code),
            referral_code_display: Self::display_referral_code(&referral_code),
            referral_code,
            total_invites,
            total_earned_credits_nano_usd,
            invites,
        })
    }
}
