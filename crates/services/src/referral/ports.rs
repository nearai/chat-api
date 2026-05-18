use crate::system_configs::ports::ReferralRewardTrigger;
use crate::UserId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Referral {
    pub id: Uuid,
    pub inviter_user_id: UserId,
    pub invitee_user_id: UserId,
    pub referral_code_used: String,
    pub reward_trigger_policy: ReferralRewardTrigger,
    pub invitee_reward_amount_nano_usd: i64,
    pub invitee_reward_credit_transaction_id: Option<Uuid>,
    pub invitee_reward_granted_at: Option<DateTime<Utc>>,
    pub inviter_reward_amount_nano_usd: i64,
    pub inviter_reward_credit_transaction_id: Option<Uuid>,
    pub inviter_reward_granted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ReferralListItem {
    pub invitee_user_id: UserId,
    pub invitee_email: String,
    pub registered_at: DateTime<Utc>,
    pub reward_trigger_policy: String,
    pub invitee_reward_amount_nano_usd: i64,
    pub invitee_reward_granted: bool,
    pub invitee_reward_granted_at: Option<DateTime<Utc>>,
    pub subscription_status: Option<String>,
    pub inviter_reward_amount_nano_usd: i64,
    pub inviter_reward_granted: bool,
    pub inviter_reward_granted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ReferralDashboard {
    pub referral_code: String,
    pub referral_code_display: String,
    pub referral_link: String,
    pub total_invites: i64,
    pub total_earned_credits_nano_usd: i64,
    pub invites: Vec<ReferralListItem>,
}

#[derive(Debug, Clone)]
pub struct NewReferral {
    pub inviter_user_id: UserId,
    pub invitee_user_id: UserId,
    pub referral_code_used: String,
    pub reward_trigger_policy: ReferralRewardTrigger,
    pub invitee_reward_amount_nano_usd: i64,
    pub inviter_reward_amount_nano_usd: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReferralError {
    #[error("Invalid referral code")]
    InvalidReferralCode,
    #[error("A user cannot refer themselves")]
    SelfReferral,
    #[error("Referral reward configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
}

#[async_trait]
pub trait ReferralRepository: Send + Sync {
    async fn get_referral_code(&self, user_id: UserId) -> anyhow::Result<Option<String>>;

    /// Attempts to assign a code. Returns true if this call assigned the code.
    /// Returns false if the user already has a code or the candidate code collided.
    async fn try_assign_referral_code(&self, user_id: UserId, code: &str) -> anyhow::Result<bool>;

    async fn find_user_by_referral_code(&self, code: &str) -> anyhow::Result<Option<UserId>>;

    async fn create_referral(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral: NewReferral,
    ) -> anyhow::Result<Option<Referral>>;

    async fn get_referral_by_invitee_for_update(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        invitee_user_id: UserId,
    ) -> anyhow::Result<Option<Referral>>;

    async fn mark_invitee_reward_granted(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral_id: Uuid,
        transaction_id: Uuid,
    ) -> anyhow::Result<()>;

    async fn mark_inviter_reward_granted(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        referral_id: Uuid,
        transaction_id: Uuid,
    ) -> anyhow::Result<()>;

    async fn list_referrals_for_inviter(
        &self,
        inviter_user_id: UserId,
    ) -> anyhow::Result<Vec<ReferralListItem>>;
}

#[async_trait]
pub trait ReferralService: Send + Sync {
    async fn get_or_create_referral_code(&self, user_id: UserId) -> Result<String, ReferralError>;

    async fn validate_referral_code(&self, code: &str) -> Result<(), ReferralError>;

    async fn bind_referral_for_new_user(
        &self,
        invitee_user_id: UserId,
        referral_code: Option<String>,
    ) -> Result<(), ReferralError>;

    async fn apply_rewards_for_invitee_active_in_txn(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
        invitee_user_id: UserId,
    ) -> Result<(), ReferralError>;

    async fn get_dashboard(&self, user_id: UserId) -> Result<ReferralDashboard, ReferralError>;
}
