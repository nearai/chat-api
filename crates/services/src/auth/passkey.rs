use crate::types::UserId;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub algorithm: String,
    pub friendly_name: Option<String>,
    pub transports: Option<Vec<String>>,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallengeRecord {
    pub id: Uuid,
    pub challenge: String,
    pub purpose: String,
    pub user_id: Option<UserId>,
    pub metadata: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasskeyRepository: Send + Sync {
    async fn create_passkey(&self, passkey: PasskeyRecord) -> anyhow::Result<PasskeyRecord>;
    async fn get_passkeys_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeyRecord>>;
    async fn find_passkey_by_credential(
        &self,
        credential_id: &str,
    ) -> anyhow::Result<Option<PasskeyRecord>>;
    async fn update_passkey_usage(
        &self,
        credential_id: &str,
        new_sign_count: i64,
        last_used_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    async fn delete_passkey(&self, credential_id: &str) -> anyhow::Result<()>;
    async fn store_challenge(
        &self,
        challenge: String,
        purpose: &str,
        user_id: Option<UserId>,
        metadata: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> anyhow::Result<Option<PasskeyChallengeRecord>>;
    async fn cleanup_expired_challenges(&self) -> anyhow::Result<u64>;
}

pub fn generate_challenge() -> String {
    let mut rng = rand::rng();
    std::iter::repeat_with(|| rng.sample(Alphanumeric))
        .take(64)
        .map(char::from)
        .collect()
}

pub fn challenge_expiry() -> DateTime<Utc> {
    Utc::now() + Duration::minutes(5)
}
