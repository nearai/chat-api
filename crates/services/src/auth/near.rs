use async_trait::async_trait;
use borsh::{to_vec, BorshSerialize};
use chrono::{DateTime, Duration, Utc};
use near_crypto::{KeyType, PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::{str::FromStr, sync::Arc};

use super::ports::{NearSignedMessage, SessionRepository, UserSession};
use crate::types::UserId;
use crate::user::ports::{OAuthProvider, UserRepository};

const NEP413_TAG: u32 = 2_147_484_061; // 2^31 + 413 (NEP-413 specification)
const DEFAULT_MAX_NONCE_AGE_MS: u64 = 5 * 60 * 1000; // 5 minutes

/// Repository trait for NEAR nonce management (replay protection)
#[async_trait]
pub trait NearNonceRepository: Send + Sync {
    /// Check if a nonce has been used and mark it as used
    /// Returns true if the nonce was successfully consumed (not previously used)
    async fn consume_nonce(&self, nonce_hash: &str) -> anyhow::Result<bool>;

    /// Clean up expired nonces (optional, for maintenance)
    async fn cleanup_expired_nonces(&self) -> anyhow::Result<u64>;
}

/// Helper to verify NEP-413 signed messages and create sessions
pub struct NearAuthService {
    session_repository: Arc<dyn SessionRepository>,
    user_repository: Arc<dyn UserRepository>,
    nonce_repository: Arc<dyn NearNonceRepository>,
}

#[derive(BorshSerialize)]
struct Nep413Payload {
    tag: u32,
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

impl NearAuthService {
    pub fn new(
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        nonce_repository: Arc<dyn NearNonceRepository>,
    ) -> Self {
        Self {
            session_repository,
            user_repository,
            nonce_repository,
        }
    }

    fn parse_public_key(public_key: &str) -> anyhow::Result<PublicKey> {
        PublicKey::from_str(public_key).map_err(|_| anyhow::anyhow!("invalid public key"))
    }

    fn parse_signature(signature_str: &str) -> anyhow::Result<Signature> {
        // Try standard NEAR format first (ed25519:base58)
        if let Ok(sig) = Signature::from_str(signature_str) {
            return Ok(sig);
        }

        // Fallback: wallet UIs sometimes return base64 without prefix
        use base64::{engine::general_purpose::STANDARD, Engine};
        let raw = STANDARD
            .decode(signature_str)
            .map_err(|_| anyhow::anyhow!("invalid signature encoding"))?;

        Signature::from_parts(KeyType::ED25519, &raw)
            .map_err(|_| anyhow::anyhow!("invalid signature bytes"))
    }

    /// Construct the NEP-413 payload that was signed using Borsh
    /// Format: SHA256(borsh_serialize(NEP413Payload))
    fn construct_nep413_payload(
        message: &str,
        nonce: &[u8; 32],
        recipient: &str,
        callback_url: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let payload = Nep413Payload {
            tag: NEP413_TAG,
            message: message.to_string(),
            nonce: *nonce,
            recipient: recipient.to_string(),
            callback_url: callback_url.map(str::to_string),
        };

        let serialized = to_vec(&payload)
            .map_err(|e| anyhow::anyhow!("Failed to serialize NEP-413 payload: {}", e))?;

        Ok(Sha256::digest(serialized).to_vec())
    }

    /// Extract timestamp from nonce (near-kit embeds timestamp in first 8 bytes)
    fn extract_nonce_timestamp(nonce: &[u8]) -> Option<DateTime<Utc>> {
        if nonce.len() < 8 {
            return None;
        }

        let timestamp_bytes: [u8; 8] = nonce[0..8].try_into().ok()?;
        let timestamp_ms = i64::from_le_bytes(timestamp_bytes);

        DateTime::from_timestamp_millis(timestamp_ms)
    }

    /// Verify the cryptographic signature
    fn verify_signature(&self, signed_message: &NearSignedMessage) -> anyhow::Result<()> {
        let public_key = Self::parse_public_key(&signed_message.public_key)?;
        let signature = Self::parse_signature(&signed_message.signature)?;

        let nonce_bytes: [u8; 32] = signed_message
            .nonce
            [..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid nonce length"))?;

        let payload_hash = Self::construct_nep413_payload(
            &signed_message.message,
            &nonce_bytes,
            &signed_message.recipient,
            None,
        )?;

        if !signature.verify(payload_hash.as_ref(), &public_key) {
            return Err(anyhow::anyhow!("invalid signature"));
        }

        Ok(())
    }

    /// Find or create user from NEAR account
    async fn find_or_create_user(&self, account_id: &str) -> anyhow::Result<(UserId, bool)> {
        tracing::info!("Finding or creating user for NEAR account: {}", account_id);

        // Check if user exists by NEAR account ID
        if let Some(user_id) = self
            .user_repository
            .find_user_by_oauth(OAuthProvider::Near, account_id)
            .await?
        {
            tracing::info!(
                "Found existing user by NEAR account: user_id={}, account_id={}",
                user_id,
                account_id
            );
            return Ok((user_id, false));
        }

        // Create new user with NEAR account ID as email placeholder
        // NEAR accounts don't have emails, so we use account_id@near as placeholder
        let placeholder_email = format!("{}@near", account_id);

        tracing::info!(
            "No existing user found, creating new user for NEAR account: {}",
            account_id
        );

        let user = self
            .user_repository
            .create_user(
                placeholder_email,
                Some(account_id.to_string()), // Use account ID as name
                None,
            )
            .await?;

        tracing::info!(
            "Created new user: user_id={}, account_id={}",
            user.id,
            account_id
        );

        // Link the NEAR account
        self.user_repository
            .link_oauth_account(user.id, OAuthProvider::Near, account_id.to_string())
            .await?;

        tracing::info!("Successfully linked NEAR account to user_id={}", user.id);

        Ok((user.id, true))
    }
    pub async fn verify_and_authenticate(
        &self,
        signed_message: NearSignedMessage,
        max_age_ms: Option<u64>,
    ) -> anyhow::Result<(UserSession, bool)> {
        let max_age = max_age_ms.unwrap_or(DEFAULT_MAX_NONCE_AGE_MS);

        tracing::info!(
            "NEAR authentication attempt for account: {}",
            signed_message.account_id
        );

        // 1. Verify nonce length
        if signed_message.nonce.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid nonce length: expected 32 bytes, got {}",
                signed_message.nonce.len()
            ));
        }

        // 2. Check nonce timestamp (replay protection)
        if let Some(nonce_time) = Self::extract_nonce_timestamp(&signed_message.nonce) {
            let age = Utc::now().signed_duration_since(nonce_time);
            if age > Duration::milliseconds(max_age as i64) {
                tracing::warn!(
                    "NEAR signature expired for account {}: age={:?}ms, max_age={}ms",
                    signed_message.account_id,
                    age.num_milliseconds(),
                    max_age
                );
                return Err(anyhow::anyhow!("Signature expired"));
            }
            if age < Duration::zero() {
                tracing::warn!(
                    "NEAR signature has future timestamp for account {}",
                    signed_message.account_id
                );
                return Err(anyhow::anyhow!("Invalid signature timestamp"));
            }
        }

        // 3. Check nonce hasn't been used (replay protection)
        let nonce_hash = hex::encode(Sha256::digest(&signed_message.nonce));
        let nonce_consumed = self.nonce_repository.consume_nonce(&nonce_hash).await?;
        if !nonce_consumed {
            tracing::warn!(
                "NEAR signature replay detected for account {}",
                signed_message.account_id
            );
            return Err(anyhow::anyhow!(
                "Nonce already used (replay attack detected)"
            ));
        }

        // 4. Verify cryptographic signature
        self.verify_signature(&signed_message)?;

        // 5. Find or create user
        let (user_id, is_new_user) = self.find_or_create_user(&signed_message.account_id).await?;

        // 6. Create session
        let session = self.session_repository.create_session(user_id).await?;

        tracing::info!(
            "NEAR authentication successful - user_id={}, session_id={}, is_new_user={}",
            user_id,
            session.session_id,
            is_new_user
        );

        Ok((session, is_new_user))
    }
}
