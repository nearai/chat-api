use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use near_api::{
    types::nep413::{Payload, SignedMessage},
    verify::verify_signed_message,
    NetworkConfig,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::ports::{SessionRepository, UserSession};
use crate::types::UserId;
use crate::user::ports::{OAuthProvider, UserRepository};

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
    expected_recipient: String,
    network_config: NetworkConfig,
}

impl NearAuthService {
    pub fn new(
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        nonce_repository: Arc<dyn NearNonceRepository>,
        expected_recipient: String,
        network_config: NetworkConfig,
    ) -> Self {
        Self {
            session_repository,
            user_repository,
            nonce_repository,
            expected_recipient,
            network_config,
        }
    }

    async fn cleanup_nonces(&self) {
        if let Err(err) = self.nonce_repository.cleanup_expired_nonces().await {
            tracing::warn!("Failed to cleanup expired NEAR nonces: {}", err);
        }
    }

    fn validate_recipient(&self, recipient: &str) -> anyhow::Result<()> {
        if recipient == self.expected_recipient {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Invalid recipient: expected {}, got {}",
                self.expected_recipient,
                recipient
            ))
        }
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
        signed_message: SignedMessage,
        payload: Payload,
    ) -> anyhow::Result<(UserSession, bool)> {
        let max_age = DEFAULT_MAX_NONCE_AGE_MS;
        let account_id = signed_message.account_id.to_string();

        tracing::info!("NEAR authentication attempt for account: {}", account_id);

        // 1. Validate recipient
        self.validate_recipient(&payload.recipient)?;

        // 2. Cleanup expired nonces
        self.cleanup_nonces().await;

        // 3. Check nonce timestamp (replay protection)
        let nonce_timestamp_ms = payload.extract_timestamp_from_nonce();
        if nonce_timestamp_ms > 0 {
            let nonce_time = DateTime::from_timestamp_millis(nonce_timestamp_ms as i64);
            if let Some(nonce_time) = nonce_time {
                let age = Utc::now().signed_duration_since(nonce_time);
                if age > Duration::milliseconds(max_age as i64) {
                    tracing::warn!(
                        "NEAR signature expired for account {}: age={:?}ms, max_age={}ms",
                        account_id,
                        age.num_milliseconds(),
                        max_age
                    );
                    return Err(anyhow::anyhow!("Signature expired"));
                }
                if age < Duration::zero() {
                    tracing::warn!(
                        "NEAR signature has future timestamp for account {}",
                        account_id
                    );
                    return Err(anyhow::anyhow!("Invalid signature timestamp"));
                }
            }
        }

        // 4. Verify signature AND public key ownership via near-api
        let is_valid = verify_signed_message(&signed_message, &payload, &self.network_config)
            .await
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

        if !is_valid {
            return Err(anyhow::anyhow!("Invalid signature"));
        }

        // 5. Consume nonce AFTER signature verification (replay protection)
        // This prevents attackers from burning legitimate nonces with invalid signatures
        let nonce_hash = hex::encode(Sha256::digest(payload.nonce));
        let nonce_consumed = self.nonce_repository.consume_nonce(&nonce_hash).await?;
        if !nonce_consumed {
            tracing::warn!(
                "NEAR signature replay detected for account {}",
                account_id
            );
            return Err(anyhow::anyhow!(
                "Nonce already used (replay attack detected)"
            ));
        }

        // 6. Find or create user
        let (user_id, is_new_user) = self.find_or_create_user(&account_id).await?;

        // 7. Create session
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
