use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use near_kit::{
    signer::{PublicKey, Signature},
    standards::nep413::{self, NonceValidation, SignMessageParams, VerifyOptions},
    AccountId, Near,
};
use std::sync::Arc;
use url::Url;

use super::ports::{SessionRepository, UserSession};
use crate::types::UserId;
use crate::user::ports::{OAuthProvider, UserRepository};

const MAX_NONCE_AGE_MS: u64 = 5 * 60 * 1000; // 5 minutes
const EXPECTED_MESSAGE: &str = "Sign in to NEAR AI";

fn expected_recipients() -> Vec<String> {
    let raw =
        std::env::var("NEAR_EXPECTED_RECIPIENTS").unwrap_or_else(|_| "private.near.ai".to_string());
    let recipients: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if recipients.is_empty() {
        vec!["private.near.ai".to_string()]
    } else {
        recipients
    }
}

/// Validates a nonce timestamp for replay protection
/// Returns Ok(()) if timestamp is valid, Err otherwise
fn validate_nonce_timestamp(nonce_timestamp_ms: u64) -> anyhow::Result<()> {
    if nonce_timestamp_ms == 0 {
        tracing::warn!("NEAR signature has invalid timestamp (zero)");
        return Err(anyhow::anyhow!(
            "Invalid signature timestamp: timestamp is zero"
        ));
    }

    let nonce_time = i64::try_from(nonce_timestamp_ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis)
        .ok_or_else(|| {
            tracing::warn!(
                "NEAR signature has invalid timestamp (out of range): {}ms",
                nonce_timestamp_ms
            );
            anyhow::anyhow!("Invalid signature timestamp: timestamp out of range")
        })?;

    let age = Utc::now().signed_duration_since(nonce_time);
    if age > Duration::milliseconds(MAX_NONCE_AGE_MS as i64) {
        tracing::warn!(
            "NEAR signature expired: age={}ms, max_age={}ms",
            age.num_milliseconds(),
            MAX_NONCE_AGE_MS
        );
        return Err(anyhow::anyhow!("Signature expired"));
    }
    if age < Duration::zero() {
        tracing::warn!("NEAR signature has future timestamp");
        return Err(anyhow::anyhow!(
            "Invalid signature timestamp: timestamp is in the future"
        ));
    }

    Ok(())
}

/// Signed message data received from the wallet (NEP-413 output)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedMessage {
    #[serde(rename = "accountId")]
    pub account_id: AccountId,
    #[serde(rename = "publicKey")]
    pub public_key: PublicKey,
    pub signature: Signature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

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
    network: Near,
}

impl NearAuthService {
    pub fn new(
        session_repository: Arc<dyn SessionRepository>,
        user_repository: Arc<dyn UserRepository>,
        nonce_repository: Arc<dyn NearNonceRepository>,
        near_rpc_url: Url,
    ) -> Self {
        let network = Near::custom(near_rpc_url.to_string(), "near").build();
        Self {
            session_repository,
            user_repository,
            nonce_repository,
            network,
        }
    }

    async fn cleanup_nonces(&self) {
        if let Err(err) = self.nonce_repository.cleanup_expired_nonces().await {
            tracing::warn!("Failed to cleanup expired NEAR nonces: {}", err);
        }
    }

    fn validate_recipient(recipient: &str) -> anyhow::Result<()> {
        let allowed = expected_recipients();
        if allowed.contains(&recipient.to_string()) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Invalid recipient: expected one of [{}], got {}",
                allowed.join(", "),
                recipient
            ))
        }
    }

    fn validate_message(message: &str) -> anyhow::Result<()> {
        if message == EXPECTED_MESSAGE {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Invalid message: expected '{}', got '{}'",
                EXPECTED_MESSAGE,
                message
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
        payload: SignMessageParams,
    ) -> anyhow::Result<(UserSession, bool)> {
        let account_id = signed_message.account_id.to_string();

        tracing::info!("NEAR authentication attempt for account: {}", account_id);

        // 1. Validate recipient
        Self::validate_recipient(&payload.recipient)?;

        // 2. Validate message
        Self::validate_message(&payload.message)?;

        // 3. Cleanup expired nonces
        self.cleanup_nonces().await;

        // 4. Check nonce timestamp (replay protection)
        let nonce_timestamp_ms = nep413::extract_timestamp_from_nonce(&payload.nonce);
        validate_nonce_timestamp(nonce_timestamp_ms)?;

        // 5. Verify the signature and full-access key ownership before consuming the nonce.
        verify_wallet_control(&payload, &signed_message, &self.network).await?;

        // 6. Consume nonce AFTER signature verification (replay protection)
        // This prevents attackers from burning legitimate nonces with invalid signatures
        let nonce_hex = hex::encode(payload.nonce);
        let nonce_consumed = self.nonce_repository.consume_nonce(&nonce_hex).await?;
        if !nonce_consumed {
            tracing::warn!("NEAR signature replay detected for account {}", account_id);
            return Err(anyhow::anyhow!(
                "Nonce already used (replay attack detected)"
            ));
        }

        // 7. Find or create user
        let (user_id, is_new_user) = self.find_or_create_user(&account_id).await?;

        // 8. Create session
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

async fn verify_wallet_control(
    payload: &SignMessageParams,
    message: &SignedMessage,
    network: &Near,
) -> anyhow::Result<()> {
    let signed = nep413::SignedMessage {
        account_id: message.account_id.clone(),
        public_key: message.public_key.clone(),
        signature: message.signature.clone(),
        state: message.state.clone(),
    };

    let valid = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        nep413::verify(
            &signed,
            payload,
            network,
            VerifyOptions {
                // Timestamp validation and atomic replay prevention are owned by this service.
                nonce_validation: NonceValidation::None,
                require_full_access: true,
            },
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Wallet verification timed out"))?
    .map_err(|error| {
        tracing::warn!(error_category = ?std::mem::discriminant(&error), "NEP-413 verifier error");
        anyhow::anyhow!("Wallet verification unavailable")
    })?;

    if !valid {
        return Err(anyhow::anyhow!("Invalid signature"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn nep413_hash_matches_wallet_fixtures_with_and_without_callback() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        // Sender/Meteor fixtures also used by near-api-rs. Expected hashes are
        // SHA-256 of the NEP-413 tag followed by the Borsh-encoded payload.
        for (callback_url, expected) in [
            (
                None,
                "036a114cfadb42200dc972aff40b994039571359cbcdd34be9c097d472351038",
            ),
            (
                Some("http://localhost:3000"),
                "ca89aebc4b822cb0618aa785dca563acee228e2631cff9adb7ce44989c5e8874",
            ),
        ] {
            let mut payload = SignMessageParams {
                message: "Hello NEAR!".into(),
                nonce: STANDARD
                    .decode("KNV0cOpvJ50D5vfF9pqWom8wo2sliQ4W+Wa7uZ3Uk6Y=")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                recipient: "example.near".into(),
                callback_url: callback_url.map(str::to_owned),
                state: None,
            };

            let hash = nep413::serialize_message(&payload);

            assert_eq!(hex::encode(hash.as_bytes()), expected);

            payload.state = Some("wallet-callback-state".into());

            assert_eq!(nep413::serialize_message(&payload), hash);
        }
    }

    #[tokio::test]
    async fn wallet_verification_requires_full_access_and_rejects_tampering() {
        use near_kit::signer::SecretKey;
        use serde_json::json;
        use wiremock::{matchers::body_partial_json, Mock, MockServer, ResponseTemplate};

        for key in [
            SecretKey::ed25519_from_bytes([7; 32]),
            SecretKey::secp256k1_from_bytes([7; 32]).unwrap(),
            SecretKey::ml_dsa65_from_seed([7; 32]),
        ] {
            let payload = SignMessageParams {
                message: EXPECTED_MESSAGE.into(),
                nonce: [9; 32],
                recipient: "private.near.ai".into(),
                callback_url: None,
                state: None,
            };
            let message = SignedMessage {
                account_id: "alice.near".parse().unwrap(),
                public_key: key.public_key(),
                signature: key.sign(nep413::serialize_message(&payload).as_bytes()),
                state: None,
            };

            for permission in [
                json!("FullAccess"),
                json!({
                    "FunctionCall": {
                        "allowance": null,
                        "receiver_id": "app.near",
                        "method_names": [],
                    },
                }),
                serde_json::Value::Null,
            ] {
                let rpc = MockServer::start().await;
                let response = if permission.is_null() {
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32000,
                            "message": "Server error",
                            "name": "HANDLER_ERROR",
                            "cause": {
                                "name": "UNKNOWN_ACCESS_KEY",
                                "info": { "public_key": message.public_key },
                            },
                        },
                    })
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "block_hash": "11111111111111111111111111111111",
                            "block_height": 1,
                            "nonce": 0,
                            "permission": permission,
                        },
                    })
                };

                Mock::given(body_partial_json(json!({
                    "method": "EXPERIMENTAL_view_access_key",
                    "params": {
                        "account_id": "alice.near",
                        "public_key": message.public_key,
                        "finality": "optimistic",
                    },
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&rpc)
                .await;
                let network = Near::custom(rpc.uri(), "near").build();

                let result = verify_wallet_control(&payload, &message, &network).await;

                assert_eq!(result.is_ok(), permission == json!("FullAccess"));

                let mut tampered = payload.clone();
                tampered.message.push_str("changed");

                assert!(verify_wallet_control(&tampered, &message, &network)
                    .await
                    .is_err());
                rpc.verify().await;
            }
        }
    }

    #[test]
    fn test_zero_timestamp_should_fail() {
        let result = validate_nonce_timestamp(0);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid signature timestamp: timestamp is zero"
        );
    }

    #[test]
    fn test_large_timestamp_overflow() {
        let large_timestamp = u64::MAX;
        let result = validate_nonce_timestamp(large_timestamp);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid signature timestamp: timestamp out of range"
        );
    }

    #[test]
    fn test_future_timestamp_should_fail() {
        let future_ms = (Utc::now().timestamp_millis() + 3600 * 1000) as u64;
        let result = validate_nonce_timestamp(future_ms);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid signature timestamp: timestamp is in the future"
        );
    }

    #[test]
    fn test_expired_timestamp_should_fail() {
        let expired_ms = (Utc::now().timestamp_millis() - (MAX_NONCE_AGE_MS as i64 + 1000)) as u64;
        let result = validate_nonce_timestamp(expired_ms);
        assert_eq!(result.unwrap_err().to_string(), "Signature expired");
    }

    #[test]
    fn test_valid_recent_timestamp_should_succeed() {
        let recent_ms = (Utc::now().timestamp_millis() - 60 * 1000) as u64;
        let result = validate_nonce_timestamp(recent_ms);
        assert!(
            result.is_ok(),
            "Recent valid timestamp should pass validation"
        );
    }
}
