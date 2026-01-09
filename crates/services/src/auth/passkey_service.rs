use super::passkey::{challenge_expiry, PasskeyRecord, PasskeyRepository};
use super::webauthn::{base64url_encode, verify_webauthn_signature, WebAuthnAlgorithm};
use crate::types::UserId;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

const FLAG_USER_PRESENT: u8 = 0x01;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PasskeyRegistrationOptions {
    pub challenge: String,
    pub rp_id: String,
    pub timeout: u64,
    pub user: PasskeyUser,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PasskeyUser {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PasskeyAssertionOptions {
    pub challenge: String,
    pub rp_id: String,
    pub timeout: u64,
    pub allow_credentials: Vec<AllowCredentialDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AllowCredentialDescriptor {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct RegistrationCredential {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub algorithm: i32,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct AssertionCredential {
    pub credential_id: String,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

struct ParsedAuthData {
    sign_count: u32,
    flags: u8,
    rp_id_hash: [u8; 32],
}

#[async_trait]
pub trait PasskeyService: Send + Sync {
    async fn generate_registration_options(
        &self,
        user_id: UserId,
        friendly_name: Option<String>,
    ) -> Result<PasskeyRegistrationOptions>;

    async fn complete_registration(
        &self,
        user_id: UserId,
        challenge: String,
        credential: RegistrationCredential,
    ) -> Result<PasskeyRecord>;

    async fn generate_assertion_options(
        &self,
        user_id: Option<UserId>,
    ) -> Result<PasskeyAssertionOptions>;

    async fn verify_assertion(&self, credential: AssertionCredential) -> Result<PasskeyRecord>;

    async fn list_user_passkeys(&self, user_id: UserId) -> Result<Vec<PasskeyRecord>>;

    async fn delete_passkey(&self, user_id: UserId, credential_id: &str) -> Result<()>;
}

pub struct PasskeyServiceImpl {
    repository: Arc<dyn PasskeyRepository>,
    relying_party_id: String,
    relying_party_hash: [u8; 32],
    expected_origin: String,
}

impl PasskeyServiceImpl {
    pub fn new(repository: Arc<dyn PasskeyRepository>, origin: Url) -> Result<Self> {
        let rp_id = origin
            .host_str()
            .ok_or_else(|| anyhow!("Passkey origin must include host"))?
            .to_string();
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            repository,
            relying_party_id: rp_id,
            relying_party_hash: hash,
            expected_origin: origin.origin().ascii_serialization(),
        })
    }

    fn map_algorithm(&self, alg: i32) -> Result<WebAuthnAlgorithm> {
        match alg {
            -7 => Ok(WebAuthnAlgorithm::Es256),
            -8 => Ok(WebAuthnAlgorithm::EdDsa),
            other => Err(anyhow!("Unsupported algorithm {other}")),
        }
    }
}

#[async_trait]
impl PasskeyService for PasskeyServiceImpl {
    async fn generate_registration_options(
        &self,
        user_id: UserId,
        friendly_name: Option<String>,
    ) -> Result<PasskeyRegistrationOptions> {
        let mut challenge_bytes = vec![0u8; 32];
        rand::rng().fill_bytes(&mut challenge_bytes);
        let challenge = base64url_encode(&challenge_bytes);

        self.repository
            .store_challenge(
                challenge.clone(),
                "registration",
                Some(user_id),
                serde_json::json!({ "friendly_name": friendly_name }),
                challenge_expiry(),
            )
            .await?;

        Ok(PasskeyRegistrationOptions {
            challenge,
            rp_id: self.relying_party_id.clone(),
            timeout: 60_000,
            user: PasskeyUser {
                id: base64url_encode(user_id.as_uuid().as_bytes()),
                name: format!("user-{}", user_id),
                display_name: friendly_name.unwrap_or_else(|| "Passkey User".to_string()),
            },
        })
    }

    async fn complete_registration(
        &self,
        user_id: UserId,
        challenge: String,
        credential: RegistrationCredential,
    ) -> Result<PasskeyRecord> {
        let challenge_record = self
            .repository
            .consume_challenge(&challenge)
            .await?
            .ok_or_else(|| anyhow!("Registration challenge not found"))?;

        if challenge_record.purpose != "registration" {
            return Err(anyhow!("Challenge is not for registration"));
        }
        if challenge_record.user_id != Some(user_id) {
            return Err(anyhow!("Challenge user mismatch"));
        }
        if challenge_record.expires_at < Utc::now() {
            return Err(anyhow!("Challenge expired"));
        }

        let client_data: ClientDataJson = serde_json::from_slice(&credential.client_data_json)
            .context("Invalid client data JSON")?;
        if client_data.typ != "webauthn.create" {
            return Err(anyhow!("Invalid client data type"));
        }
        if client_data.origin != self.expected_origin {
            return Err(anyhow!("Origin mismatch"));
        }
        if client_data.challenge != challenge {
            return Err(anyhow!("Challenge does not match request"));
        }

        let parsed_auth =
            parse_authenticator_data(&credential.authenticator_data, &self.relying_party_hash)?;
        if credential.public_key.is_empty() {
            return Err(anyhow!("Missing public key"));
        }

        let algorithm = self.map_algorithm(credential.algorithm)?;

        let passkey = PasskeyRecord {
            id: Uuid::new_v4(),
            user_id,
            credential_id: credential.credential_id,
            public_key: credential.public_key,
            user_handle: None,
            algorithm: algorithm.label().to_string(),
            friendly_name: challenge_record
                .metadata
                .get("friendly_name")
                .and_then(|v| v.as_str().map(|s| s.to_string())),
            transports: credential.transports,
            sign_count: parsed_auth.sign_count as i64,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
        };

        let stored = self.repository.create_passkey(passkey).await?;
        Ok(stored)
    }

    async fn generate_assertion_options(
        &self,
        user_id: Option<UserId>,
    ) -> Result<PasskeyAssertionOptions> {
        let mut challenge_bytes = vec![0u8; 32];
        rand::rng().fill_bytes(&mut challenge_bytes);
        let challenge = base64url_encode(&challenge_bytes);

        let allow_credentials = if let Some(user_id) = user_id {
            self.repository
                .get_passkeys_by_user(user_id)
                .await?
                .into_iter()
                .map(|p| AllowCredentialDescriptor {
                    id: p.credential_id,
                    cred_type: "public-key".to_string(),
                    transports: p.transports,
                })
                .collect()
        } else {
            vec![]
        };

        self.repository
            .store_challenge(
                challenge.clone(),
                "assertion",
                user_id,
                serde_json::Value::Null,
                challenge_expiry(),
            )
            .await?;

        Ok(PasskeyAssertionOptions {
            challenge,
            rp_id: self.relying_party_id.clone(),
            timeout: 60_000,
            allow_credentials,
        })
    }

    async fn verify_assertion(&self, credential: AssertionCredential) -> Result<PasskeyRecord> {
        let client_data: ClientDataJson = serde_json::from_slice(&credential.client_data_json)
            .context("Invalid client data JSON")?;
        if client_data.typ != "webauthn.get" {
            return Err(anyhow!("Invalid assertion type"));
        }
        if client_data.origin != self.expected_origin {
            return Err(anyhow!("Assertion origin mismatch"));
        }

        let challenge_record = self
            .repository
            .consume_challenge(&client_data.challenge)
            .await?
            .ok_or_else(|| anyhow!("Assertion challenge not found"))?;

        if challenge_record.purpose != "assertion" {
            return Err(anyhow!("Challenge is not for assertion"));
        }
        if challenge_record.expires_at < Utc::now() {
            return Err(anyhow!("Challenge expired"));
        }

        let passkey = self
            .repository
            .find_passkey_by_credential(&credential.credential_id)
            .await?
            .ok_or_else(|| anyhow!("Passkey not found"))?;

        let algorithm = match passkey.algorithm.as_str() {
            "p256" => WebAuthnAlgorithm::Es256,
            "ed25519" => WebAuthnAlgorithm::EdDsa,
            _ => return Err(anyhow!("Unsupported algorithm stored on passkey")),
        };

        let parsed =
            parse_authenticator_data(&credential.authenticator_data, &self.relying_party_hash)?;
        if parsed.flags & FLAG_USER_PRESENT == 0 {
            return Err(anyhow!("User presence not confirmed"));
        }

        verify_webauthn_signature(
            &algorithm,
            &passkey.public_key,
            &credential.signature,
            &credential.authenticator_data,
            &credential.client_data_json,
        )?;

        self.repository
            .update_passkey_usage(&passkey.credential_id, parsed.sign_count as i64, Utc::now())
            .await?;

        Ok(passkey)
    }

    async fn list_user_passkeys(&self, user_id: UserId) -> Result<Vec<PasskeyRecord>> {
        self.repository.get_passkeys_by_user(user_id).await
    }

    async fn delete_passkey(&self, user_id: UserId, credential_id: &str) -> Result<()> {
        let passkey = self
            .repository
            .find_passkey_by_credential(credential_id)
            .await?
            .ok_or_else(|| anyhow!("Passkey not found"))?;

        if passkey.user_id != user_id {
            return Err(anyhow!("Cannot delete passkey you do not own"));
        }

        self.repository.delete_passkey(credential_id).await
    }
}

fn parse_authenticator_data(data: &[u8], expected_rp_hash: &[u8; 32]) -> Result<ParsedAuthData> {
    if data.len() < 37 {
        return Err(anyhow!("Authenticator data too short"));
    }

    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&data[..32]);
    if &rp_hash != expected_rp_hash {
        return Err(anyhow!("RP ID hash mismatch"));
    }

    let flags = data[32];
    let sign_count = u32::from_be_bytes(data[33..37].try_into().unwrap());

    Ok(ParsedAuthData {
        rp_id_hash: rp_hash,
        flags,
        sign_count,
    })
}
