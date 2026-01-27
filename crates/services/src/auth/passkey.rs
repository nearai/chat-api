use super::ports::{
    Passkey, PasskeyAuthenticatePublicKeyCredential, PasskeyBeginAuthenticationResponse,
    PasskeyBeginResponse, PasskeyChallengeKind, PasskeyChallengeRepository, PasskeyChallengeState,
    PasskeyRegisterPublicKeyCredential, PasskeyRepository, PasskeyService, PasskeySummary,
    SessionRepository, UserSession,
};
use crate::types::{PasskeyChallengeId, PasskeyId, UserId};
use crate::user::ports::UserRepository;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;
use webauthn_rs::prelude::Webauthn;

pub struct PasskeyServiceImpl {
    webauthn: Webauthn,
    passkey_repository: Arc<dyn PasskeyRepository>,
    passkey_challenge_repository: Arc<dyn PasskeyChallengeRepository>,
    user_repository: Arc<dyn UserRepository>,
    session_repository: Arc<dyn SessionRepository>,
    challenge_ttl: Duration,
}

impl PasskeyServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn: Webauthn,
        passkey_repository: Arc<dyn PasskeyRepository>,
        passkey_challenge_repository: Arc<dyn PasskeyChallengeRepository>,
        user_repository: Arc<dyn UserRepository>,
        session_repository: Arc<dyn SessionRepository>,
    ) -> Self {
        Self {
            webauthn,
            passkey_repository,
            passkey_challenge_repository,
            user_repository,
            session_repository,
            // Keep this short to reduce replay window, but long enough for UX.
            challenge_ttl: Duration::minutes(5),
        }
    }

    async fn cleanup_expired_challenges_best_effort(&self) {
        // Best-effort cleanup; failures should never block auth flows.
        let _ = self
            .passkey_challenge_repository
            .delete_expired(Utc::now())
            .await;
    }
}

#[async_trait]
impl PasskeyService for PasskeyServiceImpl {
    async fn begin_registration(&self, user_id: UserId) -> anyhow::Result<PasskeyBeginResponse> {
        self.cleanup_expired_challenges_best_effort().await;

        let user = self
            .user_repository
            .get_user(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let display_name = user.name.clone().unwrap_or_else(|| user.email.clone());

        let existing = self.passkey_repository.list_by_user(user_id).await?;
        let mut exclude: Vec<_> = Vec::with_capacity(existing.len());
        for rec in existing {
            exclude.push(rec.passkey.cred_id().clone());
        }
        let exclude = if exclude.is_empty() {
            None
        } else {
            Some(exclude)
        };

        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            user_id.into_uuid(),
            &user.email,
            &display_name,
            exclude,
        )?;

        let expires_at = Utc::now() + self.challenge_ttl;
        let challenge_id = self
            .passkey_challenge_repository
            .create_challenge(
                Some(user_id),
                PasskeyChallengeState::Registration(reg_state),
                expires_at,
            )
            .await?;

        Ok(PasskeyBeginResponse {
            challenge_id,
            public_key: ccr,
        })
    }

    async fn finish_registration(
        &self,
        user_id: UserId,
        challenge_id: PasskeyChallengeId,
        credential: PasskeyRegisterPublicKeyCredential,
        label: Option<String>,
    ) -> anyhow::Result<PasskeyId> {
        let challenge = self
            .passkey_challenge_repository
            .consume_challenge(challenge_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Registration challenge not found"))?;

        if challenge.kind != PasskeyChallengeKind::Registration {
            return Err(anyhow::anyhow!("Invalid challenge kind"));
        }
        if challenge.user_id != Some(user_id) {
            return Err(anyhow::anyhow!("Challenge does not belong to user"));
        }
        if challenge.expires_at < Utc::now() {
            return Err(anyhow::anyhow!("Registration challenge expired"));
        }

        let PasskeyChallengeState::Registration(reg_state) = challenge.state else {
            return Err(anyhow::anyhow!("Invalid challenge kind"));
        };

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &reg_state)?;

        // Browser-provided credential id string is base64url; use it as our lookup key.
        let credential_id = credential.id.clone();

        let id = self
            .passkey_repository
            .insert_passkey(user_id, credential_id, passkey, label)
            .await?;

        Ok(id)
    }

    async fn begin_authentication(
        &self,
        email: String,
    ) -> anyhow::Result<PasskeyBeginAuthenticationResponse> {
        self.cleanup_expired_challenges_best_effort().await;

        let expires_at = Utc::now() + self.challenge_ttl;

        let user = self
            .user_repository
            .get_user_by_email(&email)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let records = self.passkey_repository.list_by_user(user.id).await?;
        if records.is_empty() {
            return Err(anyhow::anyhow!("No passkeys registered for user"));
        }

        let passkeys: Vec<Passkey> = records.into_iter().map(|r| r.passkey).collect();

        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&passkeys)?;

        let challenge_id = self
            .passkey_challenge_repository
            .create_challenge(
                Some(user.id),
                PasskeyChallengeState::Authentication(auth_state),
                expires_at,
            )
            .await?;

        Ok(PasskeyBeginAuthenticationResponse {
            challenge_id,
            public_key: rcr,
        })
    }

    async fn finish_authentication(
        &self,
        challenge_id: PasskeyChallengeId,
        credential: PasskeyAuthenticatePublicKeyCredential,
    ) -> anyhow::Result<UserSession> {
        let challenge = self
            .passkey_challenge_repository
            .consume_challenge(challenge_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Authentication challenge not found"))?;

        if challenge.expires_at < Utc::now() {
            return Err(anyhow::anyhow!("Authentication challenge expired"));
        }

        let (user_id, auth_result) = match challenge.kind {
            PasskeyChallengeKind::Authentication => {
                let user_id = challenge
                    .user_id
                    .ok_or_else(|| anyhow::anyhow!("Missing user_id"))?;
                let PasskeyChallengeState::Authentication(auth_state) = challenge.state else {
                    return Err(anyhow::anyhow!("Invalid challenge kind"));
                };

                let auth_result = self
                    .webauthn
                    .finish_passkey_authentication(&credential, &auth_state)?;

                (user_id, auth_result)
            }
            PasskeyChallengeKind::Registration => {
                return Err(anyhow::anyhow!("Invalid challenge kind"));
            }
        };

        // Update credential properties if needed (e.g., counter/backup flags).
        if let Some(rec) = self
            .passkey_repository
            .get_by_credential_id(&credential.id)
            .await?
        {
            if rec.user_id != user_id {
                return Err(anyhow::anyhow!("Credential does not belong to user"));
            }

            let mut passkey: Passkey = rec.passkey;
            // This may or may not update based on authenticator type.
            let _ = passkey.update_credential(&auth_result);

            let now = Utc::now();
            self.passkey_repository
                .update_passkey_and_last_used_at(rec.id, passkey, now)
                .await?;
        }

        // Create a normal session token (same as OAuth/NEAR).
        let session = self.session_repository.create_session(user_id).await?;
        Ok(session)
    }

    async fn list_passkeys(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeySummary>> {
        let records = self.passkey_repository.list_by_user(user_id).await?;
        Ok(records
            .into_iter()
            .map(|r| PasskeySummary {
                id: r.id,
                credential_id: r.credential_id,
                label: r.label,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
            })
            .collect())
    }

    async fn delete_passkey(&self, user_id: UserId, passkey_id: PasskeyId) -> anyhow::Result<bool> {
        self.passkey_repository
            .delete_passkey(user_id, passkey_id)
            .await
    }
}
