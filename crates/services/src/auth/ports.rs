use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::types::{PasskeyChallengeId, PasskeyId, SessionId, UserId};

// Re-export OAuthProvider from user module for convenience
pub use crate::user::ports::OAuthProvider;

/// Represents an OAuth session state
#[derive(Debug, Clone)]
pub struct OAuthState {
    pub state: String,
    pub provider: OAuthProvider,
    pub redirect_uri: String,
    pub frontend_callback: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Represents OAuth tokens
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Represents user information from OAuth provider
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// OAuth session created after successful authentication
#[derive(Debug, Clone)]
pub struct UserSession {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The actual session token (only populated on creation, not on retrieval)
    pub token: Option<String>,
}

/// Repository trait for authentication session management
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Create a user session (returns the session with the unhashed token)
    async fn create_session(&self, user_id: UserId) -> anyhow::Result<UserSession>;

    /// Retrieve a session by token hash
    async fn get_session_by_token_hash(
        &self,
        token_hash: String,
    ) -> anyhow::Result<Option<UserSession>>;

    /// Retrieve a session by session ID
    async fn get_session_by_id(&self, session_id: SessionId)
        -> anyhow::Result<Option<UserSession>>;

    /// Delete a session
    async fn delete_session(&self, session_id: SessionId) -> anyhow::Result<()>;
}

/// Repository trait for OAuth state and token management
#[async_trait]
pub trait OAuthRepository: Send + Sync {
    /// Store OAuth state for verification during callback
    async fn store_oauth_state(&self, state: &OAuthState) -> anyhow::Result<()>;

    /// Retrieve and remove OAuth state (one-time use)
    async fn consume_oauth_state(&self, state: &str) -> anyhow::Result<Option<OAuthState>>;

    /// Store OAuth tokens for a user
    async fn store_oauth_tokens(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
        tokens: &OAuthTokens,
    ) -> anyhow::Result<()>;

    /// Retrieve OAuth tokens for a user
    async fn get_oauth_tokens(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
    ) -> anyhow::Result<Option<OAuthTokens>>;
}

/// Service trait for OAuth authentication operations
#[async_trait]
pub trait OAuthService: Send + Sync {
    /// Generate authorization URL for OAuth flow
    async fn get_authorization_url(
        &self,
        provider: OAuthProvider,
        redirect_uri: String,
        frontend_callback: Option<String>,
    ) -> anyhow::Result<String>;

    /// Unified callback handler that determines provider from state
    /// Returns (UserSession, frontend_callback_url, is_new_user, provider)
    async fn handle_callback_unified(
        &self,
        code: String,
        state: String,
    ) -> anyhow::Result<(UserSession, Option<String>, bool, OAuthProvider)>;

    /// Refresh an access token
    async fn refresh_token(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
    ) -> anyhow::Result<OAuthTokens>;

    /// Revoke access (logout)
    async fn revoke_session(&self, session_id: SessionId) -> anyhow::Result<()>;

    /// Authenticate with NEAR signed message (NEP-413)
    /// Returns (UserSession, is_new_user)
    async fn authenticate_near(
        &self,
        signed_message: super::near::SignedMessage,
        payload: near_api::signer::NEP413Payload,
    ) -> anyhow::Result<(UserSession, bool)>;
}

// -----------------------------
// Passkeys (WebAuthn)
// -----------------------------

/// Passkey (WebAuthn) registered to a user.
#[derive(Debug, Clone)]
pub struct PasskeyRecord {
    pub id: PasskeyId,
    pub user_id: UserId,
    /// Base64url credential ID (`PublicKeyCredential.id`)
    pub credential_id: String,
    /// Serialized `webauthn_rs::prelude::Passkey` (JSON)
    pub passkey: serde_json::Value,
    pub nickname: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Summary used for UI listing (never includes key material).
#[derive(Debug, Clone)]
pub struct PasskeySummary {
    pub id: PasskeyId,
    pub credential_id: String,
    pub nickname: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyChallengeKind {
    Registration,
    Authentication,
    DiscoverableAuthentication,
}

impl PasskeyChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyChallengeKind::Registration => "registration",
            PasskeyChallengeKind::Authentication => "authentication",
            PasskeyChallengeKind::DiscoverableAuthentication => "discoverable_authentication",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyChallenge {
    pub id: PasskeyChallengeId,
    pub kind: PasskeyChallengeKind,
    pub user_id: Option<UserId>,
    /// Serialized server-side ceremony state (JSON)
    pub state: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasskeyRepository: Send + Sync {
    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeyRecord>>;
    async fn get_by_id(&self, id: PasskeyId) -> anyhow::Result<Option<PasskeyRecord>>;
    async fn get_by_credential_id(
        &self,
        credential_id: &str,
    ) -> anyhow::Result<Option<PasskeyRecord>>;

    async fn insert_passkey(
        &self,
        user_id: UserId,
        credential_id: String,
        passkey: serde_json::Value,
        nickname: Option<String>,
    ) -> anyhow::Result<PasskeyId>;

    async fn update_passkey_and_last_used_at(
        &self,
        id: PasskeyId,
        passkey: serde_json::Value,
        last_used_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    async fn delete_passkey(&self, user_id: UserId, id: PasskeyId) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait PasskeyChallengeRepository: Send + Sync {
    async fn create_challenge(
        &self,
        kind: PasskeyChallengeKind,
        user_id: Option<UserId>,
        state: serde_json::Value,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<PasskeyChallengeId>;

    /// Consume (retrieve and delete) a challenge. Returns None if missing.
    async fn consume_challenge(
        &self,
        id: PasskeyChallengeId,
    ) -> anyhow::Result<Option<PasskeyChallenge>>;

    async fn delete_expired(&self, now: DateTime<Utc>) -> anyhow::Result<u64>;
}

#[derive(Debug, Clone)]
pub struct PasskeyBeginResponse {
    pub challenge_id: PasskeyChallengeId,
    /// JSON options to be passed directly into `navigator.credentials.*({ publicKey: ... })`
    pub public_key: serde_json::Value,
}

#[async_trait]
pub trait PasskeyService: Send + Sync {
    /// Begin binding a passkey for an already-authenticated user.
    async fn begin_registration(&self, user_id: UserId) -> anyhow::Result<PasskeyBeginResponse>;

    /// Finish binding: verify and store the passkey.
    async fn finish_registration(
        &self,
        user_id: UserId,
        challenge_id: PasskeyChallengeId,
        credential: serde_json::Value,
        nickname: Option<String>,
    ) -> anyhow::Result<PasskeyId>;

    /// Begin authentication. If `email` is provided, options will restrict to that user’s passkeys.
    /// If `email` is None, a discoverable authentication flow is started.
    async fn begin_authentication(
        &self,
        email: Option<String>,
    ) -> anyhow::Result<PasskeyBeginResponse>;

    /// Finish authentication: verify assertion and create a new session.
    async fn finish_authentication(
        &self,
        challenge_id: PasskeyChallengeId,
        credential: serde_json::Value,
    ) -> anyhow::Result<UserSession>;

    /// List passkeys for UI management.
    async fn list_passkeys(&self, user_id: UserId) -> anyhow::Result<Vec<PasskeySummary>>;

    /// Delete a passkey (must belong to user).
    async fn delete_passkey(&self, user_id: UserId, passkey_id: PasskeyId) -> anyhow::Result<bool>;
}
