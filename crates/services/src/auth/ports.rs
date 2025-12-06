use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::types::{SessionId, UserId};

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
