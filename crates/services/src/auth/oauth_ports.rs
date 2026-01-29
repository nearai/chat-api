//! OAuth 2.0 client and token management ports (repository traits).
//!
//! These traits define the interface for storing and retrieving OAuth clients,
//! authorization codes, access tokens, refresh tokens, and user consent grants.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::types::UserId;

/// A developer project that owns OAuth clients.
#[derive(Debug, Clone)]
pub struct Project {
    pub id: Uuid,
    pub owner_id: UserId,
    pub name: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new project.
#[derive(Debug, Clone)]
pub struct CreateProject {
    pub owner_id: UserId,
    pub name: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
}

/// Input for updating a project.
#[derive(Debug, Clone, Default)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_url: Option<String>,
}

/// OAuth client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClientType {
    /// Confidential clients can keep secrets (backend servers).
    Confidential,
    /// Public clients cannot keep secrets (SPAs, mobile apps).
    Public,
}

impl OAuthClientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "confidential" => Some(Self::Confidential),
            "public" => Some(Self::Public),
            _ => None,
        }
    }
}

/// An OAuth 2.0 client registered to a project.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub id: Uuid,
    pub project_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl OAuthClient {
    /// Check if this client is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Check if a redirect URI is allowed for this client.
    pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Check if a scope is allowed for this client.
    pub fn is_scope_allowed(&self, scope: &str) -> bool {
        self.allowed_scopes.iter().any(|allowed| allowed == scope)
    }
}

/// Input for creating a new OAuth client.
#[derive(Debug, Clone)]
pub struct CreateOAuthClient {
    pub project_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_type: OAuthClientType,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

/// An OAuth authorization code (short-lived, used once).
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new authorization code.
#[derive(Debug, Clone)]
pub struct CreateAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// An OAuth access token.
#[derive(Debug, Clone)]
pub struct OAuthAccessToken {
    pub id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: UserId,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl OAuthAccessToken {
    /// Check if this token is currently valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > Utc::now()
    }
}

/// Input for creating a new access token.
#[derive(Debug, Clone)]
pub struct CreateAccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub user_id: UserId,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

/// An OAuth refresh token.
#[derive(Debug, Clone)]
pub struct OAuthRefreshToken {
    pub id: Uuid,
    pub token_hash: String,
    pub access_token_id: Uuid,
    pub user_id: Option<UserId>,
    pub client_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl OAuthRefreshToken {
    /// Check if this token is currently valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > Utc::now()
    }
}

/// Input for creating a new refresh token.
#[derive(Debug, Clone)]
pub struct CreateRefreshToken {
    pub token_hash: String,
    pub access_token_id: Uuid,
    pub user_id: UserId,
    pub client_id: String,
    pub expires_at: DateTime<Utc>,
}

/// A user's consent grant to an OAuth client.
#[derive(Debug, Clone)]
pub struct OAuthAccessGrant {
    pub id: Uuid,
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl OAuthAccessGrant {
    /// Check if this grant is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Check if all requested scopes are covered by this grant.
    pub fn covers_scopes(&self, requested: &[String]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }
}

/// Input for creating or updating an access grant.
#[derive(Debug, Clone)]
pub struct UpsertAccessGrant {
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
}

// =============================================================================
// Repository Traits
// =============================================================================

/// Repository for managing developer projects.
#[async_trait]
pub trait ProjectRepository: Send + Sync {
    /// Create a new project.
    async fn create(&self, input: CreateProject) -> anyhow::Result<Project>;

    /// Get a project by ID.
    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<Project>>;

    /// List all projects owned by a user.
    async fn list_by_owner(&self, owner_id: UserId) -> anyhow::Result<Vec<Project>>;

    /// Update a project.
    async fn update(&self, id: Uuid, input: UpdateProject) -> anyhow::Result<Option<Project>>;

    /// Delete a project (cascades to clients).
    async fn delete(&self, id: Uuid) -> anyhow::Result<bool>;
}

/// Repository for managing OAuth clients.
#[async_trait]
pub trait OAuthClientRepository: Send + Sync {
    /// Create a new OAuth client.
    async fn create(&self, input: CreateOAuthClient) -> anyhow::Result<OAuthClient>;

    /// Get an OAuth client by its public client_id.
    async fn get_by_client_id(&self, client_id: &str) -> anyhow::Result<Option<OAuthClient>>;

    /// Get an OAuth client by its internal UUID.
    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthClient>>;

    /// List all clients for a project.
    async fn list_by_project(&self, project_id: Uuid) -> anyhow::Result<Vec<OAuthClient>>;

    /// Revoke a client (soft delete).
    async fn revoke(&self, client_id: &str) -> anyhow::Result<bool>;

    /// Update the client secret hash (for secret rotation).
    async fn update_secret(&self, client_id: &str, new_secret_hash: String) -> anyhow::Result<bool>;
}

/// Repository for managing authorization codes.
#[async_trait]
pub trait AuthorizationCodeRepository: Send + Sync {
    /// Store a new authorization code.
    async fn create(&self, input: CreateAuthorizationCode) -> anyhow::Result<()>;

    /// Consume an authorization code (retrieve and delete).
    /// Returns None if the code doesn't exist or is expired.
    async fn consume(&self, code: &str) -> anyhow::Result<Option<OAuthAuthorizationCode>>;

    /// Delete expired authorization codes (cleanup).
    async fn delete_expired(&self) -> anyhow::Result<u64>;
}

/// Repository for managing access tokens.
#[async_trait]
pub trait AccessTokenRepository: Send + Sync {
    /// Create a new access token.
    async fn create(&self, input: CreateAccessToken) -> anyhow::Result<OAuthAccessToken>;

    /// Get an access token by its hash.
    async fn get_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<OAuthAccessToken>>;

    /// Get an access token by ID.
    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthAccessToken>>;

    /// List all access tokens for a user.
    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<OAuthAccessToken>>;

    /// Revoke an access token.
    async fn revoke(&self, id: Uuid) -> anyhow::Result<bool>;

    /// Revoke all access tokens for a user-client pair.
    async fn revoke_by_user_and_client(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> anyhow::Result<u64>;

    /// Delete expired tokens (cleanup).
    async fn delete_expired(&self) -> anyhow::Result<u64>;
}

/// Repository for managing refresh tokens.
#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// Create a new refresh token.
    async fn create(&self, input: CreateRefreshToken) -> anyhow::Result<OAuthRefreshToken>;

    /// Get a refresh token by its hash.
    async fn get_by_hash(&self, token_hash: &str) -> anyhow::Result<Option<OAuthRefreshToken>>;

    /// Revoke a refresh token.
    async fn revoke(&self, id: Uuid) -> anyhow::Result<bool>;

    /// Revoke refresh token by access token ID.
    async fn revoke_by_access_token(&self, access_token_id: Uuid) -> anyhow::Result<bool>;

    /// Delete expired tokens (cleanup).
    async fn delete_expired(&self) -> anyhow::Result<u64>;
}

/// Repository for managing user consent grants.
#[async_trait]
pub trait AccessGrantRepository: Send + Sync {
    /// Create or update a user's grant to a client.
    /// If a grant already exists, the scopes are merged.
    async fn upsert(&self, input: UpsertAccessGrant) -> anyhow::Result<OAuthAccessGrant>;

    /// Get the grant for a user-client pair.
    async fn get(&self, user_id: UserId, client_id: &str) -> anyhow::Result<Option<OAuthAccessGrant>>;

    /// List all grants for a user (apps they've authorized).
    async fn list_by_user(&self, user_id: UserId) -> anyhow::Result<Vec<OAuthAccessGrant>>;

    /// Revoke a grant (user revoking app access).
    async fn revoke(&self, user_id: UserId, client_id: &str) -> anyhow::Result<bool>;
}

// =============================================================================
// Pending Authorization (for consent flow)
// =============================================================================

/// A pending OAuth authorization request awaiting user consent.
#[derive(Debug, Clone)]
pub struct OAuthPendingAuthorization {
    pub id: Uuid,
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new pending authorization.
#[derive(Debug, Clone)]
pub struct CreatePendingAuthorization {
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Repository for managing pending authorizations.
#[async_trait]
pub trait PendingAuthorizationRepository: Send + Sync {
    /// Create a new pending authorization.
    async fn create(&self, input: CreatePendingAuthorization) -> anyhow::Result<OAuthPendingAuthorization>;

    /// Get a pending authorization by ID.
    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<OAuthPendingAuthorization>>;

    /// Consume (get and delete) a pending authorization.
    /// Returns None if the authorization doesn't exist or is expired.
    async fn consume(&self, id: Uuid) -> anyhow::Result<Option<OAuthPendingAuthorization>>;

    /// Delete expired pending authorizations (cleanup).
    async fn delete_expired(&self) -> anyhow::Result<u64>;
}
