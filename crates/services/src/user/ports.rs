use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::types::UserId;

/// Represents a user in the system
#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// OAuth provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    Google,
    Github,
    Near,
}

/// Types of user bans / blacklist reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanType {
    /// User is banned due to NEAR balance being below the required minimum
    NearBalanceLow,
    /// Manually created ban (e.g. by admin) or other generic reasons
    Manual,
}

impl BanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BanType::NearBalanceLow => "near_balance_low",
            BanType::Manual => "manual",
        }
    }
}

impl std::fmt::Display for BanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a linked OAuth account
#[derive(Debug, Clone)]
pub struct LinkedOAuthAccount {
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub linked_at: DateTime<Utc>,
}

/// Detailed user profile with linked accounts
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub user: User,
    pub linked_accounts: Vec<LinkedOAuthAccount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeletionStatus {
    Pending,
    Processing,
    Retrying,
    Completed,
    FailedNeedsReview,
}

impl AccountDeletionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Retrying => "retrying",
            Self::Completed => "completed",
            Self::FailedNeedsReview => "failed_needs_review",
        }
    }

    pub fn parse_db_value(value: &str) -> anyhow::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "retrying" => Ok(Self::Retrying),
            "completed" => Ok(Self::Completed),
            "failed_needs_review" => Ok(Self::FailedNeedsReview),
            _ => anyhow::bail!("unknown account deletion status: {value}"),
        }
    }
}

impl std::fmt::Display for AccountDeletionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct AccountDeletion {
    pub id: Uuid,
    pub user_id: UserId,
    pub status: AccountDeletionStatus,
    pub requested_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub lease_until: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub progress: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Errors returned when deleting a user account.
#[derive(Debug, Error)]
pub enum AccountDeletionError {
    #[error("User not found")]
    UserNotFound,
    #[error("Cannot delete account while active subscriptions exist")]
    ActiveSubscriptions { count: i64 },
    #[error("Cannot delete account while instances are not stopped")]
    InstancesNotStopped { count: i64, statuses: Vec<String> },
    #[error("Cannot delete account because conversation cleanup is incomplete")]
    ConversationCleanupIncomplete { conversation_ids: Vec<String> },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Repository trait for user-related data operations
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Get user by ID
    async fn get_user(&self, user_id: UserId) -> anyhow::Result<Option<User>>;

    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<User>>;

    /// Create a new user
    async fn create_user(
        &self,
        email: String,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User>;

    /// Update user information
    async fn update_user(
        &self,
        user_id: UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User>;

    /// Delete a user account and direct PII rows while preserving audit and billing data.
    async fn delete_user_account(
        &self,
        user_id: UserId,
        cloud_deleted_conversation_ids: &[String],
    ) -> Result<(), AccountDeletionError>;

    /// Create or return an existing deletion request after validating preconditions.
    async fn create_account_deletion_request(
        &self,
        user_id: UserId,
    ) -> Result<AccountDeletion, AccountDeletionError>;

    async fn get_account_deletion_by_user_id(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<AccountDeletion>>;

    async fn get_account_deletion(
        &self,
        deletion_id: Uuid,
    ) -> anyhow::Result<Option<AccountDeletion>>;

    async fn claim_account_deletion(
        &self,
        deletion_id: Uuid,
        lease_seconds: i64,
    ) -> anyhow::Result<Option<AccountDeletion>>;

    async fn update_account_deletion_progress(
        &self,
        deletion_id: Uuid,
        progress: serde_json::Value,
    ) -> anyhow::Result<()>;

    async fn mark_account_deletion_retrying(
        &self,
        deletion_id: Uuid,
        last_error: String,
        progress: serde_json::Value,
    ) -> anyhow::Result<()>;

    async fn mark_account_deletion_completed(&self, deletion_id: Uuid) -> anyhow::Result<()>;

    /// List locally tracked conversations owned by a user.
    async fn list_owned_conversation_ids(&self, user_id: UserId) -> anyhow::Result<Vec<String>>;

    /// Validate current account deletion preconditions without deleting any data.
    async fn validate_account_deletion_preconditions(
        &self,
        user_id: UserId,
    ) -> Result<(), AccountDeletionError>;

    /// Get linked OAuth accounts for a user
    async fn get_linked_accounts(&self, user_id: UserId)
        -> anyhow::Result<Vec<LinkedOAuthAccount>>;

    /// Link an OAuth account to a user
    async fn link_oauth_account(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
        provider_user_id: String,
    ) -> anyhow::Result<()>;

    /// Find user by OAuth provider and provider user ID
    async fn find_user_by_oauth(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> anyhow::Result<Option<UserId>>;

    /// List users with pagination
    async fn list_users(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<User>, u64)>;

    /// Check if the user currently has an active ban
    async fn has_active_ban(&self, user_id: UserId) -> anyhow::Result<bool>;

    /// Create a new ban record for the user
    async fn create_user_ban(
        &self,
        user_id: UserId,
        ban_type: BanType,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()>;
}

/// Service trait for user-related operations
#[async_trait]
pub trait UserService: Send + Sync {
    /// Get user profile by ID
    async fn get_user_profile(&self, user_id: UserId) -> anyhow::Result<UserProfile>;

    /// Update user profile
    async fn update_profile(
        &self,
        user_id: UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User>;

    /// Delete user account
    async fn delete_account(
        &self,
        user_id: UserId,
        cloud_deleted_conversation_ids: &[String],
    ) -> Result<(), AccountDeletionError>;

    async fn create_account_deletion_request(
        &self,
        user_id: UserId,
    ) -> Result<AccountDeletion, AccountDeletionError>;

    async fn is_account_deletion_requested(&self, user_id: UserId) -> anyhow::Result<bool>;

    /// List locally tracked conversations owned by a user.
    async fn list_owned_conversation_ids(&self, user_id: UserId) -> anyhow::Result<Vec<String>>;

    /// Validate current account deletion preconditions without deleting any data.
    async fn validate_account_deletion_preconditions(
        &self,
        user_id: UserId,
    ) -> Result<(), AccountDeletionError>;

    /// List users with pagination
    async fn list_users(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<User>, u64)>;

    /// Check if the user currently has an active ban
    async fn has_active_ban(&self, user_id: UserId) -> anyhow::Result<bool>;

    /// Ban a user for a specific duration
    async fn ban_user_for_duration(
        &self,
        user_id: UserId,
        ban_type: BanType,
        reason: Option<String>,
        duration: chrono::Duration,
    ) -> anyhow::Result<()>;
}

/// Appearance preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Appearance {
    Light,
    Dark,
    System,
}

/// User settings content structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSettingsContent {
    pub notification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    pub web_search: bool,
    pub appearance: Appearance,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialUserSettingsContent {
    pub notification: Option<bool>,
    pub system_prompt: Option<String>,
    pub web_search: Option<bool>,
    pub appearance: Option<Appearance>,
}

impl Default for UserSettingsContent {
    // When retrieving settings, default values are used to fill in any unset values.
    // If the value type is `Option<T>`, we cannot distinguish between "unset" and "set null".
    // Therefore, using `Some(T)` as the default value is NOT recommended, may cause unexpected behavior.
    fn default() -> Self {
        Self {
            notification: false,
            system_prompt: None,
            web_search: true,
            appearance: Appearance::System,
        }
    }
}

impl UserSettingsContent {
    pub fn into_updated(self, content: PartialUserSettingsContent) -> Self {
        Self {
            notification: content.notification.unwrap_or(self.notification),
            system_prompt: content.system_prompt.or(self.system_prompt),
            web_search: content.web_search.unwrap_or(self.web_search),
            appearance: content.appearance.unwrap_or(self.appearance),
        }
    }
}

/// User settings stored as JSONB in the database
#[derive(Debug, Clone)]
pub struct UserSettings {
    pub id: uuid::Uuid,
    pub user_id: UserId,
    pub content: UserSettingsContent,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository trait for user settings operations
#[async_trait]
pub trait UserSettingsRepository: Send + Sync {
    /// Get user settings by user ID
    /// Returns default settings if not found, and fills missing fields with default values
    async fn get_settings(&self, user_id: UserId) -> anyhow::Result<Option<UserSettings>>;

    /// Create or update user settings
    async fn upsert_settings(
        &self,
        user_id: UserId,
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettings>;
}

/// Service trait for user settings operations
#[async_trait]
pub trait UserSettingsService: Send + Sync {
    /// Get user settings by user ID
    async fn get_settings(&self, user_id: UserId) -> anyhow::Result<UserSettingsContent>;

    /// Update user settings
    async fn update_settings(
        &self,
        user_id: UserId,
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettingsContent>;

    /// Update user settings partially
    async fn update_settings_partially(
        &self,
        user_id: UserId,
        content: PartialUserSettingsContent,
    ) -> anyhow::Result<UserSettingsContent>;
}
