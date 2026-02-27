use async_trait::async_trait;
use chrono::{DateTime, Utc};

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

/// User with admin dashboard stats (subscription, agent count, spending, etc.)
#[derive(Debug, Clone)]
pub struct AdminUserWithStats {
    pub user: User,
    pub subscription_status: Option<String>,
    pub subscription_price_id: Option<String>,
    pub agent_count: i64,
    pub total_spent_nano: i64,
    pub agent_spent_nano: i64,
    pub agent_token_usage: i64,
    pub last_activity_at: Option<DateTime<Utc>>,
}

/// Filter for admin user list
#[derive(Debug, Clone, Default)]
pub struct AdminListUsersFilter {
    /// Filter by subscription status: "active", "canceled", "past_due", or "none" for no subscription
    pub subscription_status: Option<String>,
    /// Filter by subscription plan name (e.g. "Pro", "Starter") or "none" for no subscription.
    /// Requires price_ids resolved from system config.
    pub subscription_plan_price_ids: Option<Vec<String>>,
    /// Filter by subscription plan = none (no subscription)
    pub subscription_plan_none: bool,
    /// Substring search on email and name (case-insensitive)
    pub search: Option<String>,
}

/// Sort options for admin user list
#[derive(Debug, Clone)]
pub struct AdminListUsersSort {
    pub sort_by: AdminUsersSortBy,
    pub sort_order: AdminUsersSortOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminUsersSortBy {
    CreatedAt,
    TotalSpentNano,
    AgentSpentNano,
    AgentTokenUsage,
    LastActivityAt,
    AgentCount,
    Email,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminUsersSortOrder {
    Asc,
    Desc,
}

impl Default for AdminListUsersSort {
    fn default() -> Self {
        Self {
            sort_by: AdminUsersSortBy::CreatedAt,
            sort_order: AdminUsersSortOrder::Desc,
        }
    }
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

    /// Delete a user
    async fn delete_user(&self, user_id: UserId) -> anyhow::Result<()>;

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

    /// List users with admin stats, filter and sort
    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &AdminListUsersFilter,
        sort: &AdminListUsersSort,
    ) -> anyhow::Result<(Vec<AdminUserWithStats>, u64)>;

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
    async fn delete_account(&self, user_id: UserId) -> anyhow::Result<()>;

    /// List users with pagination
    async fn list_users(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<User>, u64)>;

    /// List users with admin stats, filter and sort
    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &AdminListUsersFilter,
        sort: &AdminListUsersSort,
    ) -> anyhow::Result<(Vec<AdminUserWithStats>, u64)>;

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
