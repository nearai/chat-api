use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::UserId;

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Conversation not found")]
    NotFound,
    #[error("OpenAI API error: {0}")]
    ApiError(String),
    #[error("Access denied")]
    AccessDenied,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    Read,
    Write,
}

impl SharePermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            SharePermission::Read => "read",
            SharePermission::Write => "write",
        }
    }

    pub fn allows_write(&self) -> bool {
        matches!(self, SharePermission::Write)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareRecipientKind {
    Email,
    NearAccount,
}

impl ShareRecipientKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareRecipientKind::Email => "email",
            ShareRecipientKind::NearAccount => "near",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareRecipient {
    pub kind: ShareRecipientKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareType {
    Direct,
    Group,
    Organization,
    Public,
}

impl ShareType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareType::Direct => "direct",
            ShareType::Group => "group",
            ShareType::Organization => "organization",
            ShareType::Public => "public",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareGroup {
    pub id: Uuid,
    pub owner_user_id: UserId,
    pub name: String,
    pub members: Vec<ShareRecipient>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ConversationShare {
    pub id: Uuid,
    pub conversation_id: String,
    pub owner_user_id: UserId,
    pub share_type: ShareType,
    pub permission: SharePermission,
    pub recipient: Option<ShareRecipient>,
    pub group_id: Option<Uuid>,
    pub org_email_pattern: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewConversationShare {
    pub conversation_id: String,
    pub owner_user_id: UserId,
    pub share_type: ShareType,
    pub permission: SharePermission,
    pub recipient: Option<ShareRecipient>,
    pub group_id: Option<Uuid>,
    pub org_email_pattern: Option<String>,
}

#[async_trait]
pub trait ConversationRepository: Send + Sync {
    /// Track a conversation ID for a user
    async fn upsert_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;

    /// List all conversation IDs for a user
    async fn list_conversations(&self, user_id: UserId) -> Result<Vec<String>, ConversationError>;

    /// Check if a conversation exists for a user
    async fn access_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;

    /// Get the owner of a conversation (returns None if conversation doesn't exist)
    async fn get_conversation_owner(
        &self,
        conversation_id: &str,
    ) -> Result<Option<UserId>, ConversationError>;

    /// Delete a conversation for a user
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;
}

#[async_trait]
pub trait ConversationShareRepository: Send + Sync {
    async fn create_group(
        &self,
        owner_user_id: UserId,
        name: &str,
        members: &[ShareRecipient],
    ) -> Result<ShareGroup, ConversationError>;

    async fn list_groups(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ShareGroup>, ConversationError>;

    /// List groups where the user is a member (by email or NEAR account)
    async fn list_groups_for_member(
        &self,
        member_identifiers: &[ShareRecipient],
    ) -> Result<Vec<ShareGroup>, ConversationError>;

    async fn get_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<Option<ShareGroup>, ConversationError>;

    async fn update_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
        name: Option<&str>,
        members: Option<&[ShareRecipient]>,
    ) -> Result<ShareGroup, ConversationError>;

    async fn delete_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<(), ConversationError>;

    async fn create_share(
        &self,
        share: NewConversationShare,
    ) -> Result<ConversationShare, ConversationError>;

    /// Create multiple shares atomically (all succeed or all fail)
    async fn create_shares_batch(
        &self,
        shares: Vec<NewConversationShare>,
    ) -> Result<Vec<ConversationShare>, ConversationError>;

    async fn list_shares(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
    ) -> Result<Vec<ConversationShare>, ConversationError>;

    async fn delete_share(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
        share_id: Uuid,
    ) -> Result<(), ConversationError>;

    async fn get_share_permission_for_user(
        &self,
        conversation_id: &str,
        email: &str,
        near_accounts: &[String],
    ) -> Result<Option<SharePermission>, ConversationError>;

    /// Get the public share for a conversation by conversation ID (if one exists)
    async fn get_public_share_by_conversation_id(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationShare>, ConversationError>;

    /// List all conversation IDs that have been shared with the user (excludes user's own conversations)
    async fn list_conversations_shared_with_user(
        &self,
        user_id: UserId,
        email: &str,
        near_accounts: &[String],
    ) -> Result<Vec<(String, SharePermission)>, ConversationError>;
}

#[async_trait]
pub trait ConversationService: Send + Sync {
    /// Track a conversation ID for a user
    async fn track_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;

    /// List all conversations for a user with details from OpenAI
    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<serde_json::Value>, ConversationError>;

    /// Get a conversation with details from OpenAI (checks user access first)
    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, ConversationError>;

    /// Ensure the user has access to a conversation using only the local database
    async fn access_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;

    /// Get the owner of a conversation (returns None if conversation doesn't exist)
    async fn get_conversation_owner(
        &self,
        conversation_id: &str,
    ) -> Result<Option<UserId>, ConversationError>;

    /// Delete a conversation for a user
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, ConversationError>;
}

#[derive(Debug, Clone)]
pub enum ShareTarget {
    Direct(Vec<ShareRecipient>),
    Group(Uuid),
    Organization(String),
    Public,
}

#[async_trait]
pub trait ConversationShareService: Send + Sync {
    async fn ensure_access(
        &self,
        conversation_id: &str,
        user_id: UserId,
        required_permission: SharePermission,
    ) -> Result<(), ConversationError>;

    /// Get public access for a conversation by ID (if it has a public share)
    async fn get_public_access_by_conversation_id(
        &self,
        conversation_id: &str,
        required_permission: SharePermission,
    ) -> Result<ConversationShare, ConversationError>;

    async fn create_group(
        &self,
        owner_user_id: UserId,
        name: &str,
        members: Vec<ShareRecipient>,
    ) -> Result<ShareGroup, ConversationError>;

    async fn list_groups(
        &self,
        owner_user_id: UserId,
    ) -> Result<Vec<ShareGroup>, ConversationError>;

    /// List all groups accessible to a user (owned + member of)
    async fn list_accessible_groups(
        &self,
        owner_user_id: UserId,
        member_identifiers: &[ShareRecipient],
    ) -> Result<Vec<ShareGroup>, ConversationError>;

    async fn update_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
        name: Option<String>,
        members: Option<Vec<ShareRecipient>>,
    ) -> Result<ShareGroup, ConversationError>;

    async fn delete_group(
        &self,
        owner_user_id: UserId,
        group_id: Uuid,
    ) -> Result<(), ConversationError>;

    async fn create_share(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
        permission: SharePermission,
        target: ShareTarget,
    ) -> Result<Vec<ConversationShare>, ConversationError>;

    async fn list_shares(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
    ) -> Result<Vec<ConversationShare>, ConversationError>;

    async fn delete_share(
        &self,
        owner_user_id: UserId,
        conversation_id: &str,
        share_id: Uuid,
    ) -> Result<(), ConversationError>;

    /// List all conversations that have been shared with the user
    async fn list_shared_with_me(
        &self,
        user_id: UserId,
    ) -> Result<Vec<(String, SharePermission)>, ConversationError>;
}
