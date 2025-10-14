use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::UserId;

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Conversation not found")]
    NotFound,
}

/// A conversation tracked for a user
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: String, // OpenAI conversation ID
    pub user_id: UserId,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait ConversationRepository: Send + Sync {
    /// Create or update a conversation for a user
    async fn upsert_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
        title: Option<String>,
    ) -> Result<Conversation, ConversationError>;

    /// List all conversations for a user
    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Conversation>, ConversationError>;

    /// Get a specific conversation
    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<Conversation, ConversationError>;

    /// Delete a conversation
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;
}

#[async_trait]
pub trait ConversationService: Send + Sync {
    /// Track a conversation for a user (create or update)
    async fn track_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
        title: Option<String>,
    ) -> Result<Conversation, ConversationError>;

    /// List all conversations for a user
    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Conversation>, ConversationError>;

    /// Get a specific conversation
    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<Conversation, ConversationError>;

    /// Delete a conversation
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;
}
