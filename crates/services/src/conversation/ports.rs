use async_trait::async_trait;

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
    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;

    /// Delete a conversation for a user
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;
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

    /// Delete a conversation for a user
    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError>;
}
