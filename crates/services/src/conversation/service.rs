use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{Conversation, ConversationError, ConversationRepository, ConversationService};
use crate::UserId;

pub struct ConversationServiceImpl {
    repository: Arc<dyn ConversationRepository>,
}

impl ConversationServiceImpl {
    pub fn new(repository: Arc<dyn ConversationRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl ConversationService for ConversationServiceImpl {
    async fn track_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
        title: Option<String>,
    ) -> Result<Conversation, ConversationError> {
        tracing::info!(
            "Tracking conversation: conversation_id={}, user_id={}, title={:?}",
            conversation_id,
            user_id,
            title
        );

        let conversation = self
            .repository
            .upsert_conversation(conversation_id, user_id, title.clone())
            .await?;

        tracing::info!(
            "Conversation tracked successfully: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        Ok(conversation)
    }

    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Conversation>, ConversationError> {
        tracing::info!("Listing conversations for user_id={}", user_id);

        let conversations = self.repository.list_conversations(user_id).await?;

        tracing::info!(
            "Retrieved {} conversation(s) for user_id={}",
            conversations.len(),
            user_id
        );

        Ok(conversations)
    }

    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<Conversation, ConversationError> {
        tracing::info!(
            "Getting conversation: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        let conversation = self
            .repository
            .get_conversation(conversation_id, user_id)
            .await?;

        tracing::debug!(
            "Conversation retrieved: id={}, title={:?}, created_at={}",
            conversation.id,
            conversation.title,
            conversation.created_at
        );

        Ok(conversation)
    }

    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        tracing::info!(
            "Deleting conversation: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        self.repository
            .delete_conversation(conversation_id, user_id)
            .await?;

        tracing::info!(
            "Conversation deleted successfully: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        Ok(())
    }
}
