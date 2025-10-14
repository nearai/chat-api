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
        self.repository
            .upsert_conversation(conversation_id, user_id, title)
            .await
    }

    async fn list_conversations(&self, user_id: UserId) -> Result<Vec<Conversation>, ConversationError> {
        self.repository.list_conversations(user_id).await
    }

    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<Conversation, ConversationError> {
        self.repository
            .get_conversation(conversation_id, user_id)
            .await
    }

    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        self.repository
            .delete_conversation(conversation_id, user_id)
            .await
    }
}

