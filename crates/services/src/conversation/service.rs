use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use http::Method;
use std::sync::Arc;

use super::ports::{ConversationError, ConversationRepository, ConversationService};
use crate::response::ports::OpenAIProxyService;
use crate::UserId;

pub struct ConversationServiceImpl {
    repository: Arc<dyn ConversationRepository>,
    openai_proxy: Arc<dyn OpenAIProxyService>,
}

impl ConversationServiceImpl {
    pub fn new(
        repository: Arc<dyn ConversationRepository>,
        openai_proxy: Arc<dyn OpenAIProxyService>,
    ) -> Self {
        Self {
            repository,
            openai_proxy,
        }
    }
}

#[async_trait]
impl ConversationService for ConversationServiceImpl {
    async fn track_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        tracing::info!(
            "Tracking conversation: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        self.repository
            .upsert_conversation(conversation_id, user_id)
            .await?;

        tracing::info!(
            "Conversation tracked successfully: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        Ok(())
    }

    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<serde_json::Value>, ConversationError> {
        tracing::info!("Listing conversations for user_id={}", user_id);

        // Get conversation IDs from database
        let conversation_ids = self.repository.list_conversations(user_id).await?;

        tracing::info!(
            "Retrieved {} conversation ID(s) from database for user_id={}",
            conversation_ids.len(),
            user_id
        );

        // Fetch details from OpenAI for each conversation
        let mut conversations = Vec::new();
        for conversation_id in conversation_ids {
            match self.fetch_conversation_from_openai(&conversation_id).await {
                Ok(conversation) => conversations.push(conversation),
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch conversation {} from OpenAI: {}",
                        conversation_id,
                        e
                    );
                    // Continue with other conversations even if one fails
                }
            }
        }

        tracing::info!(
            "Successfully fetched {} conversation(s) from OpenAI for user_id={}",
            conversations.len(),
            user_id
        );

        Ok(conversations)
    }

    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, ConversationError> {
        tracing::info!(
            "Getting conversation: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        // Check if user has access to this conversation
        self.repository
            .get_conversation(conversation_id, user_id)
            .await?;

        tracing::debug!(
            "User {} has access to conversation {}, fetching from OpenAI",
            user_id,
            conversation_id
        );

        // Fetch details from OpenAI
        let conversation = self.fetch_conversation_from_openai(conversation_id).await?;

        tracing::info!(
            "Successfully fetched conversation {} from OpenAI for user_id={}",
            conversation_id,
            user_id
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

impl ConversationServiceImpl {
    /// Fetch conversation details from OpenAI API
    async fn fetch_conversation_from_openai(
        &self,
        conversation_id: &str,
    ) -> Result<serde_json::Value, ConversationError> {
        let path = format!("conversations/{}", conversation_id);

        tracing::debug!("Fetching conversation from OpenAI: {}", path);

        let response = self
            .openai_proxy
            .forward_request(Method::GET, &path, http::HeaderMap::new(), None)
            .await
            .map_err(|e| ConversationError::ApiError(e.to_string()))?;

        if response.status != 200 {
            tracing::error!(
                "OpenAI API returned status {} for conversation {}",
                response.status,
                conversation_id
            );
            return Err(ConversationError::ApiError(format!(
                "OpenAI API returned status {}",
                response.status
            )));
        }

        // Collect the response body
        let body_bytes: Bytes = response
            .body
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| ConversationError::ApiError(format!("Failed to read response: {}", e)))?
            .into_iter()
            .flatten()
            .collect();

        // Parse as JSON
        let conversation: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| ConversationError::ApiError(format!("Failed to parse JSON: {}", e)))?;

        tracing::debug!(
            "Successfully fetched conversation {} from OpenAI",
            conversation_id
        );

        Ok(conversation)
    }
}
