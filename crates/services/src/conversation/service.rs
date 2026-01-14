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

        // Early return if no conversations
        if conversation_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch all conversations using batch API
        let conversations = self.batch_fetch_conversations(&conversation_ids).await?;

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
            .access_conversation(conversation_id, user_id)
            .await?;

        tracing::debug!(
            "User {} has access to conversation {}, fetching from OpenAI",
            user_id,
            conversation_id
        );

        // Fetch details from OpenAI
        let conversation = self.fetch_conversation_from_openai(conversation_id).await?;

        Ok(conversation)
    }

    async fn access_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        self.repository
            .access_conversation(conversation_id, user_id)
            .await
    }

    async fn get_conversation_owner(
        &self,
        conversation_id: &str,
    ) -> Result<Option<UserId>, ConversationError> {
        self.repository
            .get_conversation_owner(conversation_id)
            .await
    }

    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, ConversationError> {
        tracing::info!(
            "Deleting conversation: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        self.access_conversation(conversation_id, user_id).await?;

        // First delete conversation from OpenAI
        let deleted = self
            .delete_conversation_from_openai(conversation_id)
            .await?;

        // Then delete from database
        self.repository
            .delete_conversation(conversation_id, user_id)
            .await?;

        tracing::info!(
            "Conversation deleted successfully: conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        Ok(deleted)
    }
}

impl ConversationServiceImpl {
    /// Batch fetch multiple conversations from OpenAI API
    /// Handles large lists by chunking into batches and making parallel requests
    async fn batch_fetch_conversations(
        &self,
        conversation_ids: &[String],
    ) -> Result<Vec<serde_json::Value>, ConversationError> {
        const BATCH_SIZE: usize = 1000;

        tracing::debug!(
            "Batch fetching {} conversations from OpenAI",
            conversation_ids.len()
        );

        // Split conversation IDs into chunks of 1000
        let chunks: Vec<&[String]> = conversation_ids.chunks(BATCH_SIZE).collect();

        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        tracing::debug!(
            "Splitting {} conversations into {} batch request(s) of max {} each",
            conversation_ids.len(),
            chunks.len(),
            BATCH_SIZE
        );

        // Create futures for all batch requests
        let futures: Vec<_> = chunks
            .into_iter()
            .enumerate()
            .map(|(idx, chunk)| {
                let openai_proxy = self.openai_proxy.clone();
                async move {
                    tracing::debug!(
                        "Batch request {}: fetching {} conversations",
                        idx + 1,
                        chunk.len()
                    );
                    Self::make_batch_request(openai_proxy, chunk).await
                }
            })
            .collect();

        // Execute all batch requests in parallel
        let results = futures::future::join_all(futures).await;

        // Combine results from all batch requests
        let mut all_conversations = Vec::new();
        let mut all_missing_ids = Vec::new();

        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok((conversations, missing_ids)) => {
                    all_conversations.extend(conversations);
                    all_missing_ids.extend(missing_ids);
                }
                Err(e) => {
                    tracing::error!("Batch request {} failed: {}", idx + 1, e);
                    return Err(e);
                }
            }
        }

        // Log any missing conversations
        if !all_missing_ids.is_empty() {
            tracing::warn!(
                "Failed to fetch {} conversation(s) from OpenAI: {:?}",
                all_missing_ids.len(),
                all_missing_ids
            );
        }

        tracing::debug!(
            "Successfully batch fetched {} conversations from OpenAI",
            all_conversations.len()
        );

        Ok(all_conversations)
    }

    /// Make a single batch request to OpenAI API
    async fn make_batch_request(
        openai_proxy: std::sync::Arc<dyn crate::response::ports::OpenAIProxyService>,
        conversation_ids: &[String],
    ) -> Result<(Vec<serde_json::Value>, Vec<String>), ConversationError> {
        let path = "conversations/batch";

        // Build request body
        #[derive(serde::Serialize)]
        struct BatchRequest {
            ids: Vec<String>,
        }

        let request_body = BatchRequest {
            ids: conversation_ids.to_vec(),
        };

        let body_bytes = serde_json::to_vec(&request_body).map_err(|e| {
            ConversationError::ApiError(format!("Failed to serialize request: {}", e))
        })?;

        // Make batch request with Content-Type header
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let response = openai_proxy
            .forward_request(Method::POST, path, headers, Some(Bytes::from(body_bytes)))
            .await
            .map_err(|e| ConversationError::ApiError(e.to_string()))?;

        if response.status != 200 {
            tracing::error!(
                "OpenAI batch API returned status {} for conversations batch",
                response.status
            );
            return Err(ConversationError::ApiError(format!(
                "OpenAI batch API returned status {}",
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

        // Parse batch response
        #[derive(serde::Deserialize)]
        struct BatchResponse {
            data: Vec<serde_json::Value>,
            missing_ids: Vec<String>,
        }

        let batch_response: BatchResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| ConversationError::ApiError(format!("Failed to parse JSON: {}", e)))?;

        Ok((batch_response.data, batch_response.missing_ids))
    }

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

    /// Delete conversation from OpenAI API and return the delete response
    async fn delete_conversation_from_openai(
        &self,
        conversation_id: &str,
    ) -> Result<serde_json::Value, ConversationError> {
        let path = format!("conversations/{}", conversation_id);

        tracing::debug!("Deleting conversation from OpenAI: {}", path);

        let response = self
            .openai_proxy
            .forward_request(Method::DELETE, &path, http::HeaderMap::new(), None)
            .await
            .map_err(|e| ConversationError::ApiError(e.to_string()))?;

        if response.status != 200 {
            tracing::error!(
                "OpenAI API returned status {} for conversation delete {}",
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
        let value: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| ConversationError::ApiError(format!("Failed to parse JSON: {}", e)))?;

        tracing::debug!(
            "Successfully deleted conversation {} from OpenAI",
            conversation_id
        );

        Ok(value)
    }
}
