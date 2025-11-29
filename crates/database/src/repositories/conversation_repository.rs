use crate::pool::DbPool;
use async_trait::async_trait;
use services::conversation::ports::{ConversationError, ConversationRepository};
use services::UserId;

pub struct PostgresConversationRepository {
    pool: DbPool,
}

impl PostgresConversationRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConversationRepository for PostgresConversationRepository {
    async fn upsert_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        tracing::debug!(
            "Repository: Upserting conversation - conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        client
            .execute(
                "INSERT INTO conversations (id, user_id)
                 VALUES ($1, $2)
                 ON CONFLICT (id) 
                 DO UPDATE SET updated_at = NOW()",
                &[&conversation_id, &user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        tracing::debug!(
            "Repository: Conversation upserted - conversation_id={}, user_id={}",
            conversation_id,
            user_id
        );

        Ok(())
    }

    async fn list_conversations(&self, user_id: UserId) -> Result<Vec<String>, ConversationError> {
        tracing::debug!("Repository: Listing conversations for user_id={}", user_id);

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id FROM conversations 
                 WHERE user_id = $1 
                 ORDER BY updated_at DESC",
                &[&user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let conversation_ids: Vec<String> = rows.iter().map(|row| row.get(0)).collect();

        tracing::debug!(
            "Repository: Found {} conversation(s) for user_id={}",
            conversation_ids.len(),
            user_id
        );

        Ok(conversation_ids)
    }

    async fn access_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id FROM conversations 
                 WHERE id = $1 AND user_id = $2",
                &[&conversation_id, &user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        match row {
            Some(_) => Ok(()),
            None => Err(ConversationError::NotFound),
        }
    }

    async fn delete_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<(), ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let result = client
            .execute(
                "DELETE FROM conversations WHERE id = $1 AND user_id = $2",
                &[&conversation_id, &user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        if result == 0 {
            Err(ConversationError::NotFound)
        } else {
            Ok(())
        }
    }
}
