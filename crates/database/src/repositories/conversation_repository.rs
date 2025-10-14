use crate::pool::DbPool;
use async_trait::async_trait;
use services::conversation::ports::{Conversation, ConversationError, ConversationRepository};
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
        title: Option<String>,
    ) -> Result<Conversation, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_one(
                "INSERT INTO conversations (id, user_id, title)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (id, user_id) 
                 DO UPDATE SET 
                    title = COALESCE($3, conversations.title),
                    updated_at = NOW()
                 RETURNING id, user_id, title, created_at, updated_at",
                &[&conversation_id, &user_id.0, &title],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        Ok(Conversation {
            id: row.get(0),
            user_id: UserId(row.get(1)),
            title: row.get(2),
            created_at: row.get(3),
            updated_at: row.get(4),
        })
    }

    async fn list_conversations(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Conversation>, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id, user_id, title, created_at, updated_at 
                 FROM conversations 
                 WHERE user_id = $1 
                 ORDER BY updated_at DESC",
                &[&user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| Conversation {
                id: row.get(0),
                user_id: UserId(row.get(1)),
                title: row.get(2),
                created_at: row.get(3),
                updated_at: row.get(4),
            })
            .collect())
    }

    async fn get_conversation(
        &self,
        conversation_id: &str,
        user_id: UserId,
    ) -> Result<Conversation, ConversationError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, user_id, title, created_at, updated_at 
                 FROM conversations 
                 WHERE id = $1 AND user_id = $2",
                &[&conversation_id, &user_id.0],
            )
            .await
            .map_err(|e| ConversationError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(Conversation {
                id: row.get(0),
                user_id: UserId(row.get(1)),
                title: row.get(2),
                created_at: row.get(3),
                updated_at: row.get(4),
            }),
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
