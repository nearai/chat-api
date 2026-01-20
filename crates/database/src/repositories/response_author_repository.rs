use deadpool_postgres::Pool;
use std::collections::HashMap;
use tokio_postgres::Row;
use uuid::Uuid;

/// Information about who authored a response
#[derive(Debug, Clone)]
pub struct ResponseAuthor {
    pub conversation_id: String,
    pub response_id: String,
    pub user_id: Uuid,
    pub author_name: Option<String>,
}

impl From<Row> for ResponseAuthor {
    fn from(row: Row) -> Self {
        Self {
            conversation_id: row.get("conversation_id"),
            response_id: row.get("response_id"),
            user_id: row.get("user_id"),
            author_name: row.get("author_name"),
        }
    }
}

pub struct ResponseAuthorRepository {
    pool: Pool,
}

impl ResponseAuthorRepository {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Store author information for a response
    pub async fn store_author(
        &self,
        conversation_id: &str,
        response_id: &str,
        user_id: Uuid,
        author_name: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
                INSERT INTO response_authors (conversation_id, response_id, user_id, author_name)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (conversation_id, response_id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    author_name = EXCLUDED.author_name
                "#,
                &[&conversation_id, &response_id, &user_id, &author_name],
            )
            .await?;
        Ok(())
    }

    /// Get all authors for a conversation, keyed by response_id
    pub async fn get_authors_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<HashMap<String, ResponseAuthor>, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT conversation_id, response_id, user_id, author_name FROM response_authors WHERE conversation_id = $1",
                &[&conversation_id],
            )
            .await?;

        let mut authors = HashMap::new();
        for row in rows {
            let author = ResponseAuthor::from(row);
            authors.insert(author.response_id.clone(), author);
        }
        Ok(authors)
    }
}
