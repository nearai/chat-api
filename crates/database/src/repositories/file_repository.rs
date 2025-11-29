use crate::pool::DbPool;
use async_trait::async_trait;
use services::file::ports::{FileError, FileRepository};
use services::UserId;

pub struct PostgresFileRepository {
    pool: DbPool,
}

impl PostgresFileRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FileRepository for PostgresFileRepository {
    async fn upsert_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        tracing::debug!(
            "Repository: Upserting file - file_id={}, user_id={}",
            file_id,
            user_id
        );

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        client
            .execute(
                "INSERT INTO files (id, user_id)
                 VALUES ($1, $2)
                 ON CONFLICT (id) 
                 DO UPDATE SET updated_at = NOW()",
                &[&file_id, &user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        tracing::debug!(
            "Repository: File upserted - file_id={}, user_id={}",
            file_id,
            user_id
        );

        Ok(())
    }

    async fn list_files(&self, user_id: UserId) -> Result<Vec<String>, FileError> {
        tracing::debug!("Repository: Listing files for user_id={}", user_id);

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id FROM files 
                 WHERE user_id = $1 
                 ORDER BY updated_at DESC",
                &[&user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let file_ids: Vec<String> = rows.iter().map(|row| row.get(0)).collect();

        tracing::debug!(
            "Repository: Found {} file(s) for user_id={}",
            file_ids.len(),
            user_id
        );

        Ok(file_ids)
    }

    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id FROM files 
                 WHERE id = $1 AND user_id = $2",
                &[&file_id, &user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        match row {
            Some(_) => Ok(()),
            None => Err(FileError::NotFound),
        }
    }

    async fn delete_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let result = client
            .execute(
                "DELETE FROM files WHERE id = $1 AND user_id = $2",
                &[&file_id, &user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        if result == 0 {
            Err(FileError::NotFound)
        } else {
            Ok(())
        }
    }
}
