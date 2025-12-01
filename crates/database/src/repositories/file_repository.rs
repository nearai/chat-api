use crate::pool::DbPool;
use async_trait::async_trait;
use services::file::ports::{FileData, FileError, FileRepository};
use services::UserId;
use tokio_postgres::Row;

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
    async fn upsert_file(&self, file: &FileData, user_id: UserId) -> Result<(), FileError> {
        tracing::debug!(
            "Repository: Upserting file - file_id={}, user_id={}",
            file.id,
            user_id
        );

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        client
            .execute(
                "INSERT INTO files (id, user_id, bytes, file_created_at, file_expires_at, filename, purpose)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (id) 
                 DO UPDATE SET 
                     bytes = EXCLUDED.bytes,
                     file_created_at = EXCLUDED.file_created_at,
                     file_expires_at = EXCLUDED.file_expires_at,
                     filename = EXCLUDED.filename,
                     purpose = EXCLUDED.purpose,
                     updated_at = NOW()",
                &[
                    &file.id,
                    &user_id.0,
                    &file.bytes,
                    &file.created_at,
                    &file.expires_at,
                    &file.filename,
                    &file.purpose,
                ],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        tracing::debug!(
            "Repository: File upserted - file_id={}, user_id={}",
            file.id,
            user_id
        );

        Ok(())
    }

    async fn get_file(&self, file_id: &str, user_id: UserId) -> Result<FileData, FileError> {
        tracing::debug!(
            "Repository: Getting file - file_id={}, user_id={}",
            file_id,
            user_id
        );

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                 FROM files 
                 WHERE id = $1 AND user_id = $2",
                &[&file_id, &user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(raw_to_file_data(&r)),
            None => Err(FileError::NotFound),
        }
    }

    async fn list_files(
        &self,
        user_id: UserId,
        after: Option<String>,
        limit: i64,
        order: &str,
        purpose: Option<String>,
    ) -> Result<Vec<FileData>, FileError> {
        tracing::debug!(
            "Repository: Listing files with pagination for user_id={}, after={:?}, limit={}, order={}",
            user_id,
            after,
            limit,
            order
        );

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        // Validate order parameter
        let order_clause = match order {
            "asc" => "ASC",
            "desc" => "DESC",
            _ => {
                return Err(FileError::DatabaseError(
                    "Invalid order parameter".to_string(),
                ))
            }
        };

        // Build query with cursor-based pagination and optional purpose filter
        let rows =
            if let Some(after_id) = &after {
                match (order, &purpose) {
                    ("asc", Some(purpose)) => client
                        .query(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                             FROM files 
                             WHERE user_id = $1
                               AND purpose = $2
                               AND file_created_at > (
                                   SELECT file_created_at
                                   FROM files
                                   WHERE id = $3 AND user_id = $1 AND purpose = $2
                               )
                             ORDER BY file_created_at ASC
                             LIMIT $4",
                            &[&user_id.0, purpose, after_id, &limit],
                        )
                        .await,
                    ("asc", None) => client
                        .query(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                             FROM files 
                             WHERE user_id = $1
                               AND file_created_at > (
                                   SELECT file_created_at
                                   FROM files
                                   WHERE id = $2 AND user_id = $1
                               )
                             ORDER BY file_created_at ASC
                             LIMIT $3",
                            &[&user_id.0, after_id, &limit],
                        )
                        .await,
                    (_, Some(purpose)) => client
                        .query(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                             FROM files 
                             WHERE user_id = $1
                               AND purpose = $2
                               AND file_created_at < (
                                   SELECT file_created_at
                                   FROM files
                                   WHERE id = $3 AND user_id = $1 AND purpose = $2
                               )
                             ORDER BY file_created_at DESC
                             LIMIT $4",
                            &[&user_id.0, purpose, after_id, &limit],
                        )
                        .await,
                    (_, None) => client
                        .query(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                             FROM files 
                             WHERE user_id = $1
                               AND file_created_at < (
                                   SELECT file_created_at
                                   FROM files
                                   WHERE id = $2 AND user_id = $1
                               )
                             ORDER BY file_created_at DESC
                             LIMIT $3",
                            &[&user_id.0, after_id, &limit],
                        )
                        .await,
                }
            } else {
                match &purpose {
                    Some(purpose) => {
                        let query = format!(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                         FROM files 
                         WHERE user_id = $1
                           AND purpose = $2
                         ORDER BY file_created_at {}
                         LIMIT $3",
                            order_clause
                        );
                        client.query(&query, &[&user_id.0, purpose, &limit]).await
                    }
                    None => {
                        let query = format!(
                            "SELECT id, bytes, file_created_at, file_expires_at, filename, purpose
                         FROM files 
                         WHERE user_id = $1 
                         ORDER BY file_created_at {}
                         LIMIT $2",
                            order_clause
                        );
                        client.query(&query, &[&user_id.0, &limit]).await
                    }
                }
            }
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let files: Vec<FileData> = rows.iter().map(raw_to_file_data).collect();

        tracing::debug!(
            "Repository: Found {} file(s) with pagination for user_id={}",
            files.len(),
            user_id
        );

        Ok(files)
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

fn raw_to_file_data(row: &Row) -> FileData {
    FileData {
        id: row.get("id"),
        bytes: row.get("bytes"),
        created_at: row.get("file_created_at"),
        expires_at: row.get("file_expires_at"),
        filename: row.get("filename"),
        purpose: row.get("purpose"),
    }
}
