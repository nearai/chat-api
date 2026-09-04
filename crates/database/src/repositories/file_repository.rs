use crate::pool::DbPool;
use async_trait::async_trait;
use services::file::ports::{FileData, FileError, FileRepository};
use services::UserId;
use tokio_postgres::Row;
use uuid::Uuid;

pub struct PostgresFileRepository {
    pool: DbPool,
}

impl PostgresFileRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn encode_filename(&self, id: Uuid, value: &str) -> Result<String, FileError> {
        match self.pool.field_encryption() {
            Some(config) if config.write_enabled => crate::field_encryption::encrypt(
                &config.key,
                &config.key_id,
                "files",
                "filename",
                id,
                value,
            )
            .map_err(|e| FileError::DatabaseError(e.to_string())),
            _ => Ok(value.to_string()),
        }
    }

    fn decode_filename(&self, id: Uuid, value: String) -> Result<String, FileError> {
        match self.pool.field_encryption() {
            Some(config) => crate::field_encryption::decrypt_if_encrypted(
                &config.key,
                &config.key_id,
                "files",
                "filename",
                id,
                value,
            )
            .map_err(|e| FileError::DatabaseError(e.to_string())),
            None => Ok(value),
        }
    }

    fn raw_to_file_data(&self, row: &Row) -> Result<FileData, FileError> {
        Ok(FileData {
            id: row.get("id"),
            bytes: row.get("bytes"),
            created_at: row.get("file_created_at"),
            expires_at: row.get("file_expires_at"),
            filename: self.decode_filename(row.get("encryption_id"), row.get("filename"))?,
            purpose: row.get("purpose"),
        })
    }
}

#[async_trait]
impl FileRepository for PostgresFileRepository {
    async fn upsert_file(&self, file: &FileData, user_id: UserId) -> Result<(), FileError> {
        tracing::debug!("Repository: Upserting file for user_id={}", user_id);

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let encryption_id = client
            .query_opt("SELECT encryption_id FROM files WHERE id=$1", &[&file.id])
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?
            .map(|row| row.get(0))
            .unwrap_or_else(Uuid::new_v4);
        let filename = self.encode_filename(encryption_id, &file.filename)?;
        client
            .execute(
                "INSERT INTO files (id, encryption_id, user_id, bytes, file_created_at, file_expires_at, filename, purpose)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) 
                 DO UPDATE SET 
                     user_id = EXCLUDED.user_id,
                     bytes = EXCLUDED.bytes,
                     file_created_at = EXCLUDED.file_created_at,
                     file_expires_at = EXCLUDED.file_expires_at,
                     filename = EXCLUDED.filename,
                     purpose = EXCLUDED.purpose,
                     updated_at = NOW()",
                &[
                    &file.id,
                    &encryption_id,
                    &user_id.0,
                    &file.bytes,
                    &file.created_at,
                    &file.expires_at,
                    &filename,
                    &file.purpose,
                ],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        tracing::debug!("Repository: File upserted for user_id={}", user_id);

        Ok(())
    }

    async fn get_file(&self, file_id: &str, user_id: UserId) -> Result<FileData, FileError> {
        tracing::debug!("Repository: Getting file for user_id={}", user_id);

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, encryption_id, bytes, file_created_at, file_expires_at, filename, purpose
                 FROM files 
                 WHERE id = $1 AND user_id = $2",
                &[&file_id, &user_id.0],
            )
            .await
            .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => self.raw_to_file_data(&r),
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

        // Build query with optional purpose and optional cursor (after)
        let rows = if let Some(after_id) = after {
            // With cursor
            let op = if order == "asc" { ">" } else { "<" };
            let sql = format!(
                "SELECT id, encryption_id, bytes, file_created_at, file_expires_at, filename, purpose
                 FROM files
                 WHERE user_id = $1
                   AND ($2::text IS NULL OR purpose = $2)
                   AND file_created_at {} (
                       SELECT file_created_at
                       FROM files
                       WHERE id = $3
                         AND user_id = $1
                         AND ($2::text IS NULL OR purpose = $2)
                   )
                 ORDER BY file_created_at {}
                 LIMIT $4",
                op, order_clause
            );
            client
                .query(&sql, &[&user_id.0, &purpose, &after_id, &limit])
                .await
        } else {
            // Without cursor
            let sql = format!(
                "SELECT id, encryption_id, bytes, file_created_at, file_expires_at, filename, purpose
                 FROM files
                 WHERE user_id = $1
                   AND ($2::text IS NULL OR purpose = $2)
                 ORDER BY file_created_at {}
                 LIMIT $3",
                order_clause
            );
            client.query(&sql, &[&user_id.0, &purpose, &limit]).await
        }
        .map_err(|e| FileError::DatabaseError(e.to_string()))?;

        let files: Vec<FileData> = rows
            .iter()
            .map(|row| self.raw_to_file_data(row))
            .collect::<Result<_, _>>()?;

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
