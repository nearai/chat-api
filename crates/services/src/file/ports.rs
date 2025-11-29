use async_trait::async_trait;

use crate::UserId;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("File not found")]
    NotFound,
    #[error("OpenAI API error: {0}")]
    ApiError(String),
    #[error("Access denied")]
    AccessDenied,
}

#[async_trait]
pub trait FileRepository: Send + Sync {
    /// Track a file ID for a user
    async fn upsert_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// List all file IDs for a user
    async fn list_files(&self, user_id: UserId) -> Result<Vec<String>, FileError>;

    /// Check if a file exists for a user
    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// Delete a file for a user
    async fn delete_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;
}

#[async_trait]
pub trait FileService: Send + Sync {
    /// Track a file ID for a user
    async fn track_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// List all files for a user with details from OpenAI
    async fn list_files(&self, user_id: UserId) -> Result<Vec<serde_json::Value>, FileError>;

    /// Get a file with details from OpenAI (checks user access first)
    async fn get_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, FileError>;

    /// Ensure the user has access to a file using only the local database
    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// Delete a file for a user
    async fn delete_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, FileError>;
}
