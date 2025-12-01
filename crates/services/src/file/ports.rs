use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::UserId;

/// File data structure for tracking files (internal and list response)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileData {
    pub id: String,
    pub bytes: i64,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub filename: String,
    pub purpose: String,
}

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
    /// Store complete file object for a user
    async fn upsert_file(&self, file: &FileData, user_id: UserId) -> Result<(), FileError>;

    /// Get a file object by ID
    async fn get_file(&self, file_id: &str, user_id: UserId) -> Result<FileData, FileError>;

    /// List file objects for a user with pagination
    async fn list_files(
        &self,
        user_id: UserId,
        after: Option<String>,
        limit: i64,
        order: &str,
    ) -> Result<Vec<FileData>, FileError>;

    /// Check if a file exists for a user
    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// Delete a file for a user
    async fn delete_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;
}

#[async_trait]
pub trait FileService: Send + Sync {
    /// Track a file by storing complete information
    async fn track_file(&self, file: FileData, user_id: UserId) -> Result<(), FileError>;

    /// List files for a user with pagination from local database
    async fn list_files(
        &self,
        user_id: UserId,
        after: Option<String>,
        limit: i64,
        order: &str,
    ) -> Result<(Vec<FileData>, bool), FileError>;

    /// Get a file from local database (checks user access)
    async fn get_file(&self, file_id: &str, user_id: UserId) -> Result<FileData, FileError>;

    /// Ensure the user has access to a file using only the local database
    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError>;

    /// Delete a file for a user
    async fn delete_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, FileError>;
}
