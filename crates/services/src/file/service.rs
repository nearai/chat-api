use super::ports::{FileData, FileError, FileRepository, FileService};
use crate::response::ports::OpenAIProxyService;
use crate::UserId;
use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use http::Method;
use std::sync::Arc;

pub struct FileServiceImpl {
    repository: Arc<dyn FileRepository>,
    openai_proxy: Arc<dyn OpenAIProxyService>,
}

impl FileServiceImpl {
    pub fn new(
        repository: Arc<dyn FileRepository>,
        openai_proxy: Arc<dyn OpenAIProxyService>,
    ) -> Self {
        Self {
            repository,
            openai_proxy,
        }
    }
}

#[async_trait]
impl FileService for FileServiceImpl {
    async fn track_file(
        &self,
        file: FileData,
        user_id: UserId,
    ) -> Result<(), FileError> {
        tracing::info!("Tracking file: file_id={}, user_id={}", file.id, user_id);

        // Store complete file object in database
        self.repository.upsert_file(&file, user_id).await?;

        tracing::info!(
            "File tracked successfully: file_id={}, user_id={}",
            file.id,
            user_id
        );

        Ok(())
    }

    async fn list_files(&self, user_id: UserId) -> Result<Vec<FileData>, FileError> {
        tracing::info!("Listing files for user_id={}", user_id);

        // Get files directly from database
        let files = self.repository.list_files(user_id).await?;

        tracing::info!(
            "Retrieved {} file(s) from database for user_id={}",
            files.len(),
            user_id
        );

        Ok(files)
    }

    async fn list_files_paginated(
        &self,
        user_id: UserId,
        after: Option<String>,
        limit: i64,
        order: &str,
    ) -> Result<(Vec<FileData>, bool), FileError> {
        tracing::info!(
            "Listing files with pagination for user_id={}, after={:?}, limit={}, order={}",
            user_id,
            after,
            limit,
            order
        );

        // Fetch limit + 1 to determine if there are more results
        let fetch_limit = limit + 1;

        // Get files directly from database with pagination
        let files = self
            .repository
            .list_files_paginated(user_id, after, fetch_limit, order)
            .await?;

        tracing::info!(
            "Retrieved {} file(s) from database for user_id={}",
            files.len(),
            user_id
        );

        // Determine if there are more results
        let has_more = files.len() > limit as usize;
        let files_to_return: Vec<_> = files.into_iter().take(limit as usize).collect();

        Ok((files_to_return, has_more))
    }

    async fn get_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<FileData, FileError> {
        tracing::info!("Getting file: file_id={}, user_id={}", file_id, user_id);

        // Get file directly from database
        let file = self.repository.get_file(file_id, user_id).await?;

        tracing::debug!(
            "Retrieved file {} from database for user {}",
            file_id,
            user_id
        );

        Ok(file)
    }

    async fn access_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        self.repository.access_file(file_id, user_id).await
    }

    async fn delete_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, FileError> {
        tracing::info!("Deleting file: file_id={}, user_id={}", file_id, user_id);

        // Then delete from database
        self.repository.delete_file(file_id, user_id).await?;

        tracing::info!(
            "File deleted successfully: file_id={}, user_id={}",
            file_id,
            user_id
        );

        // Delete from OpenAI first
        self.delete_file_from_openai(file_id).await
    }
}

impl FileServiceImpl {
    /// Delete file from OpenAI API
    async fn delete_file_from_openai(&self, file_id: &str) -> Result<serde_json::Value, FileError> {
        let path = format!("files/{}", file_id);

        tracing::debug!("Deleting file from OpenAI: {}", path);

        let response = self
            .openai_proxy
            .forward_request(Method::DELETE, &path, http::HeaderMap::new(), None)
            .await
            .map_err(|e| FileError::ApiError(e.to_string()))?;

        if response.status != 200 {
            tracing::error!(
                "OpenAI API returned status {} for file deletion {}",
                response.status,
                file_id
            );
            return Err(FileError::ApiError(format!(
                "OpenAI API returned status {}",
                response.status
            )));
        }

        tracing::debug!("Successfully deleted file {} from OpenAI", file_id);

        // Collect the response body
        let body_bytes: Bytes = response
            .body
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| FileError::ApiError(format!("Failed to read response: {}", e)))?
            .into_iter()
            .flatten()
            .collect();

        // Parse as JSON
        let file: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| FileError::ApiError(format!("Failed to parse JSON: {}", e)))?;

        Ok(file)
    }
}
