use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use http::Method;
use std::sync::Arc;

use super::ports::{FileError, FileRepository, FileService};
use crate::response::ports::OpenAIProxyService;
use crate::UserId;

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
    async fn track_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        tracing::info!("Tracking file: file_id={}, user_id={}", file_id, user_id);

        self.repository.upsert_file(file_id, user_id).await?;

        tracing::info!(
            "File tracked successfully: file_id={}, user_id={}",
            file_id,
            user_id
        );

        Ok(())
    }

    async fn list_files(&self, user_id: UserId) -> Result<Vec<serde_json::Value>, FileError> {
        tracing::info!("Listing files for user_id={}", user_id);

        // Get file IDs from database
        let file_ids = self.repository.list_files(user_id).await?;

        tracing::info!(
            "Retrieved {} file ID(s) from database for user_id={}",
            file_ids.len(),
            user_id
        );

        // Early return if no files
        if file_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch all files from OpenAI
        let files = self.batch_fetch_files(&file_ids).await?;

        tracing::info!(
            "Successfully fetched {} file(s) from OpenAI for user_id={}",
            files.len(),
            user_id
        );

        Ok(files)
    }

    async fn get_file(
        &self,
        file_id: &str,
        user_id: UserId,
    ) -> Result<serde_json::Value, FileError> {
        tracing::info!("Getting file: file_id={}, user_id={}", file_id, user_id);

        // Check if user has access to this file
        self.repository.get_file(file_id, user_id).await?;

        tracing::debug!(
            "User {} has access to file {}, fetching from OpenAI",
            user_id,
            file_id
        );

        // Fetch details from OpenAI
        let file = self.fetch_file_from_openai(file_id).await?;

        tracing::info!(
            "Successfully fetched file {} from OpenAI for user_id={}",
            file_id,
            user_id
        );

        Ok(file)
    }

    async fn delete_file(&self, file_id: &str, user_id: UserId) -> Result<(), FileError> {
        tracing::info!("Deleting file: file_id={}, user_id={}", file_id, user_id);

        // Check if user has access to this file
        self.repository.get_file(file_id, user_id).await?;

        // Delete from OpenAI first
        self.delete_file_from_openai(file_id).await?;

        // Then delete from database
        self.repository.delete_file(file_id, user_id).await?;

        tracing::info!(
            "File deleted successfully: file_id={}, user_id={}",
            file_id,
            user_id
        );

        Ok(())
    }
}

impl FileServiceImpl {
    /// Batch fetch multiple files from OpenAI API
    async fn batch_fetch_files(
        &self,
        file_ids: &[String],
    ) -> Result<Vec<serde_json::Value>, FileError> {
        // Fetch files in parallel
        let futures: Vec<_> = file_ids
            .iter()
            .map(|file_id| {
                let openai_proxy = self.openai_proxy.clone();
                let file_id = file_id.clone();
                async move { Self::fetch_file_from_openai_internal(openai_proxy, &file_id).await }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        let mut files = Vec::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(file) => files.push(file),
                Err(e) => {
                    tracing::warn!("Failed to fetch file {} from OpenAI: {}", file_ids[idx], e);
                }
            }
        }

        Ok(files)
    }

    /// Fetch file details from OpenAI API
    async fn fetch_file_from_openai(&self, file_id: &str) -> Result<serde_json::Value, FileError> {
        Self::fetch_file_from_openai_internal(self.openai_proxy.clone(), file_id).await
    }

    async fn fetch_file_from_openai_internal(
        openai_proxy: Arc<dyn OpenAIProxyService>,
        file_id: &str,
    ) -> Result<serde_json::Value, FileError> {
        let path = format!("files/{}", file_id);

        tracing::debug!("Fetching file from OpenAI: {}", path);

        let response = openai_proxy
            .forward_request(Method::GET, &path, http::HeaderMap::new(), None)
            .await
            .map_err(|e| FileError::ApiError(e.to_string()))?;

        if response.status != 200 {
            tracing::error!(
                "OpenAI API returned status {} for file {}",
                response.status,
                file_id
            );
            return Err(FileError::ApiError(format!(
                "OpenAI API returned status {}",
                response.status
            )));
        }

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

        tracing::debug!("Successfully fetched file {} from OpenAI", file_id);

        Ok(file)
    }

    /// Delete file from OpenAI API
    async fn delete_file_from_openai(&self, file_id: &str) -> Result<(), FileError> {
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

        Ok(())
    }
}
