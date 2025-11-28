use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{FileError, FileRepository, FileService};
use crate::UserId;

pub struct FileServiceImpl {
    repository: Arc<dyn FileRepository>,
}

impl FileServiceImpl {
    pub fn new(repository: Arc<dyn FileRepository>) -> Self {
        Self { repository }
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
}
