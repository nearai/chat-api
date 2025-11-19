use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    PartialUserSettingsContent, UserSettingsContent, UserSettingsRepository, UserSettingsService,
};
use crate::types::UserId;

pub struct UserSettingsServiceImpl {
    user_settings_repository: Arc<dyn UserSettingsRepository>,
}

impl UserSettingsServiceImpl {
    pub fn new(user_settings_repository: Arc<dyn UserSettingsRepository>) -> Self {
        Self {
            user_settings_repository,
        }
    }
}

#[async_trait]
impl UserSettingsService for UserSettingsServiceImpl {
    async fn get_settings(&self, user_id: UserId) -> anyhow::Result<UserSettingsContent> {
        tracing::info!("Getting user settings for user_id={}", user_id);

        let settings = self
            .user_settings_repository
            .get_settings(user_id)
            .await?
            .map(|settings| settings.content)
            .unwrap_or_else(UserSettingsContent::default);

        Ok(settings)
    }

    async fn update_settings(
        &self,
        user_id: UserId,
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettingsContent> {
        tracing::info!(
            "Upserting user settings: user_id={}, content={:?}",
            user_id,
            content
        );

        let settings = self
            .user_settings_repository
            .upsert_settings(user_id, content)
            .await?;

        tracing::info!("User settings upserted successfully: user_id={}", user_id);

        Ok(settings.content)
    }

    async fn update_settings_partially(
        &self,
        user_id: UserId,
        content: PartialUserSettingsContent,
    ) -> anyhow::Result<UserSettingsContent> {
        let old_content = self.get_settings(user_id).await?;
        self.update_settings(user_id, old_content.into_updated(content))
            .await
    }
}
