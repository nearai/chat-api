use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{
    UserSettings, UserSettingsContent, UserSettingsRepository, UserSettingsService,
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
    async fn get_settings(&self, user_id: UserId) -> anyhow::Result<UserSettings> {
        tracing::info!("Getting user settings for user_id={}", user_id);

        let settings = self
            .user_settings_repository
            .get_settings(user_id)
            .await?
            .ok_or_else(|| {
                tracing::error!("User settings not found: user_id={}", user_id);
                anyhow::anyhow!("User settings not found")
            })?;

        tracing::info!("User settings retrieved successfully: user_id={}", user_id);

        Ok(settings)
    }

    async fn upsert_settings(
        &self,
        user_id: UserId,
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettings> {
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

        Ok(settings)
    }

    async fn update_settings(
        &self,
        user_id: UserId,
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettings> {
        tracing::info!(
            "Updating user settings: user_id={}, content={:?}",
            user_id,
            content
        );

        let settings = self
            .user_settings_repository
            .update_settings(user_id, content)
            .await?;

        tracing::info!("User settings updated successfully: user_id={}", user_id);

        Ok(settings)
    }
}
