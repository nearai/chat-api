use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    user::ports::{UserSettings, UserSettingsRepository},
    UserId,
};

pub struct PostgresUserSettingsRepository {
    pool: DbPool,
}

impl PostgresUserSettingsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserSettingsRepository for PostgresUserSettingsRepository {
    async fn get_settings(&self, user_id: UserId) -> anyhow::Result<Option<UserSettings>> {
        tracing::debug!("Repository: Fetching user settings for user_id={}", user_id);

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, user_id, content, created_at, updated_at 
                 FROM user_settings 
                 WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        let result = row.map(|r| UserSettings {
            id: r.get(0),
            user_id: r.get(1),
            content: r.get(2),
            created_at: r.get(3),
            updated_at: r.get(4),
        });

        if result.is_some() {
            tracing::debug!("Repository: User settings found for user_id={}", user_id);
        } else {
            tracing::debug!("Repository: No user settings found for user_id={}", user_id);
        }

        Ok(result)
    }

    async fn upsert_settings(
        &self,
        user_id: UserId,
        content: serde_json::Value,
    ) -> anyhow::Result<UserSettings> {
        tracing::info!(
            "Repository: Upserting user settings for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO user_settings (user_id, content) 
                 VALUES ($1, $2) 
                 ON CONFLICT (user_id) 
                 DO UPDATE SET content = $2, updated_at = NOW()
                 RETURNING id, user_id, content, created_at, updated_at",
                &[&user_id, &content],
            )
            .await?;

        let settings = UserSettings {
            id: row.get(0),
            user_id: row.get(1),
            content: row.get(2),
            created_at: row.get(3),
            updated_at: row.get(4),
        };

        tracing::info!(
            "Repository: User settings upserted successfully for user_id={}",
            user_id
        );

        Ok(settings)
    }

    async fn update_settings(
        &self,
        user_id: UserId,
        content: serde_json::Value,
    ) -> anyhow::Result<UserSettings> {
        tracing::info!("Repository: Updating user settings for user_id={}", user_id);

        let client = self.pool.get().await?;

        // First get existing settings to merge
        let existing = self.get_settings(user_id).await?;
        let merged_content = if let Some(existing_settings) = existing {
            // Merge existing content with new content
            let mut existing_obj = existing_settings
                .content
                .as_object()
                .cloned()
                .unwrap_or_default();
            if let Some(new_obj) = content.as_object() {
                for (key, value) in new_obj {
                    existing_obj.insert(key.clone(), value.clone());
                }
            }
            serde_json::Value::Object(existing_obj)
        } else {
            content
        };

        let row = client
            .query_one(
                "INSERT INTO user_settings (user_id, content) 
                 VALUES ($1, $2) 
                 ON CONFLICT (user_id) 
                 DO UPDATE SET content = $2, updated_at = NOW()
                 RETURNING id, user_id, content, created_at, updated_at",
                &[&user_id, &merged_content],
            )
            .await?;

        let settings = UserSettings {
            id: row.get(0),
            user_id: row.get(1),
            content: row.get(2),
            created_at: row.get(3),
            updated_at: row.get(4),
        };

        tracing::info!(
            "Repository: User settings updated successfully for user_id={}",
            user_id
        );

        Ok(settings)
    }
}
