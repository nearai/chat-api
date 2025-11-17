use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    user::ports::{UserSettings, UserSettingsContent, UserSettingsRepository},
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

        let result = row.map(|r| {
            let content_json: serde_json::Value = r.get(2);
            let content: UserSettingsContent =
                serde_json::from_value(content_json).unwrap_or_else(|_| UserSettingsContent {
                    notification: false,
                    system_prompt: String::new(),
                });
            UserSettings {
                id: r.get(0),
                user_id: r.get(1),
                content,
                created_at: r.get(3),
                updated_at: r.get(4),
            }
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
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettings> {
        tracing::info!(
            "Repository: Upserting user settings for user_id={}",
            user_id
        );

        let client = self.pool.get().await?;

        // Serialize content to JSONB
        let content_json = serde_json::to_value(&content)?;

        let row = client
            .query_one(
                "INSERT INTO user_settings (user_id, content) 
                 VALUES ($1, $2) 
                 ON CONFLICT (user_id) 
                 DO UPDATE SET content = $2, updated_at = NOW()
                 RETURNING id, user_id, content, created_at, updated_at",
                &[&user_id, &content_json],
            )
            .await?;

        let content_json: serde_json::Value = row.get(2);
        let content: UserSettingsContent = serde_json::from_value(content_json)?;

        let settings = UserSettings {
            id: row.get(0),
            user_id: row.get(1),
            content,
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
        content: UserSettingsContent,
    ) -> anyhow::Result<UserSettings> {
        tracing::info!("Repository: Updating user settings for user_id={}", user_id);

        let client = self.pool.get().await?;

        // Serialize content to JSONB
        let content_json = serde_json::to_value(&content)?;

        let row = client
            .query_one(
                "INSERT INTO user_settings (user_id, content) 
                 VALUES ($1, $2) 
                 ON CONFLICT (user_id) 
                 DO UPDATE SET content = $2, updated_at = NOW()
                 RETURNING id, user_id, content, created_at, updated_at",
                &[&user_id, &content_json],
            )
            .await?;

        let content_json: serde_json::Value = row.get(2);
        let content: UserSettingsContent = serde_json::from_value(content_json)?;

        let settings = UserSettings {
            id: row.get(0),
            user_id: row.get(1),
            content,
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
