use async_trait::async_trait;
use std::sync::Arc;

use crate::types::UserId;
use super::ports::{User, UserProfile, UserRepository, UserService};

pub struct UserServiceImpl {
    user_repository: Arc<dyn UserRepository>,
}

impl UserServiceImpl {
    pub fn new(user_repository: Arc<dyn UserRepository>) -> Self {
        Self { user_repository }
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    async fn get_user_profile(&self, user_id: UserId) -> anyhow::Result<UserProfile> {
        // Get the user
        let user = self
            .user_repository
            .get_user(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        // Get linked accounts
        let linked_accounts = self.user_repository.get_linked_accounts(user_id).await?;

        Ok(UserProfile {
            user,
            linked_accounts,
        })
    }

    async fn update_profile(
        &self,
        user_id: UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User> {
        self.user_repository
            .update_user(user_id, name, avatar_url)
            .await
    }

    async fn delete_account(&self, user_id: UserId) -> anyhow::Result<()> {
        self.user_repository.delete_user(user_id).await
    }
}
