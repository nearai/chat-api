use async_trait::async_trait;
use std::sync::Arc;

use super::ports::{User, UserProfile, UserRepository, UserService};
use crate::types::UserId;

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
        tracing::info!("Getting user profile for user_id={}", user_id);

        // Get the user
        tracing::debug!("Fetching user data from repository for user_id={}", user_id);
        let user = self
            .user_repository
            .get_user(user_id)
            .await?
            .ok_or_else(|| {
                tracing::error!("User not found: user_id={}", user_id);
                anyhow::anyhow!("User not found")
            })?;

        tracing::debug!(
            "User data retrieved: user_id={}, email={}, name={:?}",
            user.id,
            user.email,
            user.name
        );

        // Get linked accounts
        tracing::debug!("Fetching linked OAuth accounts for user_id={}", user_id);
        let linked_accounts = self.user_repository.get_linked_accounts(user_id).await?;

        tracing::info!(
            "User profile retrieved successfully: user_id={}, {} linked account(s)",
            user_id,
            linked_accounts.len()
        );

        for account in &linked_accounts {
            tracing::debug!(
                "Linked account: provider={:?}, linked_at={}",
                account.provider,
                account.linked_at
            );
        }

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
        tracing::info!(
            "Updating user profile: user_id={}, name={:?}, avatar_url={:?}",
            user_id,
            name,
            avatar_url
        );

        let user = self
            .user_repository
            .update_user(user_id, name.clone(), avatar_url.clone())
            .await?;

        tracing::info!(
            "User profile updated successfully: user_id={}, email={}",
            user.id,
            user.email
        );

        Ok(user)
    }

    async fn delete_account(&self, user_id: UserId) -> anyhow::Result<()> {
        tracing::warn!("Deleting user account: user_id={}", user_id);

        self.user_repository.delete_user(user_id).await?;

        tracing::info!("User account deleted successfully: user_id={}", user_id);

        Ok(())
    }

    async fn list_users(&self, page: u32, page_size: u32) -> anyhow::Result<(Vec<User>, u64)> {
        tracing::info!("Listing users with page={}, page_size={}", page, page_size);

        let (users, total_count) = self.user_repository.list_users(page, page_size).await?;

        tracing::info!(
            "Retrieved {} user(s) (total: {}) for page={}, page_size={}",
            users.len(),
            total_count,
            page,
            page_size
        );

        Ok((users, total_count))
    }
}
