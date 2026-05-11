use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    AccountDeletion, AccountDeletionError, AccountDeletionStatus, BanType, User, UserProfile,
    UserRepository, UserService,
};
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

    async fn delete_account(
        &self,
        user_id: UserId,
        cloud_deleted_conversation_ids: &[String],
    ) -> Result<(), AccountDeletionError> {
        tracing::warn!("Deleting user account: user_id={}", user_id);

        self.user_repository
            .delete_user_account(user_id, cloud_deleted_conversation_ids)
            .await?;

        tracing::info!("User account deleted successfully: user_id={}", user_id);

        Ok(())
    }

    async fn create_account_deletion_request(
        &self,
        user_id: UserId,
    ) -> Result<AccountDeletion, AccountDeletionError> {
        tracing::warn!(
            "Creating user account deletion request: user_id={}",
            user_id
        );
        self.user_repository
            .create_account_deletion_request(user_id)
            .await
    }

    async fn delete_account_deletion_request(&self, deletion_id: Uuid) -> anyhow::Result<()> {
        self.user_repository
            .delete_account_deletion_request(deletion_id)
            .await
    }

    async fn is_account_deletion_requested(&self, user_id: UserId) -> anyhow::Result<bool> {
        Ok(self
            .user_repository
            .get_account_deletion_by_user_id(user_id)
            .await?
            .map(|deletion| deletion.status != crate::user::ports::AccountDeletionStatus::Completed)
            .unwrap_or(false))
    }

    async fn list_owned_conversation_ids(&self, user_id: UserId) -> anyhow::Result<Vec<String>> {
        self.user_repository
            .list_owned_conversation_ids(user_id)
            .await
    }

    async fn list_owned_file_ids(&self, user_id: UserId) -> anyhow::Result<Vec<String>> {
        self.user_repository.list_owned_file_ids(user_id).await
    }

    async fn list_account_deletions(
        &self,
        status: Option<AccountDeletionStatus>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<AccountDeletion>> {
        self.user_repository
            .list_account_deletions(status, limit, offset)
            .await
    }

    async fn validate_account_deletion_preconditions(
        &self,
        user_id: UserId,
    ) -> Result<(), AccountDeletionError> {
        self.user_repository
            .validate_account_deletion_preconditions(user_id)
            .await
    }

    async fn list_users(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<User>, u64)> {
        tracing::info!("Listing users with limit={}, offset={}", limit, offset);

        let (users, total_count) = self.user_repository.list_users(limit, offset).await?;

        tracing::info!(
            "Retrieved {} user(s) (total: {}) for limit={}, offset={}",
            users.len(),
            total_count,
            limit,
            offset
        );

        Ok((users, total_count))
    }

    async fn has_active_ban(&self, user_id: UserId) -> anyhow::Result<bool> {
        tracing::debug!("Checking active ban status for user_id={}", user_id);
        self.user_repository.has_active_ban(user_id).await
    }

    async fn ban_user_for_duration(
        &self,
        user_id: UserId,
        ban_type: BanType,
        reason: Option<String>,
        duration: Duration,
    ) -> anyhow::Result<()> {
        // Avoid creating duplicate active bans for the same user.
        // This keeps the user_bans table from accumulating redundant rows
        // when multiple failing checks happen close together.
        if self.user_repository.has_active_ban(user_id).await? {
            tracing::debug!(
                "User already has active ban, skipping new ban: user_id={}, ban_type={}",
                user_id,
                ban_type
            );
            return Ok(());
        }

        let expires_at = Some(Utc::now() + duration);

        tracing::warn!(
            "Banning user: user_id={}, ban_type={}, duration_secs={}",
            user_id,
            ban_type,
            duration.num_seconds()
        );

        self.user_repository
            .create_user_ban(user_id, ban_type, reason, expires_at)
            .await
    }
}
