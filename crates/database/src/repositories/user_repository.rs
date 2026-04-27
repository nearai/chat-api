use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::user::ports::{
    AccountDeletionError, BanType, LinkedOAuthAccount, OAuthProvider, User, UserRepository,
};
use services::UserId;
use std::collections::HashSet;
use tokio_postgres::GenericClient;

pub struct PostgresUserRepository {
    pool: DbPool,
}

impl PostgresUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn validate_account_deletion_preconditions_with_client(
        client: &impl GenericClient,
        user_id: UserId,
        lock_user: bool,
    ) -> Result<(), AccountDeletionError> {
        let user_query = if lock_user {
            "SELECT 1 FROM users WHERE id = $1 FOR UPDATE"
        } else {
            "SELECT 1 FROM users WHERE id = $1"
        };
        let user_exists = client
            .query_opt(user_query, &[&user_id])
            .await
            .map_err(anyhow::Error::from)?
            .is_some();
        if !user_exists {
            return Err(AccountDeletionError::UserNotFound);
        }

        let active_subscription_count: i64 = client
            .query_one(
                "SELECT COUNT(*)
                 FROM subscriptions
                 WHERE user_id = $1 AND status IN ('active', 'trialing')",
                &[&user_id],
            )
            .await
            .map_err(anyhow::Error::from)?
            .get(0);
        if active_subscription_count > 0 {
            return Err(AccountDeletionError::ActiveSubscriptions {
                count: active_subscription_count,
            });
        }

        let blocking_instance_rows = client
            .query(
                "SELECT status, COUNT(*)::bigint AS count
                 FROM agent_instances
                 WHERE user_id = $1 AND status NOT IN ('stopped', 'deleted')
                 GROUP BY status
                 ORDER BY status",
                &[&user_id],
            )
            .await
            .map_err(anyhow::Error::from)?;
        if !blocking_instance_rows.is_empty() {
            let mut total = 0_i64;
            let mut statuses = Vec::with_capacity(blocking_instance_rows.len());
            for row in blocking_instance_rows {
                let status: String = row.get("status");
                let count: i64 = row.get("count");
                total += count;
                statuses.push(format!("{status}:{count}"));
            }
            return Err(AccountDeletionError::InstancesNotStopped {
                count: total,
                statuses,
            });
        }

        Ok(())
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn get_user(&self, user_id: UserId) -> anyhow::Result<Option<User>> {
        tracing::debug!("Repository: Fetching user by user_id={}", user_id);

        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, email, name, avatar_url, created_at, updated_at 
                 FROM users 
                 WHERE id = $1",
                &[&user_id],
            )
            .await?;

        let result = row.map(|r| User {
            id: r.get(0),
            email: r.get(1),
            name: r.get(2),
            avatar_url: r.get(3),
            created_at: r.get(4),
            updated_at: r.get(5),
        });

        if result.is_some() {
            tracing::debug!("Repository: User found for user_id={}", user_id);
        } else {
            tracing::debug!("Repository: No user found for user_id={}", user_id);
        }

        Ok(result)
    }

    async fn get_user_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT id, email, name, avatar_url, created_at, updated_at 
                 FROM users 
                 WHERE email = $1",
                &[&email],
            )
            .await?;

        Ok(row.map(|r| User {
            id: r.get(0),
            email: r.get(1),
            name: r.get(2),
            avatar_url: r.get(3),
            created_at: r.get(4),
            updated_at: r.get(5),
        }))
    }

    async fn create_user(
        &self,
        email: String,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User> {
        tracing::info!(
            "Repository: Creating user with email={}, name={:?}",
            email,
            name
        );

        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "INSERT INTO users (email, name, avatar_url) 
                 VALUES ($1, $2, $3) 
                 RETURNING id, email, name, avatar_url, created_at, updated_at",
                &[&email, &name, &avatar_url],
            )
            .await?;

        let user = User {
            id: row.get(0),
            email: row.get(1),
            name: row.get(2),
            avatar_url: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        };

        tracing::info!(
            "Repository: User created successfully with user_id={}, email={}",
            user.id,
            user.email
        );

        Ok(user)
    }

    async fn update_user(
        &self,
        user_id: UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> anyhow::Result<User> {
        let client = self.pool.get().await?;

        let row = client
            .query_one(
                "UPDATE users 
                 SET name = $2, avatar_url = $3 
                 WHERE id = $1 
                 RETURNING id, email, name, avatar_url, created_at, updated_at",
                &[&user_id, &name, &avatar_url],
            )
            .await?;

        Ok(User {
            id: row.get(0),
            email: row.get(1),
            name: row.get(2),
            avatar_url: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        })
    }

    async fn delete_user_account(
        &self,
        user_id: UserId,
        cloud_deleted_conversation_ids: &[String],
    ) -> Result<(), AccountDeletionError> {
        let mut client = self.pool.get().await.map_err(anyhow::Error::from)?;
        let tx = client.transaction().await.map_err(anyhow::Error::from)?;

        Self::validate_account_deletion_preconditions_with_client(&*tx, user_id, true).await?;

        let verified_conversation_ids: HashSet<&str> = cloud_deleted_conversation_ids
            .iter()
            .map(String::as_str)
            .collect();
        let current_conversation_rows = tx
            .query(
                "SELECT id FROM conversations WHERE user_id = $1 ORDER BY id",
                &[&user_id],
            )
            .await
            .map_err(anyhow::Error::from)?;
        let missing_cloud_deletes: Vec<String> = current_conversation_rows
            .into_iter()
            .map(|row| row.get::<_, String>("id"))
            .filter(|id| !verified_conversation_ids.contains(id.as_str()))
            .collect();
        if !missing_cloud_deletes.is_empty() {
            return Err(AccountDeletionError::ConversationCleanupIncomplete {
                conversation_ids: missing_cloud_deletes,
            });
        }

        tx.execute(
            "DELETE FROM conversation_shares
             WHERE owner_user_id = $1
                OR conversation_id IN (SELECT id FROM conversations WHERE user_id = $1)
                OR group_id IN (SELECT id FROM conversation_share_groups WHERE owner_user_id = $1)",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute(
            "DELETE FROM conversation_share_group_members
             WHERE group_id IN (SELECT id FROM conversation_share_groups WHERE owner_user_id = $1)",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute(
            "DELETE FROM conversation_share_groups WHERE owner_user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM conversations WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM files WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM user_settings WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute(
            "DELETE FROM user_passkey_credentials WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM sessions WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM oauth_tokens WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM oauth_accounts WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM user_bans WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute(
            "DELETE FROM user_activity_log WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute(
            "DELETE FROM stripe_customers WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM user_credits WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute("DELETE FROM agent_api_keys WHERE user_id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;

        tx.execute(
            "WITH candidates AS (
                 SELECT id, status AS old_status
                 FROM agent_instances
                 WHERE user_id = $1 AND status != 'deleted'
                 FOR UPDATE
             ),
             updated AS (
                 UPDATE agent_instances ai
                 SET status = 'deleted',
                     name = 'deleted-account-instance',
                     public_ssh_key = NULL,
                     instance_url = NULL,
                     instance_token = NULL,
                     dashboard_url = NULL,
                     agent_api_base_url = NULL,
                     updated_at = NOW()
                 FROM candidates c
                 WHERE ai.id = c.id
                 RETURNING ai.id, c.old_status
             )
             INSERT INTO agent_instance_status_history
                 (instance_id, old_status, new_status, changed_by_user_id, change_reason, changed_at)
             SELECT id, old_status, 'deleted', NULL, 'user_account_deleted', NOW()
             FROM updated
             WHERE old_status != 'deleted'",
            &[&user_id],
        )
        .await
        .map_err(anyhow::Error::from)?;

        let deleted = tx
            .execute("DELETE FROM users WHERE id = $1", &[&user_id])
            .await
            .map_err(anyhow::Error::from)?;
        if deleted == 0 {
            return Err(AccountDeletionError::UserNotFound);
        }

        tx.commit().await.map_err(anyhow::Error::from)?;
        Ok(())
    }

    async fn list_owned_conversation_ids(&self, user_id: UserId) -> anyhow::Result<Vec<String>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT id FROM conversations WHERE user_id = $1 ORDER BY id",
                &[&user_id],
            )
            .await?;
        Ok(rows.into_iter().map(|row| row.get("id")).collect())
    }

    async fn validate_account_deletion_preconditions(
        &self,
        user_id: UserId,
    ) -> Result<(), AccountDeletionError> {
        let mut client = self.pool.get().await.map_err(anyhow::Error::from)?;
        let tx = client.transaction().await.map_err(anyhow::Error::from)?;
        Self::validate_account_deletion_preconditions_with_client(&*tx, user_id, false).await
    }

    async fn get_linked_accounts(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Vec<LinkedOAuthAccount>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT provider, provider_user_id, linked_at 
                 FROM oauth_accounts 
                 WHERE user_id = $1 
                 ORDER BY linked_at DESC",
                &[&user_id],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let provider_str: String = r.get(0);
                let provider = match provider_str.as_str() {
                    "google" => OAuthProvider::Google,
                    "github" => OAuthProvider::Github,
                    "near" => OAuthProvider::Near,
                    _ => OAuthProvider::Google, // fallback
                };
                LinkedOAuthAccount {
                    provider,
                    provider_user_id: r.get(1),
                    linked_at: r.get(2),
                }
            })
            .collect())
    }

    async fn link_oauth_account(
        &self,
        user_id: UserId,
        provider: OAuthProvider,
        provider_user_id: String,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Repository: Linking OAuth account - user_id={}, provider={:?}, provider_user_id={}",
            user_id,
            provider,
            provider_user_id
        );

        let client = self.pool.get().await?;

        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        let rows_affected = client
            .execute(
                "INSERT INTO oauth_accounts (user_id, provider, provider_user_id) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (provider, provider_user_id) DO NOTHING",
                &[&user_id, &provider_str, &provider_user_id],
            )
            .await?;

        if rows_affected > 0 {
            tracing::info!(
                "Repository: OAuth account linked successfully - user_id={}, provider={:?}",
                user_id,
                provider
            );
        } else {
            tracing::debug!(
                "Repository: OAuth account already linked - user_id={}, provider={:?}",
                user_id,
                provider
            );
        }

        Ok(())
    }

    async fn find_user_by_oauth(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> anyhow::Result<Option<UserId>> {
        tracing::debug!(
            "Repository: Finding user by OAuth - provider={:?}, provider_user_id={}",
            provider,
            provider_user_id
        );

        let client = self.pool.get().await?;

        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
            OAuthProvider::Near => "near",
        };

        let row = client
            .query_opt(
                "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
                &[&provider_str, &provider_user_id],
            )
            .await?;

        let result = row.map(|r| r.get(0));

        if let Some(ref user_id) = result {
            tracing::debug!(
                "Repository: Found user_id={} for provider={:?}",
                user_id,
                provider
            );
        } else {
            tracing::debug!(
                "Repository: No user found for provider={:?}, provider_user_id={}",
                provider,
                provider_user_id
            );
        }

        Ok(result)
    }

    async fn list_users(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<User>, u64)> {
        let client = self.pool.get().await?;

        // Get paginated users and total count in a single query using window function
        // This ensures consistency by avoiding race conditions between COUNT and SELECT queries
        let rows = client
            .query(
                "SELECT id, email, name, avatar_url, created_at, updated_at,
                        COUNT(*) OVER() as total_count
                 FROM users 
                 ORDER BY created_at DESC 
                 LIMIT $1 OFFSET $2",
                &[&limit, &offset],
            )
            .await?;

        // Extract total count from the first row (all rows have the same total_count)
        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let users = rows
            .into_iter()
            .map(|r| User {
                id: r.get("id"),
                email: r.get("email"),
                name: r.get("name"),
                avatar_url: r.get("avatar_url"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect();

        Ok((users, total_count as u64))
    }

    async fn has_active_ban(&self, user_id: UserId) -> anyhow::Result<bool> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT 1 FROM user_bans
                 WHERE user_id = $1
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())
                 LIMIT 1",
                &[&user_id],
            )
            .await?;

        Ok(row.is_some())
    }

    async fn create_user_ban(
        &self,
        user_id: UserId,
        ban_type: BanType,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()> {
        let mut client = self.pool.get().await?;

        // Start a transaction to ensure atomicity
        let transaction = client.transaction().await?;

        // First, revoke any expired bans for this user and ban_type to avoid unique index conflicts.
        // The unique index only checks revoked_at IS NULL, so expired bans that haven't been
        // explicitly revoked would still cause conflicts when inserting a new ban.
        transaction
            .execute(
                "UPDATE user_bans
                 SET revoked_at = NOW()
                 WHERE user_id = $1
                   AND ban_type = $2
                   AND revoked_at IS NULL
                   AND expires_at IS NOT NULL
                   AND expires_at <= NOW()",
                &[&user_id, &ban_type.as_str()],
            )
            .await?;

        // Now insert the new ban
        transaction
            .execute(
                "INSERT INTO user_bans (user_id, reason, ban_type, expires_at)
                 VALUES ($1, $2, $3, $4)",
                &[&user_id, &reason, &ban_type.as_str(), &expires_at],
            )
            .await?;

        // Commit the transaction
        transaction.commit().await?;

        Ok(())
    }
}
