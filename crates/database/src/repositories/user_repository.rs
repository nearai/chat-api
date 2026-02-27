use crate::pool::DbPool;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use services::user::ports::{
    AdminListUsersFilter, AdminListUsersSort, AdminUserWithStats, AdminUsersSortBy,
    AdminUsersSortOrder, BanType, LinkedOAuthAccount, OAuthProvider, User, UserRepository,
};
use services::UserId;

pub struct PostgresUserRepository {
    pool: DbPool,
}

impl PostgresUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

fn order_clause(sort: &AdminListUsersSort) -> String {
    let col = match sort.sort_by {
        AdminUsersSortBy::CreatedAt => "enriched.created_at",
        AdminUsersSortBy::TotalSpentNano => "enriched.total_spent_nano",
        AdminUsersSortBy::AgentSpentNano => "enriched.agent_spent_nano",
        AdminUsersSortBy::AgentTokenUsage => "enriched.agent_token_usage",
        AdminUsersSortBy::LastActivityAt => "enriched.last_activity_at",
        AdminUsersSortBy::AgentCount => "enriched.agent_count",
        AdminUsersSortBy::Email => "enriched.email",
        AdminUsersSortBy::Name => "enriched.name",
    };
    let order = match sort.sort_order {
        AdminUsersSortOrder::Asc => "ASC",
        AdminUsersSortOrder::Desc => "DESC",
    };
    // NULLS LAST for nullable columns so nulls don't dominate
    let nulls = match sort.sort_by {
        AdminUsersSortBy::LastActivityAt | AdminUsersSortBy::Name => " NULLS LAST",
        _ => "",
    };
    format!("{col} {order}{nulls}")
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

    async fn delete_user(&self, user_id: UserId) -> anyhow::Result<()> {
        let client = self.pool.get().await?;

        client
            .execute("DELETE FROM users WHERE id = $1", &[&user_id])
            .await?;

        Ok(())
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

    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &AdminListUsersFilter,
        sort: &AdminListUsersSort,
    ) -> anyhow::Result<(Vec<AdminUserWithStats>, u64)> {
        let client = self.pool.get().await?;

        let mut filter_clauses = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_idx = 1u32;

        if let Some(s) = filter.subscription_status.as_ref() {
            match s.as_str() {
                "none" => filter_clauses.push("enriched.subscription_status IS NULL".to_string()),
                "active" | "canceled" | "past_due" | "trialing" | "unpaid" => {
                    filter_clauses.push(format!("enriched.subscription_status = ${param_idx}"));
                    params.push(Box::new(s.to_string()));
                    param_idx += 1;
                }
                _ => {}
            }
        }

        if filter.subscription_plan_none {
            filter_clauses.push("enriched.subscription_price_id IS NULL".to_string());
        }

        if let Some(ref price_ids) = filter.subscription_plan_price_ids {
            if price_ids.is_empty() {
                // Plan requested but not found in config → return no users
                filter_clauses.push("1 = 0".to_string());
            } else {
                // Explicit ::text[] cast for PostgreSQL array binding
                filter_clauses.push(format!(
                    "enriched.subscription_price_id = ANY(${param_idx}::text[])"
                ));
                params.push(Box::new(price_ids.clone()));
                param_idx += 1;
            }
        }

        if let Some(ref search) = filter.search {
            let escaped = search
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = format!("%{escaped}%");
            filter_clauses.push(format!(
                "(enriched.email ILIKE ${param_idx} OR COALESCE(enriched.name, '') ILIKE ${param_idx})"
            ));
            params.push(Box::new(pattern));
            param_idx += 1;
        }

        let filter_sql = if filter_clauses.is_empty() {
            String::new()
        } else {
            " AND ".to_string() + &filter_clauses.join(" AND ")
        };

        let order_sql = order_clause(sort);
        let limit_param = param_idx;
        let offset_param = param_idx + 1;

        let base_query = r#"
WITH agent_counts AS (
    SELECT user_id, COUNT(*)::bigint AS agent_count
    FROM agent_instances
    WHERE status != 'deleted'
    GROUP BY user_id
),
usage_stats AS (
    SELECT
        user_id,
        (COALESCE(SUM(cost_nano_usd), 0))::bigint AS total_spent_nano,
        (COALESCE(SUM(CASE WHEN instance_id IS NOT NULL THEN cost_nano_usd ELSE 0 END), 0))::bigint AS agent_spent_nano,
        (COALESCE(SUM(CASE WHEN instance_id IS NOT NULL AND metric_key = 'llm.tokens' THEN quantity ELSE 0 END), 0))::bigint AS agent_token_usage,
        MAX(created_at) AS last_usage_at
    FROM user_usage_event
    GROUP BY user_id
),
enriched AS (
    SELECT
        u.id,
        u.email,
        u.name,
        u.avatar_url,
        u.created_at,
        u.updated_at,
        sub.status AS subscription_status,
        sub.price_id AS subscription_price_id,
        COALESCE(ac.agent_count, 0) AS agent_count,
        COALESCE(us.total_spent_nano, 0) AS total_spent_nano,
        COALESCE(us.agent_spent_nano, 0) AS agent_spent_nano,
        COALESCE(us.agent_token_usage, 0) AS agent_token_usage,
        COALESCE(us.last_usage_at, u.updated_at) AS last_activity_at
    FROM users u
    LEFT JOIN LATERAL (
        SELECT status, price_id FROM subscriptions s
        WHERE s.user_id = u.id
        ORDER BY s.updated_at DESC
        LIMIT 1
    ) sub ON true
    LEFT JOIN agent_counts ac ON u.id = ac.user_id
    LEFT JOIN usage_stats us ON u.id = us.user_id
)
SELECT id, email, name, avatar_url, created_at, updated_at,
       subscription_status, subscription_price_id, agent_count, total_spent_nano, agent_spent_nano,
       agent_token_usage, last_activity_at,
       COUNT(*) OVER() AS total_count
FROM enriched
WHERE 1=1
"#;

        let query = format!(
            "{} {} ORDER BY {} LIMIT ${} OFFSET ${}",
            base_query, filter_sql, order_sql, limit_param, offset_param,
        );

        let mut query_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = params;
        query_params.push(Box::new(limit));
        query_params.push(Box::new(offset));

        let rows = client
            .query(
                &query,
                &query_params
                    .iter()
                    .map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>(),
            )
            .await?;

        let total_count: i64 = if rows.is_empty() {
            0
        } else {
            rows[0].get("total_count")
        };

        let users = rows
            .into_iter()
            .map(|r| {
                let id: UserId = r.get("id");
                let email: String = r.get("email");
                let name: Option<String> = r.get("name");
                let avatar_url: Option<String> = r.get("avatar_url");
                let created_at: DateTime<Utc> = r.get("created_at");
                let updated_at: DateTime<Utc> = r.get("updated_at");
                AdminUserWithStats {
                    user: User {
                        id,
                        email,
                        name,
                        avatar_url,
                        created_at,
                        updated_at,
                    },
                    subscription_status: r.get("subscription_status"),
                    subscription_price_id: r.get("subscription_price_id"),
                    agent_count: r.get::<_, i64>("agent_count"),
                    total_spent_nano: r.get::<_, i64>("total_spent_nano"),
                    agent_spent_nano: r.get::<_, i64>("agent_spent_nano"),
                    agent_token_usage: r.get::<_, i64>("agent_token_usage"),
                    last_activity_at: r.get("last_activity_at"),
                }
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
