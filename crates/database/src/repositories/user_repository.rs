use crate::pool::DbPool;
use async_trait::async_trait;
use services::{
    user::ports::{LinkedOAuthAccount, OAuthProvider, User, UserRepository},
    UserId,
};

pub struct PostgresUserRepository {
    pool: DbPool,
}

impl PostgresUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn get_user(&self, user_id: UserId) -> anyhow::Result<Option<User>> {
        let client = self.pool.get().await?;
        
        let row = client
            .query_opt(
                "SELECT id, email, name, avatar_url, created_at, updated_at 
                 FROM users 
                 WHERE id = $1",
                &[&user_id],
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
        let client = self.pool.get().await?;
        
        let row = client
            .query_one(
                "INSERT INTO users (email, name, avatar_url) 
                 VALUES ($1, $2, $3) 
                 RETURNING id, email, name, avatar_url, created_at, updated_at",
                &[&email, &name, &avatar_url],
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

    async fn get_linked_accounts(&self, user_id: UserId) -> anyhow::Result<Vec<LinkedOAuthAccount>> {
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
        let client = self.pool.get().await?;
        
        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
        };

        client
            .execute(
                "INSERT INTO oauth_accounts (user_id, provider, provider_user_id) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (provider, provider_user_id) DO NOTHING",
                &[&user_id, &provider_str, &provider_user_id],
            )
            .await?;

        Ok(())
    }

    async fn find_user_by_oauth(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> anyhow::Result<Option<UserId>> {
        let client = self.pool.get().await?;
        
        let provider_str = match provider {
            OAuthProvider::Google => "google",
            OAuthProvider::Github => "github",
        };

        let row = client
            .query_opt(
                "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
                &[&provider_str, &provider_user_id],
            )
            .await?;

        Ok(row.map(|r| r.get(0)))
    }
}

