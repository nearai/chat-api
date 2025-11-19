pub mod migrations;
pub mod pool;
pub mod repositories;

pub use pool::{create_pool, DbPool};
pub use repositories::{
    PostgresConversationRepository, PostgresOAuthRepository, PostgresSessionRepository,
    PostgresUserRepository, PostgresUserSettingsRepository,
};

use anyhow::Result;
use std::sync::Arc;

/// Database service combining all repositories
pub struct Database {
    pool: DbPool,
    user_repository: Arc<PostgresUserRepository>,
    session_repository: Arc<PostgresSessionRepository>,
    oauth_repository: Arc<PostgresOAuthRepository>,
    conversation_repository: Arc<PostgresConversationRepository>,
    user_settings_repository: Arc<PostgresUserSettingsRepository>,
}

impl Database {
    /// Create a new database service from a connection pool
    pub fn new(pool: DbPool) -> Self {
        let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));
        let session_repository = Arc::new(PostgresSessionRepository::new(pool.clone()));
        let oauth_repository = Arc::new(PostgresOAuthRepository::new(pool.clone()));
        let conversation_repository = Arc::new(PostgresConversationRepository::new(pool.clone()));
        let user_settings_repository = Arc::new(PostgresUserSettingsRepository::new(pool.clone()));

        Self {
            pool,
            user_repository,
            session_repository,
            oauth_repository,
            conversation_repository,
            user_settings_repository,
        }
    }

    /// Create a new database service from configuration
    pub async fn from_config(config: &config::DatabaseConfig) -> Result<Self> {
        let pool = create_pool(config).await?;
        Ok(Self::new(pool))
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        migrations::run(&self.pool).await
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// Get the user repository
    pub fn user_repository(&self) -> Arc<PostgresUserRepository> {
        self.user_repository.clone()
    }

    /// Get the session repository
    pub fn session_repository(&self) -> Arc<PostgresSessionRepository> {
        self.session_repository.clone()
    }

    /// Get the OAuth repository
    pub fn oauth_repository(&self) -> Arc<PostgresOAuthRepository> {
        self.oauth_repository.clone()
    }

    /// Get the conversation repository
    pub fn conversation_repository(&self) -> Arc<PostgresConversationRepository> {
        self.conversation_repository.clone()
    }

    /// Get the user settings repository
    pub fn user_settings_repository(&self) -> Arc<PostgresUserSettingsRepository> {
        self.user_settings_repository.clone()
    }
}
