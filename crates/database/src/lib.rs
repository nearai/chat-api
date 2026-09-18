pub mod cluster_manager;
pub mod encryption;
pub mod field_encryption;
pub mod migrations;
pub mod patroni_discovery;
pub mod pool;
pub mod repositories;

pub use pool::DbPool;
pub use repositories::{
    PostgresAgentRepository, PostgresAmlReportRepository, PostgresAnalyticsRepository,
    PostgresAppConfigRepository, PostgresBiMetricsRepository, PostgresConversationRepository,
    PostgresConversationShareRepository, PostgresCreditsRepository,
    PostgresEmailVerificationChallengeRepository, PostgresFileRepository, PostgresModelRepository,
    PostgresNearNonceRepository, PostgresOAuthRepository, PostgresPaymentWebhookRepository,
    PostgresSessionRepository, PostgresStripeCustomerRepository, PostgresSubscriptionRepository,
    PostgresSystemConfigsRepository, PostgresUserRepository, PostgresUserSettingsRepository,
    PostgresUserUsageRepository,
};

use crate::pool::{create_pool_with_native_tls, create_pool_with_rustls};
use anyhow::Result;
use cluster_manager::{ClusterManager, DatabaseConfig as ClusterDbConfig, ReadPreference};
use deadpool_postgres::Runtime;
use patroni_discovery::PatroniDiscovery;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Database service combining all repositories
pub struct Database {
    pool: DbPool,
    user_repository: Arc<PostgresUserRepository>,
    session_repository: Arc<PostgresSessionRepository>,
    oauth_repository: Arc<PostgresOAuthRepository>,
    conversation_repository: Arc<PostgresConversationRepository>,
    conversation_share_repository: Arc<PostgresConversationShareRepository>,
    file_repository: Arc<PostgresFileRepository>,
    user_settings_repository: Arc<PostgresUserSettingsRepository>,
    system_configs_repository: Arc<PostgresSystemConfigsRepository>,
    app_config_repository: Arc<PostgresAppConfigRepository>,
    near_nonce_repository: Arc<PostgresNearNonceRepository>,
    analytics_repository: Arc<PostgresAnalyticsRepository>,
    email_verification_challenge_repository: Arc<PostgresEmailVerificationChallengeRepository>,
    user_usage_repository: Arc<PostgresUserUsageRepository>,
    model_repository: Arc<PostgresModelRepository>,
    credits_repository: Arc<PostgresCreditsRepository>,
    stripe_customer_repository: Arc<PostgresStripeCustomerRepository>,
    subscription_repository: Arc<PostgresSubscriptionRepository>,
    payment_webhook_repository: Arc<PostgresPaymentWebhookRepository>,
    agent_repository: Arc<PostgresAgentRepository>,
    bi_metrics_repository: Arc<PostgresBiMetricsRepository>,
    aml_report_repository: Arc<PostgresAmlReportRepository>,
    cluster_manager: Option<Arc<ClusterManager>>,
}

impl Database {
    /// Create a new database service from a connection pool
    pub fn new(pool: DbPool) -> Self {
        let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));
        let session_repository = Arc::new(PostgresSessionRepository::new(pool.clone()));
        let oauth_repository = Arc::new(PostgresOAuthRepository::new(pool.clone()));
        let conversation_repository = Arc::new(PostgresConversationRepository::new(pool.clone()));
        let conversation_share_repository =
            Arc::new(PostgresConversationShareRepository::new(pool.clone()));
        let file_repository = Arc::new(PostgresFileRepository::new(pool.clone()));
        let user_settings_repository = Arc::new(PostgresUserSettingsRepository::new(pool.clone()));
        let system_configs_repository =
            Arc::new(PostgresSystemConfigsRepository::new(pool.clone()));
        let app_config_repository = Arc::new(PostgresAppConfigRepository::new(pool.clone()));
        let near_nonce_repository = Arc::new(PostgresNearNonceRepository::new(pool.clone()));
        let analytics_repository = Arc::new(PostgresAnalyticsRepository::new(pool.clone()));
        let email_verification_challenge_repository = Arc::new(
            PostgresEmailVerificationChallengeRepository::new(pool.clone()),
        );
        let user_usage_repository = Arc::new(PostgresUserUsageRepository::new(pool.clone()));
        let model_repository = Arc::new(PostgresModelRepository::new(pool.clone()));
        let credits_repository = Arc::new(PostgresCreditsRepository::new(pool.clone()));
        let stripe_customer_repository =
            Arc::new(PostgresStripeCustomerRepository::new(pool.clone()));
        let subscription_repository = Arc::new(PostgresSubscriptionRepository::new(pool.clone()));
        let payment_webhook_repository =
            Arc::new(PostgresPaymentWebhookRepository::new(pool.clone()));
        let agent_repository = Arc::new(PostgresAgentRepository::new(pool.clone()));
        let bi_metrics_repository = Arc::new(PostgresBiMetricsRepository::new(pool.clone()));
        let aml_report_repository = Arc::new(PostgresAmlReportRepository::new(pool.clone()));

        Self {
            pool,
            user_repository,
            session_repository,
            oauth_repository,
            conversation_repository,
            conversation_share_repository,
            file_repository,
            user_settings_repository,
            system_configs_repository,
            app_config_repository,
            near_nonce_repository,
            analytics_repository,
            email_verification_challenge_repository,
            user_usage_repository,
            model_repository,
            credits_repository,
            stripe_customer_repository,
            subscription_repository,
            payment_webhook_repository,
            agent_repository,
            bi_metrics_repository,
            aml_report_repository,
            cluster_manager: None,
        }
    }

    /// Create a database service using direct connectivity, a simple local
    /// connection, or Patroni discovery.
    pub async fn from_config(config: &config::DatabaseConfig) -> Result<Self> {
        // If mock flag is set, use mock database
        if config.mock {
            info!("Using mock database for testing (not implemented yet, falling back to simple postgres)");
            // return create_mock_database().await;
        }

        if config.connection_mode == config::DatabaseConnectionMode::Direct {
            info!("Initializing database with a direct PostgreSQL endpoint");
            return Self::from_direct_postgres_config(config).await;
        }

        // For tests or simple setup, use simple postgres connection without Patroni
        if config.primary_app_id.is_empty() || config.primary_app_id == "postgres-test" {
            info!("Using simple PostgreSQL connection");
            return Self::from_simple_postgres_config(config).await;
        }

        info!("Initializing database with Patroni discovery");
        debug!("Primary app ID: {}", config.primary_app_id);
        info!("Refresh interval: {} seconds", config.refresh_interval);

        // Create Patroni discovery
        let discovery = Arc::new(PatroniDiscovery::new(
            config.primary_app_id.clone(),
            config.gateway_subdomain.clone(),
            config.refresh_interval,
        ));

        // Perform initial cluster discovery
        info!("Performing initial cluster discovery...");
        discovery.update_cluster_state().await?;

        if let Some(leader) = discovery.get_leader().await {
            debug!("Found leader: {} at {}", leader.name, leader.host);
        } else {
            return Err(anyhow::anyhow!(
                "No leader found in cluster during initialization"
            ));
        }

        let replicas = discovery.get_replicas().await;
        info!("Found {} replicas", replicas.len());

        // Start background refresh task
        info!("Starting cluster discovery refresh task");
        discovery.clone().start_refresh_task();

        // Create cluster manager
        let db_config = ClusterDbConfig {
            database: config.database.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            max_write_connections: config.max_connections,
            max_read_connections: config.max_connections,
            tls_enabled: config.tls_enabled,
            tls_ca_cert_path: config.tls_ca_cert_path.clone(),
        };

        let cluster_manager = Arc::new(ClusterManager::new(
            discovery,
            db_config,
            ReadPreference::LeastLag,
            Some(10000), // 10 second max lag for replicas
        ));

        // Initialize cluster manager (creates initial pools)
        info!("Initializing cluster manager...");
        cluster_manager.initialize().await?;

        // Start background tasks for leader failover handling
        info!("Starting cluster manager background tasks");
        cluster_manager.clone().start_background_tasks();

        // Shared write-pool handle for the repositories; clones of it follow
        // the leader across failovers because ClusterManager installs new
        // pools into this same handle.
        let pool = cluster_manager.write_pool();

        info!("Database initialization with Patroni discovery complete");

        let mut db = Self::new(pool);
        db.cluster_manager = Some(cluster_manager);
        Ok(db)
    }

    /// Create database connection for testing without Patroni
    async fn from_simple_postgres_config(config: &config::DatabaseConfig) -> Result<Self> {
        use tokio_postgres::NoTls;

        let mut pg_config = deadpool_postgres::Config::new();
        pg_config.host = Some(
            config
                .host
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
        );
        pg_config.port = Some(config.port);
        pg_config.dbname = Some(config.database.clone());
        pg_config.user = Some(config.username.clone());
        pg_config.password = Some(config.password.clone());

        let pool = if config.tls_enabled {
            create_pool_with_native_tls(pg_config, true)?
        } else {
            pg_config.create_pool(Some(Runtime::Tokio1), NoTls)?
        };

        Ok(Self::new(DbPool::new(pool)))
    }

    async fn from_direct_postgres_config(config: &config::DatabaseConfig) -> Result<Self> {
        let pg_config = direct_pool_config(config)?;
        let pool = create_pool_with_rustls(pg_config, config.tls_ca_cert_path.as_deref())?;
        Ok(Self::new(DbPool::new(pool)))
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        migrations::run(&self.pool).await
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// Get a reference to the cluster manager (if using Patroni)
    pub fn cluster_manager(&self) -> Option<&Arc<ClusterManager>> {
        self.cluster_manager.as_ref()
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

    /// Get the conversation share repository
    pub fn conversation_share_repository(&self) -> Arc<PostgresConversationShareRepository> {
        self.conversation_share_repository.clone()
    }

    /// Get the file repository
    pub fn file_repository(&self) -> Arc<PostgresFileRepository> {
        self.file_repository.clone()
    }

    /// Get the user settings repository
    pub fn user_settings_repository(&self) -> Arc<PostgresUserSettingsRepository> {
        self.user_settings_repository.clone()
    }

    /// Get the app config repository
    pub fn app_config_repository(&self) -> Arc<PostgresAppConfigRepository> {
        self.app_config_repository.clone()
    }

    /// Get the NEAR nonce repository
    pub fn near_nonce_repository(&self) -> Arc<PostgresNearNonceRepository> {
        self.near_nonce_repository.clone()
    }

    /// Get the analytics repository
    pub fn analytics_repository(&self) -> Arc<PostgresAnalyticsRepository> {
        self.analytics_repository.clone()
    }

    /// Get the email verification challenge repository
    pub fn email_verification_challenge_repository(
        &self,
    ) -> Arc<PostgresEmailVerificationChallengeRepository> {
        self.email_verification_challenge_repository.clone()
    }

    /// Get the user usage repository
    pub fn user_usage_repository(&self) -> Arc<PostgresUserUsageRepository> {
        self.user_usage_repository.clone()
    }

    /// Get the model settings repository
    pub fn model_repository(&self) -> Arc<PostgresModelRepository> {
        self.model_repository.clone()
    }

    /// Get the credits repository
    pub fn credits_repository(&self) -> Arc<PostgresCreditsRepository> {
        self.credits_repository.clone()
    }

    /// Get the system configs repository
    pub fn system_configs_repository(&self) -> Arc<PostgresSystemConfigsRepository> {
        self.system_configs_repository.clone()
    }

    /// Get the Stripe customer repository
    pub fn stripe_customer_repository(&self) -> Arc<PostgresStripeCustomerRepository> {
        self.stripe_customer_repository.clone()
    }

    /// Get the subscription repository
    pub fn subscription_repository(&self) -> Arc<PostgresSubscriptionRepository> {
        self.subscription_repository.clone()
    }

    /// Get the payment webhook repository
    pub fn payment_webhook_repository(&self) -> Arc<PostgresPaymentWebhookRepository> {
        self.payment_webhook_repository.clone()
    }

    /// Get the agent repository
    pub fn agent_repository(&self) -> Arc<PostgresAgentRepository> {
        self.agent_repository.clone()
    }

    /// Get the BI metrics repository
    pub fn bi_metrics_repository(&self) -> Arc<PostgresBiMetricsRepository> {
        self.bi_metrics_repository.clone()
    }

    /// Get the AML audit repository
    pub fn aml_report_repository(&self) -> Arc<PostgresAmlReportRepository> {
        self.aml_report_repository.clone()
    }
}

fn direct_pool_config(config: &config::DatabaseConfig) -> Result<deadpool_postgres::Config> {
    let host = config
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow::anyhow!("DATABASE_HOST is required in direct mode"))?;
    anyhow::ensure!(
        config.max_connections > 0,
        "DATABASE_MAX_CONNECTIONS must be positive"
    );
    anyhow::ensure!(
        config.tls_enabled,
        "Direct database mode requires DATABASE_TLS_ENABLED=true"
    );
    anyhow::ensure!(
        !config.database.trim().is_empty(),
        "DATABASE_NAME cannot be empty in direct mode"
    );
    anyhow::ensure!(
        !config.username.trim().is_empty(),
        "DATABASE_USER cannot be empty in direct mode"
    );
    anyhow::ensure!(
        !config.password.is_empty(),
        "DATABASE_PASSWORD cannot be empty in direct mode"
    );

    let mut pg = deadpool_postgres::Config::new();
    pg.host = Some(host.to_owned());
    pg.port = Some(config.port);
    pg.dbname = Some(config.database.clone());
    pg.user = Some(config.username.clone());
    pg.password = Some(config.password.clone());
    pg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: config.max_connections as usize,
        timeouts: deadpool_postgres::Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(10)),
            recycle: Some(Duration::from_secs(5)),
        },
        queue_mode: deadpool::managed::QueueMode::Fifo,
    });
    pg.manager = Some(deadpool_postgres::ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Verified,
    });
    pg.ssl_mode = Some(deadpool_postgres::SslMode::Require);
    pg.connect_timeout = Some(Duration::from_secs(10));
    Ok(pg)
}

#[cfg(test)]
mod direct_connection_tests {
    use super::*;

    fn config() -> config::DatabaseConfig {
        config::DatabaseConfig {
            connection_mode: config::DatabaseConnectionMode::Direct,
            primary_app_id: String::new(),
            gateway_subdomain: String::new(),
            host: Some("example.us-east-1.rds.amazonaws.com".into()),
            port: 5432,
            database: "chat_api".into(),
            username: "application".into(),
            password: "test-only".into(),
            max_connections: 7,
            tls_enabled: true,
            tls_ca_cert_path: None,
            refresh_interval: 30,
            mock: false,
        }
    }

    #[test]
    fn direct_pool_requires_tls_and_honors_connection_settings() {
        let source = config();
        let pool = direct_pool_config(&source).unwrap();
        assert_eq!(pool.host, source.host);
        assert_eq!(pool.port, Some(5432));
        assert_eq!(pool.dbname.as_deref(), Some("chat_api"));
        assert_eq!(pool.user.as_deref(), Some("application"));
        let settings = pool.pool.unwrap();
        assert_eq!(settings.max_size, 7);
        assert_eq!(settings.timeouts.wait, Some(Duration::from_secs(5)));
        assert_eq!(settings.timeouts.create, Some(Duration::from_secs(10)));
        assert_eq!(settings.timeouts.recycle, Some(Duration::from_secs(5)));
        assert!(matches!(
            pool.manager.unwrap().recycling_method,
            deadpool_postgres::RecyclingMethod::Verified
        ));
        assert!(matches!(
            pool.ssl_mode,
            Some(deadpool_postgres::SslMode::Require)
        ));
        assert_eq!(pool.connect_timeout, Some(Duration::from_secs(10)));
    }

    #[test]
    fn direct_host_is_normalized_and_identifiers_are_validated() {
        let mut source = config();
        source.host = Some(" \texample.us-east-1.rds.amazonaws.com\n".into());
        assert_eq!(
            direct_pool_config(&source).unwrap().host.as_deref(),
            Some("example.us-east-1.rds.amazonaws.com")
        );
        for value in ["", " \t\n"] {
            source.database = value.into();
            assert!(direct_pool_config(&source)
                .unwrap_err()
                .to_string()
                .contains("DATABASE_NAME"));
            source.database = "chat_api".into();
            source.username = value.into();
            assert!(direct_pool_config(&source)
                .unwrap_err()
                .to_string()
                .contains("DATABASE_USER"));
            source.username = "application".into();
        }
        source.database = " database ".into();
        source.username = " user ".into();
        let pool = direct_pool_config(&source).unwrap();
        assert_eq!(pool.dbname, source.database.into());
        assert_eq!(pool.user, source.username.into());
    }

    #[test]
    fn invalid_direct_configuration_fails_closed() {
        let mut source = config();
        source.host = None;
        assert!(direct_pool_config(&source).is_err());
        source.host = Some(" ".into());
        assert!(direct_pool_config(&source).is_err());
        source.host = Some("localhost".into());
        source.max_connections = 0;
        assert!(direct_pool_config(&source).is_err());
        source.max_connections = 1;
        source.tls_enabled = false;
        source.tls_ca_cert_path = Some("ca.pem".into());
        assert!(direct_pool_config(&source).is_err());
        source.tls_enabled = true;
        source.password.clear();
        assert!(direct_pool_config(&source).is_err());
    }

    #[tokio::test]
    async fn direct_pool_creation_times_out_if_server_stalls_after_tcp_accept() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut source = config();
        source.host = Some("127.0.0.1".into());
        source.port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut pg = direct_pool_config(&source).unwrap();
        pg.pool.as_mut().unwrap().timeouts.create = Some(Duration::from_millis(100));
        let pool = crate::pool::create_pool_with_rustls(pg, None).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(3), pool.get()).await;
        server.abort();
        assert!(matches!(
            result.unwrap(),
            Err(deadpool_postgres::PoolError::Timeout(
                deadpool::managed::TimeoutType::Create
            ))
        ));
    }

    #[tokio::test]
    async fn direct_mode_bypasses_patroni_and_requires_configured_ca() {
        let mut source = config();
        source.tls_ca_cert_path = Some("/nonexistent-chat-api-test-ca.pem".into());
        let error = Database::from_config(&source).await.err().unwrap();
        assert!(error
            .to_string()
            .contains("Failed to open certificate file"));
        source.tls_ca_cert_path = None;
        source.tls_enabled = false;
        for host in [
            "example.us-east-1.rds.amazonaws.com",
            "localhost",
            "127.0.0.1",
        ] {
            source.host = Some(host.into());
            let error = Database::from_config(&source).await.err().unwrap();
            assert!(error.to_string().contains("DATABASE_TLS_ENABLED=true"));
        }
    }
}
