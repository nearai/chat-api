pub mod cluster_manager;
pub mod migrations;
pub mod patroni_discovery;
pub mod pool;
pub mod repositories;

pub use pool::DbPool;
pub use repositories::{
    PostgresAnalyticsRepository, PostgresAppConfigRepository, PostgresAuditRepository,
    PostgresConversationRepository, PostgresDomainRepository, PostgresFileRepository,
    PostgresModelRepository, PostgresNearNonceRepository, PostgresOAuthRepository,
    PostgresOrganizationRepository, PostgresPermissionRepository, PostgresRoleRepository,
    PostgresSamlAuthStateRepository, PostgresSamlIdpConfigRepository, PostgresSessionRepository,
    PostgresSystemConfigsRepository, PostgresUserRepository, PostgresUserSettingsRepository,
    PostgresWorkspaceRepository,
};

use crate::pool::create_pool_with_native_tls;
use anyhow::Result;
use cluster_manager::{ClusterManager, DatabaseConfig as ClusterDbConfig, ReadPreference};
use deadpool_postgres::Runtime;
use patroni_discovery::PatroniDiscovery;
use std::sync::Arc;
use tracing::{debug, info};

/// Database service combining all repositories
pub struct Database {
    pool: DbPool,
    user_repository: Arc<PostgresUserRepository>,
    session_repository: Arc<PostgresSessionRepository>,
    oauth_repository: Arc<PostgresOAuthRepository>,
    conversation_repository: Arc<PostgresConversationRepository>,
    file_repository: Arc<PostgresFileRepository>,
    user_settings_repository: Arc<PostgresUserSettingsRepository>,
    system_configs_repository: Arc<PostgresSystemConfigsRepository>,
    app_config_repository: Arc<PostgresAppConfigRepository>,
    near_nonce_repository: Arc<PostgresNearNonceRepository>,
    analytics_repository: Arc<PostgresAnalyticsRepository>,
    model_repository: Arc<PostgresModelRepository>,
    cluster_manager: Option<Arc<ClusterManager>>,
    // Enterprise repositories
    organization_repository: Arc<PostgresOrganizationRepository>,
    workspace_repository: Arc<PostgresWorkspaceRepository>,
    permission_repository: Arc<PostgresPermissionRepository>,
    role_repository: Arc<PostgresRoleRepository>,
    audit_repository: Arc<PostgresAuditRepository>,
    saml_idp_config_repository: Arc<PostgresSamlIdpConfigRepository>,
    saml_auth_state_repository: Arc<PostgresSamlAuthStateRepository>,
    domain_repository: Arc<PostgresDomainRepository>,
}

impl Database {
    /// Create a new database service from a connection pool
    pub fn new(pool: DbPool) -> Self {
        let user_repository = Arc::new(PostgresUserRepository::new(pool.clone()));
        let session_repository = Arc::new(PostgresSessionRepository::new(pool.clone()));
        let oauth_repository = Arc::new(PostgresOAuthRepository::new(pool.clone()));
        let conversation_repository = Arc::new(PostgresConversationRepository::new(pool.clone()));
        let file_repository = Arc::new(PostgresFileRepository::new(pool.clone()));
        let user_settings_repository = Arc::new(PostgresUserSettingsRepository::new(pool.clone()));
        let system_configs_repository =
            Arc::new(PostgresSystemConfigsRepository::new(pool.clone()));
        let app_config_repository = Arc::new(PostgresAppConfigRepository::new(pool.clone()));
        let near_nonce_repository = Arc::new(PostgresNearNonceRepository::new(pool.clone()));
        let analytics_repository = Arc::new(PostgresAnalyticsRepository::new(pool.clone()));
        let model_repository = Arc::new(PostgresModelRepository::new(pool.clone()));

        // Enterprise repositories
        let organization_repository = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
        let workspace_repository = Arc::new(PostgresWorkspaceRepository::new(pool.clone()));
        let permission_repository = Arc::new(PostgresPermissionRepository::new(pool.clone()));
        let role_repository = Arc::new(PostgresRoleRepository::new(pool.clone()));
        let audit_repository = Arc::new(PostgresAuditRepository::new(pool.clone()));
        let saml_idp_config_repository =
            Arc::new(PostgresSamlIdpConfigRepository::new(pool.clone()));
        let saml_auth_state_repository =
            Arc::new(PostgresSamlAuthStateRepository::new(pool.clone()));
        let domain_repository = Arc::new(PostgresDomainRepository::new(pool.clone()));

        Self {
            pool,
            user_repository,
            session_repository,
            oauth_repository,
            conversation_repository,
            file_repository,
            user_settings_repository,
            system_configs_repository,
            app_config_repository,
            near_nonce_repository,
            analytics_repository,
            model_repository,
            cluster_manager: None,
            organization_repository,
            workspace_repository,
            permission_repository,
            role_repository,
            audit_repository,
            saml_idp_config_repository,
            saml_auth_state_repository,
            domain_repository,
        }
    }

    /// Create a new database service from configuration
    pub async fn from_config(config: &config::DatabaseConfig) -> Result<Self> {
        // If mock flag is set, use mock database
        if config.mock {
            info!("Using mock database for testing (not implemented yet, falling back to simple postgres)");
            // return create_mock_database().await;
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

        // Get write pool to use for repositories
        let pool = cluster_manager.get_write_pool().await?;

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

    /// Get the model settings repository
    pub fn model_repository(&self) -> Arc<PostgresModelRepository> {
        self.model_repository.clone()
    }

    /// Get the system configs repository
    pub fn system_configs_repository(&self) -> Arc<PostgresSystemConfigsRepository> {
        self.system_configs_repository.clone()
    }

    /// Get the organization repository
    pub fn organization_repository(&self) -> Arc<PostgresOrganizationRepository> {
        self.organization_repository.clone()
    }

    /// Get the workspace repository
    pub fn workspace_repository(&self) -> Arc<PostgresWorkspaceRepository> {
        self.workspace_repository.clone()
    }

    /// Get the permission repository
    pub fn permission_repository(&self) -> Arc<PostgresPermissionRepository> {
        self.permission_repository.clone()
    }

    /// Get the role repository
    pub fn role_repository(&self) -> Arc<PostgresRoleRepository> {
        self.role_repository.clone()
    }

    /// Get the audit repository
    pub fn audit_repository(&self) -> Arc<PostgresAuditRepository> {
        self.audit_repository.clone()
    }

    /// Get the SAML IdP config repository
    pub fn saml_idp_config_repository(&self) -> Arc<PostgresSamlIdpConfigRepository> {
        self.saml_idp_config_repository.clone()
    }

    /// Get the SAML auth state repository
    pub fn saml_auth_state_repository(&self) -> Arc<PostgresSamlAuthStateRepository> {
        self.saml_auth_state_repository.clone()
    }

    /// Get the domain repository
    pub fn domain_repository(&self) -> Arc<PostgresDomainRepository> {
        self.domain_repository.clone()
    }
}
