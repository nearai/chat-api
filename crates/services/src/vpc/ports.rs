use async_trait::async_trait;

/// VPC credentials for making authenticated API calls to Cloud API
#[derive(Clone, Debug)]
pub struct VpcCredentials {
    pub organization_id: String,
    pub api_key: String,
}

/// Repository for storing VPC credentials
#[async_trait]
pub trait VpcCredentialsRepository: Send + Sync {
    /// Get a credential value by key
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>>;

    /// Set a credential value
    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;

    /// Delete a credential value by key
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

/// Configuration for VPC authentication
#[derive(Clone)]
pub struct VpcAuthConfig {
    pub client_id: String,
    pub shared_secret: String,
    pub base_url: String,
}

/// Service for managing VPC credentials
#[async_trait]
pub trait VpcCredentialsService: Send + Sync {
    /// Get valid VPC credentials, refreshing tokens if necessary
    /// Returns None if VPC is not configured
    async fn get_credentials(&self) -> anyhow::Result<Option<VpcCredentials>>;

    /// Get the current API key (either static or from VPC auth)
    async fn get_api_key(&self) -> anyhow::Result<String>;

    /// Revoke the stored API key (DB and in-memory cache)
    /// This will request a new API key from the VPC in next request.
    async fn revoke(&self) -> anyhow::Result<()>;

    /// Check if VPC is configured
    fn is_configured(&self) -> bool;
}
