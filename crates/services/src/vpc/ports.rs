use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// VPC (Virtual Private Cloud) metadata included in attestation reports
/// This information is helpful to identify the VPC server and this VPC node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcInfo {
    /// VPC server app ID
    pub vpc_server_app_id: Option<String>,
    /// VPC hostname of this node
    pub vpc_hostname: Option<String>,
}

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
    /// Get cached credentials, using VPC login on a miss only when configured.
    /// Returns None for a cache miss without VPC login; static keys have no
    /// associated organization metadata here.
    async fn get_credentials(&self) -> anyhow::Result<Option<VpcCredentials>>;

    /// Get the cached API key, or the static key on a miss without VPC login.
    async fn get_api_key(&self) -> anyhow::Result<String>;

    /// Revoke the stored API key (DB and in-memory cache)
    /// The next request uses static fallback when VPC login is disabled.
    /// Other processes must separately clear/reload their in-memory caches.
    async fn revoke_credentials(&self) -> anyhow::Result<()>;

    /// Check if VPC is configured
    fn is_configured(&self) -> bool;
}
