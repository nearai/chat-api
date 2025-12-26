use super::ports::{
    VpcAuthConfig, VpcCredentials, VpcCredentialsRepository, VpcCredentialsService,
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// Database keys for storing VPC credentials
const VPC_API_KEY_CONFIG_KEY: &str = "vpc_api_key";
const VPC_ORGANIZATION_ID_CONFIG_KEY: &str = "vpc_organization_id";

/// Response from VPC login endpoint
#[derive(serde::Deserialize)]
struct VpcLoginResponse {
    organization: VpcOrganization,
    api_key: String,
    #[allow(unused)]
    access_token: String,
    #[allow(unused)]
    refresh_token: String,
}

#[derive(serde::Deserialize)]
struct VpcOrganization {
    id: String,
}

/// Cached credentials with tokens
struct CachedCredentials {
    organization_id: String,
    api_key: String,
}

/// Implementation of VpcCredentialsService
pub struct VpcCredentialsServiceImpl {
    config: Option<VpcAuthConfig>,
    repository: Arc<dyn VpcCredentialsRepository>,
    cached: RwLock<Option<CachedCredentials>>,
    http_client: reqwest::Client,
    static_api_key: Option<String>,
}

impl VpcCredentialsServiceImpl {
    pub fn new(
        config: Option<VpcAuthConfig>,
        repository: Arc<dyn VpcCredentialsRepository>,
        static_api_key: Option<String>,
    ) -> Self {
        Self {
            config,
            repository,
            cached: RwLock::new(None),
            http_client: reqwest::Client::new(),
            static_api_key,
        }
    }

    /// Perform VPC authentication to obtain fresh credentials
    async fn vpc_authenticate(&self, config: &VpcAuthConfig) -> anyhow::Result<VpcLoginResponse> {
        // Generate timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Generate HMAC-SHA256 signature
        let mut mac = HmacSha256::new_from_slice(config.shared_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(timestamp.to_string().as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        tracing::info!(
            "Performing VPC authentication with client_id: {}",
            config.client_id
        );

        // Build the auth URL
        let auth_url = format!("{}/auth/vpc/login", config.base_url.trim_end_matches('/'));

        // Make authentication request
        let response = self
            .http_client
            .post(&auth_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "timestamp": timestamp,
                "signature": signature,
                "client_id": config.client_id
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("VPC authentication failed with status {}: {}", status, body);
        }

        let login_response: VpcLoginResponse = response.json().await?;
        tracing::info!(
            "VPC authentication successful, organization_id: {}",
            login_response.organization.id
        );

        Ok(login_response)
    }

    /// Load credentials from database
    async fn load_from_db(&self) -> anyhow::Result<Option<CachedCredentials>> {
        let org_id = self.repository.get(VPC_ORGANIZATION_ID_CONFIG_KEY).await?;
        let api_key = self.repository.get(VPC_API_KEY_CONFIG_KEY).await?;

        match (org_id, api_key) {
            (Some(org_id), Some(api_key)) => Ok(Some(CachedCredentials {
                organization_id: org_id,
                api_key,
            })),
            _ => Ok(None),
        }
    }

    /// Save credentials to database
    async fn save_to_db(&self, creds: &CachedCredentials) {
        if !creds.api_key.is_empty() {
            if let Err(e) = self
                .repository
                .set(VPC_API_KEY_CONFIG_KEY, &creds.api_key)
                .await
            {
                tracing::warn!("Failed to cache VPC API key: {}", e);
            }
        }

        if let Err(e) = self
            .repository
            .set(VPC_ORGANIZATION_ID_CONFIG_KEY, &creds.organization_id)
            .await
        {
            tracing::warn!("Failed to cache VPC organization ID: {}", e);
        }
    }

    /// Get or refresh credentials
    async fn get_or_refresh_credentials(
        &self,
        config: &VpcAuthConfig,
    ) -> anyhow::Result<VpcCredentials> {
        // First, try to use cached credentials if still valid
        {
            let cached = self.cached.read().await;
            if let Some(creds) = cached.as_ref() {
                return Ok(VpcCredentials {
                    organization_id: creds.organization_id.clone(),
                    api_key: creds.api_key.clone(),
                });
            }
        }

        // Need to get/refresh credentials - acquire write lock
        let mut cached = self.cached.write().await;

        // Double-check after acquiring write lock
        if let Some(creds) = cached.as_ref() {
            return Ok(VpcCredentials {
                organization_id: creds.organization_id.clone(),
                api_key: creds.api_key.clone(),
            });
        }

        // Try to load from database if not cached
        if cached.is_none() {
            if let Some(db_creds) = self.load_from_db().await? {
                *cached = Some(db_creds);
            }
        }

        // No cached credentials or refresh failed - perform full VPC auth
        tracing::info!("Performing full VPC authentication...");
        let login_response = self.vpc_authenticate(config).await?;

        let new_creds = CachedCredentials {
            organization_id: login_response.organization.id.clone(),
            api_key: login_response.api_key.clone(),
        };

        // Save to database
        self.save_to_db(&new_creds).await;

        *cached = Some(new_creds);

        Ok(VpcCredentials {
            organization_id: login_response.organization.id,
            api_key: login_response.api_key,
        })
    }
}

#[async_trait]
impl VpcCredentialsService for VpcCredentialsServiceImpl {
    async fn get_credentials(&self) -> anyhow::Result<Option<VpcCredentials>> {
        match &self.config {
            Some(config) => Ok(Some(self.get_or_refresh_credentials(config).await?)),
            None => Ok(None),
        }
    }

    async fn get_api_key(&self) -> anyhow::Result<String> {
        if let Some(config) = &self.config {
            // Ensure we have valid credentials (refresh/re-auth if needed)
            let creds = self.get_or_refresh_credentials(config).await?;
            Ok(creds.api_key)
        } else {
            // Not configured for VPC, use static key
            Ok(self.static_api_key.clone().unwrap_or_default())
        }
    }

    fn is_configured(&self) -> bool {
        self.config.is_some()
    }
}

/// Initialize VPC credentials and get the API key
/// This is called during startup to ensure we have a valid API key
pub async fn initialize_vpc_credentials(
    config: Option<VpcAuthConfig>,
    repository: Arc<dyn VpcCredentialsRepository>,
    static_api_key: Option<String>,
) -> anyhow::Result<Arc<dyn VpcCredentialsService>> {
    let service = Arc::new(VpcCredentialsServiceImpl::new(
        config.clone(),
        repository.clone(),
        static_api_key,
    ));

    // If VPC is configured, ensure we have valid credentials
    if config.is_some() {
        // Also ensure we can get valid credentials (this will refresh if needed)
        let _ = service.get_credentials().await?;
        tracing::info!("VPC credentials initialized");
    }

    Ok(service)
}

/// No-op VPC repository for non-VPC mode
pub struct NoOpVpcRepository;

#[async_trait]
impl VpcCredentialsRepository for NoOpVpcRepository {
    async fn get(&self, _key: &str) -> anyhow::Result<Option<String>> {
        Ok(None)
    }

    async fn set(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Test helpers for VPC credentials
pub mod test_helpers {
    use super::*;

    /// Mock VPC credentials service for tests
    pub struct MockVpcCredentialsService {
        credentials: Option<VpcCredentials>,
    }

    impl MockVpcCredentialsService {
        /// Create a mock service that returns no credentials (VPC not configured)
        pub fn not_configured() -> Self {
            Self { credentials: None }
        }

        /// Create a mock service that returns the given credentials
        pub fn with_credentials(credentials: VpcCredentials) -> Self {
            Self {
                credentials: Some(credentials),
            }
        }
    }

    #[async_trait]
    impl VpcCredentialsService for MockVpcCredentialsService {
        async fn get_credentials(&self) -> anyhow::Result<Option<VpcCredentials>> {
            Ok(self.credentials.clone())
        }

        async fn get_api_key(&self) -> anyhow::Result<String> {
            Ok("mock-api-key".to_string())
        }

        fn is_configured(&self) -> bool {
            self.credentials.is_some()
        }
    }
}
