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
const VPC_REFRESH_TOKEN_CONFIG_KEY: &str = "vpc_refresh_token";
const VPC_ORGANIZATION_ID_CONFIG_KEY: &str = "vpc_organization_id";

/// Response from VPC login endpoint
#[derive(serde::Deserialize)]
struct VpcLoginResponse {
    api_key: String,
    access_token: String,
    refresh_token: String,
    organization: VpcOrganization,
}

#[derive(serde::Deserialize)]
struct VpcOrganization {
    id: String,
}

/// Response from access token refresh endpoint
#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    refresh_token: String,
}

/// Cached credentials with tokens
struct CachedCredentials {
    access_token: String,
    access_token_created_at: std::time::Instant,
    refresh_token: String,
    organization_id: String,
}

/// How long an access token is valid (refresh proactively before expiry)
const ACCESS_TOKEN_REFRESH_BEFORE_SECS: u64 = 50 * 60; // Refresh if older than 50 minutes

/// Implementation of VpcCredentialsService
pub struct VpcCredentialsServiceImpl {
    config: Option<VpcAuthConfig>,
    repository: Arc<dyn VpcCredentialsRepository>,
    cached: RwLock<Option<CachedCredentials>>,
    http_client: reqwest::Client,
}

impl VpcCredentialsServiceImpl {
    pub fn new(
        config: Option<VpcAuthConfig>,
        repository: Arc<dyn VpcCredentialsRepository>,
    ) -> Self {
        Self {
            config,
            repository,
            cached: RwLock::new(None),
            http_client: reqwest::Client::new(),
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

    /// Refresh access token using refresh token
    async fn refresh_access_token(
        &self,
        config: &VpcAuthConfig,
        refresh_token: &str,
    ) -> anyhow::Result<AccessTokenResponse> {
        let url = format!(
            "{}/users/me/access-tokens",
            config.base_url.trim_end_matches('/')
        );

        tracing::debug!("Refreshing access token...");

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", refresh_token))
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            anyhow::bail!("Refresh token expired");
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Token refresh failed with status {}: {}", status, body);
        }

        let token_response: AccessTokenResponse = response.json().await?;
        tracing::info!("Access token refreshed successfully");

        Ok(token_response)
    }

    /// Load credentials from database
    async fn load_from_db(&self) -> anyhow::Result<Option<CachedCredentials>> {
        let refresh_token = self.repository.get(VPC_REFRESH_TOKEN_CONFIG_KEY).await?;
        let org_id = self.repository.get(VPC_ORGANIZATION_ID_CONFIG_KEY).await?;

        match (refresh_token, org_id) {
            (Some(refresh_token), Some(org_id)) => Ok(Some(CachedCredentials {
                access_token: String::new(),                        // Will be refreshed
                access_token_created_at: std::time::Instant::now(), // Will be updated on refresh
                refresh_token,
                organization_id: org_id,
            })),
            _ => Ok(None),
        }
    }

    /// Save credentials to database
    async fn save_to_db(&self, creds: &CachedCredentials, api_key: Option<&str>) {
        if let Some(api_key) = api_key {
            if let Err(e) = self.repository.set(VPC_API_KEY_CONFIG_KEY, api_key).await {
                tracing::warn!("Failed to cache VPC API key: {}", e);
            }
        }

        if let Err(e) = self
            .repository
            .set(VPC_REFRESH_TOKEN_CONFIG_KEY, &creds.refresh_token)
            .await
        {
            tracing::warn!("Failed to cache VPC refresh token: {}", e);
        }

        if let Err(e) = self
            .repository
            .set(VPC_ORGANIZATION_ID_CONFIG_KEY, &creds.organization_id)
            .await
        {
            tracing::warn!("Failed to cache VPC organization ID: {}", e);
        }
    }

    /// Check if cached access token is still valid
    fn is_access_token_valid(creds: &CachedCredentials) -> bool {
        if creds.access_token.is_empty() {
            return false;
        }
        // Refresh proactively if the token is older than 50 minutes
        creds.access_token_created_at.elapsed().as_secs() < ACCESS_TOKEN_REFRESH_BEFORE_SECS
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
                if Self::is_access_token_valid(creds) {
                    return Ok(VpcCredentials {
                        access_token: creds.access_token.clone(),
                        organization_id: creds.organization_id.clone(),
                    });
                }
            }
        }

        // Need to get/refresh credentials - acquire write lock
        let mut cached = self.cached.write().await;

        // Double-check after acquiring write lock
        if let Some(creds) = cached.as_ref() {
            if Self::is_access_token_valid(creds) {
                return Ok(VpcCredentials {
                    access_token: creds.access_token.clone(),
                    organization_id: creds.organization_id.clone(),
                });
            }
        }

        // Try to load from database if not cached
        if cached.is_none() {
            if let Some(db_creds) = self.load_from_db().await? {
                *cached = Some(db_creds);
            }
        }

        // If we have a refresh token, try to refresh
        if let Some(creds) = cached.as_mut() {
            match self
                .refresh_access_token(config, &creds.refresh_token)
                .await
            {
                Ok(token_response) => {
                    creds.access_token = token_response.access_token.clone();
                    creds.access_token_created_at = std::time::Instant::now();
                    creds.refresh_token = token_response.refresh_token.clone();

                    // Update refresh token in database (it rotates)
                    self.save_to_db(creds, None).await;

                    return Ok(VpcCredentials {
                        access_token: token_response.access_token,
                        organization_id: creds.organization_id.clone(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to refresh access token, will re-authenticate: {}",
                        e
                    );
                    // Clear cached to force re-auth
                    *cached = None;
                }
            }
        }

        // No cached credentials or refresh failed - perform full VPC auth
        tracing::info!("Performing full VPC authentication...");
        let login_response = self.vpc_authenticate(config).await?;

        let new_creds = CachedCredentials {
            access_token: login_response.access_token.clone(),
            access_token_created_at: std::time::Instant::now(),
            refresh_token: login_response.refresh_token.clone(),
            organization_id: login_response.organization.id.clone(),
        };

        // Save to database
        self.save_to_db(&new_creds, Some(&login_response.api_key))
            .await;

        *cached = Some(new_creds);

        Ok(VpcCredentials {
            access_token: login_response.access_token,
            organization_id: login_response.organization.id,
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

    fn is_configured(&self) -> bool {
        self.config.is_some()
    }
}

/// Initialize VPC credentials and get the API key
/// This is called during startup to ensure we have a valid API key
pub async fn initialize_vpc_credentials(
    config: Option<VpcAuthConfig>,
    repository: Arc<dyn VpcCredentialsRepository>,
) -> anyhow::Result<(String, Arc<dyn VpcCredentialsService>)> {
    let service = Arc::new(VpcCredentialsServiceImpl::new(
        config.clone(),
        repository.clone(),
    ));

    // If VPC is configured, ensure we have valid credentials and get the API key
    let api_key = if config.is_some() {
        // Check if we have a cached API key
        if let Some(cached_key) = repository.get(VPC_API_KEY_CONFIG_KEY).await? {
            // Also ensure we can get valid credentials (this will refresh if needed)
            let _ = service.get_credentials().await?;
            tracing::info!("Using cached VPC API key");
            cached_key
        } else {
            // No cached key - perform authentication
            let creds = service.get_credentials().await?;
            if creds.is_none() {
                anyhow::bail!("VPC is configured but authentication failed");
            }
            // The API key should now be stored, fetch it
            repository
                .get(VPC_API_KEY_CONFIG_KEY)
                .await?
                .ok_or_else(|| anyhow::anyhow!("API key not found after VPC authentication"))?
        }
    } else {
        // Not using VPC - this will be overridden by env config
        String::new()
    };

    Ok((api_key, service))
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

        fn is_configured(&self) -> bool {
            self.credentials.is_some()
        }
    }
}
