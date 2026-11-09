use super::ports::{VpcCredentials, VpcCredentialsRepository, VpcCredentialsService, VpcInfo};
use crate::logging::error_type;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Database keys for storing VPC credentials
const VPC_API_KEY_CONFIG_KEY: &str = "vpc_api_key";
const VPC_ORGANIZATION_ID_CONFIG_KEY: &str = "vpc_organization_id";

const LEGACY_VPC_REFRESH_TOKEN_CONFIG_KEY: &str = "vpc_refresh_token";

/// In-memory cached VPC authentication data.
struct CachedCredentials {
    organization_id: String,
    api_key: String,
}

// Remember static selection too, so a cache miss does not add DB reads to
// every proxied request. Explicit invalidation or restart rechecks persistence.
enum CredentialCache {
    Persisted(CachedCredentials),
    Static,
}

impl CredentialCache {
    fn credentials(&self) -> Option<VpcCredentials> {
        match self {
            Self::Persisted(creds) => Some(VpcCredentials {
                organization_id: creds.organization_id.clone(),
                api_key: creds.api_key.clone(),
            }),
            Self::Static => None,
        }
    }
}

/// Implementation of VpcCredentialsService
pub struct VpcCredentialsServiceImpl {
    repository: Arc<dyn VpcCredentialsRepository>,
    cached: RwLock<Option<CredentialCache>>,
    static_api_key: Option<String>,
}

impl VpcCredentialsServiceImpl {
    pub fn new(
        repository: Arc<dyn VpcCredentialsRepository>,
        static_api_key: Option<String>,
    ) -> Self {
        Self {
            repository,
            cached: RwLock::new(None),
            static_api_key,
        }
    }

    /// Load credentials from database
    async fn load_from_db(&self) -> anyhow::Result<Option<CachedCredentials>> {
        // Clean up legacy refresh token if it exists
        if self
            .repository
            .get(LEGACY_VPC_REFRESH_TOKEN_CONFIG_KEY)
            .await?
            .is_some()
        {
            tracing::info!("Removing legacy VPC refresh token from database");
            if let Err(e) = self
                .repository
                .delete(LEGACY_VPC_REFRESH_TOKEN_CONFIG_KEY)
                .await
            {
                tracing::warn!(
                    error_type = error_type(&e),
                    "Failed to delete legacy VPC refresh token"
                );
            }
        }

        let org_id = self.repository.get(VPC_ORGANIZATION_ID_CONFIG_KEY).await?;
        let api_key = self.repository.get(VPC_API_KEY_CONFIG_KEY).await?;

        match (org_id, api_key) {
            (Some(org_id), Some(api_key))
                if !org_id.trim().is_empty() && !api_key.trim().is_empty() =>
            {
                Ok(Some(CachedCredentials {
                    organization_id: org_id,
                    api_key,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Resolve the process cache, persisted credentials, or static fallback.
    async fn load_cached_credentials(&self) -> anyhow::Result<Option<VpcCredentials>> {
        // First, try to use cached credentials
        {
            let cached = self.cached.read().await;
            if let Some(creds) = cached.as_ref() {
                return Ok(creds.credentials());
            }
        }

        let mut cached = self.cached.write().await;

        // Double-check after acquiring write lock
        if let Some(creds) = cached.as_ref() {
            return Ok(creds.credentials());
        }

        if let Some(db_creds) = self
            .load_from_db()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to load cached Cloud API credentials"))?
        {
            let creds = VpcCredentials {
                organization_id: db_creds.organization_id.clone(),
                api_key: db_creds.api_key.clone(),
            };

            *cached = Some(CredentialCache::Persisted(db_creds));
            return Ok(Some(creds));
        }

        if self
            .static_api_key
            .as_ref()
            .is_some_and(|key| !key.trim().is_empty())
        {
            *cached = Some(CredentialCache::Static);
        }

        Ok(None)
    }
}

#[async_trait]
impl VpcCredentialsService for VpcCredentialsServiceImpl {
    async fn get_credentials(&self) -> anyhow::Result<Option<VpcCredentials>> {
        self.load_cached_credentials().await
    }

    async fn get_api_key(&self) -> anyhow::Result<String> {
        if let Some(creds) = self.get_credentials().await? {
            return Ok(creds.api_key);
        }

        self.static_api_key
            .as_ref()
            .filter(|key| !key.trim().is_empty())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("No cached Cloud API credentials or static API key available")
            })
    }

    async fn revoke_credentials(&self) -> anyhow::Result<()> {
        // Serialize invalidation with cache loading so an in-flight lookup
        // cannot repopulate this process with credentials being removed.
        let mut cached = self.cached.write().await;
        *cached = None;

        self.repository
            .delete(VPC_API_KEY_CONFIG_KEY)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to delete cached Cloud API key"))?;
        self.repository
            .delete(VPC_ORGANIZATION_ID_CONFIG_KEY)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to delete cached Cloud API organization"))?;

        Ok(())
    }
}

/// Resolve a Cloud API credential during API/worker startup.
pub async fn initialize_cloud_api_credentials(
    repository: Arc<dyn VpcCredentialsRepository>,
    static_api_key: Option<String>,
) -> anyhow::Result<Arc<dyn VpcCredentialsService>> {
    let service = Arc::new(VpcCredentialsServiceImpl::new(repository, static_api_key));

    // Both API and worker must prove that credentials are available at startup.
    // A repository error is not a cache miss and must not switch identities.
    let _ = service.get_api_key().await?;
    tracing::info!("Cloud API credentials initialized");

    Ok(service)
}

/// No-op repository for callers that deliberately have no persistent cache
pub struct NoOpVpcRepository;

#[async_trait]
impl VpcCredentialsRepository for NoOpVpcRepository {
    async fn get(&self, _key: &str) -> anyhow::Result<Option<String>> {
        Ok(None)
    }

    async fn set(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> anyhow::Result<()> {
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

        async fn revoke_credentials(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }
}

/// Load VPC (Virtual Private Cloud) information from environment variables
pub fn load_vpc_info() -> Option<VpcInfo> {
    // Read VPC server app ID from environment
    let vpc_server_app_id = std::env::var("VPC_SERVER_APP_ID").ok();

    // Read VPC hostname from file
    let vpc_hostname = if let Ok(path) = std::env::var("VPC_HOSTNAME_FILE") {
        std::fs::read_to_string(path)
            .map_err(|e| {
                tracing::warn!(
                    error_type = error_type(&e),
                    "Failed to read VPC hostname file"
                )
            })
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    // Only return Some if at least one field is present
    if vpc_server_app_id.is_some() || vpc_hostname.is_some() {
        Some(VpcInfo {
            vpc_server_app_id,
            vpc_hostname,
        })
    } else {
        None
    }
}
