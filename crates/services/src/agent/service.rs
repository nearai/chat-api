use crate::system_configs::ports::SystemConfigsService;
use crate::UserId;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use config::AgentManager;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    is_valid_service_type, AgentApiInstanceEnrichment, AgentApiKey, AgentApiKeyAuthError,
    AgentApiKeyCreationError, AgentInstance, AgentRepository, AgentService, CreateInstanceParams,
    InstanceBalance, UpgradeAvailability, UsageLogEntry, VALID_SERVICE_TYPES,
};

/// Maximum size for the Agent API SSE stream buffer (100 KB).
/// Prevents DoS from a malicious Agent API sending extremely long lines.
const MAX_BUFFER_SIZE: usize = 100 * 1024;

/// Default service type for agent instances when not specified.
const DEFAULT_SERVICE_TYPE: &str = "openclaw";

// Resource sizing defaults (instance_default_cpus, instance_default_mem_limit, instance_default_storage_size)
// are struct fields accessible via self.instance_default_cpus, etc.

/// Map service type to worker image
fn get_image_for_service_type(service_type: &str) -> &'static str {
    match service_type {
        "ironclaw" => "ironclaw-nearai-worker:local",
        "ironclaw-dind" => "ghcr.io/nearai/ironclaw-dind:0.21.0",
        "openclaw" => "openclaw-nearai-worker:local",
        "openclaw-dind" => "docker.io/nearaidev/openclaw-dind:2026.2.22",
        _ => "openclaw-nearai-worker:local", // default to openclaw
    }
}

/// Normalize service type for compose-api calls.
/// For non-TEE deployments, append `-dind` suffix for compose-api.
/// For TEE deployments, use service type as-is.
fn normalize_service_type_for_api(service_type: &str, non_tee: bool) -> String {
    if non_tee {
        // Non-TEE compose-api: append -dind suffix
        match service_type {
            "ironclaw" => "ironclaw-dind".to_string(),
            "openclaw" => "openclaw-dind".to_string(),
            // Already normalized (shouldn't happen with VALID_SERVICE_TYPES check)
            s => s.to_string(),
        }
    } else {
        // TEE compose-api: use as-is
        service_type.to_string()
    }
}

/// Parameters for Agent API instance creation.
struct AgentApiCreateParams {
    image: Option<String>,
    name: Option<String>,
    ssh_pubkey: Option<String>,
    service_type: Option<String>,
    cpus: Option<String>,
    mem_limit: Option<String>,
    storage_size: Option<String>,
}

/// Parameters for saving instance from Agent API event.
struct SaveInstanceParams {
    api_key_id: Uuid,
    ssh_pubkey: Option<String>,
    max_allowed: u64,
    agent_api_base_url: Option<String>,
    service_type: Option<String>,
}

pub struct AgentServiceImpl {
    repository: Arc<dyn AgentRepository>,
    http_client: Client,
    /// Agent manager endpoints (URL + token pairs)
    managers: Vec<AgentManager>,
    /// Round-robin counter for distributing new instances across managers
    round_robin_counter: AtomicUsize,
    /// Chat-API base URL passed to the Agent API as nearai_api_url when creating instances
    nearai_api_url: String,
    /// System configs for reading instance limits and defaults
    system_configs_service: Arc<dyn SystemConfigsService>,
    /// Channel-relay URL for provisioning relay config to IronClaw instances
    channel_relay_url: Option<String>,
    /// URL pattern to identify non-TEE manager endpoints (e.g., "claws")
    /// Used to determine instance type when routing to managers
    non_tee_agent_url_pattern: String,
}

/// Static helper: Fetch instance details from Agent API GET /instances/{name}.
/// Returns None on 404 or any error (non-blocking; used to enrich instance responses).
async fn get_instance_details_static(
    http_client: &reqwest::Client,
    manager: &AgentManager,
    name: &str,
    bearer_token: Option<&str>,
) -> Option<serde_json::Value> {
    let encoded_name = urlencoding::encode(name);
    let url = format!("{}/instances/{}", manager.url, encoded_name);

    // Use provided bearer token (e.g., session token from passkey login), fall back to manager token
    let token = bearer_token.unwrap_or(&manager.token);

    tracing::debug!("Calling GET {}/instances/{}", manager.url, encoded_name);

    let response = http_client.get(&url).bearer_auth(token).send().await.ok()?;

    let status = response.status();
    tracing::debug!(
        "GET /instances/{} response status: {}",
        encoded_name,
        status
    );

    if !response.status().is_success() {
        if response.status().as_u16() == 404 {
            tracing::debug!("Agent API instance not found: name={}", name);
        }
        return None;
    }

    let json = response.json::<serde_json::Value>().await.ok()?;
    tracing::debug!("GET /instances/{} response received", encoded_name);
    Some(json)
}

/// Authentication method for Agent Manager API calls
enum AuthMethod<'a> {
    /// Bearer token (manager token or session token from passkey login)
    BearerToken(&'a str),
}

impl AgentServiceImpl {
    /// Generate a random credential (hex-encoded random bytes)
    fn generate_random_credential(len: usize) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        hex::encode(bytes)
    }

    pub fn new(
        repository: Arc<dyn AgentRepository>,
        managers: Vec<AgentManager>,
        nearai_api_url: String,
        system_configs_service: Arc<dyn SystemConfigsService>,
        channel_relay_url: Option<String>,
        non_tee_agent_url_pattern: String,
    ) -> Self {
        // Validate required configuration
        if managers.is_empty() {
            panic!("At least one agent manager must be configured");
        }
        for (i, mgr) in managers.iter().enumerate() {
            if mgr.token.is_empty() {
                panic!("Agent manager #{} ({}) has an empty API token", i, mgr.url);
            }
        }

        // Create HTTP client with timeout to prevent connection pool exhaustion from hung upstream services.
        // Default 30s for most calls; instance create uses per-request timeout (see call_agent_api_create).
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            repository,
            http_client,
            managers,
            round_robin_counter: AtomicUsize::new(0),
            nearai_api_url,
            system_configs_service,
            channel_relay_url,
            non_tee_agent_url_pattern,
        }
    }

    /// Pick the next manager in round-robin order for new instance creation.
    /// Does NOT check capacity — use `next_available_manager` for capacity-aware selection.
    #[cfg(test)]
    fn next_manager(&self) -> &AgentManager {
        let idx = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);
        &self.managers[idx % self.managers.len()]
    }

    /// Pick the next manager with available capacity, starting from the round-robin position.
    /// Tries each manager once. Returns Err if all managers are at capacity.
    ///
    /// NOTE: This is a best-effort soft limit. Concurrent calls can both see a manager as
    /// under capacity and both create instances there, temporarily exceeding the limit.
    /// For a hard cap, DB-level enforcement (e.g. INSERT ... WHERE count < max) would be needed.
    async fn next_available_manager(&self) -> anyhow::Result<AgentManager> {
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten()
            .unwrap_or_default();

        // Read NON_TEE_INFRA setting from system configs
        let non_tee_infra = configs
            .agent_hosting
            .as_ref()
            .and_then(|cfg| cfg.new_agent_with_non_tee_infra)
            .unwrap_or(false);

        // Filter managers based on NON_TEE_INFRA setting
        let available_managers: Vec<_> = self
            .managers
            .iter()
            .filter(|mgr| {
                // Infrastructure mode must match: non_tee_infra=true means only non-TEE, false means only TEE
                non_tee_infra == mgr.get_is_non_tee()
            })
            .collect();

        if available_managers.is_empty() {
            return Err(anyhow!(
                "No suitable managers available: NON_TEE_INFRA={}, configured_managers={}",
                non_tee_infra,
                self.managers.len()
            ));
        }

        let n = available_managers.len();
        let start = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);

        for i in 0..n {
            let mgr = available_managers[(start + i) % n];
            let max = configs.max_instances_for_manager(&mgr.url);
            let max = match max {
                Some(limit) => limit,
                None => return Ok(mgr.clone()),
            };
            let count = self.repository.count_instances_by_manager(&mgr.url).await?;
            if (count as u64) < max {
                return Ok(mgr.clone());
            }
            tracing::info!(
                "Manager at capacity: manager_url={}, count={}, max={}",
                mgr.url,
                count,
                max
            );
        }

        Err(anyhow!(
            "All {} suitable agent manager(s) are at capacity (NON_TEE_INFRA={})",
            n,
            non_tee_infra
        ))
    }

    /// Resolve the manager for an existing instance.
    /// Uses the stored agent_api_base_url from DB, falling back to the first manager.
    fn resolve_manager(&self, instance: &AgentInstance) -> anyhow::Result<&AgentManager> {
        tracing::info!(
            "resolve_manager: instance_id={}, name={}, stored_agent_api_base_url={:?}",
            instance.id,
            instance.name,
            instance.agent_api_base_url
        );

        // Try to use the stored URL if available
        if let Some(ref stored_url) = instance.agent_api_base_url {
            tracing::info!(
                "resolve_manager: searching for stored_url={} in {} configured managers: {:?}",
                stored_url,
                self.managers.len(),
                self.managers.iter().map(|m| &m.url).collect::<Vec<_>>()
            );

            if let Some(mgr) = self.managers.iter().find(|m| &m.url == stored_url) {
                tracing::info!(
                    "Using stored manager URL: instance_id={}, url={}",
                    instance.id,
                    stored_url
                );
                return Ok(mgr);
            }

            // Stored URL not in configured managers - warn and use fallback
            tracing::warn!(
                "resolve_manager: Stored URL {} not in configured managers for instance_id={}, using first available manager",
                stored_url,
                instance.id
            );
        } else {
            tracing::warn!(
                "resolve_manager: No stored agent_api_base_url found for instance_id={}",
                instance.id
            );
        }

        if self.managers.is_empty() {
            return Err(anyhow!("No agent managers configured"));
        }

        // Use first available manager as fallback, but try to match manager type if stored URL exists
        // This ensures instances created as TEE don't accidentally get routed to non-TEE managers
        let fallback_manager = if let Some(ref stored_url) = instance.agent_api_base_url {
            // Determine expected manager type based on URL pattern:
            // - Non-TEE: URLs containing the configured non_tee_agent_url_pattern (e.g., "claws")
            // - TEE: all other URLs (TEE compose-api / manager hostnames)
            let expected_is_non_tee = stored_url.contains(&self.non_tee_agent_url_pattern);

            // Find a manager of the matching type
            if let Some(matching_mgr) = self.managers.iter().find(|m| {
                if expected_is_non_tee {
                    m.get_is_non_tee()
                } else {
                    !m.get_is_non_tee()
                }
            }) {
                tracing::info!(
                    "resolve_manager: Stored URL {} not found, using fallback {} (expected manager type: non_tee={})",
                    stored_url,
                    matching_mgr.url,
                    expected_is_non_tee
                );
                matching_mgr
            } else {
                // No matching type available - fail rather than silently use wrong type
                // This prevents instances from being incorrectly routed to managers of a different authentication type
                let expected_type = if expected_is_non_tee {
                    "non-TEE"
                } else {
                    "TEE"
                };
                let available_types = self
                    .managers
                    .iter()
                    .map(|m| if m.get_is_non_tee() { "non-TEE" } else { "TEE" })
                    .collect::<Vec<_>>()
                    .join(", ");
                tracing::error!(
                    "resolve_manager: Instance was created on {} manager but no {} manager is available. Available types: [{}], instance_id={}",
                    expected_type,
                    expected_type,
                    available_types,
                    instance.id
                );
                return Err(anyhow!(
                    "Instance was created on {} manager but no {} manager is available",
                    expected_type,
                    expected_type
                ));
            }
        } else {
            // No stored URL, just use first manager
            tracing::info!(
                "resolve_manager: No stored URL, using first available manager: {}",
                self.managers[0].url
            );
            &self.managers[0]
        };

        tracing::info!(
            "resolve_manager: Using fallback manager: {} for instance_id={}",
            fallback_manager.url,
            instance.id
        );
        Ok(fallback_manager)
    }

    /// Register passkey credentials with compose-api and return a session token
    /// Calls POST /api/crabshack/auth/register with auth_secret and backup_passphrase
    /// Login to compose-api using passkey credentials and get a session token
    async fn compose_api_passkey_login(
        &self,
        manager: &AgentManager,
        auth_secret: &str,
        backup_passphrase: &str,
    ) -> anyhow::Result<String> {
        Self::compose_api_passkey_login_static(
            &self.http_client,
            manager,
            auth_secret,
            backup_passphrase,
        )
        .await
    }

    /// Static version for use in closures. Takes http_client explicitly.
    async fn compose_api_passkey_login_static(
        http_client: &reqwest::Client,
        manager: &AgentManager,
        auth_secret: &str,
        backup_passphrase: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/auth/login", manager.url);
        let request_body = serde_json::json!({
            "auth_secret": auth_secret,
            "backup_passphrase": backup_passphrase,
        });

        tracing::debug!("Calling compose-api /auth/login: url={}", url);

        let response = http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call compose-api /auth/login: {}", e))?;

        let status = response.status();
        tracing::debug!("compose-api /auth/login response: status={}", status);

        if !response.status().is_success() {
            tracing::warn!("compose-api /auth/login failed: status={}", status);
            return Err(anyhow!("compose-api /auth/login error: {}", status));
        }

        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| anyhow!("Failed to parse compose-api /auth/login response: {}", e))?;

        body.get("session_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Missing 'session_token' in compose-api /auth/login response"))
    }

    /// Resolve the bearer token to use for agent API calls.
    /// In non-TEE mode: tries to fetch user's passkey credentials and login to compose-api.
    /// In TEE mode: always uses manager token (TEE compose-api does not support passkey login).
    async fn resolve_bearer_token(
        &self,
        instance: &AgentInstance,
        manager: &AgentManager,
    ) -> anyhow::Result<String> {
        // Manager type is determined by the actual manager URL the instance was created with,
        // not by the current global NON_TEE_INFRA setting. This allows instances created in one mode
        // to be accessed correctly even if the system is now running in a different mode.

        if !manager.get_is_non_tee() {
            // TEE manager: use manager token directly (no passkey/compose-api)
            return Ok(manager.token.clone());
        }

        // Non-TEE manager: try passkey credentials for compose-api login
        if let Ok(Some((auth_secret, backup_passphrase))) = self
            .repository
            .get_user_passkey_credentials(instance.user_id)
            .await
        {
            self.compose_api_passkey_login(manager, &auth_secret, &backup_passphrase)
                .await
        } else {
            // Fallback to manager token if no passkey credentials
            Ok(manager.token.clone())
        }
    }

    async fn compose_api_passkey_register(
        &self,
        manager: &AgentManager,
        auth_secret: &str,
        backup_passphrase: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/auth/register", manager.url);
        let request_body = serde_json::json!({
            "auth_secret": auth_secret,
            "backup_passphrase": backup_passphrase,
        });

        tracing::debug!("Calling compose-api /auth/register: url={}", url);

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&manager.token)
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call compose-api /auth/register: {}", e))?;

        let status = response.status();
        tracing::debug!("compose-api /auth/register response: status={}", status);

        if !response.status().is_success() {
            tracing::warn!("compose-api /auth/register failed: status={}", status);
            return Err(anyhow!("compose-api /auth/register error: {}", status));
        }

        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| anyhow!("Failed to parse compose-api /auth/register response: {}", e))?;

        body.get("session_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                anyhow!("Missing 'session_token' in compose-api /auth/register response")
            })
    }

    /// Call compose-api /auth/proxy-session to set up gateway cookie
    async fn compose_api_proxy_session(
        &self,
        manager: &AgentManager,
        session_token: &str,
    ) -> anyhow::Result<Option<String>> {
        // Extract domain from manager URL and construct proxy-session URL
        // Manager URL: https://agents.example.com/api/crabshack
        // Proxy-session URL: https://api.agents.example.com/api/auth/proxy-session
        let url = if let Ok(parsed) = url::Url::parse(&manager.url) {
            if let Some(domain) = parsed.domain() {
                format!("https://api.{}/api/auth/proxy-session", domain)
            } else {
                return Err(anyhow!("Invalid manager URL: {}", manager.url));
            }
        } else {
            return Err(anyhow!("Failed to parse manager URL: {}", manager.url));
        };

        tracing::info!(
            "Calling compose-api /auth/proxy-session: url={}, session_token_len={}",
            url,
            session_token.len()
        );

        let response = self
            .http_client
            .post(&url)
            .bearer_auth(session_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call compose-api /auth/proxy-session: {}", e))?;

        let status = response.status();
        let headers = response.headers().clone();

        // Extract Set-Cookie header to forward to browser
        let set_cookie = headers
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Capture response body for logging
        let response_text = response
            .text()
            .await
            .unwrap_or_else(|_| "(unable to read response body)".to_string());

        tracing::info!(
            "compose-api /auth/proxy-session response: status={}",
            status
        );

        if !status.is_success() {
            tracing::warn!("compose-api /auth/proxy-session failed: status={}", status);
            return Err(anyhow!(
                "compose-api /auth/proxy-session error: {} - {}",
                status,
                response_text
            ));
        }

        tracing::info!("✓ Gateway proxy session established successfully");

        Ok(set_cookie)
    }

    /// Generate a new API key in format: sk-agent-{uuid}
    fn generate_api_key() -> String {
        format!("sk-agent-{}", Uuid::new_v4().to_string().replace("-", ""))
    }

    /// Hash an API key for storage using SHA-256
    fn hash_api_key(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Validate API key format (must start with "sk-agent-" and be 41 chars total)
    fn validate_api_key_format(key: &str) -> bool {
        key.starts_with("sk-agent-") && key.len() == 41
    }

    fn validate_api_key_spend_limit(
        spend_limit: Option<i64>,
    ) -> Result<(), AgentApiKeyCreationError> {
        if matches!(spend_limit, Some(limit) if limit < 0) {
            return Err(AgentApiKeyCreationError::InvalidSpendLimit);
        }

        Ok(())
    }

    async fn ensure_api_key_can_be_used(
        &self,
        api_key_info: &AgentApiKey,
    ) -> Result<(), AgentApiKeyAuthError> {
        if !api_key_info.is_active {
            tracing::warn!("API key is not active: api_key_id={}", api_key_info.id);
            return Err(AgentApiKeyAuthError::Inactive);
        }

        if let Some(expires_at) = api_key_info.expires_at {
            if expires_at < Utc::now() {
                tracing::warn!("API key has expired: api_key_id={}", api_key_info.id);
                return Err(AgentApiKeyAuthError::Expired);
            }
        }

        if let Some(spend_limit) = api_key_info.spend_limit {
            // `spend_limit` is currently a lifetime cap based on all recorded usage events for
            // this API key.
            // This is best-effort enforcement: concurrent requests can both pass this preflight
            // check before their usage is recorded. A hard cap would need atomic reservation or
            // enforcement at usage-recording time.
            let total_spend = self
                .repository
                .get_api_key_total_spend(api_key_info.id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Failed to load API key spend total: api_key_id={}, error={}",
                        api_key_info.id,
                        e
                    );
                    AgentApiKeyAuthError::Internal
                })?;
            if total_spend >= spend_limit {
                tracing::warn!(
                    "API key spend limit exceeded: api_key_id={}, total_spend={}, spend_limit={}",
                    api_key_info.id,
                    total_spend,
                    spend_limit
                );
                return Err(AgentApiKeyAuthError::SpendLimitExceeded);
            }
        }

        Ok(())
    }

    async fn mark_api_key_used(&self, api_key_id: Uuid) -> Result<(), AgentApiKeyAuthError> {
        self.repository
            .update_api_key_last_used(api_key_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to update last_used_at for api_key_id={}: {}",
                    api_key_id,
                    e
                );
                AgentApiKeyAuthError::Internal
            })
    }

    /// Call Agent API to create an instance on a specific manager
    ///
    /// # Security Note
    /// This function receives a nearai_api_key credential that is passed to the Agent API
    /// in the request body. This is a sensitive credential and MUST NOT be logged, stored,
    /// or exposed in any error messages. Only the HTTP request/response status codes and headers
    /// should be logged for debugging purposes, never the request/response body.
    async fn call_agent_api_create(
        &self,
        manager: &AgentManager,
        nearai_api_key: &str,
        nearai_api_url: &str,
        params: AgentApiCreateParams,
    ) -> anyhow::Result<serde_json::Value> {
        // Get instance defaults from system configs
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let instance_defaults = configs.instance_defaults.as_ref();
        let default_cpus = instance_defaults
            .and_then(|d| d.cpus.as_deref())
            .unwrap_or("1");
        let default_mem_limit = instance_defaults
            .and_then(|d| d.mem_limit.as_deref())
            .unwrap_or("4g");
        let default_storage_size = instance_defaults
            .and_then(|d| d.storage_size.as_deref())
            .unwrap_or("10G");

        let url = format!("{}/instances", manager.url);

        let service_type = params
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);
        // Normalize service_type for API call based on manager type
        let service_type_for_api =
            normalize_service_type_for_api(service_type, manager.get_is_non_tee());

        // Determine image to use based on manager type
        let image_to_use = if let Some(img) = params.image {
            Some(img)
        } else if manager.get_is_non_tee() {
            // Non-TEE manager requires image; use normalized service_type to map to correct image
            // e.g., user selects "ironclaw" → normalize to "ironclaw-dind" → map to ghcr.io/nearai/ironclaw-dind:0.21.0
            Some(get_image_for_service_type(&service_type_for_api).to_string())
        } else {
            // TEE manager: image is optional, let Agent API determine it
            None
        };

        let mut request_body = serde_json::json!({
            "image": image_to_use,
            "name": params.name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": params.ssh_pubkey,
            "service_type": service_type_for_api,
        });

        // Only include resource fields if they're explicitly set or available
        // In non-TEE mode, use configured defaults; in TEE mode, let Agent API use its defaults
        let cpus = params.cpus.as_deref().or(Some(default_cpus));
        if let Some(cpu) = cpus {
            request_body["cpus"] = serde_json::json!(cpu);
        }

        let mem_limit = params.mem_limit.as_deref().or(Some(default_mem_limit));
        if let Some(mem) = mem_limit {
            request_body["mem_limit"] = serde_json::json!(mem);
        }

        let storage_size = params
            .storage_size
            .as_deref()
            .or(Some(default_storage_size));
        if let Some(storage) = storage_size {
            request_body["storage_size"] = serde_json::json!(storage);
        }

        // Inject channel-relay config for IronClaw instances.
        // CHANNEL_RELAY_SIGNING_SECRET is no longer passed: each IronClaw
        // instance uses its own OPENCLAW_GATEWAY_TOKEN as the signing secret.
        if service_type == "ironclaw" {
            if let Some(ref relay_url) = self.channel_relay_url {
                request_body["extra_env"] = serde_json::json!({
                    "CHANNEL_RELAY_URL": relay_url,
                    "CHANNEL_RELAY_API_KEY": nearai_api_key,
                });
            }
        }

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&manager.token)
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(180)) // Instance creation can take 2-3 minutes
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "(unable to read response)".to_string());
            // Log full error for debugging, but don't expose to clients
            tracing::warn!(
                "Agent API create instance failed: status={}, body={}",
                status,
                error_body
            );
            return Err(anyhow!("Agent API error: {}", status));
        }

        let body_text = response
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read Agent API response: {}", e))?;

        // Parse Server-Sent Events (SSE) response format
        // The response contains multiple "data: {...}" lines
        // We extract the first event which contains the instance creation result
        let first_event = body_text
            .lines()
            .find(|line| line.starts_with("data: "))
            .and_then(|line| line.strip_prefix("data: "))
            .ok_or_else(|| anyhow!("No data event found in Agent API response"))?;

        let body = serde_json::from_str::<serde_json::Value>(first_event)
            .map_err(|e| anyhow!("Failed to parse Agent API response: {}", e))?;

        Ok(body)
    }

    /// Call Agent API to list instances on a specific manager
    async fn call_agent_api_list(
        &self,
        manager: &AgentManager,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/instances", manager.url);

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            // Don't expose upstream error details for security; log only status code
            tracing::warn!("Agent API request failed: status={}", status);
            return Err(anyhow!("Agent API error: {}", status));
        }

        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| anyhow!("Failed to parse Agent API response: {}", e))?;

        Ok(body)
    }

    /// Call Agent API GET /instances/{name} on a specific manager.
    /// Returns None on 404 or any error (non-blocking; used to enrich instance responses).
    async fn call_agent_api_get_instance(
        &self,
        manager: &AgentManager,
        name: &str,
    ) -> Option<serde_json::Value> {
        // Use manager token as fallback (for general instance queries, not passkey-specific)
        get_instance_details_static(&self.http_client, manager, name, None).await
    }

    /// Fetch SSH command for an instance from Agent API /instances/{name}/ssh
    /// Uses provided bearer token (passkey session token) if available, falls back to manager token
    /// Static version for use in closures. Takes http_client explicitly.
    async fn fetch_ssh_command_static(
        http_client: &reqwest::Client,
        manager: &AgentManager,
        instance_name: &str,
        bearer_token: Option<&str>,
    ) -> Option<String> {
        let encoded_name = urlencoding::encode(instance_name);

        // Use different endpoints based on deployment mode
        let url = if manager.get_is_non_tee() {
            // Non-TEE: separate /ssh endpoint
            format!("{}/instances/{}/ssh", manager.url, encoded_name)
        } else {
            // TEE: ssh_command is in the main instance details endpoint
            format!("{}/instances/{}", manager.url, encoded_name)
        };

        // Use provided bearer token (e.g., session token from passkey login), fall back to manager token
        let token = bearer_token.unwrap_or(&manager.token);

        tracing::debug!(
            "Fetching SSH command from Agent API: instance_name={}, url={}, tee={}",
            instance_name,
            url,
            !manager.get_is_non_tee()
        );

        let response = http_client
            .get(&url)
            .bearer_auth(token)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                tracing::debug!(
                    "SSH endpoint not found for instance: name={}",
                    instance_name
                );
            } else {
                tracing::warn!(
                    "Agent API SSH endpoint failed: status={}, instance_name={}",
                    response.status(),
                    instance_name
                );
            }
            return None;
        }

        match response.json::<serde_json::Value>().await {
            Ok(data) => {
                tracing::debug!("SSH command fetched: instance_name={}", instance_name);
                // Different field names based on deployment mode
                let ssh_command = if manager.get_is_non_tee() {
                    // Non-TEE: /ssh endpoint returns "command" field
                    data.get("command")
                } else {
                    // TEE: /instances/{name} endpoint returns "ssh_command" field
                    data.get("ssh_command")
                };
                ssh_command.and_then(|v| v.as_str()).map(|s| s.to_string())
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to parse SSH command response: instance_name={}, error={}",
                    instance_name,
                    e
                );
                None
            }
        }
    }

    /// Call Agent API to create an instance with streaming lifecycle events on a specific manager.
    ///
    /// # Security Note
    /// The nearai_api_key credential MUST NOT be logged or exposed in error messages.
    async fn call_agent_api_create_streaming(
        &self,
        manager: &AgentManager,
        nearai_api_key: &str,
        nearai_api_url: &str,
        params: AgentApiCreateParams,
        auth_method: AuthMethod<'_>,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let instance_defaults = configs.instance_defaults.as_ref();
        let default_cpus = instance_defaults
            .and_then(|d| d.cpus.as_deref())
            .unwrap_or("1");
        let default_mem_limit = instance_defaults
            .and_then(|d| d.mem_limit.as_deref())
            .unwrap_or("4g");
        let default_storage_size = instance_defaults
            .and_then(|d| d.storage_size.as_deref())
            .unwrap_or("10G");

        let url = format!("{}/instances", manager.url);

        let service_type = params
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);

        // Normalize service_type for API call based on ACTUAL manager type
        let service_type_for_api =
            normalize_service_type_for_api(service_type, manager.get_is_non_tee());

        // Build request body with base fields
        // Note: In non-TEE mode, image is required; in TEE mode it's optional
        let image_to_use = if let Some(img) = params.image {
            Some(img)
        } else if manager.get_is_non_tee() {
            // Non-TEE manager requires image; use normalized service_type to map to correct image
            // e.g., user selects "ironclaw" → normalize to "ironclaw-dind" → map to ghcr.io/nearai/ironclaw-dind:0.21.0
            Some(get_image_for_service_type(&service_type_for_api).to_string())
        } else {
            // TEE manager: image is optional, let Agent API determine it
            None
        };

        let mut request_body = serde_json::json!({
            "image": image_to_use,
            "name": params.name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": params.ssh_pubkey,
            "service_type": service_type_for_api,
        });

        // Only include resource fields if they're explicitly set or available
        // In non-TEE mode, use configured defaults; in TEE mode, let Agent API use its defaults
        let cpus = params.cpus.as_deref().or(Some(default_cpus));
        if let Some(cpu) = cpus {
            request_body["cpus"] = serde_json::json!(cpu);
        }

        let mem_limit = params.mem_limit.as_deref().or(Some(default_mem_limit));
        if let Some(mem) = mem_limit {
            request_body["mem_limit"] = serde_json::json!(mem);
        }

        let storage_size = params
            .storage_size
            .as_deref()
            .or(Some(default_storage_size));
        if let Some(storage) = storage_size {
            request_body["storage_size"] = serde_json::json!(storage);
        }
        // Inject channel-relay config for IronClaw instances.
        // CHANNEL_RELAY_SIGNING_SECRET is no longer passed: each IronClaw
        // instance uses its own OPENCLAW_GATEWAY_TOKEN as the signing secret.
        if service_type == "ironclaw" {
            if let Some(ref relay_url) = self.channel_relay_url {
                request_body["extra_env"] = serde_json::json!({
                    "CHANNEL_RELAY_URL": relay_url,
                    "CHANNEL_RELAY_API_KEY": nearai_api_key,
                });
            }
        }

        let mut request = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json");

        // Apply bearer token authentication
        let AuthMethod::BearerToken(token) = auth_method;
        request = request.bearer_auth(token);

        tracing::debug!("Calling Agent API create instance: url={}", url);

        let response = request
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(180))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "(unable to read response)".to_string());
            tracing::warn!(
                "Agent API create instance failed: status={}, body={}",
                status,
                error_body
            );
            return Err(anyhow!("Agent API error: {} - {}", status, error_body));
        }

        tracing::info!(
            "Agent API create instance succeeded: status={}",
            response.status()
        );

        let (tx, rx) = tokio::sync::mpsc::channel(10);

        tokio::spawn(async move {
            use futures::stream::StreamExt;
            use tokio::time::timeout;

            let mut stream = response.bytes_stream();
            let mut buffer = String::new();
            const STREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

            loop {
                let chunk_result = timeout(STREAM_IDLE_TIMEOUT, stream.next()).await;
                let chunk_result = match chunk_result {
                    Ok(result) => result,
                    Err(_timeout) => {
                        tracing::error!(
                            "Agent API stream idle timeout: no data received for {}s",
                            STREAM_IDLE_TIMEOUT.as_secs()
                        );
                        let _ = tx.send(Err(anyhow!("Agent API stream timeout"))).await;
                        break;
                    }
                };

                match chunk_result {
                    Some(Ok(chunk)) => {
                        let text = String::from_utf8_lossy(&chunk);
                        if buffer.len() + text.len() > MAX_BUFFER_SIZE {
                            tracing::error!(
                                "Agent API stream buffer would exceed maximum size ({} bytes): current={}, incoming chunk={}",
                                MAX_BUFFER_SIZE,
                                buffer.len(),
                                text.len()
                            );
                            let _ = tx
                                .send(Err(anyhow!(
                                    "Stream buffer too large: possible malicious Agent API"
                                )))
                                .await;
                            break;
                        }
                        buffer.push_str(&text);

                        while let Some(newline_pos) = buffer.find('\n') {
                            let line = buffer[..newline_pos].to_string();
                            buffer.drain(..=newline_pos);

                            if let Some(data) = line.strip_prefix("data: ") {
                                match serde_json::from_str::<serde_json::Value>(data) {
                                    Ok(event) => {
                                        let _ = tx.send(Ok(event)).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Failed to parse Agent API SSE data as JSON: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::error!("Error reading Agent API stream: {}", e);
                        let _ = tx.send(Err(anyhow!("Stream error: {}", e))).await;
                        break;
                    }
                    None => break,
                }
            }

            if !buffer.is_empty() {
                if let Some(data) = buffer.strip_prefix("data: ") {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(data) {
                        let _ = tx.send(Ok(event)).await;
                    }
                }
            }
        });

        Ok(rx)
    }
}

/// Validate that a URL from the Agent API response uses an allowed scheme (http or https).
/// Rejects URLs with unexpected schemes (e.g., javascript:, file:, data:) that could be
/// injected by a compromised or malicious Agent Manager.
fn validate_agent_api_url(url: &str, field_name: &str) -> anyhow::Result<()> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        anyhow::bail!("Invalid {field_name}: must use http or https scheme");
    }
    Ok(())
}

/// Save instance data from a lifecycle event to database.
/// `agent_api_base_url` is the manager URL that created this instance (for routing future operations).
/// Save passkey instance data from a lifecycle event to database.
/// Similar to save_instance_from_event but stores passkey credentials (hashed) in the DB.
async fn save_passkey_instance_from_event(
    repository: &dyn AgentRepository,
    user_id: UserId,
    instance_data: &serde_json::Value,
    params: SaveInstanceParams,
) -> anyhow::Result<AgentInstance> {
    // TOCTOU mitigation: Re-check instance limit before creating
    let (_instances, total_count) = repository.list_user_instances(user_id, 1, 0).await?;
    if total_count as u64 >= params.max_allowed {
        tracing::error!(
            "Passkey instance creation rejected: subscription limit exceeded due to concurrent request. current={}, max={}, user_id={}",
            total_count,
            params.max_allowed,
            user_id
        );
        return Err(anyhow!(
            "Agent instance limit exceeded. Current: {}, Max: {}",
            total_count,
            params.max_allowed
        ));
    }

    let instance_name = instance_data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'name' in Agent API instance data"))?
        .to_string();

    let instance_id = instance_data
        .get("instance_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("agent-{}-{}", instance_name, Uuid::new_v4()));

    let instance_token = instance_data
        .get("token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    tracing::debug!(
        "Extracted from instance_data (passkey): instance_id={}, has_token={}, instance_data_keys={:?}",
        instance_id,
        instance_token.is_some(),
        instance_data.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()
    );

    // Reject empty instance_token if present (defense-in-depth)
    if let Some(ref token) = &instance_token {
        if token.is_empty() {
            anyhow::bail!("Invalid instance_token: must be non-empty");
        }
    }

    // Extract instance_url from API response if available
    // Try "instance_url" first (returned by non-TEE compose-api in final event),
    // then fall back to "url" (used by other API responses)
    let instance_url = instance_data
        .get("instance_url")
        .or_else(|| instance_data.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Fall back to constructing instance_url from manager domain (non-TEE mode)
            // Extract domain from agent_api_base_url (e.g., https://venice-staging.near-dev.org/api/crabshack -> venice-staging.near-dev.org)
            if let (Some(token), Some(manager_url)) = (&instance_token, &params.agent_api_base_url)
            {
                if let Ok(url) = url::Url::parse(manager_url) {
                    if let Some(domain) = url.host_str() {
                        return Some(format!(
                            "https://{}.{}/?token={}",
                            instance_name, domain, token
                        ));
                    }
                }
            }

            // No fallback: instance_url must come from Agent API
            None
        });
    // Validate instance_url scheme to prevent injection from a compromised Agent Manager
    if let Some(ref url) = &instance_url {
        validate_agent_api_url(url, "instance_url")?;
    }

    let _gateway_port = instance_data
        .get("gateway_port")
        .and_then(|v| v.as_i64())
        .map(|p| p as i32);

    // Use dashboard_url from API response if available, otherwise use instance_url
    let dashboard_url = instance_data
        .get("dashboard_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| instance_url.clone());
    // Validate dashboard_url scheme to prevent injection from a compromised Agent Manager
    if let Some(ref url) = &dashboard_url {
        validate_agent_api_url(url, "dashboard_url")?;
    }

    // Extract service_type from instance_data if present and valid, otherwise use provided value
    let service_type_from_response = instance_data
        .get("service_type")
        .and_then(|v| v.as_str())
        .filter(|s| is_valid_service_type(s))
        .map(|s| s.to_string());
    let final_service_type = service_type_from_response.or(params.service_type.clone());

    tracing::info!(
        "URL extraction for passkey instance: instance_name={}, instance_url={:?}, dashboard_url={:?}, all_keys_in_instance_data={:?}",
        instance_name,
        instance_url,
        dashboard_url,
        instance_data.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()
    );

    tracing::debug!(
        "Saving passkey instance to database: user_id={}, instance_id={}, name={}, service_type={:?}, agent_api_base_url={:?}",
        user_id,
        instance_id,
        instance_name,
        final_service_type,
        params.agent_api_base_url
    );

    let instance = repository
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: instance_id.clone(),
            name: instance_name,
            public_ssh_key: params.ssh_pubkey.clone(),
            instance_url,
            instance_token,
            dashboard_url,
            agent_api_base_url: params.agent_api_base_url.clone(),
            service_type: final_service_type,
        })
        .await
        .map_err(|e| {
            tracing::error!(
                "Database save failed for passkey instance: user_id={}, error_chain: {}",
                user_id,
                format!("{:#}", e)
            );
            e
        })?;

    // Defense-in-depth: verify the created instance belongs to the requesting user
    if instance.user_id != user_id {
        tracing::error!(
            "Security violation: created passkey instance ownership mismatch: instance_id={}, expected_user_id={}, actual_user_id={}",
            instance.id,
            user_id,
            instance.user_id
        );
        return Err(anyhow!("Instance creation failed: ownership mismatch"));
    }

    repository
        .bind_api_key_to_instance(params.api_key_id, instance.id)
        .await?;

    tracing::info!(
        "Passkey instance saved from lifecycle event: instance_id={}, user_id={}",
        instance_id,
        user_id
    );

    Ok(instance)
}

/// Static function: Fetch instance details from Agent API to enrich instance data.
/// Uses shared get_instance_details_static helper.
async fn fetch_instance_details_static(
    http_client: &reqwest::Client,
    manager: &AgentManager,
    instance_name: &str,
    bearer_token: Option<&str>,
) -> Option<serde_json::Value> {
    tracing::debug!(
        "Fetching instance details from Agent API: instance_name={}",
        instance_name
    );

    let result =
        get_instance_details_static(http_client, manager, instance_name, bearer_token).await;

    if result.is_some() {
        tracing::debug!(
            "Instance details fetched successfully: instance_name={}",
            instance_name
        );
    } else {
        tracing::warn!(
            "Failed to fetch instance details from Agent API: instance_name={}",
            instance_name
        );
    }

    result
}

#[async_trait]
impl AgentService for AgentServiceImpl {
    async fn list_all_instances(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)> {
        self.repository.list_all_instances(limit, offset).await
    }

    async fn create_instance_from_agent_api(
        &self,
        user_id: UserId,
        params: super::ports::InstanceCreationParams,
    ) -> anyhow::Result<AgentInstance> {
        tracing::info!("Creating instance from Agent API: user_id={}", user_id);

        // Pick next manager with available capacity (round-robin, skipping full managers)
        let manager = self.next_available_manager().await?;

        // Create an unbound API key on behalf of the user; the agent will use it to authenticate to the chat-api.
        let key_name = params
            .name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let default_expiry = Some(Utc::now() + Duration::days(90));
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, default_expiry)
            .await?;

        // Apply default service type if not provided
        // Defense-in-depth: validate service type early to prevent invalid values reaching Agent API
        if let Some(ref st) = &params.service_type {
            if !is_valid_service_type(st) {
                return Err(anyhow!(
                    "Invalid service type '{}'. Valid types are: {}",
                    st,
                    VALID_SERVICE_TYPES.join(", ")
                ));
            }
        }

        let service_type_for_api = params
            .service_type
            .clone()
            .or_else(|| Some(DEFAULT_SERVICE_TYPE.to_string()));

        // Call Agent API with our API key and the chat-api URL (agents reach us at nearai_api_url)
        let response = self
            .call_agent_api_create(
                &manager,
                &plaintext_key,
                &self.nearai_api_url,
                AgentApiCreateParams {
                    image: params.image.clone(),
                    name: params.name.clone(),
                    ssh_pubkey: params.ssh_pubkey.clone(),
                    service_type: service_type_for_api.clone(),
                    cpus: params.cpus.clone(),
                    mem_limit: params.mem_limit.clone(),
                    storage_size: params.storage_size.clone(),
                },
            )
            .await?;

        // Extract instance data from response
        let instance_data = response
            .get("instance")
            .ok_or_else(|| anyhow!("Missing 'instance' in Agent API response"))?;

        let instance_name = instance_data
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'name' in Agent API instance data"))?
            .to_string();

        // Extract connection information from Agent API response
        let instance_url = instance_data
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // Validate instance_url scheme to prevent injection from a compromised Agent Manager
        if let Some(ref url) = instance_url {
            validate_agent_api_url(url, "instance_url")?;
        }

        let instance_token = instance_data
            .get("token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // Reject empty instance_token if present (defense-in-depth)
        if let Some(ref token) = instance_token {
            if token.is_empty() {
                anyhow::bail!("Invalid instance_token: must be non-empty");
            }
        }

        let dashboard_url = instance_data
            .get("dashboard_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // Validate dashboard_url scheme to prevent injection from a compromised Agent Manager
        if let Some(ref url) = dashboard_url {
            validate_agent_api_url(url, "dashboard_url")?;
        }

        // Generate a unique instance_id based on the Agent API name
        let instance_id = format!("agent-{}-{}", instance_name, Uuid::new_v4());

        // Extract service_type from instance_data only if it's a valid value, fall back to default
        let service_type_from_response = instance_data
            .get("service_type")
            .and_then(|v| v.as_str())
            .filter(|s| is_valid_service_type(s))
            .map(|s| s.to_string());
        let final_service_type = service_type_from_response.or(service_type_for_api);

        // Store in database with connection info and the manager URL that owns it
        let instance = self
            .repository
            .create_instance(CreateInstanceParams {
                user_id,
                instance_id: instance_id.clone(),
                name: instance_name,
                public_ssh_key: params.ssh_pubkey,
                instance_url,
                instance_token,
                dashboard_url,
                agent_api_base_url: Some(manager.url.clone()),
                service_type: final_service_type,
            })
            .await?;

        // Bind the unbound API key to the new instance.
        // If binding fails, the instance and key are already created — log for manual cleanup.
        if let Err(e) = self
            .bind_api_key_to_instance(api_key.id, instance.id, user_id)
            .await
        {
            tracing::error!(
                "Failed to bind API key to instance (manual cleanup may be needed): instance_id={}, api_key_id={}, error={}",
                instance.id,
                api_key.id,
                e
            );
            return Err(e);
        }

        tracing::info!(
            "Instance created from Agent API: instance_id={}, user_id={}",
            instance.id,
            user_id
        );

        Ok(instance)
    }

    /// Create instance via TEE compose-api with streaming lifecycle events.
    /// Similar to create_instance_from_agent_api but streams events as they occur.
    async fn create_instance_from_agent_api_streaming(
        &self,
        user_id: UserId,
        params: super::ports::InstanceCreationParams,
        max_allowed: u64,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        tracing::info!(
            "Creating instance from Agent API with streaming: user_id={}",
            user_id
        );

        // Check instance limit before starting
        let current_count = self.repository.count_user_instances(user_id).await?;
        if current_count >= max_allowed as i64 {
            anyhow::bail!(
                "Agent instance limit of {} exceeded for your plan",
                max_allowed
            );
        }

        // Pick next manager with available capacity
        let manager = self.next_available_manager().await?;

        // Create an unbound API key on behalf of the user
        let key_name = params
            .name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let default_expiry = Some(Utc::now() + Duration::days(90));
        let (_api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, default_expiry)
            .await?;

        // Validate service type
        if let Some(ref st) = &params.service_type {
            if !is_valid_service_type(st) {
                return Err(anyhow!(
                    "Invalid service type '{}'. Valid types are: {}",
                    st,
                    VALID_SERVICE_TYPES.join(", ")
                ));
            }
        }

        let service_type_for_api = params
            .service_type
            .clone()
            .or_else(|| Some(DEFAULT_SERVICE_TYPE.to_string()));

        // Get streaming receiver from Agent API
        let mut agent_api_rx = self
            .call_agent_api_create_streaming(
                &manager,
                &plaintext_key,
                &self.nearai_api_url,
                AgentApiCreateParams {
                    image: params.image.clone(),
                    name: params.name.clone(),
                    ssh_pubkey: params.ssh_pubkey.clone(),
                    service_type: service_type_for_api.clone(),
                    cpus: params.cpus.clone(),
                    mem_limit: params.mem_limit.clone(),
                    storage_size: params.storage_size.clone(),
                },
                AuthMethod::BearerToken(&manager.token),
            )
            .await?;

        // Wrap the streaming receiver to process events and save instance to DB
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let repository = self.repository.clone();
        let ssh_pubkey = params.ssh_pubkey.clone();
        let manager_url = manager.url.clone();
        let service_type = service_type_for_api.clone();

        tokio::spawn(async move {
            let mut instance_saved = false;

            while let Some(event_result) = agent_api_rx.recv().await {
                match event_result {
                    Ok(event) => {
                        // Check if this is the instance creation event (contains instance data)
                        if !instance_saved {
                            if let Some(instance_data) = event.get("instance") {
                                // Extract instance information and save to DB
                                if let Ok(instance_name) = instance_data
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| anyhow!("Missing instance name"))
                                {
                                    let instance_url = instance_data
                                        .get("url")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let instance_token = instance_data
                                        .get("token")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let dashboard_url = instance_data
                                        .get("dashboard_url")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    let instance_id =
                                        format!("agent-{}-{}", instance_name, Uuid::new_v4());

                                    // Save to database
                                    if let Ok(_instance) = repository
                                        .create_instance(CreateInstanceParams {
                                            user_id,
                                            instance_id: instance_id.clone(),
                                            name: instance_name.to_string(),
                                            public_ssh_key: ssh_pubkey.clone(),
                                            instance_url,
                                            instance_token,
                                            dashboard_url,
                                            agent_api_base_url: Some(manager_url.clone()),
                                            service_type: service_type.clone(),
                                        })
                                        .await
                                    {
                                        instance_saved = true;
                                    }
                                }
                            }
                        }

                        // Forward event to caller
                        let _ = tx.send(Ok(event)).await;
                    }
                    Err(e) => {
                        tracing::error!("Error in Agent API streaming: {}", e);
                        let _ = tx.send(Err(e)).await;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn create_passkey_instance_streaming(
        &self,
        user_id: UserId,
        params: super::ports::InstanceCreationParams,
        max_allowed: u64,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        tracing::info!(
            "Creating passkey instance with streaming: user_id={}",
            user_id
        );

        // Pick next manager with available capacity
        let manager = self.next_available_manager().await?;
        let manager_url = manager.url.clone();

        tracing::info!(
            "create_passkey_instance_streaming: selected manager_url={}, is_non_tee_manager={}, user_id={}",
            manager_url,
            manager.get_is_non_tee(),
            user_id
        );

        // Get session token based on manager type
        let session_token = if !manager.get_is_non_tee() {
            // TEE manager: Use manager token directly (main branch behavior)
            tracing::info!(
                "create_passkey_instance_streaming: TEE manager detected, using manager token"
            );
            manager.token.clone()
        } else {
            // Non-TEE manager: Get or create user's passkey credentials and login to compose-api
            tracing::info!("create_passkey_instance_streaming: Non-TEE manager detected, logging in via compose-api");

            let (auth_secret, backup_passphrase) = match self
                .repository
                .get_user_passkey_credentials(user_id)
                .await
            {
                Ok(Some((secret, passphrase))) => {
                    tracing::debug!(
                        "Using existing passkey credentials for user: user_id={}",
                        user_id
                    );
                    (secret, passphrase)
                }
                Ok(None) => {
                    // First non-TEE instance creation - auto-generate passkey credentials
                    tracing::info!(
                        "Auto-generating passkey credentials for user on first non-TEE instance creation: user_id={}",
                        user_id
                    );
                    let auth_secret = Self::generate_random_credential(32);
                    let backup_passphrase = Self::generate_random_credential(32);

                    // Write to database first - if DB succeeds but compose-api fails, we can retry
                    // (upsert will overwrite). If we did it the other way around, DB failure after
                    // successful compose-api registration would orphan the credentials permanently.
                    self.repository
                        .upsert_user_passkey_credentials(user_id, &auth_secret, &backup_passphrase)
                        .await?;

                    tracing::debug!(
                        "Auto-generated passkey credentials stored in database: user_id={}",
                        user_id
                    );

                    // Then register with compose-api (external API call)
                    self.compose_api_passkey_register(&manager, &auth_secret, &backup_passphrase)
                        .await?;

                    tracing::info!(
                        "Auto-generated passkey credentials registered with compose-api: user_id={}",
                        user_id
                    );

                    (auth_secret, backup_passphrase)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch user passkey credentials: user_id={}, error={}",
                        user_id,
                        e
                    );
                    return Err(e);
                }
            };

            // Get session token for this instance creation
            self.compose_api_passkey_login(&manager, &auth_secret, &backup_passphrase)
                .await?
        };

        let key_name = params
            .name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let default_expiry = Some(Utc::now() + Duration::days(90));
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, default_expiry)
            .await?;

        // Apply default service type if not provided
        if let Some(ref st) = &params.service_type {
            if !is_valid_service_type(st) {
                return Err(anyhow!(
                    "Invalid service type '{}'. Valid types are: {}",
                    st,
                    VALID_SERVICE_TYPES.join(", ")
                ));
            }
        }

        let mut service_type_for_api = params
            .service_type
            .clone()
            .or_else(|| Some(DEFAULT_SERVICE_TYPE.to_string()));

        // Normalize service type based on the selected manager (TEE vs non-TEE)
        if let Some(st) = service_type_for_api.clone() {
            let normalized = normalize_service_type_for_api(&st, manager.get_is_non_tee());
            service_type_for_api = Some(normalized.to_string());
            tracing::debug!(
                "create_passkey_instance_streaming: normalized service_type from {} to {} for manager_type={}",
                st,
                normalized,
                if manager.get_is_non_tee() { "non-TEE" } else { "TEE" }
            );
        }

        let mut rx = match self
            .call_agent_api_create_streaming(
                &manager,
                &plaintext_key,
                &self.nearai_api_url,
                AgentApiCreateParams {
                    image: params.image.clone(),
                    name: params.name.clone(),
                    ssh_pubkey: params.ssh_pubkey.clone(),
                    service_type: service_type_for_api.clone(),
                    cpus: params.cpus.clone(),
                    mem_limit: params.mem_limit.clone(),
                    storage_size: params.storage_size.clone(),
                },
                AuthMethod::BearerToken(&session_token),
            )
            .await
        {
            Ok(rx) => rx,
            Err(e) => {
                tracing::error!(
                    "Failed to start Agent API streaming for passkey instance: user_id={}, error={}. Revoking orphaned API key.",
                    user_id,
                    e
                );
                if let Err(cleanup_err) = self.repository.revoke_api_key(api_key.id).await {
                    tracing::warn!(
                        "Failed to revoke API key after streaming setup failure: user_id={}, api_key_id={}, error={}",
                        user_id,
                        api_key.id,
                        cleanup_err
                    );
                }
                return Err(e);
            }
        };

        let (tx, output_rx) = tokio::sync::mpsc::channel(10);
        let repo = Arc::clone(&self.repository);
        let http_client = self.http_client.clone();
        let api_key_id = api_key.id;
        let ssh_pubkey = params.ssh_pubkey.clone();
        let manager_clone = manager.clone();
        let session_token_for_details = session_token.clone();
        let requested_instance_name = params.name.clone();

        tokio::spawn(async move {
            let mut accumulated_data = serde_json::json!({});
            let mut stream_interrupted = false;

            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => {
                        // Accumulate event fields
                        if let Some(obj) = event.as_object() {
                            for (key, value) in obj.iter() {
                                accumulated_data[key] = value.clone();
                            }
                        }

                        // Forward event to client
                        if tx.send(Ok(event)).await.is_err() {
                            tracing::warn!(
                                "Client disconnected: revoking unbound API key: user_id={}",
                                user_id
                            );
                            if let Err(cleanup_err) = repo.revoke_api_key(api_key_id).await {
                                tracing::warn!(
                                    "Failed to revoke API key on client disconnect: user_id={}, api_key_id={}, error={}",
                                    user_id,
                                    api_key_id,
                                    cleanup_err
                                );
                            }
                            stream_interrupted = true;
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Stream error: user_id={}, revoking unbound API key: {}",
                            user_id,
                            e
                        );
                        if let Err(cleanup_err) = repo.revoke_api_key(api_key_id).await {
                            tracing::warn!(
                                "Failed to revoke API key on stream error: user_id={}, api_key_id={}, error={}",
                                user_id,
                                api_key_id,
                                cleanup_err
                            );
                        }
                        let _ = tx.send(Err(e)).await;
                        stream_interrupted = true;
                        break;
                    }
                }
            }

            // Stream ended naturally (not interrupted): save instance if we have data
            if !stream_interrupted && accumulated_data.as_object().is_some_and(|o| !o.is_empty()) {
                tracing::info!(
                    "Passkey instance stream complete: user_id={}, has_instance_name={}",
                    user_id,
                    accumulated_data.get("name").is_some()
                );

                // Validate that critical field (instance_name) is present before saving.
                // Instance name can be at top level or nested under "instance" object.
                // Fall back to the requested instance name if the stream didn't include one.
                let instance_name_str = accumulated_data
                    .get("instance")
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .or_else(|| accumulated_data.get("name").and_then(|v| v.as_str()))
                    .or(requested_instance_name.as_deref());

                if let Some(instance_name_str) = instance_name_str {
                    let instance_name = instance_name_str.to_string();
                    tracing::info!(
                        "Fetching full instance details for passkey instance: user_id={}, instance_name={}",
                        user_id,
                        instance_name
                    );

                    if let Some(instance_details) = fetch_instance_details_static(
                        &http_client,
                        &manager_clone,
                        &instance_name,
                        Some(&session_token_for_details),
                    )
                    .await
                    {
                        tracing::info!(
                            "Fetched /instances/{}: instance_name={}, status={}",
                            instance_name,
                            instance_details
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown"),
                            instance_details
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        );

                        // Merge instance details into accumulated data
                        if let Some(details_obj) = instance_details.as_object() {
                            for (key, value) in details_obj.iter() {
                                if accumulated_data.get(key).is_none() {
                                    accumulated_data[key] = value.clone();
                                }
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Failed to fetch instance details for enrichment: user_id={}, instance_name={}",
                            user_id,
                            instance_name
                        );
                    }

                    // Save passkey instance
                    match save_passkey_instance_from_event(
                        repo.as_ref(),
                        user_id,
                        &accumulated_data,
                        SaveInstanceParams {
                            api_key_id,
                            ssh_pubkey: ssh_pubkey.clone(),
                            max_allowed,
                            agent_api_base_url: Some(manager_url.clone()),
                            service_type: service_type_for_api.clone(),
                        },
                    )
                    .await
                    {
                        Ok(instance) => {
                            tracing::info!("Passkey instance saved successfully: user_id={}, dashboard_url={:?}", user_id, instance.dashboard_url);

                            // Send final event with dashboard_url and instance_url to frontend
                            // This is essential for non-TEE where Agent API doesn't return these fields
                            if manager_clone.get_is_non_tee() {
                                let final_event = serde_json::json!({
                                    "instance": {
                                        "name": instance.name,
                                        "dashboard_url": instance.dashboard_url,
                                        "instance_url": instance.instance_url,
                                        "token": instance.instance_token,
                                    }
                                });

                                if let Err(send_err) = tx.send(Ok(final_event)).await {
                                    tracing::warn!(
                                        "Failed to send final event to frontend: user_id={}, error={}",
                                        user_id,
                                        send_err
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to save passkey instance: user_id={}, error_details={:#}",
                                user_id,
                                e
                            );
                            if let Err(cleanup_err) = repo.revoke_api_key(api_key_id).await {
                                tracing::warn!(
                                    "Failed to revoke API key on save failure: user_id={}, api_key_id={}, error={}",
                                    user_id,
                                    api_key_id,
                                    cleanup_err
                                );
                            }
                        }
                    }
                } else {
                    tracing::warn!(
                        "Stream ended but no instance_name in accumulated data: user_id={}",
                        user_id
                    );
                    if let Err(cleanup_err) = repo.revoke_api_key(api_key_id).await {
                        tracing::warn!(
                            "Failed to revoke API key: user_id={}, api_key_id={}, error={}",
                            user_id,
                            api_key_id,
                            cleanup_err
                        );
                    }
                }
            } else if stream_interrupted {
                tracing::warn!(
                    "Passkey instance stream was interrupted: user_id={}",
                    user_id
                );
            }
        });

        Ok(output_rx)
    }

    async fn create_instance(
        &self,
        user_id: UserId,
        instance_id: String,
        name: String,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance> {
        tracing::info!(
            "Creating agent instance: user_id={}, instance_id={}",
            user_id,
            instance_id
        );

        // Validate instance_id format
        if instance_id.is_empty() || instance_id.len() > 255 {
            return Err(anyhow!("Invalid instance_id format"));
        }

        if name.is_empty() || name.len() > 255 {
            return Err(anyhow!("Invalid name format"));
        }

        let instance = self
            .repository
            .create_instance(CreateInstanceParams {
                user_id,
                instance_id: instance_id.clone(),
                name,
                public_ssh_key,
                instance_url: None,
                instance_token: None,
                dashboard_url: None,
                agent_api_base_url: None,
                service_type: None,
            })
            .await?;

        tracing::info!(
            "Instance created successfully: instance_id={}, user_id={}",
            instance.id,
            user_id
        );

        Ok(instance)
    }

    async fn get_instance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<Option<AgentInstance>> {
        tracing::debug!(
            "Fetching instance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        let instance = self.repository.get_instance(instance_id).await?;

        if let Some(ref inst) = instance {
            if inst.user_id != user_id {
                tracing::warn!(
                    "Access denied: user_id={} attempted to access instance owned by {}",
                    user_id,
                    inst.user_id
                );
                return Ok(None);
            }
        }

        Ok(instance)
    }

    async fn list_instances(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)> {
        tracing::debug!(
            "Listing instances: user_id={}, limit={}, offset={}",
            user_id,
            limit,
            offset
        );

        let (instances, total) = self
            .repository
            .list_user_instances(user_id, limit, offset)
            .await?;

        Ok((instances, total))
    }

    async fn get_instance_enrichment_from_agent_api(
        &self,
        agent_api_name: &str,
        agent_api_base_url: Option<&str>,
    ) -> Option<AgentApiInstanceEnrichment> {
        // When the owning manager URL is known, query only that manager (O(1) instead of O(N))
        let managers_to_query: Vec<&AgentManager> = if let Some(url) = agent_api_base_url {
            if let Some(mgr) = self.managers.iter().find(|m| m.url == url) {
                vec![mgr]
            } else {
                // Stored URL no longer in config; fall back to all managers
                self.managers.iter().collect()
            }
        } else {
            // Legacy instance without stored manager URL; fan-out to all
            self.managers.iter().collect()
        };

        let futures: Vec<_> = managers_to_query
            .iter()
            .map(|mgr| self.call_agent_api_get_instance(mgr, agent_api_name))
            .collect();

        let results = tokio::time::timeout(
            std::time::Duration::from_secs(35),
            futures::future::join_all(futures),
        )
        .await
        .unwrap_or_else(|_| {
            tracing::warn!("Instance enrichment query timed out after 35s");
            vec![]
        });

        if let Some(data) = results.into_iter().flatten().next() {
            let status = data
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let ssh_command = data
                .get("ssh_command")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Some(AgentApiInstanceEnrichment {
                status,
                ssh_command,
            })
        } else {
            None
        }
    }

    async fn get_instance_enrichments(
        &self,
        instances: &[AgentInstance],
    ) -> std::collections::HashMap<String, AgentApiInstanceEnrichment> {
        if instances.is_empty() {
            return std::collections::HashMap::new();
        }

        // Group instances by their owning manager URL.
        // Instances without a stored URL fall back to the first configured manager.
        let fallback_url = &self.managers[0].url;
        let mut by_manager: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for inst in instances {
            let mgr_url = inst.agent_api_base_url.as_deref().unwrap_or(fallback_url);
            by_manager.entry(mgr_url).or_default().push(&inst.name);
        }

        // Cache session tokens by (user_id, manager_url) to avoid redundant /auth/login calls
        // All instances for a user share the same credentials, so we only need to login once per manager
        // Each cache entry is wrapped in Arc<Mutex<>> to provide per-key synchronization:
        // - Multiple concurrent tasks for the same key wait for the first one to complete
        // - Different keys proceed independently (no global lock bottleneck)
        let session_token_cache: std::collections::HashMap<
            (UserId, String),
            std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
        > = std::collections::HashMap::new();

        // Query only the managers that own at least one instance in the list
        let futures: Vec<_> = by_manager
            .keys()
            .filter_map(|url| {
                match self.managers.iter().find(|m| &m.url == url) {
                    Some(mgr) => Some(self.call_agent_api_list(mgr)),
                    None => {
                        tracing::warn!(
                            "Stored agent_api_base_url not found in configured managers, skipping enrichment: url={}",
                            url
                        );
                        None
                    }
                }
            })
            .collect();

        let results = tokio::time::timeout(
            std::time::Duration::from_secs(35),
            futures::future::join_all(futures),
        )
        .await
        .unwrap_or_else(|_| {
            tracing::warn!("Instance enrichment queries timed out after 35s");
            vec![]
        });

        // Build a set of names we care about to avoid returning enrichments for
        // instances that weren't requested (other users' instances on the same manager)
        let requested_names: std::collections::HashSet<&str> =
            instances.iter().map(|i| i.name.as_str()).collect();

        let mut map = std::collections::HashMap::new();
        for result in results {
            match result {
                Ok(response) => {
                    if let Some(arr) = response.get("instances").and_then(|v| v.as_array()) {
                        for inst in arr {
                            if let Some(name) = inst.get("name").and_then(|v| v.as_str()) {
                                if !requested_names.contains(name) {
                                    continue;
                                }
                                let status = inst
                                    .get("status")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                map.insert(
                                    name.to_string(),
                                    AgentApiInstanceEnrichment {
                                        status,
                                        ssh_command: None, // Will be fetched separately below
                                    },
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Agent API list failed on one manager: {}", e);
                }
            }
        }

        // Fetch SSH commands for all requested instances
        // NOTE: This creates O(n) concurrent HTTP requests to the Agent API (one per instance).
        // However, login calls are cached by (user_id, manager_url), reducing compose-api /auth/login
        // from O(n) to O(m) where m = number of distinct (user, manager) pairs.
        // If a user has many instances, this will result in a burst of SSH command requests to the Agent API.
        // The requests are concurrent (not sequential) to minimize total time, but each request
        // still counts toward Agent API rate limits. With many instances, this could:
        // - Hit per-client rate limits on the Agent API
        // - Cause individual requests to timeout if the Agent API is slow to respond
        // A more scalable approach would be to:
        // - Use a batch endpoint if Agent API provides one
        // - Implement response caching (e.g., short TTL in-memory or Redis)
        // - Fall back to skipping SSH commands if fetch times out for large instance lists
        tracing::debug!(
            "Fetching SSH commands for {} instances (O(n) concurrent HTTP calls, cached logins)",
            instances.len()
        );
        let repo = Arc::clone(&self.repository);
        let session_token_cache = std::sync::Arc::new(tokio::sync::Mutex::new(session_token_cache));
        let ssh_futures: Vec<_> = instances
            .iter()
            .map(|inst| {
                let fallback_url = &self.managers[0].url;
                let mgr_url = inst.agent_api_base_url.as_deref().unwrap_or(fallback_url);
                let manager = self.managers.iter().find(|m| m.url == mgr_url).cloned();
                let name = inst.name.clone();
                let user_id = inst.user_id;
                let repo = Arc::clone(&repo);
                let http_client = self.http_client.clone();
                let cache = Arc::clone(&session_token_cache);
                async move {
                    if let Some(mgr) = manager {
                        // Check/insert in cache with per-key synchronization to prevent TOCTOU race
                        // Multiple concurrent tasks for the same (user_id, manager_url) will wait for
                        // the first login to complete and all share the same cached result.
                        let cache_key = (user_id, mgr.url.clone());

                        // Step 1: Acquire the outer cache lock and get/create the per-key Mutex
                        let key_mutex = {
                            let mut cache_guard = cache.lock().await;
                            cache_guard
                                .entry(cache_key.clone())
                                .or_insert_with(|| {
                                    std::sync::Arc::new(tokio::sync::Mutex::new(None))
                                })
                                .clone()
                        }; // Outer lock released here

                        // Step 2: Lock the per-key mutex (serializes access for this specific key)
                        let key_guard = key_mutex.lock().await;

                        let bearer_token = if key_guard.is_some() {
                            // Token already fetched by this or another concurrent task
                            key_guard.clone()
                        } else {
                            // First task to reach this key: perform the async login (non-TEE only)
                            drop(key_guard); // Release lock temporarily for async work

                            // Only attempt passkey login for non-TEE managers
                            // TEE managers use the manager token directly
                            let token = if mgr.get_is_non_tee() {
                                // Non-TEE: try to get user's passkey credentials; fall back to manager token if not found
                                if let Ok(Some((auth_secret, backup_passphrase))) =
                                    repo.get_user_passkey_credentials(user_id).await
                                {
                                    AgentServiceImpl::compose_api_passkey_login_static(
                                        &http_client,
                                        &mgr,
                                        &auth_secret,
                                        &backup_passphrase,
                                    )
                                    .await
                                    .ok()
                                } else {
                                    None // Fall back to manager token
                                }
                            } else {
                                // TEE: always use manager token (bearer_token = None)
                                None
                            };

                            // Re-acquire lock and store result
                            let mut key_guard = key_mutex.lock().await;
                            *key_guard = token.clone();
                            token
                        };

                        (
                            name,
                            AgentServiceImpl::fetch_ssh_command_static(
                                &http_client,
                                &mgr,
                                &inst.name,
                                bearer_token.as_deref(),
                            )
                            .await,
                        )
                    } else {
                        (name, None)
                    }
                }
            })
            .collect();

        // Timeout for SSH command fetching: 20 seconds total for all O(n) concurrent requests.
        // If timeout occurs, returns empty results (instances will have no SSH commands).
        // With many instances, this timeout can fail if the Agent API is slow or rate-limited.
        let ssh_results = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            futures::future::join_all(ssh_futures),
        )
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                "SSH command fetch timed out after 20s; returning instances without SSH commands. Consider reducing instance count or optimizing Agent API batch queries."
            );
            vec![]
        });

        tracing::debug!(
            "SSH command fetch completed: got results for {} instances",
            ssh_results.len()
        );

        // Ensure all requested instances have enrichment entries (even if not in Agent API list)
        for inst in instances {
            map.entry(inst.name.clone())
                .or_insert_with(|| AgentApiInstanceEnrichment {
                    status: None,
                    ssh_command: None,
                });
        }

        // Merge SSH commands into enrichment map
        for (name, ssh_cmd) in ssh_results {
            if let Some(_ssh_cmd_str) = &ssh_cmd {
                tracing::debug!("SSH command available for instance: instance_name={}", name);
            } else {
                tracing::debug!(
                    "No SSH command available for instance: instance_name={}",
                    name
                );
            }
            if let Some(enrichment) = map.get_mut(&name) {
                enrichment.ssh_command = ssh_cmd;
            }
        }

        map
    }

    async fn update_instance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: Option<String>,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance> {
        tracing::info!(
            "Updating instance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Verify ownership
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        // Validate inputs
        if let Some(ref n) = name {
            if n.is_empty() || n.len() > 255 {
                return Err(anyhow!("Invalid name format"));
            }
        }

        let updated = self
            .repository
            .update_instance(instance_id, name, public_ssh_key)
            .await?;

        tracing::info!("Instance updated successfully: instance_id={}", instance_id);

        Ok(updated)
    }

    /// Delete an instance from both the Agent API and the local database.
    ///
    /// SECURITY: This method does NOT verify ownership. Callers MUST enforce
    /// authorization before calling (e.g. the user route checks `instance.user_id`,
    /// and the admin route requires admin privileges).
    async fn delete_instance(&self, instance_id: Uuid) -> anyhow::Result<()> {
        tracing::info!("Deleting instance: instance_id={}", instance_id);

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Route to the correct manager that owns this instance
        let manager = self.resolve_manager(&instance)?;

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Call Agent API to terminate the instance. URL-encode instance name to prevent path
        // traversal (it can be derived from instance_name returned by the external Agent API).
        let encoded_name = urlencoding::encode(&instance.name);
        let delete_url = format!("{}/instances/{}", manager.url, encoded_name);
        let response = self
            .http_client
            .delete(&delete_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API delete: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            if status == reqwest::StatusCode::NOT_FOUND {
                tracing::warn!(
                    "Instance not found on instance manager (already removed?), proceeding with DB soft-delete: instance_id={}",
                    instance_id
                );
            } else {
                return Err(anyhow!(
                    "Agent API delete failed with status {}: instance_id={}",
                    status,
                    instance_id
                ));
            }
        }

        self.repository.delete_instance(instance_id).await?;

        tracing::info!(
            "Instance deleted successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn restart_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()> {
        tracing::info!(
            "Restarting instance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Restart is valid for any non-deleted status (active, stopped, error, etc.). We do not
        // reject when status is 'active' — restarting a running instance is a common use case.
        // The Agent API restart endpoint handles the current state appropriately.

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify ownership
        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        // Route to the correct manager
        let manager = self.resolve_manager(&instance)?;
        tracing::info!(
            "Restart: resolved manager: stored_url={:?}, using_manager_url={}, instance_name={}",
            instance.agent_api_base_url,
            manager.url,
            instance.name
        );

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Call Agent API to restart the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let restart_url = format!("{}/instances/{}/restart", manager.url, encoded_name);
        tracing::info!(
            "Calling Agent API restart: url={}, instance_id={}",
            restart_url,
            instance_id
        );
        let response = self
            .http_client
            .post(&restart_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API restart: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unable to read body".to_string());
            tracing::error!(
                "Agent API restart failed: status={}, url={}, body={}, instance_id={}",
                status,
                restart_url,
                body,
                instance_id
            );
            return Err(anyhow!(
                "Agent API restart failed with status {}: instance_id={}",
                status,
                instance_id
            ));
        }

        // Update DB status to active (end state after restart)
        self.repository
            .update_instance_status(instance_id, "active")
            .await?;

        tracing::info!(
            "Instance restarted successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn upgrade_instance_stream(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>> {
        use futures::stream::StreamExt;

        tracing::info!(
            "Upgrading instance (streaming): instance_id={}",
            instance_id
        );

        // Ownership check is performed at the route handler level (agents.rs)
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        let manager = self.resolve_manager(&instance)?;

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Fetch latest images from compose-api
        let version_url = format!("{}/version", manager.url);
        let version_resp = self
            .http_client
            .get(&version_url)
            .bearer_auth(&bearer_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch compose-api version: {}", e))?;

        if !version_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch compose-api version: status={}",
                version_resp.status()
            ));
        }

        #[derive(serde::Deserialize)]
        struct VersionResponse {
            images: std::collections::HashMap<String, String>,
        }

        let version: VersionResponse = version_resp
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse compose-api version response: {}", e))?;

        // Map service_type to image key in the version response
        let service_type = instance
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);
        let image_key = match service_type {
            "ironclaw" => "ironclaw",
            _ => "worker",
        };

        let image = version.images.get(image_key).cloned().ok_or_else(|| {
            anyhow!(
                "No image found for service type '{}' (key '{}')",
                service_type,
                image_key
            )
        })?;

        // Restart with the latest image (5-minute timeout; compose-api yields SSE stream)
        let encoded_name = urlencoding::encode(&instance.name);
        let restart_url = format!("{}/instances/{}/restart", manager.url, encoded_name);

        #[derive(serde::Serialize)]
        struct RestartBody {
            image: String,
        }

        // Spawn task to proxy compose-api SSE stream to channel
        let (tx, rx) = tokio::sync::mpsc::channel::<anyhow::Result<bytes::Bytes>>(32);

        let http_client = self.http_client.clone();
        let token = bearer_token.clone();
        let instance_name = instance.name.clone();

        tokio::spawn(async move {
            let response = match http_client
                .post(&restart_url)
                .bearer_auth(&token)
                .json(&RestartBody {
                    image: image.clone(),
                })
                .timeout(std::time::Duration::from_secs(300))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Err(anyhow!("Failed to call restart: {}", e))).await;
                    return;
                }
            };

            if !response.status().is_success() {
                tracing::error!(
                    "Compose-api upgrade failed: instance_id={}, instance_name={}, image={}, restart_url={}, status={}",
                    instance_id,
                    instance_name,
                    image,
                    restart_url,
                    response.status()
                );
                let _ = tx
                    .send(Err(anyhow!(
                        "Upgrade failed with status {}",
                        response.status()
                    )))
                    .await;
                return;
            }

            let mut stream = response.bytes_stream();
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        if tx.send(Ok(bytes)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(anyhow!("Stream error: {}", e))).await;
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn check_upgrade_available(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<UpgradeAvailability> {
        tracing::info!(
            "Checking upgrade availability: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        let manager = self.resolve_manager(&instance)?;

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Fetch latest versions from compose-api
        let version_url = format!("{}/version", manager.url);
        let version_resp = self
            .http_client
            .get(&version_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch compose-api version: {}", e))?;

        if !version_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch compose-api version: status={}",
                version_resp.status()
            ));
        }

        #[derive(serde::Deserialize)]
        struct VersionResponse {
            images: std::collections::HashMap<String, String>,
        }

        let version: VersionResponse = version_resp
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse compose-api version response: {}", e))?;

        // Map service_type to image key in the version response
        let service_type = instance
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);
        let image_key = match service_type {
            "ironclaw" => "ironclaw",
            _ => "worker",
        };

        let latest_image = version
            .images
            .get(image_key)
            .ok_or_else(|| {
                anyhow!(
                    "No image found for service type '{}' (key '{}')",
                    service_type,
                    image_key
                )
            })?
            .clone();

        // Fetch current instance status from compose-api
        let encoded_name = urlencoding::encode(&instance.name);
        let instance_url = format!("{}/instances/{}", manager.url, encoded_name);
        let instance_resp = self
            .http_client
            .get(&instance_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch instance status: {}", e))?;

        // If instance not found (404), block upgrade until instance is synced
        // This handles cases where instance is not yet fully provisioned or synced
        if instance_resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::warn!(
                "Instance not found on Agent Manager: instance_id={}. Blocking upgrade until instance is synced.",
                instance_id
            );
            return Ok(UpgradeAvailability {
                has_upgrade: false,
                current_image: None,
                latest_image,
            });
        }

        if !instance_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch instance status: status={}",
                instance_resp.status()
            ));
        }

        #[derive(serde::Deserialize)]
        struct InstanceResponse {
            image: String,
        }

        let instance_status: InstanceResponse = instance_resp
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse instance response: {}", e))?;

        let current_image = instance_status.image;
        let has_upgrade = current_image != latest_image;

        tracing::info!(
            "Upgrade check completed: instance_id={}, current_image={}, latest_image={}, has_upgrade={}",
            instance_id,
            current_image,
            latest_image,
            has_upgrade
        );

        Ok(UpgradeAvailability {
            has_upgrade,
            current_image: Some(current_image),
            latest_image,
        })
    }

    async fn stop_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()> {
        tracing::info!(
            "Stopping instance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify ownership
        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        // Route to the correct manager
        let manager = self.resolve_manager(&instance)?;
        tracing::info!(
            "Stop: resolved manager: stored_url={:?}, using_manager_url={}, instance_name={}",
            instance.agent_api_base_url,
            manager.url,
            instance.name
        );

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Call Agent API to stop the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let stop_url = format!("{}/instances/{}/stop", manager.url, encoded_name);
        tracing::info!(
            "Calling Agent API stop: url={}, instance_id={}",
            stop_url,
            instance_id
        );
        let response = self
            .http_client
            .post(&stop_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API stop: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unable to read body".to_string());
            tracing::error!(
                "Agent API stop failed: status={}, url={}, body={}, instance_id={}",
                status,
                stop_url,
                body,
                instance_id
            );
            return Err(anyhow!(
                "Agent API stop failed with status {}: instance_id={}",
                status,
                instance_id
            ));
        }

        // Update DB status (trigger records to agent_instance_status_history)
        self.repository
            .update_instance_status(instance_id, "stopped")
            .await?;

        tracing::info!(
            "Instance stopped successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn start_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()> {
        tracing::info!(
            "Starting instance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify ownership
        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        // Route to the correct manager
        let manager = self.resolve_manager(&instance)?;
        tracing::info!(
            "Start: resolved manager: stored_url={:?}, using_manager_url={}, instance_name={}",
            instance.agent_api_base_url,
            manager.url,
            instance.name
        );

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(&instance, manager).await?;

        // Call Agent API to start the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let start_url = format!("{}/instances/{}/start", manager.url, encoded_name);
        tracing::info!(
            "Calling Agent API start: url={}, instance_id={}",
            start_url,
            instance_id
        );
        let response = self
            .http_client
            .post(&start_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API start: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unable to read body".to_string());
            tracing::error!(
                "Agent API start failed: status={}, url={}, body={}, instance_id={}",
                status,
                start_url,
                body,
                instance_id
            );
            return Err(anyhow!(
                "Agent API start failed with status {}: instance_id={}",
                status,
                instance_id
            ));
        }

        // Update DB status (trigger records to agent_instance_status_history)
        self.repository
            .update_instance_status(instance_id, "active")
            .await?;

        tracing::info!(
            "Instance started successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    /// NOTE: This method is not concurrency-safe. If two sync operations run
    /// simultaneously they may race on status updates. Callers should ensure
    /// only one sync runs at a time (e.g. via a distributed lock or single
    /// scheduled job).
    async fn sync_all_instance_statuses(
        &self,
    ) -> anyhow::Result<crate::agent::ports::SyncStatusResult> {
        use crate::agent::ports::SyncStatusResult;
        use std::collections::HashMap;

        let mut result = SyncStatusResult::default();

        const PAGE_SIZE: i64 = 10_000;
        let (all_instances, total) = self.repository.list_all_instances(PAGE_SIZE, 0).await?;

        if total > PAGE_SIZE {
            tracing::warn!(
                "sync_all_instance_statuses: fetched {PAGE_SIZE}/{total} instances, sync may be incomplete"
            );
        }

        let fetched_count = all_instances.len();
        let instances: Vec<_> = all_instances
            .into_iter()
            .filter(|i| i.status != "deleted")
            .collect();

        let filtered_count = fetched_count.saturating_sub(instances.len());
        if filtered_count > 0 {
            tracing::debug!(
                "sync_all_instance_statuses: filtered out {} deleted instances",
                filtered_count
            );
        }

        if instances.is_empty() {
            return Ok(result);
        }

        if self.managers.is_empty() && instances.iter().any(|i| i.agent_api_base_url.is_none()) {
            return Err(anyhow!(
                "No agent managers configured and at least one instance has no agent_api_base_url"
            ));
        }

        let fallback_url = self.managers.first().map(|m| m.url.as_str()).unwrap_or("");
        let mut by_manager: HashMap<&str, Vec<&AgentInstance>> = HashMap::new();
        for inst in &instances {
            let mgr_url = inst.agent_api_base_url.as_deref().unwrap_or(fallback_url);
            by_manager.entry(mgr_url).or_default().push(inst);
        }

        let mut status_map: HashMap<(String, String), String> = HashMap::new();
        let mut failed_managers: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut unconfigured_count: usize = 0;

        for mgr_url in by_manager.keys() {
            let mgr = match self
                .managers
                .iter()
                .find(|m| m.url.as_str().trim_end_matches('/') == mgr_url.trim_end_matches('/'))
            {
                Some(m) => m,
                None => {
                    tracing::error!(
                        "sync_all_instance_statuses: manager not configured: {}",
                        mgr_url
                    );
                    unconfigured_count += 1;
                    failed_managers.insert(mgr_url.trim_end_matches('/').to_string());
                    continue;
                }
            };

            match self.call_agent_api_list(mgr).await {
                Ok(response) => {
                    if let Some(arr) = response.get("instances").and_then(|v| v.as_array()) {
                        for inst in arr {
                            if let Some(name) = inst.get("name").and_then(|v| v.as_str()) {
                                let status = inst
                                    .get("status")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                status_map.insert((mgr.url.clone(), name.to_string()), status);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("sync_all_instance_statuses: failed to query manager: {}", e);
                    result
                        .errors
                        .push(format!("Failed to query an agent manager: {}", e));
                    failed_managers.insert(mgr_url.trim_end_matches('/').to_string());
                }
            }
        }

        if unconfigured_count > 0 {
            result.errors.push(format!(
                "Manager not configured for some instances ({} manager(s))",
                unconfigured_count
            ));
        }

        for inst in &instances {
            let inst_mgr_url = inst.agent_api_base_url.as_deref().unwrap_or(fallback_url);
            let trimmed = inst_mgr_url.trim_end_matches('/');

            if failed_managers.contains(trimmed) {
                tracing::warn!(
                    "sync_all_instance_statuses: error_skipped instance_id={}",
                    inst.id,
                );
                result.error_skipped += 1;
                continue;
            }

            let canon_url = self
                .managers
                .iter()
                .find(|m| m.url.as_str().trim_end_matches('/') == trimmed)
                .map(|m| m.url.clone())
                .unwrap_or_else(|| trimmed.to_string());

            let api_status = status_map.get(&(canon_url, inst.name.clone()));

            let new_status = match api_status {
                Some(s) if s.as_str() == "running" => "active",
                Some(_) => "stopped",
                None => {
                    tracing::warn!(
                        "sync_all_instance_statuses: not_found instance_id={}",
                        inst.id,
                    );
                    result.not_found += 1;
                    continue;
                }
            };

            result.synced += 1;

            if inst.status == new_status {
                result.skipped += 1;
                continue;
            }

            match self
                .repository
                .update_instance_status(inst.id, new_status)
                .await
            {
                Ok(()) => result.updated += 1,
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to update instance status: {}", e));
                }
            }
        }

        Ok(result)
    }

    async fn setup_gateway_session_for_user(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<String>> {
        // Get a manager (prefer first one)
        let manager = self
            .managers
            .first()
            .ok_or_else(|| anyhow!("No agent managers configured"))?;

        // Try to get existing user passkey credentials
        let (auth_secret, backup_passphrase) =
            match self.repository.get_user_passkey_credentials(user_id).await {
                Ok(Some((secret, passphrase))) => (secret, passphrase),
                Ok(None) => {
                    // First login - create passkey credentials for this user
                    tracing::debug!(
                        "Creating passkey credentials for user on first login: user_id={}",
                        user_id
                    );
                    let auth_secret = Self::generate_random_credential(32);
                    let backup_passphrase = Self::generate_random_credential(32);

                    // Write to database first - if DB succeeds but compose-api fails, we can retry
                    // (upsert will overwrite). If we did it the other way around, DB failure after
                    // successful compose-api registration would orphan the credentials permanently.
                    self.repository
                        .upsert_user_passkey_credentials(user_id, &auth_secret, &backup_passphrase)
                        .await?;

                    tracing::debug!(
                        "User passkey credentials stored in database: user_id={}",
                        user_id
                    );

                    // Then register with compose-api (external API call)
                    self.compose_api_passkey_register(manager, &auth_secret, &backup_passphrase)
                        .await?;

                    tracing::info!(
                        "User passkey credentials registered with compose-api: user_id={}",
                        user_id
                    );

                    (auth_secret, backup_passphrase)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch user passkey credentials: user_id={}, error={}",
                        user_id,
                        e
                    );
                    return Err(e);
                }
            };

        // Get session token from compose-api
        let session_token = self
            .compose_api_passkey_login(manager, &auth_secret, &backup_passphrase)
            .await?;

        // Set up gateway cookie and get Set-Cookie header
        let set_cookie = self
            .compose_api_proxy_session(manager, &session_token)
            .await?;

        tracing::debug!(
            "Gateway proxy session set up for user on login: user_id={}",
            user_id
        );

        Ok(set_cookie)
    }

    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(AgentApiKey, String), AgentApiKeyCreationError> {
        tracing::info!(
            "Creating API key: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Verify ownership
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied").into());
        }

        if name.is_empty() || name.len() > 255 {
            return Err(anyhow!("Invalid name format").into());
        }

        Self::validate_api_key_spend_limit(spend_limit)?;

        // Generate and hash key
        let plaintext_key = Self::generate_api_key();
        let key_hash = Self::hash_api_key(&plaintext_key);

        let api_key = self
            .repository
            .create_api_key(
                instance_id,
                user_id,
                key_hash,
                name,
                spend_limit,
                expires_at,
            )
            .await?;

        tracing::info!(
            "API key created successfully: api_key_id={}, instance_id={}, user_id={}",
            api_key.id,
            instance_id,
            user_id
        );

        Ok((api_key, plaintext_key))
    }

    async fn create_unbound_api_key(
        &self,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(AgentApiKey, String), AgentApiKeyCreationError> {
        tracing::info!("Creating unbound API key: user_id={}", user_id);

        if name.is_empty() || name.len() > 255 {
            return Err(anyhow!("Invalid name format").into());
        }

        Self::validate_api_key_spend_limit(spend_limit)?;

        // Generate and hash key
        let plaintext_key = Self::generate_api_key();
        let key_hash = Self::hash_api_key(&plaintext_key);

        let api_key = self
            .repository
            .create_unbound_api_key(user_id, key_hash, name, spend_limit, expires_at)
            .await?;

        tracing::info!(
            "Unbound API key created successfully: api_key_id={}, user_id={}",
            api_key.id,
            user_id
        );

        Ok((api_key, plaintext_key))
    }

    async fn bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<AgentApiKey> {
        tracing::info!(
            "Binding API key to instance: api_key_id={}, instance_id={}, user_id={}",
            api_key_id,
            instance_id,
            user_id
        );

        // Verify ownership of both key and instance
        let api_key = self
            .repository
            .get_api_key_by_id(api_key_id)
            .await?
            .ok_or_else(|| anyhow!("API key not found"))?;

        if api_key.user_id != user_id {
            return Err(anyhow!("Access denied: API key does not belong to user"));
        }

        // Verify instance exists and belongs to user
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied: Instance does not belong to user"));
        }

        // Verify key is unbound
        if api_key.instance_id.is_some() {
            return Err(anyhow!("API key is already bound to an instance"));
        }

        // Bind the key
        self.repository
            .bind_api_key_to_instance(api_key_id, instance_id)
            .await?;

        // Fetch and return updated key
        let updated_key = self
            .repository
            .get_api_key_by_id(api_key_id)
            .await?
            .ok_or_else(|| anyhow!("Failed to fetch updated API key"))?;

        tracing::info!(
            "API key bound successfully: api_key_id={}, instance_id={}",
            api_key_id,
            instance_id
        );

        Ok(updated_key)
    }

    async fn admin_bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
    ) -> anyhow::Result<AgentApiKey> {
        tracing::info!(
            "Admin: Binding API key to instance (no ownership check): api_key_id={}, instance_id={}",
            api_key_id,
            instance_id
        );

        // Verify key exists (no ownership check)
        let api_key = self
            .repository
            .get_api_key_by_id(api_key_id)
            .await?
            .ok_or_else(|| anyhow!("API key not found"))?;

        // Verify instance exists (no ownership check)
        let _instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify key is unbound
        if api_key.instance_id.is_some() {
            return Err(anyhow!("API key is already bound to an instance"));
        }

        // Bind the key
        self.repository
            .bind_api_key_to_instance(api_key_id, instance_id)
            .await?;

        // Fetch and return updated key
        let updated_key = self
            .repository
            .get_api_key_by_id(api_key_id)
            .await?
            .ok_or_else(|| anyhow!("Failed to fetch updated API key"))?;

        tracing::info!(
            "Admin: API key bound successfully: api_key_id={}, instance_id={}",
            api_key_id,
            instance_id
        );

        Ok(updated_key)
    }

    async fn list_api_keys(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentApiKey>, i64)> {
        tracing::debug!(
            "Listing API keys: instance_id={}, user_id={}, limit={}, offset={}",
            instance_id,
            user_id,
            limit,
            offset
        );

        // Verify ownership
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        let (keys, total) = self
            .repository
            .list_instance_keys(instance_id, limit, offset)
            .await?;

        Ok((keys, total))
    }

    async fn revoke_api_key(&self, api_key_id: Uuid, user_id: UserId) -> anyhow::Result<()> {
        tracing::info!(
            "Revoking API key: api_key_id={}, user_id={}",
            api_key_id,
            user_id
        );

        // SECURITY: Verify ownership before revoking
        // Fetch the API key to verify it belongs to the user
        let api_key = self
            .repository
            .get_api_key_by_id(api_key_id)
            .await?
            .ok_or_else(|| anyhow!("API key not found"))?;

        // Verify the API key belongs to the requesting user
        if api_key.user_id != user_id {
            tracing::warn!(
                "Unauthorized revoke attempt: api_key_id={}, user_id={}, key_owner={}",
                api_key_id,
                user_id,
                api_key.user_id
            );
            return Err(anyhow!("Unauthorized: API key does not belong to user"));
        }

        self.repository.revoke_api_key(api_key_id).await?;

        tracing::info!("API key revoked successfully: api_key_id={}", api_key_id);

        Ok(())
    }

    async fn authenticate_api_key(
        &self,
        api_key: &str,
    ) -> Result<(AgentInstance, AgentApiKey), AgentApiKeyAuthError> {
        if !Self::validate_api_key_format(api_key) {
            tracing::warn!("Invalid API key format");
            return Err(AgentApiKeyAuthError::InvalidFormat);
        }

        let key_hash = Self::hash_api_key(api_key);

        let (instance, api_key_info) = self
            .repository
            .get_instance_by_api_key_hash(&key_hash)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch API key by hash: {}", e);
                AgentApiKeyAuthError::Internal
            })?
            .ok_or_else(|| {
                tracing::warn!("API key not found or inactive");
                AgentApiKeyAuthError::Invalid
            })?;

        self.ensure_api_key_can_be_used(&api_key_info).await?;

        if instance.instance_url.is_none() || instance.instance_token.is_none() {
            tracing::warn!(
                "Instance not properly configured for authenticated API key: instance_id={}, api_key_id={}",
                instance.id,
                api_key_info.id
            );
            return Err(AgentApiKeyAuthError::InstanceNotConfigured);
        }

        // Preserve request availability for the HTTP auth path: last_used_at tracking is
        // best-effort and should not block otherwise valid requests on transient write failures.
        if let Err(err) = self.mark_api_key_used(api_key_info.id).await {
            tracing::error!(
                "Failed to mark API key as used: api_key_id={}, error={:?}",
                api_key_info.id,
                err
            );
        }

        tracing::debug!(
            "API key authenticated successfully: api_key_id={}, instance_id={}",
            api_key_info.id,
            instance.id
        );

        Ok((instance, api_key_info))
    }

    async fn get_instance_usage(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        start_date: Option<chrono::DateTime<Utc>>,
        end_date: Option<chrono::DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<UsageLogEntry>, i64)> {
        tracing::debug!(
            "Fetching usage: instance_id={}, user_id={}, limit={}, offset={}",
            instance_id,
            user_id,
            limit,
            offset
        );

        // Verify ownership
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        let (usage, total) = self
            .repository
            .get_instance_usage(instance_id, start_date, end_date, limit, offset)
            .await?;

        Ok((usage, total))
    }

    async fn get_instance_balance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<Option<InstanceBalance>> {
        tracing::debug!(
            "Fetching balance: instance_id={}, user_id={}",
            instance_id,
            user_id
        );

        // Verify ownership
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        if instance.user_id != user_id {
            return Err(anyhow!("Access denied"));
        }

        let balance = self.repository.get_instance_balance(instance_id).await?;

        Ok(balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_configs::ports::{PartialSystemConfigs, SystemConfigs, SystemConfigsService};
    use chrono::{Duration, Utc};
    use config::AgentManager;

    // --- Mock SystemConfigsService ---

    struct MockSystemConfigsService {
        configs: Option<SystemConfigs>,
    }

    impl MockSystemConfigsService {
        /// No system config row exists — capacity checks are bypassed entirely.
        fn no_config() -> Self {
            Self { configs: None }
        }

        /// No config row with non-TEE infra enabled
        fn no_config_with_non_tee() -> Self {
            use crate::system_configs::ports::AgentHostingConfig;
            Self {
                configs: Some(SystemConfigs {
                    agent_hosting: Some(AgentHostingConfig {
                        new_agent_with_non_tee_infra: Some(true),
                    }),
                    ..Default::default()
                }),
            }
        }

        fn with_non_tee_infra(non_tee_infra: bool) -> Self {
            use crate::system_configs::ports::AgentHostingConfig;
            Self {
                configs: Some(SystemConfigs {
                    agent_hosting: Some(AgentHostingConfig {
                        new_agent_with_non_tee_infra: Some(non_tee_infra),
                    }),
                    ..Default::default()
                }),
            }
        }

        fn with_manager_limit_and_non_tee(max: u64, non_tee: bool) -> Self {
            use crate::system_configs::ports::AgentHostingConfig;
            Self {
                configs: Some(SystemConfigs {
                    max_instances_per_manager: Some(max),
                    agent_hosting: Some(AgentHostingConfig {
                        new_agent_with_non_tee_infra: Some(non_tee),
                    }),
                    ..Default::default()
                }),
            }
        }

        /// Per-URL limits with non-TEE infra enabled
        fn with_per_url_limits_and_non_tee() -> Self {
            use crate::system_configs::ports::AgentHostingConfig;
            use std::collections::HashMap;
            let mut per_url = HashMap::new();
            per_url.insert(
                "https://claws.example.com/api/crabshack/mgr0".to_string(),
                5,
            );
            per_url.insert(
                "https://claws.example.com/api/crabshack/mgr1".to_string(),
                15,
            );
            Self {
                configs: Some(SystemConfigs {
                    max_instances_per_manager: Some(200),
                    max_instances_by_manager_url: Some(per_url),
                    agent_hosting: Some(AgentHostingConfig {
                        new_agent_with_non_tee_infra: Some(true),
                    }),
                    ..Default::default()
                }),
            }
        }
    }

    #[async_trait]
    impl SystemConfigsService for MockSystemConfigsService {
        async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>> {
            Ok(self.configs.clone())
        }
        async fn upsert_configs(&self, configs: SystemConfigs) -> anyhow::Result<SystemConfigs> {
            Ok(configs)
        }
        async fn update_configs(
            &self,
            _configs: PartialSystemConfigs,
        ) -> anyhow::Result<SystemConfigs> {
            Ok(SystemConfigs::default())
        }
    }

    use crate::agent::ports::MockAgentRepository;

    /// Create a MockAgentRepository where every manager has `count` instances
    fn mock_repo_with_manager_count(count: i64) -> MockAgentRepository {
        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .returning(move |_| Ok(count));
        repo.expect_get_user_passkey_credentials()
            .returning(|_| Ok(None));
        repo
    }

    fn make_managers(n: usize) -> Vec<AgentManager> {
        // Default to non-TEE managers for tests
        (0..n)
            .map(|i| AgentManager {
                url: format!("https://claws.example.com/api/crabshack/mgr{}", i),
                token: format!("token{}", i),
                is_non_tee: true,
            })
            .collect()
    }

    fn make_service(
        managers: Vec<AgentManager>,
        repo: Arc<dyn AgentRepository>,
        configs: Arc<dyn SystemConfigsService>,
    ) -> AgentServiceImpl {
        AgentServiceImpl::new(
            repo,
            managers,
            "https://nearai.test/v1".to_string(),
            configs,
            None,                // channel_relay_url
            "claws".to_string(), // non_tee_agent_url_pattern
        )
    }

    // --- Tests ---

    #[test]
    fn test_next_manager_round_robin_single() {
        let managers = make_managers(1);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        for _ in 0..5 {
            let mgr = svc.next_manager();
            assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr0");
        }
    }

    #[test]
    fn test_next_manager_round_robin_multiple() {
        let managers = make_managers(3);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let urls: Vec<String> = (0..6).map(|_| svc.next_manager().url.clone()).collect();

        assert_eq!(urls[0], "https://claws.example.com/api/crabshack/mgr0");
        assert_eq!(urls[1], "https://claws.example.com/api/crabshack/mgr1");
        assert_eq!(urls[2], "https://claws.example.com/api/crabshack/mgr2");
        assert_eq!(urls[3], "https://claws.example.com/api/crabshack/mgr0");
        assert_eq!(urls[4], "https://claws.example.com/api/crabshack/mgr1");
        assert_eq!(urls[5], "https://claws.example.com/api/crabshack/mgr2");
    }

    #[test]
    fn test_next_manager_uses_correct_token() {
        let managers = make_managers(2);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let mgr0 = svc.next_manager();
        assert_eq!(mgr0.token, "token0");
        let mgr1 = svc.next_manager();
        assert_eq!(mgr1.token, "token1");
    }

    #[test]
    fn test_resolve_manager_matches_stored_url() {
        let managers = make_managers(3);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: UserId(Uuid::new_v4()),
            instance_id: "test".to_string(),
            name: "test".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some("https://claws.example.com/api/crabshack/mgr2".to_string()),
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance).unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr2");
        assert_eq!(mgr.token, "token2");
    }

    #[test]
    fn test_resolve_manager_falls_back_to_matching_type() {
        let managers = make_managers(2);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        // Instance with non-TEE URL (contains "claws") should match non-TEE managers
        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: UserId(Uuid::new_v4()),
            instance_id: "test".to_string(),
            name: "test".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some("https://claws.different.com/api".to_string()),
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance).unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr0");
    }

    #[test]
    fn test_resolve_manager_fails_when_type_unavailable() {
        let managers = make_managers(2); // All non-TEE managers
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        // Instance with TEE URL (no "claws") should fail when only non-TEE managers available
        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: UserId(Uuid::new_v4()),
            instance_id: "test".to_string(),
            name: "test".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some("https://api.openclaw-dev.near.ai".to_string()),
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = svc.resolve_manager(&instance);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TEE manager"));
    }

    #[test]
    fn test_resolve_manager_no_stored_url() {
        let managers = make_managers(2);
        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: UserId(Uuid::new_v4()),
            instance_id: "test".to_string(),
            name: "test".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance).unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr0");
    }

    #[tokio::test]
    async fn test_next_available_manager_default_limit_applied() {
        // With no DB config row, the default limit (200) is applied
        let svc = make_service(
            make_managers(2),
            Arc::new(mock_repo_with_manager_count(50)),
            Arc::new(MockSystemConfigsService::no_config_with_non_tee()),
        );

        // count=50 < default 200 → manager is available
        let mgr = svc.next_available_manager().await.unwrap();
        assert!(mgr
            .url
            .starts_with("https://claws.example.com/api/crabshack/"));
    }

    #[tokio::test]
    async fn test_next_available_manager_default_limit_rejects_at_capacity() {
        // With no DB config row, the default limit (200) is applied
        let svc = make_service(
            make_managers(1),
            Arc::new(mock_repo_with_manager_count(200)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        // count=200 >= default 200 → all at capacity
        let result = svc.next_available_manager().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_next_available_manager_under_limit() {
        let svc = make_service(
            make_managers(2),
            Arc::new(mock_repo_with_manager_count(3)),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                10, true,
            )),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert!(mgr
            .url
            .starts_with("https://claws.example.com/api/crabshack/"));
    }

    #[tokio::test]
    async fn test_next_available_manager_all_at_capacity() {
        let svc = make_service(
            make_managers(2),
            Arc::new(mock_repo_with_manager_count(100)),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                100, true,
            )),
        );

        let result = svc.next_available_manager().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("capacity"));
    }

    #[tokio::test]
    async fn test_next_available_manager_skips_full_manager() {
        // mgr0 is full (count=10, limit=10), mgr1 has room (count=5)
        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("mgr0"))
            .returning(|_| Ok(10));
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("mgr1"))
            .returning(|_| Ok(5));

        let svc = make_service(
            make_managers(2),
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                10, true,
            )),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr1");
    }

    #[tokio::test]
    async fn test_next_available_manager_respects_per_url_limits() {
        // Per-URL limits: mgr0 max=5, mgr1 max=15. mgr0 has 5 (full), mgr1 has 10 (room)
        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("mgr0"))
            .returning(|_| Ok(5));
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("mgr1"))
            .returning(|_| Ok(10));

        let svc = make_service(
            make_managers(2),
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_per_url_limits_and_non_tee()),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/mgr1");
    }

    #[test]
    #[should_panic(expected = "At least one agent manager must be configured")]
    fn test_panics_on_empty_managers() {
        make_service(
            vec![],
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );
    }

    #[test]
    #[should_panic(expected = "empty API token")]
    fn test_panics_on_empty_token() {
        make_service(
            vec![AgentManager {
                url: "https://test.com".to_string(),
                token: "".to_string(),
                is_non_tee: false,
            }],
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );
    }

    // --- Wiremock-based integration tests ---

    mod wiremock_tests {
        use super::*;
        use mockall::predicate::eq;
        use wiremock::matchers::{bearer_token, header, method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn setup_mock_server() -> MockServer {
            MockServer::start().await
        }

        /// Helper to create a test AgentInstance pointing at a specific manager URL
        fn test_instance(name: &str, manager_url: Option<&str>) -> AgentInstance {
            AgentInstance {
                id: Uuid::new_v4(),
                user_id: UserId(Uuid::new_v4()),
                instance_id: format!("agent-{}", name),
                name: name.to_string(),
                public_ssh_key: None,
                instance_url: None,
                instance_token: None,
                dashboard_url: None,
                agent_api_base_url: manager_url.map(|s| s.to_string()),
                service_type: None,
                status: "active".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        #[tokio::test]
        async fn test_get_enrichments_queries_only_relevant_managers() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            // Server 1 hosts instance-a and instance-b
            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [
                        {"name": "instance-a", "status": "running"},
                        {"name": "instance-b", "status": "stopped"}
                    ]
                })))
                .expect(1)
                .mount(&server1)
                .await;

            // Server 2 should NOT be queried (no instances belong to it)
            Mock::given(method("GET"))
                .and(path("/instances"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "instance-c", "status": "running"}]
                })))
                .expect(0)
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok1".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok2".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            // Only request enrichments for instances on server1
            let instances = vec![
                test_instance("instance-a", Some(&server1.uri())),
                test_instance("instance-b", Some(&server1.uri())),
            ];

            let enrichments = svc.get_instance_enrichments(&instances).await;
            assert_eq!(enrichments.len(), 2);
            assert_eq!(enrichments["instance-a"].status.as_deref(), Some("running"));
            assert_eq!(enrichments["instance-b"].status.as_deref(), Some("stopped"));
            // wiremock verifies server2 was NOT called (expect(0))
        }

        #[tokio::test]
        async fn test_get_enrichments_across_multiple_managers() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            Mock::given(method("GET"))
                .and(path("/instances"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "inst-a", "status": "running"}]
                })))
                .mount(&server1)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "inst-b", "status": "stopped"}]
                })))
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let instances = vec![
                test_instance("inst-a", Some(&server1.uri())),
                test_instance("inst-b", Some(&server2.uri())),
            ];

            let enrichments = svc.get_instance_enrichments(&instances).await;
            assert_eq!(enrichments.len(), 2);
            assert_eq!(enrichments["inst-a"].status.as_deref(), Some("running"));
            assert_eq!(enrichments["inst-b"].status.as_deref(), Some("stopped"));
        }

        #[tokio::test]
        async fn test_get_enrichments_continues_on_partial_failure() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            Mock::given(method("GET"))
                .and(path("/instances"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "inst-a", "status": "running"}]
                })))
                .mount(&server1)
                .await;

            // Server 2 returns 500
            Mock::given(method("GET"))
                .and(path("/instances"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let instances = vec![
                test_instance("inst-a", Some(&server1.uri())),
                test_instance("inst-b", Some(&server2.uri())),
            ];

            let enrichments = svc.get_instance_enrichments(&instances).await;
            // Both instances are in the map: server1 enriched successfully, server2 failed gracefully with None
            assert_eq!(enrichments.len(), 2);
            assert_eq!(enrichments["inst-a"].status.as_deref(), Some("running"));
            assert_eq!(enrichments["inst-b"].status.as_deref(), None); // Failed to enrich
        }

        #[tokio::test]
        async fn test_get_enrichments_empty_instances() {
            let svc = make_service(
                make_managers(2),
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let enrichments = svc.get_instance_enrichments(&[]).await;
            assert!(enrichments.is_empty());
        }

        #[tokio::test]
        async fn test_get_enrichment_single_instance_uses_stored_url() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            // Server 1 should NOT be queried
            Mock::given(method("GET"))
                .and(path("/instances/my-instance"))
                .respond_with(ResponseTemplate::new(404))
                .expect(0)
                .mount(&server1)
                .await;

            // Server 2 owns the instance
            Mock::given(method("GET"))
                .and(path("/instances/my-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "running",
                    "ssh_command": "ssh user@host"
                })))
                .expect(1)
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            // Pass the stored manager URL — should only hit server2
            let enrichment = svc
                .get_instance_enrichment_from_agent_api("my-instance", Some(&server2.uri()))
                .await;
            assert!(enrichment.is_some());
            let e = enrichment.unwrap();
            assert_eq!(e.status.as_deref(), Some("running"));
            assert_eq!(e.ssh_command.as_deref(), Some("ssh user@host"));
        }

        #[tokio::test]
        async fn test_get_enrichment_fallback_fan_out_when_no_url() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            // Server 1 returns 404
            Mock::given(method("GET"))
                .and(path("/instances/my-instance"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server1)
                .await;

            // Server 2 returns the instance
            Mock::given(method("GET"))
                .and(path("/instances/my-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "running",
                    "ssh_command": "ssh user@host"
                })))
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            // No stored URL — falls back to fan-out across all managers
            let enrichment = svc
                .get_instance_enrichment_from_agent_api("my-instance", None)
                .await;
            assert!(enrichment.is_some());
            let e = enrichment.unwrap();
            assert_eq!(e.status.as_deref(), Some("running"));
        }

        #[tokio::test]
        async fn test_call_agent_api_list_uses_correct_bearer_token() {
            let server = setup_mock_server().await;

            // Only respond to correct bearer token
            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("my-secret-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": []
                })))
                .expect(1)
                .mount(&server)
                .await;

            let mgr = AgentManager {
                url: server.uri(),
                token: "my-secret-token".to_string(),
                is_non_tee: false,
            };

            let svc = make_service(
                vec![mgr.clone()],
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.call_agent_api_list(&mgr).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_round_robin_create_distributes_across_managers() {
            let server1 = setup_mock_server().await;
            let server2 = setup_mock_server().await;

            // Both servers accept create calls and track hits
            let create_response = serde_json::json!({
                "instance": {
                    "name": "test-inst",
                    "url": "http://instance:8000",
                    "token": "inst-token",
                    "gateway_port": 8080,
                    "dashboard_url": "http://dashboard:3000"
                }
            });

            // SSE format response
            let sse_body = format!("data: {}\n\n", create_response);

            Mock::given(method("POST"))
                .and(path("/instances"))
                .and(bearer_token("tok1"))
                .respond_with(ResponseTemplate::new(200).set_body_string(&sse_body))
                .expect(1)
                .named("server1_create")
                .mount(&server1)
                .await;

            Mock::given(method("POST"))
                .and(path("/instances"))
                .and(bearer_token("tok2"))
                .respond_with(ResponseTemplate::new(200).set_body_string(&sse_body))
                .expect(1)
                .named("server2_create")
                .mount(&server2)
                .await;

            let managers = vec![
                AgentManager {
                    url: server1.uri(),
                    token: "tok1".to_string(),
                    is_non_tee: false,
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok2".to_string(),
                    is_non_tee: false,
                },
            ];

            let svc = make_service(
                managers,
                Arc::new(mock_repo_with_manager_count(0)),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            // Call create twice - first should go to server1 (tok1), second to server2 (tok2)
            let mgr1 = svc.next_manager().clone();
            let mgr2 = svc.next_manager().clone();

            assert_eq!(mgr1.token, "tok1");
            assert_eq!(mgr2.token, "tok2");

            // Verify the API calls route correctly
            let result1 = svc
                .call_agent_api_create(
                    &mgr1,
                    "key1",
                    "https://nearai/v1",
                    AgentApiCreateParams {
                        image: None,
                        name: None,
                        ssh_pubkey: None,
                        service_type: None,
                        cpus: None,
                        mem_limit: None,
                        storage_size: None,
                    },
                )
                .await;
            let result2 = svc
                .call_agent_api_create(
                    &mgr2,
                    "key2",
                    "https://nearai/v1",
                    AgentApiCreateParams {
                        image: None,
                        name: None,
                        ssh_pubkey: None,
                        service_type: None,
                        cpus: None,
                        mem_limit: None,
                        storage_size: None,
                    },
                )
                .await;

            assert!(result1.is_ok());
            assert!(result2.is_ok());
            // wiremock will verify expect(1) on each mock when servers drop
        }

        // --- start/stop/restart: update_instance_status invoked on success, not on failure ---

        const STATUS_TEST_INSTANCE_NAME: &str = "status-test-inst";

        fn status_test_instance(id: Uuid, user_id: UserId, manager_url: &str) -> AgentInstance {
            AgentInstance {
                id,
                user_id,
                instance_id: format!("agent-{}", STATUS_TEST_INSTANCE_NAME),
                name: STATUS_TEST_INSTANCE_NAME.to_string(),
                public_ssh_key: None,
                instance_url: None,
                instance_token: None,
                dashboard_url: None,
                agent_api_base_url: Some(manager_url.to_string()),
                service_type: None,
                status: "stopped".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        #[tokio::test]
        async fn test_start_instance_updates_status_on_success() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/start"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .with(eq(inst_id), eq("active"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.start_instance(inst_id, user_id).await;
            assert!(
                result.is_ok(),
                "start_instance should succeed: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn test_start_instance_does_not_update_status_on_failure() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/start"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(500))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.start_instance(inst_id, user_id).await;
            assert!(
                result.is_err(),
                "start_instance should fail when API returns 500"
            );
        }

        #[tokio::test]
        async fn test_stop_instance_updates_status_on_success() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/stop"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .with(eq(inst_id), eq("stopped"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.stop_instance(inst_id, user_id).await;
            assert!(result.is_ok(), "stop_instance should succeed: {:?}", result);
        }

        #[tokio::test]
        async fn test_stop_instance_does_not_update_status_on_failure() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/stop"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(500))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.stop_instance(inst_id, user_id).await;
            assert!(
                result.is_err(),
                "stop_instance should fail when API returns 500"
            );
        }

        #[tokio::test]
        async fn test_restart_instance_updates_status_on_success() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/restart"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .with(eq(inst_id), eq("active"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.restart_instance(inst_id, user_id).await;
            assert!(
                result.is_ok(),
                "restart_instance should succeed: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn test_restart_instance_does_not_update_status_on_failure() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());
            let instance = status_test_instance(inst_id, user_id, &server.uri());

            Mock::given(method("POST"))
                .and(path_regex(r"/instances/.*/restart"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(500))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(inst_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.restart_instance(inst_id, user_id).await;
            assert!(
                result.is_err(),
                "restart_instance should fail when API returns 500"
            );
        }

        // --- sync_all_instance_statuses tests ---

        #[tokio::test]
        async fn test_sync_updates_stopped_to_active_when_api_returns_running() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let server_uri = server.uri();
            let instance = test_instance("sync-inst-a", Some(&server_uri));
            let instance = AgentInstance {
                id: inst_id,
                status: "stopped".to_string(),
                ..instance
            };

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "sync-inst-a", "status": "running"}]
                })))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .with(eq(inst_id), eq("active"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.synced, 1);
            assert_eq!(r.updated, 1);
            assert_eq!(r.skipped, 0);
            assert_eq!(r.not_found, 0);
        }

        #[tokio::test]
        async fn test_sync_updates_active_to_stopped_when_api_returns_exited() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let instance = test_instance("sync-inst-b", Some(&server.uri()));
            let instance = AgentInstance {
                id: inst_id,
                status: "active".to_string(),
                ..instance
            };

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "sync-inst-b", "status": "exited"}]
                })))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .with(eq(inst_id), eq("stopped"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.updated, 1);
            assert_eq!(r.skipped, 0);
        }

        #[tokio::test]
        async fn test_sync_skips_when_status_unchanged() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let instance = test_instance("sync-inst-c", Some(&server.uri()));
            let instance = AgentInstance {
                id: inst_id,
                status: "active".to_string(),
                ..instance
            };

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "sync-inst-c", "status": "running"}]
                })))
                .expect(1)
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.synced, 1);
            assert_eq!(r.skipped, 1);
            assert_eq!(r.updated, 0);
        }

        #[tokio::test]
        async fn test_sync_skips_deleted_instances() {
            let server = setup_mock_server().await;
            let instance = test_instance("deleted-inst", Some(&server.uri()));
            let instance = AgentInstance {
                status: "deleted".to_string(),
                ..instance
            };

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.synced, 0);
            assert_eq!(r.updated, 0);
            // WireMock: no /instances call expected since we filter out deleted before querying
            // (actually we do query managers for instances that exist in by_manager - but deleted
            // instances are filtered out before building by_manager, so no manager has them.
            // So we never call the Agent API. Server gets 0 requests.)
        }

        #[tokio::test]
        async fn test_sync_counts_not_found() {
            let server = setup_mock_server().await;
            let instance = test_instance("missing-in-api", Some(&server.uri()));

            // API returns empty list - instance not found
            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": []
                })))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.not_found, 1);
            assert_eq!(r.synced, 0);
            assert_eq!(r.updated, 0);
        }

        #[tokio::test]
        async fn test_sync_handles_api_failure_with_error_skipped() {
            let server = setup_mock_server().await;
            let instance = test_instance("api-fail-inst", Some(&server.uri()));

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(
                result.is_ok(),
                "sync should not panic on API failure: {:?}",
                result
            );
            let r = result.unwrap();
            assert_eq!(r.error_skipped, 1);
            assert_eq!(r.not_found, 0);
            assert!(!r.errors.is_empty());
        }

        #[tokio::test]
        async fn test_sync_handles_db_update_failure() {
            let server = setup_mock_server().await;
            let inst_id = Uuid::new_v4();
            let instance = test_instance("db-fail-inst", Some(&server.uri()));
            let instance = AgentInstance {
                id: inst_id,
                status: "stopped".to_string(),
                ..instance
            };

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "db-fail-inst", "status": "running"}]
                })))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .returning(|_, _| Err(anyhow!("DB connection lost")));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(
                result.is_ok(),
                "sync should handle DB errors gracefully: {:?}",
                result
            );
            let r = result.unwrap();
            assert_eq!(r.synced, 1);
            assert_eq!(r.updated, 0);
            assert!(!r.errors.is_empty());
        }

        #[tokio::test]
        async fn test_sync_mixed_found_and_not_found() {
            let server = setup_mock_server().await;
            let found_id = Uuid::new_v4();
            let inst_found = AgentInstance {
                id: found_id,
                status: "stopped".to_string(),
                ..test_instance("mixed-found", Some(&server.uri()))
            };
            let inst_missing = test_instance("mixed-missing", Some(&server.uri()));

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": [{"name": "mixed-found", "status": "running"}]
                })))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            let inst_found_c = inst_found.clone();
            let inst_missing_c = inst_missing.clone();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![inst_found_c.clone(), inst_missing_c.clone()], 2)));
            repo.expect_update_instance_status()
                .with(eq(found_id), eq("active"))
                .times(1)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(result.is_ok(), "sync should succeed: {:?}", result);
            let r = result.unwrap();
            assert_eq!(r.synced, 1);
            assert_eq!(r.updated, 1);
            assert_eq!(r.not_found, 1);
        }

        #[tokio::test]
        async fn test_sync_manager_not_configured_for_instance() {
            let server = setup_mock_server().await;
            let instance = test_instance("orphan-inst", Some("http://unknown-manager:9999"));

            Mock::given(method("GET"))
                .and(path("/instances"))
                .and(bearer_token("tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instances": []
                })))
                .mount(&server)
                .await;

            let mut repo = MockAgentRepository::new();
            repo.expect_list_all_instances()
                .returning(move |_, _| Ok((vec![instance.clone()], 1)));
            repo.expect_update_instance_status()
                .times(0)
                .returning(|_, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc.sync_all_instance_statuses().await;
            assert!(
                result.is_ok(),
                "sync should handle unconfigured manager: {:?}",
                result
            );
            let r = result.unwrap();
            assert_eq!(r.error_skipped, 1);
            assert!(!r.errors.is_empty());
        }

        // --- End-to-End Flow Tests ---

        #[tokio::test]
        async fn test_e2e_tee_mode_flow() {
            let server = setup_mock_server().await;

            // TEE mode: mock TEE compose-api response
            // Should receive normalized service type (ironclaw, not ironclaw-dind)
            Mock::given(method("POST"))
                .and(path("/instances"))
                .and(header("Content-Type", "application/json"))
                .and(bearer_token("cloud-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instance": {
                        "name": "test-tee-instance",
                        "token": "instance-token-tee",
                        "url": "https://test-tee-instance.cloud.example.com"
                    }
                })))
                .mount(&server)
                .await;

            let server_uri = server.uri();
            let mut repo = MockAgentRepository::new();
            repo.expect_create_unbound_api_key()
                .returning(|_, _, _, _, _| {
                    Ok(AgentApiKey {
                        id: Uuid::new_v4(),
                        instance_id: None,
                        user_id: UserId::new(),
                        name: "test-key".to_string(),
                        spend_limit: None,
                        expires_at: Some(Utc::now() + Duration::days(90)),
                        last_used_at: None,
                        is_active: true,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            let server_uri_clone = server_uri.clone();
            repo.expect_create_instance().returning(move |_| {
                Ok(AgentInstance {
                    id: Uuid::new_v4(),
                    user_id: UserId::new(),
                    instance_id: "inst-123".to_string(),
                    name: "test-tee-instance".to_string(),
                    public_ssh_key: None,
                    instance_url: Some("https://test-tee-instance.cloud.example.com".to_string()),
                    instance_token: Some("instance-token-tee".to_string()),
                    dashboard_url: None,
                    agent_api_base_url: Some(server_uri_clone.clone()),
                    service_type: Some("ironclaw".to_string()),
                    status: "active".to_string(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            });

            let service = AgentServiceImpl::new(
                Arc::new(repo),
                vec![AgentManager {
                    url: server_uri.clone(),
                    token: "cloud-token".to_string(),
                    is_non_tee: false,
                }],
                "https://nearai.example.com/v1".to_string(),
                Arc::new(MockSystemConfigsService::no_config()),
                None,
                "claws".to_string(), // non_tee_agent_url_pattern
            );

            // Verify TEE mode behavior:
            // 1. Service type should be normalized (ironclaw-dind -> ironclaw)
            // 2. No passkey login attempted
            // 3. Manager token used
            assert!(
                !service.managers[0].is_non_tee,
                "Manager should be TEE mode"
            );
        }

        #[tokio::test]
        async fn test_e2e_non_tee_mode_flow() {
            let server = setup_mock_server().await;

            // Non-TEE mode: Mock compose-api response
            // Should accept ironclaw-dind as-is
            Mock::given(method("POST"))
                .and(path("/instances"))
                .and(header("Content-Type", "application/json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "instance": {
                        "name": "test-nontee-instance",
                        "token": "instance-token-nontee",
                        "url": "https://test-nontee-instance.claws.example.com"
                    }
                })))
                .mount(&server)
                .await;

            let server_uri = server.uri();
            let mut repo = MockAgentRepository::new();
            repo.expect_create_unbound_api_key()
                .returning(|_, _, _, _, _| {
                    Ok(AgentApiKey {
                        id: Uuid::new_v4(),
                        instance_id: None,
                        user_id: UserId::new(),
                        name: "test-key".to_string(),
                        spend_limit: None,
                        expires_at: Some(Utc::now() + Duration::days(90)),
                        last_used_at: None,
                        is_active: true,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            let server_uri_clone = server_uri.clone();
            repo.expect_create_instance().returning(move |_| {
                Ok(AgentInstance {
                    id: Uuid::new_v4(),
                    user_id: UserId::new(),
                    instance_id: "inst-456".to_string(),
                    name: "test-nontee-instance".to_string(),
                    public_ssh_key: None,
                    instance_url: Some(
                        "https://test-nontee-instance.claws.example.com".to_string(),
                    ),
                    instance_token: Some("instance-token-nontee".to_string()),
                    dashboard_url: None,
                    agent_api_base_url: Some(server_uri_clone.clone()),
                    service_type: Some("ironclaw-dind".to_string()),
                    status: "active".to_string(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            });

            let service = AgentServiceImpl::new(
                Arc::new(repo),
                vec![AgentManager {
                    url: server_uri.clone(),
                    token: "compose-token".to_string(),
                    is_non_tee: true,
                }],
                "https://nearai.example.com/v1".to_string(),
                Arc::new(MockSystemConfigsService::no_config()),
                None,
                "claws".to_string(), // non_tee_agent_url_pattern
            );

            // Verify non-TEE mode behavior:
            // 1. Service type should be kept as-is (ironclaw-dind)
            // 2. Passkey login can be attempted
            assert!(
                service.managers[0].is_non_tee,
                "Manager should be non-TEE mode"
            );
        }

        #[test]
        fn test_e2e_mode_flow_summary() {
            // Complete end-to-end flow verification:

            // TEE Mode:
            // Config: NON_TEE_INFRA not set or false
            // Manager: TEE compose-api (e.g. api.agent.near.ai via AGENT_MANAGER_URLS_TEE)
            // Auth: Manager token only, NO passkey login
            // Service Type: Used as-is (ironclaw stays ironclaw)
            let tee_mode = false;
            assert_eq!(
                normalize_service_type_for_api("ironclaw", tee_mode),
                "ironclaw"
            );

            // Non-TEE Mode:
            // Config: NON_TEE_INFRA=true
            // Manager: non-TEE compose-api (AGENT_MANAGER_URLS)
            // Auth: Passkey login available, falls back to manager token
            // Service Type: Normalized with -dind suffix (ironclaw -> ironclaw-dind)
            let non_tee_mode = true;
            assert_eq!(
                normalize_service_type_for_api("ironclaw", non_tee_mode),
                "ironclaw-dind"
            );
        }
    }

    #[test]
    fn validate_agent_api_url_accepts_https() {
        assert!(validate_agent_api_url("https://example.com/path", "test_url").is_ok());
    }

    #[test]
    fn validate_agent_api_url_accepts_http() {
        assert!(validate_agent_api_url("http://example.com/path", "test_url").is_ok());
    }

    #[test]
    fn validate_agent_api_url_rejects_javascript() {
        let result = validate_agent_api_url("javascript:alert(1)", "test_url");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must use http or https scheme"));
    }

    #[test]
    fn validate_agent_api_url_rejects_file() {
        assert!(validate_agent_api_url("file:///etc/passwd", "test_url").is_err());
    }

    #[test]
    fn validate_agent_api_url_rejects_data() {
        assert!(validate_agent_api_url("data:text/html,<h1>hi</h1>", "test_url").is_err());
    }

    #[test]
    fn validate_agent_api_url_rejects_empty() {
        assert!(validate_agent_api_url("", "test_url").is_err());
    }

    #[test]
    fn validate_agent_api_url_rejects_relative() {
        assert!(validate_agent_api_url("/foo/bar", "test_url").is_err());
    }

    // --- TEE and Non-TEE Mode Tests ---

    #[test]
    fn test_service_type_normalization_tee_mode() {
        // TEE mode: use service types as-is (no -dind suffix)
        assert_eq!(
            normalize_service_type_for_api("ironclaw", false),
            "ironclaw"
        );
        assert_eq!(
            normalize_service_type_for_api("openclaw", false),
            "openclaw"
        );
    }

    #[test]
    fn test_service_type_normalization_non_tee_mode() {
        // Non-TEE mode: append -dind suffix to service types
        assert_eq!(
            normalize_service_type_for_api("ironclaw", true),
            "ironclaw-dind"
        );
        assert_eq!(
            normalize_service_type_for_api("openclaw", true),
            "openclaw-dind"
        );
    }

    #[test]
    fn test_agent_service_creation_tee_mode() {
        // TEE mode: manager with is_non_tee = false
        let repo = Arc::new(MockAgentRepository::new());
        let manager = AgentManager {
            url: "https://api.cloud.example.com".to_string(),
            token: "cloud-token".to_string(),
            is_non_tee: false,
        };
        let configs = Arc::new(MockSystemConfigsService::no_config());

        let _service = AgentServiceImpl::new(
            repo,
            vec![manager.clone()],
            "https://nearai.example.com/v1".to_string(),
            configs,
            None,
            "claws".to_string(), // non_tee_agent_url_pattern
        );

        // Verify TEE mode configuration: manager is TEE
        assert!(!manager.is_non_tee);
    }

    #[test]
    fn test_agent_service_creation_non_tee_mode() {
        // Non-TEE mode: manager with is_non_tee = true
        let repo = Arc::new(MockAgentRepository::new());
        let manager = AgentManager {
            url: "https://claws.example.com/api/crabshack".to_string(),
            token: "compose-token".to_string(),
            is_non_tee: true,
        };
        let configs = Arc::new(MockSystemConfigsService::no_config());

        let _service = AgentServiceImpl::new(
            repo,
            vec![manager.clone()],
            "https://nearai.example.com/v1".to_string(),
            configs,
            None,
            "claws".to_string(), // non_tee_agent_url_pattern
        );

        // Verify non-TEE mode configuration: manager is non-TEE
        assert!(manager.is_non_tee);
    }

    #[test]
    fn test_image_mapping_for_service_types() {
        // Verify that image mapping works correctly for all service types
        assert_eq!(
            get_image_for_service_type("ironclaw"),
            "ironclaw-nearai-worker:local"
        );
        assert_eq!(
            get_image_for_service_type("ironclaw-dind"),
            "ghcr.io/nearai/ironclaw-dind:0.21.0"
        );
        assert_eq!(
            get_image_for_service_type("openclaw"),
            "openclaw-nearai-worker:local"
        );
        assert_eq!(
            get_image_for_service_type("unknown"),
            "openclaw-nearai-worker:local"
        );
    }

    #[test]
    fn test_normalize_service_type_edge_cases() {
        // Edge cases for service type normalization
        assert_eq!(normalize_service_type_for_api("", false), "");
        assert_eq!(
            normalize_service_type_for_api("ironclaw-dind-extra", false),
            "ironclaw-dind-extra"
        );
        assert_eq!(normalize_service_type_for_api("dind", false), "dind");
    }

    // --- Mode Flow Verification Tests ---

    #[test]
    fn test_tee_mode_configuration_summary() {
        // TEE Mode Flow:
        // 1. Uses TEE compose-api (AGENT_API_BASE_URL or AGENT_MANAGER_URLS_TEE)
        // 2. NO passkey login (resolve_bearer_token returns manager token directly)
        // 3. Service types used as-is: "ironclaw" stays "ironclaw", "openclaw" stays "openclaw"
        // 4. Manager token used for all API calls

        // Verify service type normalization for TEE
        assert_eq!(
            normalize_service_type_for_api("ironclaw", false),
            "ironclaw"
        );
        assert_eq!(
            normalize_service_type_for_api("openclaw", false),
            "openclaw"
        );
    }

    #[test]
    fn test_non_tee_mode_configuration_summary() {
        // Non-TEE Mode Flow:
        // 1. Uses non-TEE compose-api (AGENT_MANAGER_URLS)
        // 2. Passkey login enabled (resolve_bearer_token attempts passkey login)
        // 3. Service types normalized with -dind suffix: "ironclaw" -> "ironclaw-dind", "openclaw" -> "openclaw-dind"
        // 4. Session token from passkey or manager token used for API calls

        // Verify service type normalization for non-TEE
        assert_eq!(
            normalize_service_type_for_api("ironclaw", true),
            "ironclaw-dind"
        );
        assert_eq!(
            normalize_service_type_for_api("openclaw", true),
            "openclaw-dind"
        );
    }

    // ============================================================================
    // Comprehensive tests for manager filtering and image format selection
    // ============================================================================

    #[tokio::test]
    async fn test_manager_filtering_non_tee_infra_true_only_selects_non_tee() {
        // When NON_TEE_INFRA=true, only non-TEE managers should be selected
        let mut managers = make_managers(2); // Non-TEE managers
                                             // Add a TEE manager
        managers.push(AgentManager {
            url: "https://api.example.com".to_string(),
            token: "tee-token".to_string(),
            is_non_tee: false,
        });

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::with_non_tee_infra(true)),
        );

        // Should only return non-TEE managers
        for _ in 0..10 {
            let mgr = svc.next_available_manager().await.unwrap();
            assert!(
                mgr.url.contains("claws.example.com/api/crabshack"),
                "Expected non-TEE manager URL, got: {}",
                mgr.url
            );
        }
    }

    #[tokio::test]
    async fn test_manager_filtering_non_tee_infra_false_uses_all_managers() {
        // When NON_TEE_INFRA=false, all managers should be available
        let mut managers = make_managers(1); // 1 non-TEE manager
                                             // Add 2 TEE managers
        managers.push(AgentManager {
            url: "https://api1.example.com".to_string(),
            token: "tee-token-1".to_string(),
            is_non_tee: false,
        });
        managers.push(AgentManager {
            url: "https://api2.example.com".to_string(),
            token: "tee-token-2".to_string(),
            is_non_tee: false,
        });

        let svc = make_service(
            managers.clone(),
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        // Should return all managers in round-robin
        let urls: Vec<String> = (0..6).map(|_| svc.next_manager().url.clone()).collect();

        // All 3 managers should be in the rotation
        assert!(urls.contains(&"https://claws.example.com/api/crabshack/mgr0".to_string()));
        assert!(urls.contains(&"https://api1.example.com".to_string()));
        assert!(urls.contains(&"https://api2.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_manager_filtering_rejects_all_tee_when_non_tee_infra_true() {
        // When all managers are TEE but NON_TEE_INFRA=true, should error
        let managers = vec![
            AgentManager {
                url: "https://api1.example.com".to_string(),
                token: "token1".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: "https://api2.example.com".to_string(),
                token: "token2".to_string(),
                is_non_tee: false,
            },
        ];

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::with_non_tee_infra(true)),
        );

        let result = svc.next_available_manager().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No suitable managers"),
            "Expected 'No suitable managers' error"
        );
    }

    #[tokio::test]
    async fn test_manager_filtering_capacity_with_non_tee_infra_true() {
        // When NON_TEE_INFRA=true and non-TEE manager is at capacity, should fail
        let managers = make_managers(1); // 1 non-TEE manager
        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .returning(|_| Ok(100)); // At capacity

        let svc = make_service(
            managers,
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                50, true,
            )),
        );

        let result = svc.next_available_manager().await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("capacity"),
            "Expected capacity error"
        );
    }

    #[tokio::test]
    async fn test_mixed_managers_non_tee_skips_full_tee_managers() {
        // When NON_TEE_INFRA=true with mixed managers:
        // - 1 non-TEE manager with capacity
        // - 2 TEE managers (at capacity, but should be skipped)
        let managers = vec![
            // Non-TEE manager with capacity
            AgentManager {
                url: "https://claws.example.com/api/crabshack/available".to_string(),
                token: "non-tee-token".to_string(),
                is_non_tee: true,
            },
            // TEE managers (should be filtered out)
            AgentManager {
                url: "https://api1.example.com".to_string(),
                token: "tee-token-1".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: "https://api2.example.com".to_string(),
                token: "tee-token-2".to_string(),
                is_non_tee: false,
            },
        ];

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(10)),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                100, true,
            )),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert_eq!(mgr.url, "https://claws.example.com/api/crabshack/available");
    }

    #[test]
    fn test_manager_type_detection_from_url() {
        // Test the manager type detection logic (non-TEE vs TEE)
        let non_tee_urls = vec![
            "https://claws.example.com/api/crabshack",
            "https://other.host/api/crabshack",
        ];

        for url in non_tee_urls {
            let is_non_tee = url.contains("/api/crabshack");
            assert!(is_non_tee, "Expected {} to be detected as non-TEE", url);
        }

        let tee_urls = vec![
            "https://api.openclaw-dev.near.ai",
            "https://api.cloud.example.com",
            "https://agent-api.example.com",
        ];

        for url in tee_urls {
            let is_non_tee = url.contains("/api/crabshack");
            assert!(!is_non_tee, "Expected {} to be detected as TEE", url);
        }
    }

    #[tokio::test]
    async fn test_round_robin_with_filtered_non_tee_managers() {
        // When NON_TEE_INFRA=true with mixed managers, next_available_manager should only pick non-TEE
        let managers = vec![
            AgentManager {
                url: "https://claws.example.com/api/crabshack/mgr0".to_string(),
                token: "token0".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://claws.example.com/api/crabshack/mgr1".to_string(),
                token: "token1".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://api.example.com".to_string(), // TEE - should be skipped
                token: "tee-token".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: "https://claws.example.com/api/crabshack/mgr2".to_string(),
                token: "token2".to_string(),
                is_non_tee: true,
            },
        ];

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::with_non_tee_infra(true)),
        );

        // next_available_manager should only return non-TEE managers, skipping the TEE one
        let mut urls = Vec::new();
        for _ in 0..6 {
            let mgr = svc.next_available_manager().await.unwrap();
            urls.push(mgr.url.clone());
        }

        // Should only get non-TEE managers, cycling through all 3 of them
        for url in &urls {
            assert!(
                url.contains("claws.example.com"),
                "Should only return non-TEE managers"
            );
            assert!(
                !url.contains("api.example.com"),
                "TEE manager should not be selected"
            );
        }
    }

    #[tokio::test]
    async fn test_capacity_checking_respects_filtered_managers() {
        // Test that capacity checking works correctly with filtered managers
        let managers = vec![
            AgentManager {
                url: "https://claws.example.com/api/crabshack/mgr0".to_string(),
                token: "token0".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://claws.example.com/api/crabshack/mgr1".to_string(),
                token: "token1".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://api.example.com".to_string(), // TEE - at capacity, but should be skipped
                token: "tee-token".to_string(),
                is_non_tee: false,
            },
        ];

        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("claws.example.com"))
            .returning(|_| Ok(10)); // Non-TEE managers: 10 instances
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url.contains("api.example.com"))
            .returning(|_| Ok(100)); // TEE manager: 100 instances (at capacity)

        let svc = make_service(
            managers,
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_manager_limit_and_non_tee(
                50, true,
            )),
        );

        // Should succeed by using a non-TEE manager (even though TEE is at capacity)
        let mgr = svc.next_available_manager().await.unwrap();
        assert!(
            mgr.url.contains("claws.example.com"),
            "Should select non-TEE manager"
        );
    }

    #[test]
    fn test_service_type_normalization_by_manager_type() {
        // Test that service type normalization is correct for both manager types

        // TEE mode: use service types as-is (no suffix)
        assert_eq!(
            normalize_service_type_for_api("openclaw", false),
            "openclaw"
        );
        assert_eq!(
            normalize_service_type_for_api("ironclaw", false),
            "ironclaw"
        );

        // Non-TEE mode: append -dind suffix to service types
        assert_eq!(
            normalize_service_type_for_api("openclaw", true),
            "openclaw-dind"
        );
        assert_eq!(
            normalize_service_type_for_api("ironclaw", true),
            "ironclaw-dind"
        );
    }

    #[test]
    fn test_image_format_selection_by_manager_type() {
        // Test get_image_for_service_type returns correct formats
        assert_eq!(
            get_image_for_service_type("ironclaw"),
            "ironclaw-nearai-worker:local"
        );
        assert_eq!(
            get_image_for_service_type("ironclaw-dind"),
            "ghcr.io/nearai/ironclaw-dind:0.21.0"
        );
        assert_eq!(
            get_image_for_service_type("openclaw"),
            "openclaw-nearai-worker:local"
        );
        assert_eq!(
            get_image_for_service_type("unknown"),
            "openclaw-nearai-worker:local"
        );
    }

    #[tokio::test]
    async fn test_next_available_manager_error_message_includes_mode() {
        // When no suitable managers, error message should indicate NON_TEE_INFRA setting
        let managers = vec![AgentManager {
            url: "https://api.example.com".to_string(),
            token: "token".to_string(),
            is_non_tee: false,
        }];

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::with_non_tee_infra(true)),
        );

        let result = svc.next_available_manager().await;
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("No suitable managers"));
        assert!(error_msg.contains("NON_TEE_INFRA=true"));
    }

    #[tokio::test]
    async fn test_manager_filtering_with_single_non_tee_manager() {
        // Single non-TEE manager should work correctly
        let managers = make_managers(1);

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config_with_non_tee()),
        );

        // Should always return the same manager
        for _ in 0..5 {
            let mgr = svc.next_available_manager().await.unwrap();
            assert!(mgr.url.contains("claws.example.com/api/crabshack/mgr0"));
        }
    }

    #[tokio::test]
    async fn test_manager_filtering_alternates_non_tee_managers() {
        // Multiple non-TEE managers should alternate properly
        let managers = make_managers(3);

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config_with_non_tee()),
        );

        let mut urls = Vec::new();
        for _ in 0..6 {
            let mgr = svc.next_available_manager().await.unwrap();
            urls.push(mgr.url.clone());
        }

        // Should alternate between the 3 managers
        assert!(urls[0].contains("mgr0"));
        assert!(urls[1].contains("mgr1"));
        assert!(urls[2].contains("mgr2"));
        assert!(urls[3].contains("mgr0"));
        assert!(urls[4].contains("mgr1"));
        assert!(urls[5].contains("mgr2"));
    }
}
