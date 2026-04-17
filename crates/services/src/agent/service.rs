use crate::system_configs::ports::{AgentHostingConfig, SystemConfigs, SystemConfigsService};
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
    AgentApiKeyCreationError, AgentInstance, AgentRepository, AgentService, AgentServiceError,
    CreateInstanceParams, InstanceBalance, UpgradeAvailability, UsageLogEntry,
    DEFAULT_AGENT_SERVICE_TYPE, VALID_SERVICE_TYPES,
};

/// Maximum size for the Agent API SSE stream buffer (100 KB).
/// Prevents DoS from a malicious Agent API sending extremely long lines.
const MAX_BUFFER_SIZE: usize = 100 * 1024;

/// How many instances to load when deciding if gateway session setup should run for legacy non-TEE users
/// (global TEE flag but instances on a non-TEE manager). Cap keeps login-path DB work bounded.
const GATEWAY_SESSION_INSTANCE_SCAN_LIMIT: i64 = 50;

// Resource sizing defaults (instance_default_cpus, instance_default_mem_limit, instance_default_storage_size)
// are struct fields accessible via self.instance_default_cpus, etc.

/// Extract version tag from Docker/OCI image ref
///
/// Properly parses image references like:
/// - `docker.io/repo/image:0.23.0` → `Some("0.23.0")`
/// - `localhost:5000/image:v1.0` → `Some("v1.0")`
/// - `image@sha256:abc123` → `None` (digest, not tag)
/// - `image:latest` → `None` (non-numeric tag)
/// - `image` → `None` (no tag)
///
/// Returns None for non-numeric tags like "latest", "dev", or digest references.
fn extract_version_from_image(image_ref: &str) -> Option<String> {
    // Split off the digest part if present (OCI format: image@sha256:...)
    let before_digest = image_ref.split('@').next().unwrap_or(image_ref);

    // Find the last '/' to separate repository from tag
    let last_slash_pos = before_digest.rfind('/')?;
    let after_slash = &before_digest[last_slash_pos + 1..];

    // Look for ':' in the part after the last '/' to find the tag
    // (avoids confusion with port numbers in registry URLs like localhost:5000)
    let tag = after_slash.rsplit(':').next()?;

    // Check if it's a numeric version (starts with a digit)
    if tag.chars().next()?.is_ascii_digit() {
        Some(tag.to_string())
    } else {
        // Not a semantic version (e.g., "dev", "latest")
        None
    }
}

/// Check if a version string is stable (no pre-release suffix).
/// Strips build metadata (+...) before checking for hyphen.
/// Examples: "1.0.0" → true, "1.0.0-rc.1" → false
fn is_stable_version(v: &str) -> bool {
    let core = v.split('+').next().unwrap_or(v); // strip build metadata
    !core.contains('-')
}

/// Parse semantic version string with pre-release support.
/// Requires a strict `major.minor.patch` numeric core (exactly three dot-separated components).
///
/// Returns `None` for malformed cores (e.g. `1.2.x`), extra segments (`1.0.0.1`), or empty
/// pre-release identifiers. `prerelease_str` is `""` for stable versions.
///
/// Examples:
/// - `"1.0.0"` → `Some((1, 0, 0, ""))`
/// - `"1.0.0-rc.1"` → `Some((1, 0, 0, "rc.1"))`
/// - `"1.0.0-alpha+build123"` → `Some((1, 0, 0, "alpha"))`
/// - `"1.2.x"` → `None`
fn parse_semantic_version(v: &str) -> Option<(u32, u32, u32, &str)> {
    // Strip build metadata first (everything after +)
    let v_no_build = v.split('+').next().unwrap_or(v);

    // Split on first hyphen to separate core from pre-release
    let (core, pre) = match v_no_build.split_once('-') {
        Some((c, p)) => (c, p),
        None => (v_no_build, ""),
    };

    if !pre.is_empty() && pre.split('.').any(|identifier| identifier.is_empty()) {
        return None;
    }

    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    // Reject cores with more than three segments (e.g. `1.0.0.1`).
    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch, pre))
}

/// Compare two parsed semver tuples per [semver spec §11](https://semver.org/#spec-item-11).
/// Used by [`compare_semantic_versions`] after strings are parsed; keeps ordering logic in one place.
fn compare_semver_parsed(
    (maj_a, min_a, pat_a, pre_a): (u32, u32, u32, &str),
    (maj_b, min_b, pat_b, pre_b): (u32, u32, u32, &str),
) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;

    // Compare numeric core first (major, then minor, then patch).
    let core_cmp = maj_a
        .cmp(&maj_b)
        .then(min_a.cmp(&min_b))
        .then(pat_a.cmp(&pat_b));

    if core_cmp != Equal {
        return core_cmp;
    }

    // Same core: stable > pre-release (semver §11.4).
    match (pre_a.is_empty(), pre_b.is_empty()) {
        (true, false) => return Greater,
        (false, true) => return Less,
        (true, true) => return Equal,
        (false, false) => {} // both have pre-release, compare identifier sequences below
    }

    // Compare pre-release identifier sequences.
    // Split on '.', e.g. "alpha.1" → ["alpha", "1"], "beta" → ["beta"].
    let mut ids_a = pre_a.split('.');
    let mut ids_b = pre_b.split('.');

    loop {
        match (ids_a.next(), ids_b.next()) {
            (None, None) => return Equal,
            (None, Some(_)) => return Less, // a is shorter, lower precedence
            (Some(_), None) => return Greater, // b is shorter
            (Some(id_a), Some(id_b)) => {
                // Numeric identifiers are compared numerically.
                // Alphanumeric identifiers are compared lexically (ASCII sort order).
                // Numeric identifiers always have lower precedence than alphanumeric (spec §11.4).
                let ord = match (id_a.parse::<u64>(), id_b.parse::<u64>()) {
                    (Ok(n_a), Ok(n_b)) => n_a.cmp(&n_b),
                    (Err(_), Err(_)) => id_a.cmp(id_b),
                    (Ok(_), Err(_)) => Less, // numeric < alphanumeric
                    (Err(_), Ok(_)) => Greater,
                };

                if ord != Equal {
                    return ord;
                }
                // identifiers equal, continue to next pair
            }
        }
    }
}

/// Compare two semantic versions according to semver spec §11.
/// Handles pre-release versions correctly:
/// - Stable (1.0.0) > pre-release with same core (1.0.0-rc.1)
/// - Pre-release identifiers compared left-to-right: numeric < alphanumeric
///
/// Invalid version strings sort **before** valid ones (lower precedence).
///
/// Examples:
/// - "1.0.0-alpha" < "1.0.0-alpha.1" < "1.0.0-alpha.beta" < "1.0.0-beta" < "1.0.0-beta.2"
///   < "1.0.0-beta.11" < "1.0.0-rc.1" < "1.0.0"
fn compare_semantic_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;

    match (parse_semantic_version(a), parse_semantic_version(b)) {
        (None, None) => Equal,
        (None, Some(_)) => Less, // malformed / non-strict semver sorts before valid
        (Some(_), None) => Greater,
        (Some(pa), Some(pb)) => compare_semver_parsed(pa, pb),
    }
}

/// Map service type to worker image.
///
/// Fallback chain:
/// - ironclaw: `hosting.crabshack.ironclaw_image` → "docker.io/nearaidev/ironclaw-dind:latest"
/// - openclaw: `hosting.crabshack.openclaw_image` → "docker.io/nearaidev/openclaw-nearai-worker:latest"
///
/// Does not apply crabshack `deploy_latest_version_tag` flags; use
/// `AgentServiceImpl::resolve_non_tee_worker_image_ref` for non-TEE deploys.
fn get_image_for_service_type(service_type: &str, hosting: Option<&AgentHostingConfig>) -> String {
    match service_type {
        "ironclaw" => hosting
            .and_then(|h| h.crabshack.ironclaw_image.clone())
            .unwrap_or_else(|| "docker.io/nearaidev/ironclaw-dind:latest".to_string()),
        _ => hosting
            .and_then(|h| h.crabshack.openclaw_image.clone())
            .unwrap_or_else(|| "docker.io/nearaidev/openclaw-nearai-worker:latest".to_string()),
    }
}

/// Convert canonical service type to crabshack format for non-TEE.
/// Crabshack uses inconsistent naming (configurable via AgentHostingConfig):
/// - ironclaw → ironclaw-dind by default (can be overridden via crabshack.ironclaw_service_type)
/// - openclaw → openclaw by default (can be overridden via crabshack.openclaw_service_type)
pub fn service_type_for_crabshack(
    canonical_type: &str,
    hosting_config: Option<&crate::system_configs::ports::AgentHostingConfig>,
) -> String {
    match canonical_type {
        "ironclaw" => hosting_config
            .and_then(|cfg| cfg.crabshack.ironclaw_service_type.clone())
            .unwrap_or_else(|| "ironclaw-dind".to_string()),
        "openclaw" => hosting_config
            .and_then(|cfg| cfg.crabshack.openclaw_service_type.clone())
            .unwrap_or_else(|| "openclaw".to_string()),
        other => other.to_string(), // unknown types pass through as-is
    }
}

/// `service_type` for POST `/instances`: canonical `ironclaw` / `openclaw` on TEE managers;
/// Crabshack compose name from [`service_type_for_crabshack`] on non-TEE (e.g. `ironclaw` → `ironclaw-dind`).
fn compose_api_service_type_on_create(
    manager_is_non_tee: bool,
    canonical_service_type: &str,
    hosting: Option<&AgentHostingConfig>,
) -> String {
    if manager_is_non_tee {
        service_type_for_crabshack(canonical_service_type, hosting)
    } else {
        canonical_service_type.to_string()
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
    /// Type-specific round-robin counters for capacity-aware manager selection.
    tee_manager_rr_counter: AtomicUsize,
    non_tee_manager_rr_counter: AtomicUsize,
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

#[derive(Clone, Copy, Debug)]
enum ManagerType {
    Tee,
    NonTee,
}

impl ManagerType {
    fn is_non_tee(self) -> bool {
        matches!(self, Self::NonTee)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Tee => "tee",
            Self::NonTee => "non-tee",
        }
    }
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
        // Direct connections only: agent manager URLs are explicit endpoints; skipping system proxy avoids
        // misrouted loopback in tests and broken CONNECT for internal crabshack/compose hosts.
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            repository,
            http_client,
            managers,
            tee_manager_rr_counter: AtomicUsize::new(0),
            non_tee_manager_rr_counter: AtomicUsize::new(0),
            nearai_api_url,
            system_configs_service,
            channel_relay_url,
            non_tee_agent_url_pattern,
        }
    }

    /// Pick the next manager in round-robin order for new instance creation.
    /// Does NOT check capacity — use type-specific capacity-aware helpers for production paths.
    #[cfg(test)]
    fn next_manager(&self) -> &AgentManager {
        let idx = self.tee_manager_rr_counter.fetch_add(1, Ordering::Relaxed);
        &self.managers[idx % self.managers.len()]
    }

    /// System configs from DB; on error or missing row, use `SystemConfigs::default()`.
    async fn get_system_configs(&self) -> SystemConfigs {
        self.system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Docker image for non-TEE worker deploy when the caller did not supply `image`.
    /// Honors crabshack `*_deploy_latest_version_tag` flags (latest versioned ref from the manager
    /// `/images` allowlist, same as upgrade checks), ignoring pinned `*_image`.
    async fn resolve_non_tee_worker_image_ref(
        &self,
        manager: &AgentManager,
        canonical_service_type: &str,
        hosting: Option<&AgentHostingConfig>,
    ) -> anyhow::Result<String> {
        let crab = hosting.map(|h| &h.crabshack);
        let use_latest = match canonical_service_type {
            "ironclaw" => crab.and_then(|c| c.ironclaw_deploy_latest_version_tag) == Some(true),
            "openclaw" => crab.and_then(|c| c.openclaw_deploy_latest_version_tag) == Some(true),
            _ => false,
        };

        if !use_latest {
            return Ok(get_image_for_service_type(canonical_service_type, hosting));
        }

        match self
            .get_latest_image_non_tee(manager, canonical_service_type, "deploy")
            .await
        {
            Ok((ref_, _, _)) => Ok(ref_),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    service_type = %canonical_service_type,
                    "Latest allowlist image unavailable; falling back to configured image ref"
                );
                Ok(get_image_for_service_type(canonical_service_type, hosting))
            }
        }
    }

    /// `true` when admin config says new agents use non-TEE infra (passkey / non-TEE managers).
    fn is_non_tee_infra(configs: &SystemConfigs) -> bool {
        configs
            .agent_hosting
            .as_ref()
            .and_then(|cfg| cfg.new_agent_with_non_tee_infra)
            .unwrap_or(false)
    }

    /// User has at least one instance whose stored manager URL matches a configured non-TEE manager.
    fn user_has_non_tee_routed_instance(&self, instances: &[AgentInstance]) -> bool {
        instances.iter().any(|inst| {
            inst.agent_api_base_url.as_ref().is_some_and(|url| {
                self.managers
                    .iter()
                    .any(|m| m.url == *url && m.get_is_non_tee())
            })
        })
    }

    /// Pick the next manager with available capacity for a specific manager type,
    /// starting from the round-robin position. Tries each candidate once.
    ///
    /// NOTE: This is a best-effort soft limit. Concurrent calls can both see a manager as
    /// under capacity and both create instances there, temporarily exceeding the limit.
    /// For a hard cap, DB-level enforcement (e.g. INSERT ... WHERE count < max) would be needed.
    async fn next_available_manager_for_type(
        &self,
        manager_type: ManagerType,
    ) -> anyhow::Result<AgentManager> {
        let configs = self.get_system_configs().await;
        let is_non_tee = manager_type.is_non_tee();

        let available_managers: Vec<_> = self
            .managers
            .iter()
            .filter(|mgr| is_non_tee == mgr.get_is_non_tee())
            .collect();

        if available_managers.is_empty() {
            return Err(anyhow!(
                "No suitable managers available: manager_type={}, configured_managers={}",
                manager_type.as_str(),
                self.managers.len()
            ));
        }

        let n = available_managers.len();
        let start = match manager_type {
            ManagerType::Tee => self.tee_manager_rr_counter.fetch_add(1, Ordering::Relaxed),
            ManagerType::NonTee => self
                .non_tee_manager_rr_counter
                .fetch_add(1, Ordering::Relaxed),
        };

        for i in 0..n {
            let mgr = available_managers[(start + i) % n];
            let max = configs.max_instances_for_manager(&mgr.url);
            let max = match max {
                Some(limit) => limit,
                None => {
                    tracing::info!(
                        "Manager limit missing in config, treating as unlimited: manager_url={}, manager_type={}",
                        mgr.url,
                        manager_type.as_str()
                    );
                    return Ok(mgr.clone());
                }
            };
            let count = self.repository.count_instances_by_manager(&mgr.url).await?;
            if (count as u64) < max {
                return Ok(mgr.clone());
            }
            tracing::info!(
                "Manager at capacity: manager_url={}, count={}, max={}, manager_type={}",
                mgr.url,
                count,
                max,
                manager_type.as_str()
            );
        }

        Err(anyhow!(
            "All {} suitable agent manager(s) are at capacity (manager_type={})",
            n,
            manager_type.as_str()
        ))
    }

    async fn next_available_tee_manager(&self) -> anyhow::Result<AgentManager> {
        self.next_available_manager_for_type(ManagerType::Tee).await
    }

    async fn next_available_non_tee_manager(&self) -> anyhow::Result<AgentManager> {
        self.next_available_manager_for_type(ManagerType::NonTee)
            .await
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
        user_id: UserId,
    ) -> anyhow::Result<String> {
        Self::compose_api_passkey_login_static(
            &self.http_client,
            manager,
            auth_secret,
            backup_passphrase,
            user_id,
        )
        .await
    }

    /// Static version for use in closures. Takes http_client explicitly.
    async fn compose_api_passkey_login_static(
        http_client: &reqwest::Client,
        manager: &AgentManager,
        auth_secret: &str,
        backup_passphrase: &str,
        user_id: UserId,
    ) -> anyhow::Result<String> {
        let url = format!("{}/auth/login", manager.url);
        let request_body = serde_json::json!({
            "auth_secret": auth_secret,
            "backup_passphrase": backup_passphrase,
            "user_id": user_id,
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
            self.compose_api_passkey_login(
                manager,
                &auth_secret,
                &backup_passphrase,
                instance.user_id,
            )
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
        user_id: UserId,
    ) -> anyhow::Result<String> {
        let url = format!("{}/auth/register", manager.url);
        let request_body = serde_json::json!({
            "auth_secret": auth_secret,
            "backup_passphrase": backup_passphrase,
            "user_id": user_id,
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

    /// Try to login, or if user not found (404), register and return session token.
    /// This avoids making redundant API calls and handles both existing and new users.
    async fn compose_api_get_session_token(
        &self,
        manager: &AgentManager,
        auth_secret: &str,
        backup_passphrase: &str,
        user_id: UserId,
    ) -> anyhow::Result<String> {
        // Try login first - if user is already registered on this manager, login succeeds
        match self
            .compose_api_passkey_login(manager, auth_secret, backup_passphrase, user_id)
            .await
        {
            Ok(token) => {
                tracing::info!(
                    "User already registered on compose-api, login successful: user_id={}",
                    user_id
                );
                Ok(token)
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("404") {
                    tracing::info!(
                        "User not found on compose-api, registering: user_id={}",
                        user_id
                    );
                    // Register credentials with compose-api for this manager (returns session token)
                    self.compose_api_passkey_register(
                        manager,
                        auth_secret,
                        backup_passphrase,
                        user_id,
                    )
                    .await
                } else {
                    // Some other error, not a "user not found" - propagate it
                    Err(e)
                }
            }
        }
    }

    /// Call compose-api /auth/proxy-session to set up gateway cookie
    async fn compose_api_proxy_session(
        &self,
        manager: &AgentManager,
        session_token: &str,
        user_id: UserId,
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
            .json(&serde_json::json!({ "user_id": user_id }))
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

        // Capture response body for debug logging only (do not include in errors per CLAUDE.md)
        let response_text = response
            .text()
            .await
            .unwrap_or_else(|_| "(unable to read response body)".to_string());

        if !status.is_success() {
            tracing::warn!("compose-api /auth/proxy-session failed: status={}", status);
            tracing::debug!(
                "compose-api /auth/proxy-session response body (debug only): {}",
                response_text
            );
            return Err(anyhow!(
                "compose-api /auth/proxy-session error: status {}",
                status
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
        user_id: UserId,
    ) -> anyhow::Result<serde_json::Value> {
        // Get instance defaults from system configs
        let configs = self.get_system_configs().await;
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
            .unwrap_or(DEFAULT_AGENT_SERVICE_TYPE);
        // Canonical type for DB and `get_image_for_*` match keys (`ironclaw`, `openclaw`).
        let canonical_service_type = service_type.to_string();
        let compose_api_service_type = compose_api_service_type_on_create(
            manager.get_is_non_tee(),
            &canonical_service_type,
            configs.agent_hosting.as_ref(),
        );

        // Determine image to use based on manager type
        let image_to_use = if let Some(img) = params.image {
            Some(img)
        } else if manager.get_is_non_tee() {
            // Non-TEE manager requires image; optional latest versioned ref from manager allowlist.
            Some(
                self.resolve_non_tee_worker_image_ref(
                    manager,
                    &canonical_service_type,
                    configs.agent_hosting.as_ref(),
                )
                .await?,
            )
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
            "service_type": compose_api_service_type,
            "user_id": user_id,
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
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        let configs = self.get_system_configs().await;
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
            .unwrap_or(DEFAULT_AGENT_SERVICE_TYPE);

        let canonical_service_type = service_type.to_string();
        let compose_api_service_type = compose_api_service_type_on_create(
            manager.get_is_non_tee(),
            &canonical_service_type,
            configs.agent_hosting.as_ref(),
        );

        // Build request body with base fields
        // Note: In non-TEE mode, image is required; in TEE mode it's optional
        let image_to_use = if let Some(img) = params.image {
            Some(img)
        } else if manager.get_is_non_tee() {
            Some(
                self.resolve_non_tee_worker_image_ref(
                    manager,
                    &canonical_service_type,
                    configs.agent_hosting.as_ref(),
                )
                .await?,
            )
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
            "service_type": compose_api_service_type,
            "user_id": user_id,
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
            let mut chunk_count = 0;
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
                        chunk_count += 1;
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
                                        if let Some(event_type) =
                                            event.get("event").and_then(|v| v.as_str())
                                        {
                                            tracing::info!(
                                                "Agent API SSE event received: event_type={}",
                                                event_type
                                            );
                                        }
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
                        // If stream ended after successfully processing all received data,
                        // treat as normal stream closure (connection terminated after sending events)
                        if chunk_count > 0 && buffer.is_empty() {
                            break;
                        }

                        tracing::error!(
                            "Agent API stream error: error={}, chunks_received={}, buffer_content={:?}",
                            e,
                            chunk_count,
                            buffer
                        );
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
        let manager = self.next_available_tee_manager().await?;

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
            .or_else(|| Some(DEFAULT_AGENT_SERVICE_TYPE.to_string()));

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
                user_id,
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
        let manager = self.next_available_tee_manager().await?;

        // Create an unbound API key on behalf of the user
        let key_name = params
            .name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let default_expiry = Some(Utc::now() + Duration::days(90));
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, default_expiry)
            .await?;
        let api_key_id = api_key.id;

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
            .or_else(|| Some(DEFAULT_AGENT_SERVICE_TYPE.to_string()));

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
                user_id,
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
                        let has_instance_data = event.get("instance").is_some();
                        if !instance_saved && has_instance_data {
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
                                    match repository
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
                                        Ok(instance) => {
                                            // Bind the unbound API key to this instance
                                            // Validate before binding: key exists, is unbound, and belongs to user
                                            let bind_result = async {
                                                let api_key = repository
                                                    .get_api_key_by_id(api_key_id)
                                                    .await?
                                                    .ok_or_else(|| anyhow!("API key not found"))?;

                                                if api_key.user_id != user_id {
                                                    return Err(anyhow!(
                                                        "API key does not belong to user"
                                                    ));
                                                }

                                                if api_key.instance_id.is_some() {
                                                    return Err(anyhow!(
                                                        "API key is already bound"
                                                    ));
                                                }

                                                // Verify instance belongs to user
                                                let db_instance = repository
                                                    .get_instance(instance.id)
                                                    .await?
                                                    .ok_or_else(|| {
                                                        anyhow!("Instance not found in database")
                                                    })?;

                                                if db_instance.user_id != user_id {
                                                    return Err(anyhow!(
                                                        "Instance does not belong to user"
                                                    ));
                                                }

                                                // Now safe to bind
                                                repository
                                                    .bind_api_key_to_instance(
                                                        api_key_id,
                                                        instance.id,
                                                    )
                                                    .await?;

                                                anyhow::Ok(())
                                            }
                                            .await;

                                            if let Err(e) = bind_result {
                                                let err_msg = format!(
                                                    "Failed to bind API key to instance: \
                                                     instance_id={}, api_key_id={}, error={}",
                                                    instance.id, api_key_id, e
                                                );
                                                tracing::error!("{}", err_msg);
                                                let _ = tx.send(Err(anyhow!(err_msg))).await;
                                                break;
                                            }
                                            instance_saved = true;
                                            // Forward event to caller
                                            let _ = tx.send(Ok(event)).await;
                                        }
                                        Err(e) => {
                                            let err_msg = format!(
                                                "Failed to create instance in database: {}",
                                                e
                                            );
                                            tracing::error!("{}", err_msg);
                                            let _ = tx.send(Err(anyhow!(err_msg))).await;
                                            break;
                                        }
                                    }
                                }
                            }
                        } else if !has_instance_data {
                            // Forward non-instance events to caller
                            let _ = tx.send(Ok(event)).await;
                        }
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
        let manager = self.next_available_non_tee_manager().await?;
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

            // Get session token: try login first, register on 404
            self.compose_api_get_session_token(&manager, &auth_secret, &backup_passphrase, user_id)
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

        let service_type_for_api = params
            .service_type
            .clone()
            .or_else(|| Some(DEFAULT_AGENT_SERVICE_TYPE.to_string()));

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
                user_id,
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
                                        user_id,
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
            .ok_or(AgentServiceError::InstanceNotFound)?;

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
    async fn delete_instance(
        &self,
        instance_id: Uuid,
        actor_user_id: Option<UserId>,
        reason: &str,
    ) -> anyhow::Result<()> {
        tracing::info!("Deleting instance: instance_id={}", instance_id);

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or(AgentServiceError::InstanceNotFound)?;

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

        self.repository
            .delete_instance(instance_id, actor_user_id, reason)
            .await?;

        tracing::info!(
            "Instance deleted successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn restart_instance(
        &self,
        instance_id: Uuid,
        owner_user_id: UserId,
        actor_user_id: UserId,
        reason: &str,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Restarting instance: instance_id={}, user_id={}",
            instance_id,
            owner_user_id
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
        if instance.user_id != owner_user_id {
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
            .json(&serde_json::json!({ "user_id": owner_user_id }))
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
            .update_instance_status(instance_id, "active", Some(actor_user_id), reason)
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

        tracing::info!(
            "Upgrade: manager_url={}, is_non_tee={}, instance_name={}",
            manager.url,
            manager.get_is_non_tee(),
            instance.name
        );

        // Route to appropriate logic based on infrastructure type
        if manager.get_is_non_tee() {
            self.upgrade_instance_stream_non_tee(&instance, manager, instance_id, user_id)
                .await
        } else {
            self.upgrade_instance_stream_tee(&instance, manager, instance_id, user_id)
                .await
        }
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
        tracing::info!(
            "Upgrade check: manager_url={}, is_non_tee={}, instance_name={}",
            manager.url,
            manager.get_is_non_tee(),
            instance.name
        );

        // Route to appropriate logic based on infrastructure type
        if manager.get_is_non_tee() {
            self.check_upgrade_available_non_tee(&instance, manager, instance_id)
                .await
        } else {
            self.check_upgrade_available_tee(&instance, manager, instance_id)
                .await
        }
    }

    async fn stop_instance(
        &self,
        instance_id: Uuid,
        owner_user_id: UserId,
        actor_user_id: UserId,
        reason: &str,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Stopping instance: instance_id={}, user_id={}",
            instance_id,
            owner_user_id
        );

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify ownership
        if instance.user_id != owner_user_id {
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
            .json(&serde_json::json!({ "user_id": owner_user_id }))
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

        // Update DB status; repository persists status-history/audit row explicitly.
        self.repository
            .update_instance_status(instance_id, "stopped", Some(actor_user_id), reason)
            .await?;

        tracing::info!(
            "Instance stopped successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn start_instance(
        &self,
        instance_id: Uuid,
        owner_user_id: UserId,
        actor_user_id: UserId,
        reason: &str,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Starting instance: instance_id={}, user_id={}",
            instance_id,
            owner_user_id
        );

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Verify ownership
        if instance.user_id != owner_user_id {
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
            .json(&serde_json::json!({ "user_id": owner_user_id }))
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

        // Update DB status; repository persists status-history/audit row explicitly.
        self.repository
            .update_instance_status(instance_id, "active", Some(actor_user_id), reason)
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
                .update_instance_status(inst.id, new_status, None, "sync_status_poll")
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
        let configs = match self.system_configs_service.get_configs().await {
            Err(e) => {
                tracing::warn!(
                    "Failed to load system configs for gateway session setup: {}",
                    e
                );
                return Err(e);
            }
            Ok(None) => {
                tracing::debug!(
                    "No system_configs row; using defaults for gateway session eligibility"
                );
                SystemConfigs::default()
            }
            Ok(Some(c)) => c,
        };

        let non_tee_global = Self::is_non_tee_infra(&configs);

        // Try to get existing user passkey credentials
        let passkey_existing = match self.repository.get_user_passkey_credentials(user_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch user passkey credentials: user_id={}, error={}",
                    user_id,
                    e
                );
                return Err(e);
            }
        };

        // Primary: new agents use non-TEE (admin flag). Also attempt when user still needs
        // crabshack session after an infra switch: existing passkey or non-TEE routed instances
        // (mirrors per-instance manager typing in `resolve_bearer_token`).
        let mut needs_non_tee_gateway = non_tee_global;
        if !needs_non_tee_gateway {
            if passkey_existing.is_some() {
                needs_non_tee_gateway = true;
                tracing::debug!(
                    "Gateway session: user has passkey credentials while global infra is TEE — still attempting compose session"
                );
            } else {
                let (instances, _) = self
                    .repository
                    .list_user_instances(user_id, GATEWAY_SESSION_INSTANCE_SCAN_LIMIT, 0)
                    .await?;
                if self.user_has_non_tee_routed_instance(&instances) {
                    needs_non_tee_gateway = true;
                    tracing::debug!(
                        "Gateway session: user has non-TEE instance while global infra is TEE — still attempting compose session"
                    );
                }
            }
        }

        if !needs_non_tee_gateway {
            tracing::debug!(
                "Skipping gateway session: TEE infra, no passkey, no non-TEE routed instances"
            );
            return Ok(None);
        }

        let manager = self
            .managers
            .iter()
            .find(|mgr| mgr.get_is_non_tee())
            .ok_or_else(|| {
                anyhow!(
                    "No non-TEE agent manager configured (have {} manager(s))",
                    self.managers.len()
                )
            })?;

        let (auth_secret, backup_passphrase) = match passkey_existing {
            Some((secret, passphrase)) => (secret, passphrase),
            None => {
                // First login - create passkey credentials for this user
                tracing::debug!(
                    "Creating passkey credentials for user on first login: user_id={}",
                    user_id
                );
                let auth_secret = Self::generate_random_credential(32);
                let backup_passphrase = Self::generate_random_credential(32);

                self.repository
                    .upsert_user_passkey_credentials(user_id, &auth_secret, &backup_passphrase)
                    .await?;

                tracing::debug!(
                    "User passkey credentials stored in database: user_id={}",
                    user_id
                );

                (auth_secret, backup_passphrase)
            }
        };

        // Get session token: try login first, register on 404
        let session_token = self
            .compose_api_get_session_token(manager, &auth_secret, &backup_passphrase, user_id)
            .await?;

        // Set up gateway cookie and get Set-Cookie header
        let set_cookie = self
            .compose_api_proxy_session(manager, &session_token, user_id)
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

/// Response structure from crabshack /images endpoint
/// Used to parse and filter non-TEE image allowlist
#[derive(serde::Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct CrabshackImageEntry {
    #[serde(rename = "ref")]
    ref_: String,
    service_type: String,
    status: String,
    created_at: String,
    #[serde(rename = "digest")]
    image_digest: Option<String>,
}

/// Response structure from crabshack `/instances/{name}` for non-TEE upgrade flows.
#[derive(serde::Deserialize, Debug)]
struct NonTeeInstanceResponse {
    image: String,
    #[serde(default)]
    image_digest: Option<String>,
}

impl AgentServiceImpl {
    /// Check upgrade availability for TEE infrastructure (compose-api)
    async fn check_upgrade_available_tee(
        &self,
        instance: &AgentInstance,
        manager: &AgentManager,
        instance_id: Uuid,
    ) -> anyhow::Result<UpgradeAvailability> {
        tracing::info!(
            "Checking upgrade availability (TEE): instance_id={}, instance_name={}",
            instance_id,
            instance.name
        );

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(instance, manager).await?;

        // Fetch latest versions from compose-api
        let version_url = format!("{}/version", manager.url);
        tracing::debug!("TEE: Fetching versions from: {}", version_url);
        let version_resp = self
            .http_client
            .get(&version_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch compose-api version: {}", e))?;

        tracing::debug!("TEE: /version response status: {}", version_resp.status());
        if !version_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch compose-api version: status={}",
                version_resp.status()
            ));
        }

        #[derive(serde::Deserialize, Debug)]
        struct VersionResponse {
            images: std::collections::HashMap<String, String>,
        }

        let version: VersionResponse = version_resp
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse compose-api version response: {}", e))?;

        tracing::debug!("TEE: /version response body: {:?}", version);

        // Map service_type to image key in the version response
        let service_type = instance.service_type_str();
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

        tracing::debug!(
            "TEE: Latest image for service_type='{}': {}",
            service_type,
            latest_image
        );

        // Fetch current instance status from compose-api
        let encoded_name = urlencoding::encode(&instance.name);
        let instance_url = format!("{}/instances/{}", manager.url, encoded_name);
        tracing::debug!("TEE: Fetching instance status from: {}", instance_url);
        let instance_resp = self
            .http_client
            .get(&instance_url)
            .bearer_auth(&bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch instance status: {}", e))?;

        tracing::debug!(
            "TEE: /instances/{} response status: {}",
            encoded_name,
            instance_resp.status()
        );

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
                current_digest: None,
                latest_digest: None,
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

        let response_body = instance_resp
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read instance response body: {}", e))?;

        let instance_status: InstanceResponse = serde_json::from_str(&response_body)
            .map_err(|e| anyhow!("Failed to parse instance response: {}", e))?;

        let current_image = instance_status.image;
        // Log parsed fields only — full `/instances` JSON may include tokens, URLs, or keys.
        tracing::debug!(
            "TEE: Parsed /instances/{} response: image={}",
            encoded_name,
            current_image
        );

        let has_upgrade = current_image != latest_image;

        tracing::info!(
            "TEE upgrade check completed: instance_id={}, current_image={}, latest_image={}, has_upgrade={}",
            instance_id,
            current_image,
            latest_image,
            has_upgrade
        );

        Ok(UpgradeAvailability {
            has_upgrade,
            current_image: Some(current_image),
            latest_image,
            current_digest: None,
            latest_digest: None,
        })
    }

    /// Fetch and filter allowed images from crabshack for a non-TEE manager.
    /// `target_service_type` is the canonical or stored service type (e.g. `openclaw`, `ironclaw`, or legacy compose names).
    /// Returns filtered list of images and the hosting config (to avoid redundant system_configs reads).
    async fn fetch_allowed_images_non_tee(
        &self,
        manager: &AgentManager,
        target_service_type: &str,
        context: &str,
    ) -> anyhow::Result<(Vec<CrabshackImageEntry>, Option<AgentHostingConfig>)> {
        let bearer_token = &manager.token;

        // Fetch available images from crabshack allowlist
        let images_url = format!("{}/images", manager.url);
        tracing::debug!(
            "Non-TEE ({}): Fetching image allowlist from: {}",
            context,
            images_url
        );
        let images_resp = self
            .http_client
            .get(&images_url)
            .bearer_auth(bearer_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch non-TEE images allowlist: {}", e))?;

        tracing::debug!(
            "Non-TEE ({}): /images response status: {}",
            context,
            images_resp.status()
        );

        if !images_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch non-TEE images allowlist: status={}",
                images_resp.status()
            ));
        }

        let response_body = images_resp
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read non-TEE images response body: {}", e))?;

        let response_body_len = response_body.len();

        let image_entries: Vec<CrabshackImageEntry> = serde_json::from_str(&response_body)
            .map_err(|e| anyhow!("Failed to parse non-TEE images response: {}", e))?;

        let sample_refs = image_entries
            .iter()
            .take(5)
            .map(|img| img.ref_.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        tracing::debug!(
            "Non-TEE ({}): Parsed {} allowlist images (response_bytes={}, sample_refs=[{}])",
            context,
            image_entries.len(),
            response_body_len,
            sample_refs
        );

        // Per-entry lines are verbose for large allowlists; use trace for full breakdown.
        for img in &image_entries {
            tracing::trace!(
                "Non-TEE ({}): Allowlist image: ref={}, service_type={}, status={}, has_digest={}, created_at={}",
                context,
                img.ref_,
                img.service_type,
                img.status,
                img.image_digest.is_some(),
                img.created_at
            );
        }

        // Transform canonical service type to crabshack format (configurable via system_configs)
        let system_configs = self
            .system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten();
        let hosting_config = system_configs
            .as_ref()
            .and_then(|cfg| cfg.agent_hosting.as_ref());
        let crabshack_service_type =
            service_type_for_crabshack(target_service_type, hosting_config);

        tracing::debug!(
            "Non-TEE ({}): Filtering for service_type='{}' with status='allow-create'",
            context,
            crabshack_service_type
        );

        // Filter images: must match service_type and have status='allow-create'
        let available_images: Vec<CrabshackImageEntry> = image_entries
            .iter()
            .filter(|img| {
                img.service_type == crabshack_service_type && img.status == "allow-create"
            })
            .cloned()
            .collect();

        // Warn about incomplete entries (missing image_digest) for non-versioned tags.
        // Image digest is only required for non-versioned tag comparison during upgrades.
        for img in &available_images {
            // Only warn if this is a non-versioned tag and digest is missing
            if extract_version_from_image(&img.ref_).is_none() && img.image_digest.is_none() {
                tracing::warn!(
                    "Non-TEE ({}): Allowlist entry with non-versioned tag missing image_digest (incomplete): ref={}. \
                     This entry cannot be used for non-versioned tag upgrades.",
                    context,
                    img.ref_
                );
            }
        }

        tracing::debug!(
            "Non-TEE ({}): Available images after filtering: {} images",
            context,
            available_images.len()
        );

        Ok((available_images, hosting_config.cloned()))
    }

    /// Fetch the latest versioned image from crabshack allowlist for a non-TEE manager.
    /// Returns the image ref, semantic version, and optional digest (only considers images with numeric versions)
    async fn get_latest_image_non_tee(
        &self,
        manager: &AgentManager,
        target_service_type: &str,
        context: &str, // For logging: "check", "upgrade", or "deploy"
    ) -> anyhow::Result<(String, String, Option<String>)> {
        let (available_images, hosting_config) = self
            .fetch_allowed_images_non_tee(manager, target_service_type, context)
            .await?;

        // Extract versions from image refs and log them
        let images_with_versions: Vec<(String, Option<String>, Option<String>)> = available_images
            .iter()
            .map(|img| {
                let version = extract_version_from_image(&img.ref_);
                if let Some(ref v) = version {
                    tracing::debug!(
                        "Non-TEE ({}): Available image: ref={}, version={}",
                        context,
                        img.ref_,
                        v
                    );
                } else {
                    tracing::debug!(
                        "Non-TEE ({}): Available image (non-numeric tag): ref={}",
                        context,
                        img.ref_
                    );
                }
                (img.ref_.clone(), version, img.image_digest.clone())
            })
            .collect();

        // Check if pre-release versions are allowed (defaults to false = stable-only)
        // Use the hosting_config we already fetched in fetch_allowed_images_non_tee to avoid redundant DB read
        let allow_prerelease = hosting_config
            .as_ref()
            .and_then(|h| h.crabshack.allow_prerelease_upgrades)
            .unwrap_or(false);

        if !allow_prerelease {
            tracing::debug!(
                "Non-TEE ({}): Filtering to stable versions only (allow_prerelease_upgrades=false)",
                context
            );
        }

        // Find the newest image by comparing semantic versions
        let latest_image_entry = images_with_versions
            .iter()
            .filter_map(|(ref_, version, digest)| {
                version
                    .as_ref()
                    .map(|v| (ref_.clone(), v.clone(), digest.clone()))
            })
            // Tags can look numeric (`1.2.x`) but fail strict semver — exclude them from "latest" selection.
            .filter(|(_, v, _)| parse_semantic_version(v).is_some())
            .filter(|(_, v, _)| allow_prerelease || is_stable_version(v))
            .max_by(|a, b| compare_semantic_versions(&a.1, &b.1))
            .ok_or_else(|| {
                anyhow!(
                    "No images with numeric versions available in allowlist: context='{}', service_type='{}'",
                    context,
                    target_service_type
                )
            })?;

        tracing::debug!(
            "Non-TEE ({}): Latest image: ref={}, version={}, digest={:?}",
            context,
            latest_image_entry.0,
            latest_image_entry.1,
            latest_image_entry.2
        );

        Ok((
            latest_image_entry.0,
            latest_image_entry.1,
            latest_image_entry.2,
        ))
    }

    /// Check upgrade availability for non-TEE infrastructure (crabshack)
    async fn check_upgrade_available_non_tee(
        &self,
        instance: &AgentInstance,
        manager: &AgentManager,
        instance_id: Uuid,
    ) -> anyhow::Result<UpgradeAvailability> {
        tracing::info!(
            "Checking upgrade availability (non-TEE): instance_id={}, instance_name={}",
            instance_id,
            instance.name
        );

        // Use manager token (admin secret) for non-TEE crabshack API
        let bearer_token = &manager.token;

        // Fetch current instance status from crabshack
        let encoded_name = urlencoding::encode(&instance.name);
        let instance_url = format!("{}/instances/{}", manager.url, encoded_name);
        tracing::debug!("Non-TEE: Fetching instance status from: {}", instance_url);
        let instance_resp = self
            .http_client
            .get(&instance_url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch non-TEE instance status: {}", e))?;

        tracing::debug!(
            "Non-TEE: /instances/{} response status: {}",
            encoded_name,
            instance_resp.status()
        );

        // If instance not found (404), fetch allowlist to determine latest image and block upgrade
        let instance_not_found = instance_resp.status() == reqwest::StatusCode::NOT_FOUND;
        if instance_not_found {
            tracing::warn!(
                "Instance not found on crabshack: instance_id={}. Blocking upgrade until instance is synced.",
                instance_id
            );
        } else if !instance_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch non-TEE instance status: status={}",
                instance_resp.status()
            ));
        }

        let current_image = if !instance_not_found {
            let response_body = instance_resp
                .text()
                .await
                .map_err(|e| anyhow!("Failed to read non-TEE instance response body: {}", e))?;

            let instance_status: NonTeeInstanceResponse = serde_json::from_str(&response_body)
                .map_err(|e| anyhow!("Failed to parse non-TEE instance response: {}", e))?;

            // Log image + digest only — raw body can carry sensitive crabshack instance metadata.
            tracing::debug!(
                "Non-TEE: Parsed /instances/{} response: image={}, digest={:?}",
                encoded_name,
                instance_status.image,
                instance_status.image_digest
            );
            Some((instance_status.image, instance_status.image_digest))
        } else {
            None
        };

        // If instance not found (404), block upgrade until instance is synced
        // This handles cases where instance is not yet fully provisioned or synced
        if instance_not_found {
            // Try to fetch allowlist to provide the latest_image info, but don't fail if we can't
            let (latest_image, latest_digest) = match self
                .get_latest_image_non_tee(manager, instance.service_type_str(), "check")
                .await
            {
                Ok((img, _, digest)) => (img, digest),
                Err(_) => ("unknown".to_string(), None),
            };

            tracing::info!(
                "Non-TEE upgrade check blocked: instance_id={}, instance not synced. latest_image={}",
                instance_id,
                latest_image
            );
            return Ok(UpgradeAvailability {
                has_upgrade: false,
                current_image: None,
                latest_image,
                current_digest: None,
                latest_digest,
            });
        }

        let (current_image_ref, current_digest) =
            current_image.ok_or_else(|| anyhow!("Missing current image after non-found guard"))?;

        // Determine upgrade availability based on image tag type
        let current_version = extract_version_from_image(&current_image_ref);

        if let Some(curr_v) = current_version {
            // VERSIONED TAG: Use semantic version comparison
            tracing::debug!(
                "Non-TEE: Current image has numeric version: ref={}, version={}",
                current_image_ref,
                curr_v
            );

            let (latest_image, latest_version, latest_digest) = self
                .get_latest_image_non_tee(manager, instance.service_type_str(), "check")
                .await?;

            let has_upgrade =
                compare_semantic_versions(&curr_v, &latest_version) == std::cmp::Ordering::Less;

            tracing::info!(
                "Non-TEE upgrade check (versioned): instance_id={}, current_version={}, latest_version={}, has_upgrade={}",
                instance_id,
                curr_v,
                latest_version,
                has_upgrade
            );

            Ok(UpgradeAvailability {
                has_upgrade,
                current_image: Some(current_image_ref),
                latest_image,
                current_digest,
                latest_digest,
            })
        } else {
            // NON-VERSIONED TAG: Find exact ref in allowlist and compare digests
            tracing::debug!(
                "Non-TEE: Current image has non-numeric tag: ref={}",
                current_image_ref
            );

            let (allowed_entries, _hosting_config) = self
                .fetch_allowed_images_non_tee(manager, instance.service_type_str(), "check")
                .await?;

            let matching_entry = allowed_entries.iter().find(|e| e.ref_ == current_image_ref);

            let (has_upgrade, latest_image) = match matching_entry {
                Some(entry) => {
                    // Compare digests: if both exist and differ, upgrade is available
                    let has_upgrade = match (&current_digest, &entry.image_digest) {
                        (Some(curr_dig), Some(allow_dig)) => {
                            // Both digests present: compare them
                            let differs = curr_dig != allow_dig;
                            tracing::debug!(
                                "Non-TEE: Digest comparison: current={}, allowlist={}, differs={}",
                                curr_dig,
                                allow_dig,
                                differs
                            );
                            differs
                        }
                        (Some(_), None) => {
                            // Current has digest but allowlist entry is missing it - data quality issue
                            // For non-versioned tags, crabshack should always populate image_digest
                            tracing::warn!(
                                "Non-TEE: Allowlist entry missing image_digest (incomplete data): ref={}, current_digest={:?}",
                                current_image_ref,
                                current_digest
                            );
                            false
                        }
                        (None, Some(_)) => {
                            // Current missing digest but allowlist has one - can't compare, assume no upgrade
                            tracing::debug!(
                                "Non-TEE: Current digest missing but allowlist digest present: current=None, allowlist={:?}",
                                entry.image_digest
                            );
                            false
                        }
                        (None, None) => {
                            // Both missing digests - can't compare, assume no upgrade
                            tracing::debug!("Non-TEE: Both current and allowlist digests missing");
                            false
                        }
                    };
                    (has_upgrade, entry.ref_.clone())
                }
                None => {
                    // Image ref not in allowlist anymore - no upgrade info available
                    tracing::warn!(
                        "Non-TEE: Current image ref not found in allowlist: ref={}",
                        current_image_ref
                    );
                    (false, current_image_ref.clone())
                }
            };

            let latest_digest = matching_entry
                .and_then(|e| e.image_digest.as_ref())
                .cloned();

            tracing::info!(
                "Non-TEE upgrade check (non-versioned): instance_id={}, current_ref={}, current_digest={:?}, allowlist_digest={:?}, has_upgrade={}",
                instance_id,
                current_image_ref,
                current_digest,
                latest_digest,
                has_upgrade
            );

            Ok(UpgradeAvailability {
                has_upgrade,
                current_image: Some(current_image_ref),
                latest_image,
                current_digest,
                latest_digest,
            })
        }
    }
}

impl AgentServiceImpl {
    /// Upgrade instance with SSE stream for TEE infrastructure (compose-api)
    async fn upgrade_instance_stream_tee(
        &self,
        instance: &AgentInstance,
        manager: &AgentManager,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>> {
        tracing::info!(
            "Upgrading instance (TEE streaming): instance_id={}, instance_name={}",
            instance_id,
            instance.name
        );

        // Resolve bearer token: for passkey instances, login to get a fresh token
        let bearer_token = self.resolve_bearer_token(instance, manager).await?;

        // Fetch latest images from compose-api
        let version_url = format!("{}/version", manager.url);
        tracing::debug!("TEE upgrade: Fetching versions from: {}", version_url);
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
        let service_type = instance.service_type_str();
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

        tracing::debug!(
            "TEE upgrade: Latest image for service_type='{}': {}",
            service_type,
            image
        );

        // Restart with the latest image (5-minute timeout; compose-api yields SSE stream)
        self.call_restart_streaming(manager, instance, &image, instance_id, user_id)
            .await
    }

    /// Upgrade instance with SSE stream for non-TEE infrastructure (crabshack)
    async fn upgrade_instance_stream_non_tee(
        &self,
        instance: &AgentInstance,
        manager: &AgentManager,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>> {
        tracing::info!(
            "Upgrading instance (non-TEE streaming): instance_id={}, instance_name={}",
            instance_id,
            instance.name
        );

        // Fetch current instance to determine its image tag type
        let bearer_token = &manager.token;
        let encoded_name = urlencoding::encode(&instance.name);
        let instance_url = format!("{}/instances/{}", manager.url, encoded_name);
        tracing::debug!(
            "Non-TEE upgrade: Fetching current instance from: {}",
            instance_url
        );

        let instance_resp = self
            .http_client
            .get(&instance_url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch non-TEE instance for upgrade: {}", e))?;

        if !instance_resp.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch non-TEE instance status during upgrade: status={}",
                instance_resp.status()
            ));
        }

        let response_body = instance_resp.text().await.map_err(|e| {
            anyhow!(
                "Failed to read non-TEE instance response body during upgrade: {}",
                e
            )
        })?;

        // Avoid logging the raw response body during upgrade — same sensitivity as the check path above.
        let current_instance: NonTeeInstanceResponse = serde_json::from_str(&response_body)
            .map_err(|e| {
                anyhow!(
                    "Failed to parse non-TEE instance response during upgrade: {}",
                    e
                )
            })?;

        let current_image = current_instance.image;
        tracing::debug!(
            "Non-TEE upgrade: Current instance image: {}, digest: {:?}",
            current_image,
            current_instance.image_digest
        );

        // Determine image and digest to upgrade to based on tag type
        let (image, image_digest) = if extract_version_from_image(&current_image).is_some() {
            // VERSIONED TAG: Get latest semver version
            tracing::debug!("Non-TEE upgrade: Upgrading versioned image");
            let (latest_image, _version, latest_digest) = self
                .get_latest_image_non_tee(manager, instance.service_type_str(), "upgrade")
                .await?;
            (latest_image, latest_digest)
        } else {
            // NON-VERSIONED TAG: Validate current ref exists in allowlist and use same tag
            tracing::debug!("Non-TEE upgrade: Upgrading non-versioned image");
            let (allowed_entries, _hosting_config) = self
                .fetch_allowed_images_non_tee(manager, instance.service_type_str(), "upgrade")
                .await?;

            let allowlist_entry = allowed_entries.iter().find(|e| e.ref_ == current_image);
            let entry = allowlist_entry.ok_or_else(|| {
                anyhow!(
                    "Current image ref {} not found in allowlist during upgrade",
                    current_image
                )
            })?;
            let target_digest = entry.image_digest.clone();

            tracing::debug!(
                "Non-TEE upgrade: Non-versioned tag found in allowlist: ref={}, current_digest={:?}, target_digest={:?}",
                current_image,
                current_instance.image_digest,
                target_digest
            );

            // Use the same image ref with explicit target digest to avoid ambiguity
            (current_image.clone(), target_digest)
        };

        // Combine image and digest using OCI format (name[:tag]@digest) for non-TEE.
        // Keep the original tag when present so manager /instances responses preserve mutable tag context
        // (e.g., :staging) while still pinning by digest.
        let target_image_ref = if let Some(digest) = image_digest {
            // Defensive: if image already contains a digest, replace it instead of appending
            // a second one (which would produce an invalid ref like `name@old@new`).
            let image_base = image.split('@').next().unwrap_or(&image);
            format!("{}@{}", image_base, digest)
        } else {
            image.clone()
        };

        tracing::debug!(
            "Non-TEE upgrade: Target image ref to restart with: {}",
            target_image_ref
        );

        // Restart with the target image ref (5-minute timeout; crabshack yields SSE stream)
        self.call_restart_streaming(manager, instance, &target_image_ref, instance_id, user_id)
            .await
    }

    /// Call /instances/{name}/restart with image ref and stream the response.
    /// For non-TEE, image should be in OCI format: name[:tag]@digest when digest is known.
    async fn call_restart_streaming(
        &self,
        manager: &AgentManager,
        instance: &AgentInstance,
        image: &str,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>> {
        use futures::stream::StreamExt;

        let bearer_token = &manager.token;
        let encoded_name = urlencoding::encode(&instance.name);
        let restart_url = format!("{}/instances/{}/restart", manager.url, encoded_name);

        tracing::debug!(
            "Calling restart endpoint for streaming: url={}, image={}",
            restart_url,
            image
        );

        #[derive(serde::Serialize)]
        struct RestartBody {
            image: String,
            user_id: UserId,
        }

        // Spawn task to proxy SSE stream to channel
        let (tx, rx) = tokio::sync::mpsc::channel::<anyhow::Result<bytes::Bytes>>(32);

        let http_client = self.http_client.clone();
        let token = bearer_token.clone();
        let instance_name = instance.name.clone();
        let image_for_task = image.to_string();

        tokio::spawn(async move {
            let response = match http_client
                .post(&restart_url)
                .bearer_auth(&token)
                .json(&RestartBody {
                    image: image_for_task.clone(),
                    user_id,
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
                    "Upgrade restart failed: instance_id={}, instance_name={}, image={}, restart_url={}, status={}",
                    instance_id,
                    instance_name,
                    image_for_task,
                    restart_url,
                    response.status()
                );
                let _ = tx
                    .send(Err(anyhow!(
                        "Upgrade restart failed with status {}",
                        response.status()
                    )))
                    .await;
                return;
            }

            tracing::info!(
                "Upgrade restart initiated: instance_id={}, image={}",
                instance_id,
                image_for_task
            );

            let mut stream = response.bytes_stream();

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        // Forward the chunk from manager API to client
                        if tx.send(Ok(bytes)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Upgrade stream error: instance_id={}, error={}",
                            instance_id,
                            e
                        );
                        let _ = tx.send(Err(anyhow!("Stream error: {}", e))).await;
                        return;
                    }
                }
            }

            // Stream ended naturally - send completion event
            tracing::info!(
                "Upgrade stream ended successfully: instance_id={}, image={}",
                instance_id,
                image_for_task
            );

            // Emit completion event with expected format for frontend
            let completion = serde_json::json!({"stage": "ready"}).to_string();
            let _ = tx
                .send(Ok(bytes::Bytes::from(format!("data: {}\n\n", completion))))
                .await;
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::ports::AgentService;
    use crate::system_configs::ports::{
        AgentHostingConfig, AgentHostingCrabshackConfig, PartialSystemConfigs, SystemConfigs,
        SystemConfigsService,
    };
    use chrono::{Duration, Utc};
    use config::AgentManager;

    impl AgentServiceImpl {
        /// Test-only wrapper that preserves legacy test call sites.
        async fn next_available_manager(&self) -> anyhow::Result<AgentManager> {
            let configs = self.get_system_configs().await;
            let non_tee_infra = Self::is_non_tee_infra(&configs);
            let manager_type = if non_tee_infra {
                ManagerType::NonTee
            } else {
                ManagerType::Tee
            };
            self.next_available_manager_for_type(manager_type).await
        }
    }

    #[test]
    fn compose_api_service_type_on_create_tee_passes_canonical() {
        assert_eq!(
            compose_api_service_type_on_create(false, "ironclaw", None),
            "ironclaw"
        );
        assert_eq!(
            compose_api_service_type_on_create(false, "openclaw", None),
            "openclaw"
        );
    }

    #[test]
    fn compose_api_service_type_on_create_non_tee_maps_ironclaw_and_openclaw() {
        assert_eq!(
            compose_api_service_type_on_create(true, "ironclaw", None),
            "ironclaw-dind"
        );
        assert_eq!(
            compose_api_service_type_on_create(true, "openclaw", None),
            "openclaw"
        );
    }

    #[test]
    fn compose_api_service_type_on_create_non_tee_respects_hosting_overrides() {
        let hosting = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                ironclaw_service_type: Some("iron-claw-custom".to_string()),
                openclaw_service_type: Some("oc-custom".to_string()),
                ..Default::default()
            },
        };
        assert_eq!(
            compose_api_service_type_on_create(true, "ironclaw", Some(&hosting)),
            "iron-claw-custom"
        );
        assert_eq!(
            compose_api_service_type_on_create(true, "openclaw", Some(&hosting)),
            "oc-custom"
        );
    }

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
                        crabshack: Default::default(),
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
                        crabshack: Default::default(),
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
                        crabshack: Default::default(),
                    }),
                    ..Default::default()
                }),
            }
        }

        fn with_manager_limit(max: u64) -> Self {
            Self {
                configs: Some(SystemConfigs {
                    max_instances_per_manager: Some(max),
                    ..Default::default()
                }),
            }
        }

        /// Per-URL limits with non-TEE infra enabled
        fn with_allow_prerelease_upgrades(allow_prerelease: bool) -> Self {
            use crate::system_configs::ports::{AgentHostingConfig, AgentHostingCrabshackConfig};
            Self {
                configs: Some(SystemConfigs {
                    agent_hosting: Some(AgentHostingConfig {
                        new_agent_with_non_tee_infra: None,
                        crabshack: AgentHostingCrabshackConfig {
                            allow_prerelease_upgrades: Some(allow_prerelease),
                            ..Default::default()
                        },
                    }),
                    ..Default::default()
                }),
            }
        }

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
                        crabshack: Default::default(),
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

    /// System configs service that always fails `get_configs` (for gateway / error-path tests).
    struct MockSystemConfigsServiceErr;

    #[async_trait]
    impl SystemConfigsService for MockSystemConfigsServiceErr {
        async fn get_configs(&self) -> anyhow::Result<Option<SystemConfigs>> {
            Err(anyhow!("injected system_configs get_configs failure"))
        }

        async fn upsert_configs(&self, _configs: SystemConfigs) -> anyhow::Result<SystemConfigs> {
            Err(anyhow!(
                "MockSystemConfigsServiceErr: upsert_configs not supported"
            ))
        }

        async fn update_configs(
            &self,
            _configs: PartialSystemConfigs,
        ) -> anyhow::Result<SystemConfigs> {
            Err(anyhow!(
                "MockSystemConfigsServiceErr: update_configs not supported"
            ))
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
    fn test_user_has_non_tee_routed_instance_positive() {
        let ntee_url = "https://claws.example.com/api/crabshack/mgr0".to_string();
        let managers = vec![
            AgentManager {
                url: "https://tee.example/api".to_string(),
                token: "tee-tok".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: ntee_url.clone(),
                token: "ntok".to_string(),
                is_non_tee: true,
            },
        ];
        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let uid = UserId(Uuid::new_v4());
        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: uid,
            instance_id: "i1".to_string(),
            name: "n1".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some(ntee_url),
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(svc.user_has_non_tee_routed_instance(&[instance]));
    }

    #[test]
    fn test_user_has_non_tee_routed_instance_false_when_only_tee_manager_url() {
        let tee_url = "https://tee.example/api".to_string();
        let managers = vec![AgentManager {
            url: tee_url.clone(),
            token: "tee-tok".to_string(),
            is_non_tee: false,
        }];
        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let uid = UserId(Uuid::new_v4());
        let instance = AgentInstance {
            id: Uuid::new_v4(),
            user_id: uid,
            instance_id: "i1".to_string(),
            name: "n1".to_string(),
            public_ssh_key: None,
            instance_url: None,
            instance_token: None,
            dashboard_url: None,
            agent_api_base_url: Some(tee_url),
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!svc.user_has_non_tee_routed_instance(&[instance]));
    }

    #[tokio::test]
    async fn test_setup_gateway_session_skips_when_tee_no_passkey_no_non_tee_instances() {
        let mut repo = MockAgentRepository::new();
        repo.expect_get_user_passkey_credentials()
            .times(1)
            .returning(|_| Ok(None));
        repo.expect_list_user_instances()
            .times(1)
            .returning(|_, _, _| Ok((vec![], 0)));

        let svc = make_service(
            make_managers(1),
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_non_tee_infra(false)),
        );

        let out = svc
            .setup_gateway_session_for_user(UserId(Uuid::new_v4()))
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn test_setup_gateway_session_propagates_system_config_load_error() {
        let mut repo = MockAgentRepository::new();
        repo.expect_get_user_passkey_credentials().times(0);
        repo.expect_list_user_instances().times(0);

        let svc = make_service(
            make_managers(1),
            Arc::new(repo),
            Arc::new(MockSystemConfigsServiceErr),
        );

        let err = svc
            .setup_gateway_session_for_user(UserId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("injected system_configs"),
            "err={}",
            err
        );
    }

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

    #[tokio::test]
    async fn test_next_available_manager_for_type_applies_limit_to_tee_pool() {
        let managers = vec![
            AgentManager {
                url: "https://tee-full.example.com".to_string(),
                token: "tee-full-token".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: "https://tee-room.example.com".to_string(),
                token: "tee-room-token".to_string(),
                is_non_tee: false,
            },
            AgentManager {
                url: "https://claws.example.com/api/crabshack/non-tee".to_string(),
                token: "non-tee-token".to_string(),
                is_non_tee: true,
            },
        ];

        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url == "https://tee-full.example.com")
            .returning(|_| Ok(10));
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url == "https://tee-room.example.com")
            .returning(|_| Ok(5));

        let svc = make_service(
            managers,
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_manager_limit(10)),
        );

        let mgr = svc
            .next_available_manager_for_type(ManagerType::Tee)
            .await
            .unwrap();
        assert_eq!(mgr.url, "https://tee-room.example.com");
    }

    #[tokio::test]
    async fn test_next_available_manager_for_type_applies_limit_to_non_tee_pool() {
        let managers = vec![
            AgentManager {
                url: "https://claws.example.com/api/crabshack/non-tee-full".to_string(),
                token: "non-tee-full-token".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://claws.example.com/api/crabshack/non-tee-room".to_string(),
                token: "non-tee-room-token".to_string(),
                is_non_tee: true,
            },
            AgentManager {
                url: "https://tee.example.com".to_string(),
                token: "tee-token".to_string(),
                is_non_tee: false,
            },
        ];

        let mut repo = MockAgentRepository::new();
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url == "https://claws.example.com/api/crabshack/non-tee-full")
            .returning(|_| Ok(10));
        repo.expect_count_instances_by_manager()
            .withf(|url: &str| url == "https://claws.example.com/api/crabshack/non-tee-room")
            .returning(|_| Ok(4));

        let svc = make_service(
            managers,
            Arc::new(repo),
            Arc::new(MockSystemConfigsService::with_manager_limit(10)),
        );

        let mgr = svc
            .next_available_manager_for_type(ManagerType::NonTee)
            .await
            .unwrap();
        assert_eq!(
            mgr.url,
            "https://claws.example.com/api/crabshack/non-tee-room"
        );
    }

    #[tokio::test]
    async fn test_next_available_manager_for_type_errors_on_empty_target_pool() {
        let managers = vec![AgentManager {
            url: "https://tee.example.com".to_string(),
            token: "tee-token".to_string(),
            is_non_tee: false,
        }];

        let svc = make_service(
            managers,
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        let result = svc
            .next_available_manager_for_type(ManagerType::NonTee)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No suitable managers available: manager_type=non-tee"));
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
        use wiremock::matchers::{
            bearer_token, body_partial_json, header, method, path, path_regex,
        };
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
                    UserId(Uuid::new_v4()),
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
                    UserId(Uuid::new_v4()),
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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == inst_id
                        && new_status == "active"
                        && *actor == Some(user_id)
                        && change_reason == "owner_start"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .start_instance(inst_id, user_id, user_id, "owner_start")
                .await;
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
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .start_instance(inst_id, user_id, user_id, "owner_start")
                .await;
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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == inst_id
                        && new_status == "stopped"
                        && *actor == Some(user_id)
                        && change_reason == "owner_stop"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .stop_instance(inst_id, user_id, user_id, "owner_stop")
                .await;
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
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .stop_instance(inst_id, user_id, user_id, "owner_stop")
                .await;
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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == inst_id
                        && new_status == "active"
                        && *actor == Some(user_id)
                        && change_reason == "owner_restart"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .restart_instance(inst_id, user_id, user_id, "owner_restart")
                .await;
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
                .returning(|_, _, _, _| Ok(()));

            let svc = make_service(
                vec![AgentManager {
                    url: server.uri(),
                    token: "tok".to_string(),
                    is_non_tee: false,
                }],
                Arc::new(repo),
                Arc::new(MockSystemConfigsService::no_config()),
            );

            let result = svc
                .restart_instance(inst_id, user_id, user_id, "owner_restart")
                .await;
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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == inst_id
                        && new_status == "active"
                        && actor.is_none()
                        && change_reason == "sync_status_poll"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == inst_id
                        && new_status == "stopped"
                        && actor.is_none()
                        && change_reason == "sync_status_poll"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Err(anyhow!("DB connection lost")));

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
                .withf(move |instance_id, new_status, actor, change_reason| {
                    *instance_id == found_id
                        && new_status == "active"
                        && actor.is_none()
                        && change_reason == "sync_status_poll"
                })
                .times(1)
                .returning(|_, _, _, _| Ok(()));

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
                .returning(|_, _, _, _| Ok(()));

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
            // Should receive service type as-is (ironclaw)
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
            // 1. Service type used as-is (ironclaw)
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
            // Should accept ironclaw as-is
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
                    token: "compose-token".to_string(),
                    is_non_tee: true,
                }],
                "https://nearai.example.com/v1".to_string(),
                Arc::new(MockSystemConfigsService::no_config()),
                None,
                "claws".to_string(), // non_tee_agent_url_pattern
            );

            // Verify non-TEE mode behavior:
            // 1. Service type used as-is (ironclaw)
            // 2. Passkey login can be attempted
            assert!(
                service.managers[0].is_non_tee,
                "Manager should be non-TEE mode"
            );
        }

        // --- Non-TEE `check_upgrade_available` (crabshack allowlist + instance image) ---

        fn upgrade_check_instance(
            instance_db_id: Uuid,
            user_id: UserId,
            name: &str,
            crabshack_uri: &str,
            service_type: Option<&str>,
        ) -> AgentInstance {
            AgentInstance {
                id: instance_db_id,
                user_id,
                instance_id: format!("agent-api-{}", name),
                name: name.to_string(),
                public_ssh_key: None,
                instance_url: None,
                instance_token: None,
                dashboard_url: None,
                agent_api_base_url: Some(crabshack_uri.to_string()),
                service_type: service_type.map(String::from),
                status: "active".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        fn service_for_upgrade_check(
            instance: AgentInstance,
            crabshack_uri: &str,
            token: &str,
        ) -> AgentServiceImpl {
            service_for_upgrade_check_with_configs(
                instance,
                crabshack_uri,
                token,
                Arc::new(MockSystemConfigsService::no_config()),
            )
        }

        fn service_for_upgrade_check_with_configs(
            instance: AgentInstance,
            crabshack_uri: &str,
            token: &str,
            configs: Arc<dyn SystemConfigsService>,
        ) -> AgentServiceImpl {
            let instance_db_id = instance.id;
            let mut repo = MockAgentRepository::new();
            repo.expect_get_instance()
                .with(eq(instance_db_id))
                .returning(move |_| Ok(Some(instance.clone())));
            repo.expect_get_user_passkey_credentials()
                .returning(|_| Ok(None));

            make_service(
                vec![AgentManager {
                    url: crabshack_uri.to_string(),
                    token: token.to_string(),
                    is_non_tee: true,
                }],
                Arc::new(repo),
                configs,
            )
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_legacy_openclaw_dind_filter_and_semver() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-10T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:latest",
                        "service_type": "openclaw-dind",
                        "status": "deprecated",
                        "created_at": "2024-01-01T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "test-instance",
                    "image": "docker.io/nearaidev/openclaw-dind:0.20.0",
                    "status": "running"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(out.has_upgrade);
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw-dind:0.20.0")
            );
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:0.21.0");
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_prerelease_same_numeric_max_picks_later_allowlist_entry() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-10T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0-rc1",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-16T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "test-instance",
                    "image": "docker.io/nearaidev/openclaw-dind:0.20.0",
                    "status": "running"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(out.has_upgrade);
            // Default `allow_prerelease_upgrades=false` drops `0.21.0-rc1` from the candidate set, so
            // `max_by(compare_semantic_versions)` runs only on stables (`0.20.0`, `0.21.0`) and picks `0.21.0`.
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:0.21.0");
        }

        /// With `allow_prerelease_upgrades=false` (default), latest semver from allowlist ignores pre-releases.
        #[tokio::test]
        async fn non_tee_stable_only_filter_picks_highest_stable_not_prerelease() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-10T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.22.0-rc1",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-16T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:0.20.0",
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(out.has_upgrade);
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:0.21.0");
        }

        /// With `allow_prerelease_upgrades=true`, pre-releases compete for “latest” alongside stables.
        #[tokio::test]
        async fn non_tee_allow_prerelease_includes_prerelease_in_latest() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-10T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.22.0-rc1",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-16T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:0.20.0",
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check_with_configs(
                instance,
                &uri,
                token,
                Arc::new(MockSystemConfigsService::with_allow_prerelease_upgrades(
                    true,
                )),
            );
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(out.has_upgrade);
            assert_eq!(
                out.latest_image,
                "docker.io/nearaidev/openclaw-dind:0.22.0-rc1"
            );
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_canonical_openclaw_images() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw:0.20.0",
                        "service_type": "openclaw",
                        "status": "allow-create",
                        "created_at": "2024-01-10T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw:0.21.0",
                        "service_type": "openclaw",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw:latest",
                        "service_type": "openclaw",
                        "status": "deprecated",
                        "created_at": "2024-01-01T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "test-instance",
                    "image": "docker.io/nearaidev/openclaw:0.20.0",
                    "status": "running"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(out.has_upgrade);
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw:0.20.0")
            );
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw:0.21.0");
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_instance_404_blocks_upgrade() {
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/not-synced-instance"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "not-synced-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(!out.has_upgrade);
            assert!(out.current_image.is_none());
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:0.21.0");
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_non_versioned_tag_digest_changed() {
            // Test non-versioned tags (e.g., :staging, :dev) with digest comparison
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:staging",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T10:00:00Z",
                        "digest": "sha256:new-digest-abc123"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:staging",
                    "image_digest": "sha256:old-digest-xyz789"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(
                out.has_upgrade,
                "Digest changed, upgrade should be available"
            );
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw-dind:staging")
            );
            assert_eq!(
                out.latest_image,
                "docker.io/nearaidev/openclaw-dind:staging"
            );
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_non_versioned_tag_digest_unchanged() {
            // Test non-versioned tags with same digest (no upgrade)
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:dev",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T10:00:00Z",
                        "digest": "sha256:same-digest-abc123"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:dev",
                    "image_digest": "sha256:same-digest-abc123"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(
                !out.has_upgrade,
                "Digest unchanged, upgrade should NOT be available"
            );
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw-dind:dev")
            );
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:dev");
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_non_versioned_tag_not_in_allowlist() {
            // Test non-versioned tag that's not in allowlist (no upgrade)
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:staging",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T10:00:00Z",
                        "digest": "sha256:digest-staging"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:dev",
                    "image_digest": "sha256:digest-dev"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(
                !out.has_upgrade,
                "Image ref not in allowlist, upgrade should NOT be available"
            );
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw-dind:dev")
            );
            assert_eq!(out.latest_image, "docker.io/nearaidev/openclaw-dind:dev");
        }

        #[tokio::test]
        async fn non_tee_upgrade_versioned_tag_gets_latest() {
            // Test upgrade_instance_stream with versioned tag (should get latest semver)
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:0.20.0"
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.20.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-14T00:00:00Z"
                    },
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:0.21.0",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z",
                        "digest": "sha256:latest-digest"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/instances/test-instance/restart"))
                .and(body_partial_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:0.21.0@sha256:latest-digest"
                })))
                .respond_with(
                    ResponseTemplate::new(200)
                        .append_header("content-type", "text/event-stream")
                        .set_body_string(
                            "data: {\"status\":\"upgrading\"}\n\ndata: {\"stage\":\"ready\"}\n\n",
                        ),
                )
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let result = AgentService::upgrade_instance_stream(&svc, instance_id, user_id).await;

            assert!(result.is_ok(), "Upgrade should succeed with versioned tag");
        }

        #[tokio::test]
        async fn non_tee_upgrade_non_versioned_tag_keeps_same_ref() {
            // Test upgrade_instance_stream with non-versioned tag (should keep same ref)
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:staging"
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:staging",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z",
                        "digest": "sha256:new-digest"
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/instances/test-instance/restart"))
                .and(body_partial_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:staging@sha256:new-digest"
                })))
                .respond_with(
                    ResponseTemplate::new(200)
                        .append_header("content-type", "text/event-stream")
                        .set_body_string(
                            "data: {\"status\":\"upgrading\"}\n\ndata: {\"stage\":\"ready\"}\n\n",
                        ),
                )
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let result = AgentService::upgrade_instance_stream(&svc, instance_id, user_id).await;

            assert!(
                result.is_ok(),
                "Upgrade should succeed with non-versioned tag"
            );
        }

        #[tokio::test]
        async fn non_tee_check_upgrade_non_versioned_tag_missing_allowlist_digest() {
            // When allowlist doesn't have digest (None), we can't compare - no upgrade
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:staging",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T10:00:00Z"
                        // Note: no digest field (CrabshackImageEntry uses JSON key "digest")
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:staging",
                    "image_digest": "sha256:some-digest"
                })))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let out = AgentService::check_upgrade_available(&svc, instance_id, user_id)
                .await
                .expect("check_upgrade_available");

            assert!(
                !out.has_upgrade,
                "No upgrade when allowlist digest is missing (can't compare)"
            );
            assert_eq!(
                out.current_image.as_deref(),
                Some("docker.io/nearaidev/openclaw-dind:staging")
            );
        }

        #[tokio::test]
        async fn non_tee_upgrade_non_versioned_tag_not_in_allowlist_fails() {
            // Test upgrade_instance_stream fails when non-versioned tag not in allowlist
            let server = setup_mock_server().await;
            let uri = server.uri();
            let token = "crab-token";
            let instance_id = Uuid::new_v4();
            let user_id = UserId(Uuid::new_v4());

            Mock::given(method("GET"))
                .and(path("/instances/test-instance"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "image": "docker.io/nearaidev/openclaw-dind:dev"
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/images"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "ref": "docker.io/nearaidev/openclaw-dind:staging",
                        "service_type": "openclaw-dind",
                        "status": "allow-create",
                        "created_at": "2024-01-15T00:00:00Z"
                    }
                ])))
                .mount(&server)
                .await;

            let instance = upgrade_check_instance(
                instance_id,
                user_id,
                "test-instance",
                &uri,
                Some("openclaw-dind"),
            );
            let svc = service_for_upgrade_check(instance, &uri, token);
            let result = AgentService::upgrade_instance_stream(&svc, instance_id, user_id).await;

            assert!(
                result.is_err(),
                "Upgrade should fail when non-versioned tag not in allowlist"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not found in allowlist"));
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

    // Service type normalization tests removed: normalize_service_type_for_api is now a no-op

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
        // ironclaw defaults to docker.io/nearaidev/ironclaw-dind:latest when not configured
        let ironclaw_image = get_image_for_service_type("ironclaw", None);
        assert!(
            ironclaw_image.contains("docker.io/nearaidev/ironclaw-dind:"),
            "Expected docker.io/nearaidev/ironclaw-dind image, got {}",
            ironclaw_image
        );
        assert_eq!(
            get_image_for_service_type("openclaw", None),
            "docker.io/nearaidev/openclaw-nearai-worker:latest"
        );
        assert_eq!(
            get_image_for_service_type("unknown", None),
            "docker.io/nearaidev/openclaw-nearai-worker:latest"
        );
    }

    // --- Mode Flow Verification Tests ---

    // test_tee_mode_configuration_summary and test_non_tee_mode_configuration_summary removed:
    // were entirely about the removed normalize_service_type_for_api function

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

    // test_service_type_normalization_by_manager_type removed: entirely about the removed normalize_service_type_for_api function

    #[test]
    fn test_image_format_selection_by_manager_type() {
        // Test get_image_for_service_type returns correct formats
        // ironclaw defaults to docker.io/nearaidev/ironclaw-dind:latest when not configured
        let ironclaw_image = get_image_for_service_type("ironclaw", None);
        assert!(
            ironclaw_image.contains("docker.io/nearaidev/ironclaw-dind:"),
            "Expected docker.io/nearaidev/ironclaw-dind image, got {}",
            ironclaw_image
        );
        assert_eq!(
            get_image_for_service_type("openclaw", None),
            "docker.io/nearaidev/openclaw-nearai-worker:latest"
        );
        assert_eq!(
            get_image_for_service_type("unknown", None),
            "docker.io/nearaidev/openclaw-nearai-worker:latest"
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
        assert!(error_msg.contains("manager_type=non-tee"));
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

    #[test]
    fn test_extract_version_from_image_standard_refs() {
        // Standard Docker Hub references
        assert_eq!(
            extract_version_from_image("docker.io/nearaidev/ironclaw-dind:0.23.0"),
            Some("0.23.0".to_string())
        );
        assert_eq!(
            extract_version_from_image("docker.io/nearaidev/openclaw-dind:0.21.0"),
            Some("0.21.0".to_string())
        );
    }

    #[test]
    fn test_extract_version_from_image_with_registry_port() {
        // Registry with port number - should extract tag correctly
        assert_eq!(
            extract_version_from_image("localhost:5000/image:1.0.0"),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            extract_version_from_image("registry.example.com:443/app/image:2.3.4"),
            Some("2.3.4".to_string())
        );
    }

    #[test]
    fn test_extract_version_from_image_with_digest() {
        // OCI digest references should not be parsed as versions
        assert_eq!(
            extract_version_from_image("image@sha256:abc123def456"),
            None
        );
        assert_eq!(
            extract_version_from_image("docker.io/repo/image:1.0.0@sha256:abc123"),
            Some("1.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_version_from_image_non_numeric_tags() {
        // Non-numeric tags should return None
        assert_eq!(
            extract_version_from_image("docker.io/repo/image:latest"),
            None
        );
        assert_eq!(extract_version_from_image("docker.io/repo/image:dev"), None);
        assert_eq!(
            extract_version_from_image("docker.io/repo/image:main"),
            None
        );
        assert_eq!(
            extract_version_from_image("localhost:5000/app/image:latest"),
            None
        );
    }

    #[test]
    fn test_extract_version_from_image_no_tag() {
        // References without tags should return None
        // Note: bare "image" without "/" is not a valid Docker image ref format for this function
        assert_eq!(extract_version_from_image("docker.io/repo/image"), None);
        assert_eq!(extract_version_from_image("localhost:5000/image"), None);
    }

    #[test]
    fn test_extract_version_from_image_prerelease_versions() {
        // Pre-release versions starting with digits
        assert_eq!(
            extract_version_from_image("docker.io/repo/image:1.0.0-rc1"),
            Some("1.0.0-rc1".to_string())
        );
        assert_eq!(
            extract_version_from_image("docker.io/repo/image:2.0.0-alpha"),
            Some("2.0.0-alpha".to_string())
        );
    }

    // ============================================================================
    // Comprehensive tests for AgentHostingConfig image resolution
    // ============================================================================

    #[test]
    fn test_image_resolution_ironclaw_with_config() {
        // When config provides ironclaw_image, use it
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                ironclaw_image: Some("custom.registry.io/ironclaw:0.5.0".to_string()),
                ..Default::default()
            },
        };

        let image = get_image_for_service_type("ironclaw", Some(&config));
        assert_eq!(image, "custom.registry.io/ironclaw:0.5.0");
    }

    #[test]
    fn test_image_resolution_ironclaw_without_config() {
        // When config is None, fall back to hardcoded default
        let image = get_image_for_service_type("ironclaw", None);
        assert_eq!(image, "docker.io/nearaidev/ironclaw-dind:latest");
    }

    #[test]
    fn test_image_resolution_ironclaw_config_none_fields() {
        // When config fields are None, fall back to hardcoded defaults
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig::default(),
        };

        let image = get_image_for_service_type("ironclaw", Some(&config));
        assert_eq!(image, "docker.io/nearaidev/ironclaw-dind:latest");
    }

    #[test]
    fn test_image_resolution_openclaw_with_config() {
        // When config provides openclaw_image, use it
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                openclaw_image: Some("my.registry.com/openclaw:v2.1".to_string()),
                ..Default::default()
            },
        };

        let image = get_image_for_service_type("openclaw", Some(&config));
        assert_eq!(image, "my.registry.com/openclaw:v2.1");
    }

    #[test]
    fn test_image_resolution_openclaw_without_config() {
        // When config is None, fall back to hardcoded default
        let image = get_image_for_service_type("openclaw", None);
        assert_eq!(image, "docker.io/nearaidev/openclaw-nearai-worker:latest");
    }

    #[test]
    fn test_image_resolution_openclaw_config_none_fields() {
        // When config fields are None, fall back to hardcoded defaults
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig::default(),
        };

        let image = get_image_for_service_type("openclaw", Some(&config));
        assert_eq!(image, "docker.io/nearaidev/openclaw-nearai-worker:latest");
    }

    #[test]
    fn test_image_resolution_unknown_type_defaults_to_openclaw() {
        // Unknown service types default to openclaw image
        let image = get_image_for_service_type("unknown-type", None);
        assert_eq!(image, "docker.io/nearaidev/openclaw-nearai-worker:latest");
    }

    #[test]
    fn test_image_resolution_unknown_type_with_openclaw_override() {
        // Unknown types respect openclaw_image override
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                openclaw_image: Some("override.io/openclaw:custom".to_string()),
                ..Default::default()
            },
        };

        let image = get_image_for_service_type("unknown-type", Some(&config));
        assert_eq!(image, "override.io/openclaw:custom");
    }

    #[test]
    fn test_image_resolution_both_images_configured() {
        // When both images are configured, each service type uses its own
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                ironclaw_image: Some("registry.io/ironclaw:1.0".to_string()),
                openclaw_image: Some("registry.io/openclaw:2.0".to_string()),
                ..Default::default()
            },
        };

        let ironclaw_image = get_image_for_service_type("ironclaw", Some(&config));
        let openclaw_image = get_image_for_service_type("openclaw", Some(&config));

        assert_eq!(ironclaw_image, "registry.io/ironclaw:1.0");
        assert_eq!(openclaw_image, "registry.io/openclaw:2.0");
        assert_ne!(ironclaw_image, openclaw_image);
    }

    #[test]
    fn test_image_resolution_partial_config_ironclaw_only() {
        // Config can set just ironclaw_image; openclaw uses default
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                ironclaw_image: Some("custom.io/ironclaw:beta".to_string()),
                ..Default::default()
            },
        };

        let ironclaw = get_image_for_service_type("ironclaw", Some(&config));
        let openclaw = get_image_for_service_type("openclaw", Some(&config));

        assert_eq!(ironclaw, "custom.io/ironclaw:beta");
        assert_eq!(
            openclaw,
            "docker.io/nearaidev/openclaw-nearai-worker:latest"
        );
    }

    #[test]
    fn test_image_resolution_partial_config_openclaw_only() {
        // Config can set just openclaw_image; ironclaw uses default
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: None,
            crabshack: AgentHostingCrabshackConfig {
                openclaw_image: Some("custom.io/openclaw:rc1".to_string()),
                ..Default::default()
            },
        };

        let ironclaw = get_image_for_service_type("ironclaw", Some(&config));
        let openclaw = get_image_for_service_type("openclaw", Some(&config));

        assert_eq!(ironclaw, "docker.io/nearaidev/ironclaw-dind:latest");
        assert_eq!(openclaw, "custom.io/openclaw:rc1");
    }

    #[test]
    fn test_image_resolution_config_coexists_with_tee_flag() {
        // Image config is independent of the non_tee_infra flag
        let config = AgentHostingConfig {
            new_agent_with_non_tee_infra: Some(true), // Flag doesn't affect image resolution
            crabshack: AgentHostingCrabshackConfig {
                ironclaw_image: Some("flag-independent.io/ironclaw:v1".to_string()),
                openclaw_image: Some("flag-independent.io/openclaw:v1".to_string()),
                ..Default::default()
            },
        };

        let ironclaw = get_image_for_service_type("ironclaw", Some(&config));
        let openclaw = get_image_for_service_type("openclaw", Some(&config));

        assert_eq!(ironclaw, "flag-independent.io/ironclaw:v1");
        assert_eq!(openclaw, "flag-independent.io/openclaw:v1");
    }

    // ========== SEMANTIC VERSION TESTS ==========

    #[test]
    fn test_is_stable_version_stable() {
        assert!(is_stable_version("1.0.0"));
        assert!(is_stable_version("0.21.0"));
        assert!(is_stable_version("2.3.4"));
        assert!(is_stable_version("0.0.0"));
    }

    #[test]
    fn test_is_stable_version_prerelease() {
        assert!(!is_stable_version("1.0.0-rc.1"));
        assert!(!is_stable_version("1.0.0-alpha"));
        assert!(!is_stable_version("1.0.0-beta.2"));
        assert!(!is_stable_version("2.0.0-rc"));
    }

    #[test]
    fn test_is_stable_version_with_build_metadata() {
        // Build metadata is ignored for stability check
        assert!(is_stable_version("1.0.0+build123"));
        assert!(!is_stable_version("1.0.0-rc.1+build"));
    }

    #[test]
    fn test_parse_semantic_version_stable() {
        let (maj, min, pat, pre) = parse_semantic_version("1.2.3").expect("parse");
        assert_eq!((maj, min, pat, pre), (1, 2, 3, ""));

        let (maj, min, pat, pre) = parse_semantic_version("0.21.0").expect("parse");
        assert_eq!((maj, min, pat, pre), (0, 21, 0, ""));
    }

    #[test]
    fn test_parse_semantic_version_prerelease() {
        let (maj, min, pat, pre) = parse_semantic_version("1.0.0-rc.1").expect("parse");
        assert_eq!((maj, min, pat, pre), (1, 0, 0, "rc.1"));

        let (maj, min, pat, pre) = parse_semantic_version("1.0.0-alpha").expect("parse");
        assert_eq!((maj, min, pat, pre), (1, 0, 0, "alpha"));

        let (maj, min, pat, pre) = parse_semantic_version("2.0.0-beta.2").expect("parse");
        assert_eq!((maj, min, pat, pre), (2, 0, 0, "beta.2"));
    }

    #[test]
    fn test_parse_semantic_version_with_build_metadata() {
        let (maj, min, pat, pre) = parse_semantic_version("1.0.0+build123").expect("parse");
        assert_eq!((maj, min, pat, pre), (1, 0, 0, ""));

        let (maj, min, pat, pre) = parse_semantic_version("1.0.0-rc.1+build").expect("parse");
        assert_eq!((maj, min, pat, pre), (1, 0, 0, "rc.1"));
    }

    #[test]
    fn test_parse_semantic_version_rejects_malformed_core() {
        assert!(parse_semantic_version("1.2.x").is_none());
        assert!(parse_semantic_version("1.0").is_none());
        assert!(parse_semantic_version("1.0.0.1").is_none());
        assert!(parse_semantic_version("").is_none());
    }

    #[test]
    fn test_parse_semantic_version_rejects_empty_prerelease_identifier() {
        assert!(parse_semantic_version("1.0.0-a..b").is_none());
    }

    #[test]
    fn test_compare_semantic_versions_invalid_sorts_before_valid() {
        use std::cmp::Ordering;
        assert_eq!(compare_semantic_versions("1.2.x", "1.0.0"), Ordering::Less);
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.2.x"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_semantic_versions_core_version() {
        // Core version comparison (no pre-release)
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.0.0"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.0.1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_semantic_versions("1.0.1", "1.0.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.1.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_semantic_versions("1.1.0", "2.0.0"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_semantic_versions_stable_vs_prerelease() {
        // Stable version > pre-release with same core
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.0.0-rc.1"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_semantic_versions("1.0.0-rc.1", "1.0.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_semantic_versions("2.0.0", "2.0.0-alpha"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_compare_semantic_versions_prerelease_ordering() {
        use std::cmp::Ordering;

        // Full semver pre-release ordering from spec:
        // 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0

        // alpha < alpha.1
        assert_eq!(
            compare_semantic_versions("1.0.0-alpha", "1.0.0-alpha.1"),
            Ordering::Less
        );

        // alpha.1 < alpha.beta
        assert_eq!(
            compare_semantic_versions("1.0.0-alpha.1", "1.0.0-alpha.beta"),
            Ordering::Less
        );

        // alpha.beta < beta
        assert_eq!(
            compare_semantic_versions("1.0.0-alpha.beta", "1.0.0-beta"),
            Ordering::Less
        );

        // beta < beta.2
        assert_eq!(
            compare_semantic_versions("1.0.0-beta", "1.0.0-beta.2"),
            Ordering::Less
        );

        // beta.2 < beta.11 (numeric comparison, not lexical)
        assert_eq!(
            compare_semantic_versions("1.0.0-beta.2", "1.0.0-beta.11"),
            Ordering::Less
        );

        // beta.11 < rc.1
        assert_eq!(
            compare_semantic_versions("1.0.0-beta.11", "1.0.0-rc.1"),
            Ordering::Less
        );

        // rc.1 < stable
        assert_eq!(
            compare_semantic_versions("1.0.0-rc.1", "1.0.0"),
            Ordering::Less
        );

        // Full chain test
        let versions = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];

        for i in 0..versions.len() - 1 {
            assert_eq!(
                compare_semantic_versions(versions[i], versions[i + 1]),
                Ordering::Less,
                "{} should be < {}",
                versions[i],
                versions[i + 1]
            );
        }
    }

    #[test]
    fn test_compare_semantic_versions_numeric_vs_alphanumeric() {
        use std::cmp::Ordering;

        // Numeric identifiers have lower precedence than alphanumeric
        assert_eq!(
            compare_semantic_versions("1.0.0-1", "1.0.0-alpha"),
            Ordering::Less
        );
        assert_eq!(
            compare_semantic_versions("1.0.0-alpha", "1.0.0-1"),
            Ordering::Greater
        );

        // In multi-part pre-release
        assert_eq!(
            compare_semantic_versions("1.0.0-1.alpha", "1.0.0-1.1"),
            Ordering::Greater // alpha > numeric
        );
    }

    #[test]
    fn test_compare_semantic_versions_with_build_metadata() {
        // Build metadata doesn't affect version precedence
        assert_eq!(
            compare_semantic_versions("1.0.0+build1", "1.0.0+build2"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_semantic_versions("1.0.0-rc.1+build1", "1.0.0-rc.1+build2"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_compare_semantic_versions_legacy_prerelease_case() {
        // The old test case that relied on tie-breaking: both parse to same core
        // but now stable (1.0.0) correctly wins over pre-release (1.0.0-rc1)
        // regardless of order
        assert_eq!(
            compare_semantic_versions("1.0.0-rc1", "1.0.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_semantic_versions("1.0.0", "1.0.0-rc1"),
            std::cmp::Ordering::Greater
        );
    }
}
