use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::UserId;

/// Result of sync_all_instance_statuses.
///
/// Counter semantics:
/// - `synced`: instances found in the Agent API response (updated + skipped)
/// - `updated`: instances whose DB status was changed
/// - `skipped`: instances found in API but already had the correct status
/// - `not_found`: instances missing from the API response (API succeeded but instance absent)
/// - `error_skipped`: instances skipped because their manager API call failed
/// - `errors`: human-readable error descriptions (no internal URLs)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStatusResult {
    pub synced: u32,
    pub updated: u32,
    pub skipped: u32,
    pub not_found: u32,
    pub error_skipped: u32,
    pub errors: Vec<String>,
}

// ============ Service Type Validation ============

/// Valid canonical service types for agent instances.
/// The -dind suffix variants (openclaw-dind, ironclaw-dind) are no longer used.
pub const VALID_SERVICE_TYPES: &[&str] = &["openclaw", "ironclaw"];

/// Validates that a service type is in the list of allowed values.
pub fn is_valid_service_type(service_type: &str) -> bool {
    VALID_SERVICE_TYPES.contains(&service_type)
}

/// Enrichment data from the agent compose-api (TEE or non-TEE) for instance responses
#[derive(Debug, Clone, Default)]
pub struct AgentApiInstanceEnrichment {
    pub status: Option<String>,
    pub ssh_command: Option<String>,
}

/// Upgrade availability information for an instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAvailability {
    pub has_upgrade: bool,
    pub current_image: Option<String>,
    pub latest_image: String,
}

/// Agent instance metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInstance {
    pub id: Uuid,
    pub user_id: UserId,
    pub instance_id: String,
    pub name: String,
    pub public_ssh_key: Option<String>,
    pub instance_url: Option<String>,
    pub instance_token: Option<String>,
    pub dashboard_url: Option<String>,
    /// The agent manager URL that owns this instance (for routing operations)
    pub agent_api_base_url: Option<String>,
    /// Service type (e.g. "openclaw", "ironclaw") selected when creating the instance
    pub service_type: Option<String>,
    /// DB-tracked status: active, stopped, deleted, provisioning, error
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API key metadata (without plaintext key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentApiKey {
    pub id: Uuid,
    pub instance_id: Option<Uuid>,
    pub user_id: UserId,
    pub name: String,
    /// Optional lifetime spend cap in nano-dollars for this key.
    pub spend_limit: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AgentApiKeyAuthError {
    #[error("Invalid API key format")]
    InvalidFormat,
    #[error("Invalid API key")]
    Invalid,
    #[error("API key is not active")]
    Inactive,
    #[error("API key has expired")]
    Expired,
    #[error("API key spend limit exceeded")]
    SpendLimitExceeded,
    #[error("Instance not properly configured")]
    InstanceNotConfigured,
    #[error("Internal authentication error")]
    Internal,
}

#[derive(Debug, Error)]
pub enum AgentApiKeyCreationError {
    #[error("Invalid spend limit: must be non-negative when provided")]
    InvalidSpendLimit,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Usage log entry for tracking API consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLogEntry {
    pub id: Uuid,
    pub user_id: UserId,
    pub instance_id: Uuid,
    pub api_key_id: Uuid,
    pub api_key_name: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub metric_key: String,
    pub quantity: i64,
    pub input_cost: i64,  // nano-dollars
    pub output_cost: i64, // nano-dollars
    pub total_cost: i64,  // nano-dollars
    pub model_id: String,
    pub request_type: String,
    pub created_at: DateTime<Utc>,
}

/// Instance balance snapshot (cached aggregate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceBalance {
    pub instance_id: Uuid,
    pub total_spent: i64, // nano-dollars
    pub total_requests: i64,
    pub total_tokens: i64,
    pub last_usage_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Helper for cost calculations (in nano-dollars)
#[derive(Debug, Clone)]
pub struct TokenPricing {
    pub input_cost_per_million: i64,  // nano-dollars
    pub output_cost_per_million: i64, // nano-dollars
}

impl TokenPricing {
    pub fn calculate_cost(&self, input_tokens: i64, output_tokens: i64) -> (i64, i64, i64) {
        let input_cost = (input_tokens * self.input_cost_per_million) / 1_000_000;
        let output_cost = (output_tokens * self.output_cost_per_million) / 1_000_000;
        let total_cost = input_cost + output_cost;
        (input_cost, output_cost, total_cost)
    }
}

/// Repository trait for agent operations
/// Parameters for creating an agent instance
#[derive(Debug, Clone)]
pub struct CreateInstanceParams {
    pub user_id: UserId,
    pub instance_id: String,
    pub name: String,
    pub public_ssh_key: Option<String>,
    pub instance_url: Option<String>,
    pub instance_token: Option<String>,
    pub dashboard_url: Option<String>,
    /// The agent manager URL that created this instance
    pub agent_api_base_url: Option<String>,
    /// Service type selected at creation time
    pub service_type: Option<String>,
}

/// Parameters for creating an instance via Agent API
#[derive(Debug, Clone)]
pub struct InstanceCreationParams {
    pub image: Option<String>,
    pub name: Option<String>,
    pub ssh_pubkey: Option<String>,
    pub service_type: Option<String>,
    pub cpus: Option<String>,
    pub mem_limit: Option<String>,
    pub storage_size: Option<String>,
    pub nearai_api_url: Option<String>,
    pub nearai_api_key: Option<String>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AgentRepository: Send + Sync {
    // Instance operations
    async fn create_instance(&self, params: CreateInstanceParams) -> anyhow::Result<AgentInstance>;

    async fn get_instance(&self, instance_id: Uuid) -> anyhow::Result<Option<AgentInstance>>;

    async fn get_instance_by_instance_id(
        &self,
        instance_id: &str,
    ) -> anyhow::Result<Option<AgentInstance>>;

    async fn get_instance_by_api_key_hash(
        &self,
        key_hash: &str,
    ) -> anyhow::Result<Option<(AgentInstance, AgentApiKey)>>;

    /// Get user's passkey credentials (auth_secret, backup_passphrase)
    async fn get_user_passkey_credentials(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<(String, String)>>;

    /// Store or update user's passkey credentials
    async fn upsert_user_passkey_credentials(
        &self,
        user_id: UserId,
        auth_secret: &str,
        backup_passphrase: &str,
    ) -> anyhow::Result<()>;

    async fn list_user_instances(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

    /// Count active (non-deleted) instances for a user
    async fn count_user_instances(&self, user_id: UserId) -> anyhow::Result<i64>;

    /// Count active (non-deleted) instances assigned to a specific agent manager URL
    async fn count_instances_by_manager(&self, agent_api_base_url: &str) -> anyhow::Result<i64>;

    /// List all instances (admin only); no user filter
    async fn list_all_instances(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

    async fn update_instance(
        &self,
        instance_id: Uuid,
        name: Option<String>,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance>;

    /// Update instance status in DB (triggers status_history audit via trigger).
    async fn update_instance_status(
        &self,
        instance_id: Uuid,
        new_status: &str,
    ) -> anyhow::Result<()>;

    async fn delete_instance(&self, instance_id: Uuid) -> anyhow::Result<()>;

    // API Key operations
    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        key_hash: String,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<AgentApiKey>;

    /// Create an unbound API key (instance_id = NULL)
    async fn create_unbound_api_key(
        &self,
        user_id: UserId,
        key_hash: String,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<AgentApiKey>;

    /// Bind an unbound API key to an instance
    async fn bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
    ) -> anyhow::Result<()>;

    async fn get_api_key_by_hash(&self, key_hash: &str) -> anyhow::Result<Option<AgentApiKey>>;

    async fn get_api_key_by_id(&self, api_key_id: Uuid) -> anyhow::Result<Option<AgentApiKey>>;

    async fn get_api_key_total_spend(&self, api_key_id: Uuid) -> anyhow::Result<i64>;

    async fn list_instance_keys(
        &self,
        instance_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentApiKey>, i64)>;

    async fn revoke_api_key(&self, api_key_id: Uuid) -> anyhow::Result<()>;

    async fn update_api_key_last_used(&self, api_key_id: Uuid) -> anyhow::Result<()>;

    // Usage logging
    async fn get_instance_usage(
        &self,
        instance_id: Uuid,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<UsageLogEntry>, i64)>;

    // Balance operations
    async fn get_instance_balance(
        &self,
        instance_id: Uuid,
    ) -> anyhow::Result<Option<InstanceBalance>>;

    async fn update_instance_balance(
        &self,
        instance_id: Uuid,
        total_cost: i64,
    ) -> anyhow::Result<()>;

    async fn get_user_total_spending(&self, user_id: UserId) -> anyhow::Result<i64>;
}

/// Service trait for agent business logic
#[async_trait]
pub trait AgentService: Send + Sync {
    /// List all instances from DB (admin only); correct user_id per instance
    async fn list_all_instances(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

    async fn create_instance_from_agent_api(
        &self,
        user_id: UserId,
        params: InstanceCreationParams,
    ) -> anyhow::Result<AgentInstance>;

    /// Create instance via TEE compose-api with streaming lifecycle events.
    /// Streams events from the agent API as they occur during instance creation.
    /// Returns a receiver that yields raw JSON events from the agent API.
    async fn create_instance_from_agent_api_streaming(
        &self,
        user_id: UserId,
        params: InstanceCreationParams,
        max_allowed: u64,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>>;

    /// Create instance with per-instance passkey credentials and streaming lifecycle events.
    /// Calls non-TEE compose-api /auth/register to set up the instance with unique credentials,
    /// then creates the instance using the session token instead of manager token.
    /// Returns a receiver that yields raw JSON events as they occur during instance creation.
    async fn create_passkey_instance_streaming(
        &self,
        user_id: UserId,
        params: InstanceCreationParams,
        max_allowed: u64,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>>;

    async fn create_instance(
        &self,
        user_id: UserId,
        instance_id: String,
        name: String,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance>;

    async fn get_instance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<Option<AgentInstance>>;

    async fn list_instances(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

    /// Fetch instance enrichment (status, ssh_command) from Agent API GET /instances/{name}.
    /// When `agent_api_base_url` is provided, queries only the owning manager (O(1)).
    /// Falls back to fan-out across all managers when the URL is None (legacy instances).
    /// Returns None if the Agent API call fails or returns 404.
    async fn get_instance_enrichment_from_agent_api(
        &self,
        agent_api_name: &str,
        agent_api_base_url: Option<&str>,
    ) -> Option<AgentApiInstanceEnrichment>;

    /// Fetch instance enrichments from the Agent API for a set of instances.
    /// Groups instances by their stored `agent_api_base_url` and queries only the
    /// relevant managers. Returns name -> enrichment map.
    /// Instances without a stored manager URL are queried against the first manager as fallback.
    async fn get_instance_enrichments(
        &self,
        instances: &[AgentInstance],
    ) -> std::collections::HashMap<String, AgentApiInstanceEnrichment>;

    async fn update_instance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: Option<String>,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<AgentInstance>;

    async fn delete_instance(&self, instance_id: Uuid) -> anyhow::Result<()>;

    async fn restart_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

    /// Upgrade instance with streaming SSE progress.
    /// Returns a receiver that yields SSE chunks from the agent compose-api restart stream.
    /// Uses a 5-minute timeout to allow the full upgrade to complete.
    async fn upgrade_instance_stream(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>>;

    /// Check if an upgrade is available for the instance.
    /// Compares the current deployed image with the latest available version.
    async fn check_upgrade_available(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<UpgradeAvailability>;

    async fn stop_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

    async fn start_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

    /// Sync instance status from all Agent API managers into the database.
    /// Fetches live status via GET /instances per manager, maps "running" -> "active", others -> "stopped".
    /// Skips deleted instances; only updates when status differs.
    async fn sync_all_instance_statuses(&self) -> anyhow::Result<SyncStatusResult>;

    // Gateway session management
    /// Setup gateway session for a user.
    /// Creates user passkey credentials on first login, then sets the gateway cookie via /auth/proxy-session.
    /// Returns the Set-Cookie header value to be forwarded to the browser, or None if not available.
    /// Runs when `new_agent_with_non_tee_infra` is set, or when the user already has passkey credentials
    /// or instances on a non-TEE manager (so crabshack sessions still work after switching global infra to TEE).
    /// Propagates errors if system configs cannot be loaded (callers typically log and continue).
    /// Safe to call multiple times (idempotent on subsequent logins).
    async fn setup_gateway_session_for_user(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<String>>;

    // API key management
    /// Create an API key for a specific instance - returns (api_key_info, plaintext_key)
    /// The plaintext key is ONLY returned on creation!
    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(AgentApiKey, String), AgentApiKeyCreationError>;

    /// Create an unbound API key (pre-deployment key without instance_id)
    /// Used for deploying agents before we know their instance ID.
    /// Returns (api_key_info, plaintext_key).
    /// The plaintext key is ONLY returned on creation!
    async fn create_unbound_api_key(
        &self,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(AgentApiKey, String), AgentApiKeyCreationError>;

    /// Bind an unbound API key to an instance
    /// Used when an agent registers itself after deployment.
    async fn bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<AgentApiKey>;

    /// Admin: Bind any unbound API key to any instance (no ownership checks).
    async fn admin_bind_api_key_to_instance(
        &self,
        api_key_id: Uuid,
        instance_id: Uuid,
    ) -> anyhow::Result<AgentApiKey>;

    async fn list_api_keys(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentApiKey>, i64)>;

    async fn revoke_api_key(&self, api_key_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

    // API key validation and usage
    // Centralized service entry point used by HTTP auth middleware so key validation logic
    // (active/expiry/spend limit) lives in one place.
    async fn authenticate_api_key(
        &self,
        api_key: &str,
    ) -> Result<(AgentInstance, AgentApiKey), AgentApiKeyAuthError>;

    // Usage tracking and balance
    async fn get_instance_usage(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<UsageLogEntry>, i64)>;

    async fn get_instance_balance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
    ) -> anyhow::Result<Option<InstanceBalance>>;
}
