use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::UserId;

/// Enrichment data from Agent API (compose-api) for instance responses
#[derive(Debug, Clone, Default)]
pub struct AgentApiInstanceEnrichment {
    pub status: Option<String>,
    pub ssh_command: Option<String>,
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
    pub gateway_port: Option<i32>,
    pub dashboard_url: Option<String>,
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
    pub spend_limit: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    pub gateway_port: Option<i32>,
    pub dashboard_url: Option<String>,
}

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

    async fn list_user_instances(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

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

    async fn list_instance_keys(
        &self,
        instance_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentApiKey>, i64)>;

    async fn revoke_api_key(&self, api_key_id: Uuid) -> anyhow::Result<()>;

    async fn update_api_key_last_used(&self, api_key_id: Uuid) -> anyhow::Result<()>;

    // Usage logging
    async fn log_usage(&self, usage: UsageLogEntry) -> anyhow::Result<()>;

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

    /// Log usage and update balance atomically in a single database transaction.
    /// This prevents race conditions where usage is logged but balance update fails (or vice versa).
    async fn log_usage_and_update_balance(&self, usage: UsageLogEntry) -> anyhow::Result<()>;

    async fn get_user_total_spending(&self, user_id: UserId) -> anyhow::Result<i64>;
}

/// Service trait for agent business logic
#[async_trait]
pub trait AgentService: Send + Sync {
    // Instance management
    async fn list_instances_from_agent_api(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Vec<AgentInstance>>;

    /// List all instances from DB (admin only); correct user_id per instance
    async fn list_all_instances(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AgentInstance>, i64)>;

    async fn create_instance_from_agent_api(
        &self,
        user_id: UserId,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
    ) -> anyhow::Result<AgentInstance>;

    /// Create instance with streaming lifecycle events
    /// Returns a receiver that yields raw JSON events as they occur during instance creation.
    ///
    /// **Note**: Events are streamed as untyped `serde_json::Value` (raw JSON proxy).
    /// The frontend is responsible for deserializing into the typed `LifecycleEvent` struct.
    /// This design allows flexibility if the Agent API event schema changes.
    /// If strict validation is needed, consider adding a deserialization layer before returning.
    ///
    /// This is useful for real-time UI updates instead of a loading bar.
    async fn create_instance_from_agent_api_streaming(
        &self,
        user_id: UserId,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
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
    /// Returns None if the Agent API call fails or returns 404.
    async fn get_instance_enrichment_from_agent_api(
        &self,
        agent_api_name: &str,
    ) -> Option<AgentApiInstanceEnrichment>;

    /// Fetch all instance enrichments from Agent API GET /instances (name -> enrichment).
    /// Returns empty map if the call fails; used to enrich list responses efficiently.
    async fn get_all_instance_enrichments_from_agent_api(
        &self,
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

    async fn stop_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

    async fn start_instance(&self, instance_id: Uuid, user_id: UserId) -> anyhow::Result<()>;

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
    ) -> anyhow::Result<(AgentApiKey, String)>;

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
    ) -> anyhow::Result<(AgentApiKey, String)>;

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
    async fn validate_and_use_api_key(&self, api_key: &str) -> anyhow::Result<AgentApiKey>;

    // Usage tracking and balance
    async fn record_usage(
        &self,
        api_key: &AgentApiKey,
        input_tokens: i64,
        output_tokens: i64,
        model_id: String,
        request_type: String,
        pricing: TokenPricing,
    ) -> anyhow::Result<()>;

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
