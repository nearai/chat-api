use crate::system_configs::ports::SystemConfigsService;
use crate::UserId;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use config::AgentManager;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    is_valid_service_type, AgentApiInstanceEnrichment, AgentApiKey, AgentInstance, AgentRepository,
    AgentService, CreateInstanceParams, InstanceBalance, UsageLogEntry, VALID_SERVICE_TYPES,
};

/// Maximum size for the Agent API SSE stream buffer (100 KB).
/// Prevents DoS from a malicious Agent API sending extremely long lines.
const MAX_BUFFER_SIZE: usize = 100 * 1024;

/// Default service type for agent instances when not specified.
const DEFAULT_SERVICE_TYPE: &str = "openclaw";

/// Parameters for Agent API instance creation.
struct AgentApiCreateParams {
    image: Option<String>,
    name: Option<String>,
    ssh_pubkey: Option<String>,
    service_type: Option<String>,
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
    /// System configs for reading instance limits
    system_configs_service: Arc<dyn SystemConfigsService>,
}

impl AgentServiceImpl {
    pub fn new(
        repository: Arc<dyn AgentRepository>,
        managers: Vec<AgentManager>,
        nearai_api_url: String,
        system_configs_service: Arc<dyn SystemConfigsService>,
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
        }
    }

    /// Pick the next manager in round-robin order for new instance creation.
    /// Does NOT check capacity — use `next_available_manager` for capacity-aware selection.
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
        let max = match self.get_max_instances_per_manager().await {
            Some(limit) => limit,
            None => return Ok(self.next_manager().clone()),
        };

        let n = self.managers.len();
        let start = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);

        for i in 0..n {
            let mgr = &self.managers[(start + i) % n];
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
            "All agent managers are at capacity (max {} instances per manager)",
            max
        ))
    }

    /// Read the max_instances_per_manager setting from system configs.
    /// Falls back to SystemConfigs::default() when no DB config row exists (fresh deployment).
    async fn get_max_instances_per_manager(&self) -> Option<u64> {
        let configs = self
            .system_configs_service
            .get_configs()
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        configs.max_instances_per_manager
    }

    /// Resolve the manager for an existing instance.
    /// Uses the stored agent_api_base_url from DB, falling back to the first manager.
    fn resolve_manager(&self, instance: &AgentInstance) -> &AgentManager {
        if let Some(ref stored_url) = instance.agent_api_base_url {
            if let Some(mgr) = self.managers.iter().find(|m| &m.url == stored_url) {
                return mgr;
            }
            tracing::warn!(
                "Stored agent_api_base_url not found in configured managers, using fallback: instance_id={}",
                instance.id
            );
        }
        &self.managers[0]
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
        let url = format!("{}/instances", manager.url);

        let service_type = params
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);
        let request_body = serde_json::json!({
            "image": params.image,
            "name": params.name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": params.ssh_pubkey,
            "service_type": service_type,
        });

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
            // Don't expose upstream error details for security; log only status code
            tracing::warn!("Agent API create instance failed: status={}", status);
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
        let encoded_name = urlencoding::encode(name);
        let url = format!("{}/instances/{}", manager.url, encoded_name);

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                tracing::debug!("Agent API instance not found: name={}", name);
            }
            return None;
        }

        response.json::<serde_json::Value>().await.ok()
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
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        let url = format!("{}/instances", manager.url);

        let service_type = params
            .service_type
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_TYPE);
        let request_body = serde_json::json!({
            "image": params.image,
            "name": params.name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": params.ssh_pubkey,
            "service_type": service_type,
        });

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&manager.token)
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(180))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            tracing::warn!("Agent API create instance failed: status={}", status);
            return Err(anyhow!("Agent API error: {}", status));
        }

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

/// Save instance data from a lifecycle event to database.
/// `agent_api_base_url` is the manager URL that created this instance (for routing future operations).
async fn save_instance_from_event(
    repository: &dyn AgentRepository,
    user_id: UserId,
    instance_data: &serde_json::Value,
    params: SaveInstanceParams,
) -> anyhow::Result<AgentInstance> {
    // TOCTOU mitigation: Re-check instance limit before creating
    let (_instances, total_count) = repository.list_user_instances(user_id, 1, 0).await?;
    if total_count as u64 >= params.max_allowed {
        tracing::error!(
            "Instance creation rejected: subscription limit exceeded due to concurrent request. current={}, max={}, user_id={}",
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

    let instance_url = instance_data
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let instance_token = instance_data
        .get("token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let gateway_port = instance_data
        .get("gateway_port")
        .and_then(|v| v.as_i64())
        .map(|p| p as i32);
    let dashboard_url = instance_data
        .get("dashboard_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract service_type from instance_data if present and valid, otherwise use provided value
    let service_type_from_response = instance_data
        .get("service_type")
        .and_then(|v| v.as_str())
        .filter(|s| is_valid_service_type(s))
        .map(|s| s.to_string());
    let final_service_type = service_type_from_response.or(params.service_type.clone());

    let instance = repository
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: instance_id.clone(),
            name: instance_name,
            public_ssh_key: params.ssh_pubkey.clone(),
            instance_url,
            instance_token,
            gateway_port,
            dashboard_url,
            agent_api_base_url: params.agent_api_base_url.clone(),
            service_type: final_service_type,
        })
        .await?;

    // Defense-in-depth: verify the created instance belongs to the requesting user
    if instance.user_id != user_id {
        tracing::error!(
            "Security violation: created instance ownership mismatch: instance_id={}, expected_user_id={}, actual_user_id={}",
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
        "Instance saved from lifecycle event: instance_id={}, user_id={}",
        instance_id,
        user_id
    );

    Ok(instance)
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
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
        service_type: Option<String>,
    ) -> anyhow::Result<AgentInstance> {
        tracing::info!("Creating instance from Agent API: user_id={}", user_id);

        // Pick next manager with available capacity (round-robin, skipping full managers)
        let manager = self.next_available_manager().await?;

        // Create an unbound API key on behalf of the user; the agent will use it to authenticate to the chat-api.
        let key_name = name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, None)
            .await?;

        // Apply default service type if not provided
        // Defense-in-depth: validate service type early to prevent invalid values reaching Agent API
        if let Some(ref st) = service_type {
            if !is_valid_service_type(st) {
                return Err(anyhow!(
                    "Invalid service type '{}'. Valid types are: {}",
                    st,
                    VALID_SERVICE_TYPES.join(", ")
                ));
            }
        }

        let service_type_for_api = service_type
            .clone()
            .or_else(|| Some(DEFAULT_SERVICE_TYPE.to_string()));

        // Call Agent API with our API key and the chat-api URL (agents reach us at nearai_api_url)
        let response = self
            .call_agent_api_create(
                &manager,
                &plaintext_key,
                &self.nearai_api_url,
                AgentApiCreateParams {
                    image,
                    name: name.clone(),
                    ssh_pubkey: ssh_pubkey.clone(),
                    service_type: service_type_for_api.clone(),
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

        let instance_token = instance_data
            .get("token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let gateway_port = instance_data
            .get("gateway_port")
            .and_then(|v| v.as_i64())
            .map(|p| p as i32);

        let dashboard_url = instance_data
            .get("dashboard_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

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
                public_ssh_key: ssh_pubkey,
                instance_url,
                instance_token,
                gateway_port,
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

    async fn create_instance_from_agent_api_streaming(
        &self,
        user_id: UserId,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
        service_type: Option<String>,
        max_allowed: u64,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        tracing::info!(
            "Creating instance from Agent API with streaming: user_id={}",
            user_id
        );

        // Pick next manager with available capacity
        let manager = self.next_available_manager().await?;
        let manager_url = manager.url.clone();

        let key_name = name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, None)
            .await?;

        // Apply default service type if not provided
        // Defense-in-depth: validate service type early to prevent invalid values reaching Agent API
        if let Some(ref st) = service_type {
            if !is_valid_service_type(st) {
                return Err(anyhow!(
                    "Invalid service type '{}'. Valid types are: {}",
                    st,
                    VALID_SERVICE_TYPES.join(", ")
                ));
            }
        }

        let service_type_for_api = service_type
            .clone()
            .or_else(|| Some(DEFAULT_SERVICE_TYPE.to_string()));

        let mut rx = match self
            .call_agent_api_create_streaming(
                &manager,
                &plaintext_key,
                &self.nearai_api_url,
                AgentApiCreateParams {
                    image,
                    name: name.clone(),
                    ssh_pubkey: ssh_pubkey.clone(),
                    service_type: service_type_for_api.clone(),
                },
            )
            .await
        {
            Ok(rx) => rx,
            Err(e) => {
                tracing::error!(
                    "Failed to start Agent API streaming: user_id={}, error={}. Revoking orphaned API key.",
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
        let api_key_id = api_key.id;

        tokio::spawn(async move {
            let mut created_event_processed = false;

            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => {
                        if !created_event_processed {
                            if let Some(stage) = event.get("stage").and_then(|s| s.as_str()) {
                                if stage == "created" {
                                    if let Some(instance_data) = event.get("instance") {
                                        if let Err(e) = save_instance_from_event(
                                            repo.as_ref(),
                                            user_id,
                                            instance_data,
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
                                            tracing::error!(
                                                "Failed to save instance from created event: user_id={}, error={}",
                                                user_id,
                                                e
                                            );
                                            if let Err(cleanup_err) =
                                                repo.revoke_api_key(api_key_id).await
                                            {
                                                tracing::warn!(
                                                    "Failed to revoke API key on instance save failure: user_id={}, api_key_id={}, error={}",
                                                    user_id,
                                                    api_key_id,
                                                    cleanup_err
                                                );
                                            }
                                            let _ = tx
                                                .send(Err(anyhow!("Failed to save instance")))
                                                .await;
                                            break;
                                        }
                                        created_event_processed = true;
                                    } else {
                                        tracing::error!(
                                            "Received 'created' event without instance data: user_id={}",
                                            user_id
                                        );
                                        if let Err(cleanup_err) =
                                            repo.revoke_api_key(api_key_id).await
                                        {
                                            tracing::warn!(
                                                "Failed to revoke API key on malformed event: user_id={}, api_key_id={}, error={}",
                                                user_id,
                                                api_key_id,
                                                cleanup_err
                                            );
                                        }
                                        let _ = tx
                                            .send(Err(anyhow!(
                                                "Invalid created event: missing instance data"
                                            )))
                                            .await;
                                        break;
                                    }
                                }
                            }
                        } else if let Some(stage) = event.get("stage").and_then(|s| s.as_str()) {
                            if stage == "created" {
                                tracing::warn!(
                                    "Ignoring duplicate 'created' event from Agent API: user_id={}",
                                    user_id
                                );
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                        }

                        if tx.send(Ok(event)).await.is_err() {
                            if !created_event_processed {
                                tracing::warn!(
                                    "Client disconnected before instance creation: revoking unbound API key: user_id={}",
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
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        if !created_event_processed {
                            tracing::warn!(
                                "Stream error before instance creation: user_id={}, revoking unbound API key",
                                user_id
                            );
                            if let Err(cleanup_err) = repo.revoke_api_key(api_key_id).await {
                                tracing::warn!(
                                    "Failed to revoke API key on stream error: user_id={}, api_key_id={}, error={}",
                                    user_id,
                                    api_key_id,
                                    cleanup_err
                                );
                            }
                        }
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
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
                gateway_port: None,
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
                                let ssh_command = inst
                                    .get("ssh_command")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                map.insert(
                                    name.to_string(),
                                    AgentApiInstanceEnrichment {
                                        status,
                                        ssh_command,
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
        let manager = self.resolve_manager(&instance);

        // Call Agent API to terminate the instance. URL-encode instance name to prevent path
        // traversal (it can be derived from instance_name returned by the external Agent API).
        let encoded_name = urlencoding::encode(&instance.name);
        let delete_url = format!("{}/instances/{}", manager.url, encoded_name);
        let response = self
            .http_client
            .delete(&delete_url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API delete: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Agent API delete failed with status {}: instance_id={}",
                response.status(),
                instance_id
            ));
        }

        // Only delete from database if remote deletion was successful
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
        let manager = self.resolve_manager(&instance);

        // Call Agent API to restart the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let restart_url = format!("{}/instances/{}/restart", manager.url, encoded_name);
        let response = self
            .http_client
            .post(&restart_url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API restart: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Agent API restart failed with status {}: instance_id={}",
                response.status(),
                instance_id
            ));
        }

        tracing::info!(
            "Instance restarted successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
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
        let manager = self.resolve_manager(&instance);

        // Call Agent API to stop the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let stop_url = format!("{}/instances/{}/stop", manager.url, encoded_name);
        let response = self
            .http_client
            .post(&stop_url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API stop: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Agent API stop failed with status {}: instance_id={}",
                response.status(),
                instance_id
            ));
        }

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
        let manager = self.resolve_manager(&instance);

        // Call Agent API to start the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let start_url = format!("{}/instances/{}/start", manager.url, encoded_name);
        let response = self
            .http_client
            .post(&start_url)
            .bearer_auth(&manager.token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call Agent API start: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Agent API start failed with status {}: instance_id={}",
                response.status(),
                instance_id
            ));
        }

        tracing::info!(
            "Instance started successfully: instance_id={}, name={}",
            instance_id,
            instance.name
        );

        Ok(())
    }

    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> anyhow::Result<(AgentApiKey, String)> {
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
            return Err(anyhow!("Access denied"));
        }

        if name.is_empty() || name.len() > 255 {
            return Err(anyhow!("Invalid name format"));
        }

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
    ) -> anyhow::Result<(AgentApiKey, String)> {
        tracing::info!("Creating unbound API key: user_id={}", user_id);

        if name.is_empty() || name.len() > 255 {
            return Err(anyhow!("Invalid name format"));
        }

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

    async fn validate_and_use_api_key(&self, api_key: &str) -> anyhow::Result<AgentApiKey> {
        // Validate format
        if !Self::validate_api_key_format(api_key) {
            tracing::warn!("Invalid API key format");
            return Err(anyhow!("Invalid API key format"));
        }

        // Hash the key
        let key_hash = Self::hash_api_key(api_key);

        // Look up by hash
        let api_key_info = self
            .repository
            .get_api_key_by_hash(&key_hash)
            .await?
            .ok_or_else(|| {
                tracing::warn!("API key not found or invalid");
                anyhow!("Invalid API key")
            })?;

        // Check if active
        if !api_key_info.is_active {
            tracing::warn!("API key is not active: api_key_id={}", api_key_info.id);
            return Err(anyhow!("API key is not active"));
        }

        // Check expiration
        if let Some(expires_at) = api_key_info.expires_at {
            if expires_at < Utc::now() {
                tracing::warn!("API key has expired: api_key_id={}", api_key_info.id);
                return Err(anyhow!("API key has expired"));
            }
        }

        // Update last used
        self.repository
            .update_api_key_last_used(api_key_info.id)
            .await?;

        tracing::debug!(
            "API key validated successfully: api_key_id={}",
            api_key_info.id
        );

        Ok(api_key_info)
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
    use chrono::Utc;
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

        fn with_manager_limit(max: u64) -> Self {
            Self {
                configs: Some(SystemConfigs {
                    max_instances_per_manager: Some(max),
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
        repo
    }

    fn make_managers(n: usize) -> Vec<AgentManager> {
        (0..n)
            .map(|i| AgentManager {
                url: format!("https://mgr{}.example.com", i),
                token: format!("token{}", i),
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
            assert_eq!(mgr.url, "https://mgr0.example.com");
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

        assert_eq!(urls[0], "https://mgr0.example.com");
        assert_eq!(urls[1], "https://mgr1.example.com");
        assert_eq!(urls[2], "https://mgr2.example.com");
        assert_eq!(urls[3], "https://mgr0.example.com");
        assert_eq!(urls[4], "https://mgr1.example.com");
        assert_eq!(urls[5], "https://mgr2.example.com");
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
            gateway_port: None,
            dashboard_url: None,
            agent_api_base_url: Some("https://mgr2.example.com".to_string()),
            service_type: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance);
        assert_eq!(mgr.url, "https://mgr2.example.com");
        assert_eq!(mgr.token, "token2");
    }

    #[test]
    fn test_resolve_manager_falls_back_to_first() {
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
            gateway_port: None,
            dashboard_url: None,
            agent_api_base_url: Some("https://unknown.example.com".to_string()),
            service_type: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance);
        assert_eq!(mgr.url, "https://mgr0.example.com");
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
            gateway_port: None,
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mgr = svc.resolve_manager(&instance);
        assert_eq!(mgr.url, "https://mgr0.example.com");
    }

    #[tokio::test]
    async fn test_next_available_manager_default_limit_applied() {
        // With no DB config row, the default limit (200) is applied
        let svc = make_service(
            make_managers(2),
            Arc::new(mock_repo_with_manager_count(50)),
            Arc::new(MockSystemConfigsService::no_config()),
        );

        // count=50 < default 200 → manager is available
        let mgr = svc.next_available_manager().await.unwrap();
        assert!(mgr.url.starts_with("https://mgr"));
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
            Arc::new(MockSystemConfigsService::with_manager_limit(10)),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert!(mgr.url.starts_with("https://mgr"));
    }

    #[tokio::test]
    async fn test_next_available_manager_all_at_capacity() {
        let svc = make_service(
            make_managers(2),
            Arc::new(mock_repo_with_manager_count(100)),
            Arc::new(MockSystemConfigsService::with_manager_limit(100)),
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
            Arc::new(MockSystemConfigsService::with_manager_limit(10)),
        );

        let mgr = svc.next_available_manager().await.unwrap();
        assert_eq!(mgr.url, "https://mgr1.example.com");
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
            }],
            Arc::new(mock_repo_with_manager_count(0)),
            Arc::new(MockSystemConfigsService::no_config()),
        );
    }

    // --- Wiremock-based integration tests ---

    mod wiremock_tests {
        use super::*;
        use wiremock::matchers::{bearer_token, method, path};
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
                gateway_port: None,
                dashboard_url: None,
                agent_api_base_url: manager_url.map(|s| s.to_string()),
                service_type: None,
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok2".to_string(),
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
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
            // Only server1's instance is enriched; server2 failed gracefully
            assert_eq!(enrichments.len(), 1);
            assert_eq!(enrichments["inst-a"].status.as_deref(), Some("running"));
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok".to_string(),
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
                },
                AgentManager {
                    url: server2.uri(),
                    token: "tok2".to_string(),
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
                        name: Some("inst1".to_string()),
                        ssh_pubkey: None,
                        service_type: None,
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
                        name: Some("inst2".to_string()),
                        ssh_pubkey: None,
                        service_type: None,
                    },
                )
                .await;

            assert!(result1.is_ok());
            assert!(result2.is_ok());
            // wiremock will verify expect(1) on each mock when servers drop
        }
    }
}
