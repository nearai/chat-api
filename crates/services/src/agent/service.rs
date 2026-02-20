use crate::UserId;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    AgentApiInstanceEnrichment, AgentApiKey, AgentInstance, AgentRepository, AgentService,
    CreateInstanceParams, InstanceBalance, TokenPricing, UsageLogEntry,
};

/// Maximum size for a single line in the Agent API stream (100 KB).
/// This prevents denial-of-service attacks where a malicious Agent API sends
/// extremely long lines without newlines, causing unbounded buffer growth.
const MAX_BUFFER_SIZE: usize = 100 * 1024;

pub struct AgentServiceImpl {
    repository: Arc<dyn AgentRepository>,
    http_client: Client,
    agent_api_base_url: String,
    agent_api_token: String,
    /// Chat-API base URL passed to the Agent API as nearai_api_url when creating instances
    nearai_api_url: String,
}

impl AgentServiceImpl {
    pub fn new(
        repository: Arc<dyn AgentRepository>,
        api_base_url: String,
        api_token: String,
        nearai_api_url: String,
    ) -> Self {
        // Validate required configuration
        if api_token.is_empty() {
            panic!("AGENT_API_TOKEN environment variable must be set and non-empty");
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
            agent_api_base_url: api_base_url,
            agent_api_token: api_token,
            nearai_api_url,
        }
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

    /// Call Agent API to create an instance with streaming lifecycle events
    ///
    /// # Security Note
    /// This function receives a nearai_api_key credential that is passed to the Agent API
    /// in the request body. This is a sensitive credential and MUST NOT be logged, stored,
    /// or exposed in any error messages. Only the HTTP request/response status codes and headers
    /// should be logged for debugging purposes, never the request/response body.
    async fn call_agent_api_create_streaming(
        &self,
        nearai_api_key: &str,
        nearai_api_url: &str,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        let url = format!("{}/instances", self.agent_api_base_url);

        let request_body = serde_json::json!({
            "image": image,
            "name": name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": ssh_pubkey,
        });

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&self.agent_api_token)
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

        // Create channel for streaming events
        let (tx, rx) = tokio::sync::mpsc::channel(10);

        // Spawn task to stream SSE events as they arrive from Agent API
        tokio::spawn(async move {
            use futures::stream::StreamExt;
            use tokio::time::timeout;

            let mut stream = response.bytes_stream();
            let mut buffer = String::new();
            // Idle timeout: 60 seconds with no data from Agent API indicates a stalled stream
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
                        // Decode chunk as UTF-8, replacing invalid sequences with replacement char
                        let text = String::from_utf8_lossy(&chunk);

                        // Security: Check buffer size before appending to prevent overflow
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

                        // Process complete lines (SSE events end with \n\n)
                        while let Some(newline_pos) = buffer.find('\n') {
                            let line = buffer[..newline_pos].to_string();
                            buffer.drain(..=newline_pos);

                            // Parse SSE format: "data: {...}\n\n"
                            if let Some(data) = line.strip_prefix("data: ") {
                                match serde_json::from_str::<serde_json::Value>(data) {
                                    Ok(event) => {
                                        // Send event immediately; ignore if channel is closed (client disconnected)
                                        let _ = tx.send(Ok(event)).await;
                                    }
                                    Err(e) => {
                                        // Log malformed JSON events for debugging
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
                    None => {
                        // Stream ended normally
                        break;
                    }
                }
            }

            // Process any remaining data in buffer
            if !buffer.is_empty() {
                if let Some(data) = buffer.strip_prefix("data: ") {
                    match serde_json::from_str::<serde_json::Value>(data) {
                        Ok(event) => {
                            let _ = tx.send(Ok(event)).await;
                        }
                        Err(e) => {
                            // Log malformed JSON events for debugging
                            tracing::debug!(
                                "Failed to parse final Agent API SSE data as JSON: {}",
                                e
                            );
                        }
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Call Agent API to create an instance
    ///
    /// # Security Note
    /// This function receives a nearai_api_key credential that is passed to the Agent API
    /// in the request body. This is a sensitive credential and MUST NOT be logged, stored,
    /// or exposed in any error messages. Only the HTTP request/response status codes and headers
    /// should be logged for debugging purposes, never the request/response body.
    async fn call_agent_api_create(
        &self,
        nearai_api_key: &str,
        nearai_api_url: &str,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/instances", self.agent_api_base_url);

        let request_body = serde_json::json!({
            "image": image,
            "name": name,
            "nearai_api_key": nearai_api_key,
            "nearai_api_url": nearai_api_url,
            "ssh_pubkey": ssh_pubkey,
        });

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&self.agent_api_token)
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

    /// Call Agent API to list instances
    async fn call_agent_api_list(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/instances", self.agent_api_base_url);

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&self.agent_api_token)
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

    /// Call Agent API GET /instances/{name} to fetch instance details including status.
    /// Returns None on 404 or any error (non-blocking; used to enrich instance responses).
    async fn call_agent_api_get_instance(&self, name: &str) -> Option<serde_json::Value> {
        let encoded_name = urlencoding::encode(name);
        let url = format!("{}/instances/{}", self.agent_api_base_url, encoded_name);

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&self.agent_api_token)
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
}

/// Helper function to save instance data from lifecycle event to database
async fn save_instance_from_event(
    repository: &dyn AgentRepository,
    user_id: UserId,
    instance_data: &serde_json::Value,
    api_key_id: &Uuid,
    ssh_pubkey: Option<&str>,
) -> anyhow::Result<AgentInstance> {
    // TOCTOU mitigation: Re-check instance limit before creating.
    // The route handler already checked this, but concurrent requests can race.
    // This re-check happens just before the DB insert.
    let (_instances, total_count) = repository.list_user_instances(user_id, 1, 0).await?;
    if total_count > 0 {
        // Limit re-check would go here if we had access to plan limits,
        // but for now we log the concurrent creation as a warning
        tracing::warn!(
            "Instance creation proceeding while {} existing instances exist: user_id={}",
            total_count,
            user_id
        );
    }

    let instance_name = instance_data
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'name' in Agent API instance data"))?
        .to_string();

    // Try to extract instance_id from the Agent API event (for cross-system correlation)
    // If not available, generate one from the instance name and a UUID
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

    let instance = repository
        .create_instance(CreateInstanceParams {
            user_id,
            instance_id: instance_id.clone(),
            name: instance_name,
            public_ssh_key: ssh_pubkey.map(|s| s.to_string()),
            instance_url,
            instance_token,
            gateway_port,
            dashboard_url,
        })
        .await?;

    // Security: Verify the created instance belongs to the requesting user
    // (This should always be true since we passed user_id to create_instance, but we assert for safety)
    if instance.user_id != user_id {
        return Err(anyhow!(
            "Security violation: Created instance does not belong to requesting user. instance.user_id={}, request.user_id={}",
            instance.user_id,
            user_id
        ));
    }

    // Bind the unbound API key to the new instance
    repository
        .bind_api_key_to_instance(*api_key_id, instance.id)
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
    async fn list_instances_from_agent_api(
        &self,
        _user_id: UserId,
    ) -> anyhow::Result<Vec<AgentInstance>> {
        tracing::info!("Listing instances from Agent API (read-only, no DB sync)");

        // Call Agent API
        let response = self.call_agent_api_list().await?;

        // Extract instances array from response
        let instances_array = response
            .get("instances")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Missing or invalid 'instances' array in Agent API response"))?;

        let mut instances = Vec::new();

        // Process each instance from Agent API (read-only, no database sync)
        for instance_data in instances_array {
            let instance_name = instance_data
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing 'name' in Agent API instance data"))?
                .to_string();

            let instance_ssh_pubkey = instance_data
                .get("ssh_pubkey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Generate a unique instance_id based on the Agent API name
            let instance_id = format!("agent-{}-{}", instance_name, Uuid::new_v4());

            // Create in-memory instance object (no database storage)
            let instance = AgentInstance {
                id: Uuid::new_v4(),
                user_id: _user_id,
                instance_id,
                name: instance_name,
                public_ssh_key: instance_ssh_pubkey,
                instance_url: None,
                instance_token: None,
                gateway_port: None,
                dashboard_url: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            instances.push(instance);
        }

        tracing::info!(
            "Listed {} instances from Agent API (read-only)",
            instances.len()
        );

        Ok(instances)
    }

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
    ) -> anyhow::Result<AgentInstance> {
        tracing::info!("Creating instance from Agent API: user_id={}", user_id);

        // Create an unbound API key on behalf of the user; the agent will use it to authenticate to the chat-api.
        let key_name = name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, None)
            .await?;

        // Call Agent API with our API key and the chat-api URL (agents reach us at nearai_api_url)
        let response = self
            .call_agent_api_create(
                &plaintext_key,
                &self.nearai_api_url,
                image,
                name.clone(),
                ssh_pubkey.clone(),
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

        // Store in database with connection info
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
            })
            .await?;

        // Bind the unbound API key to the new instance
        self.bind_api_key_to_instance(api_key.id, instance.id, user_id)
            .await?;

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
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<anyhow::Result<serde_json::Value>>> {
        tracing::info!(
            "Creating instance from Agent API with streaming: user_id={}",
            user_id
        );

        // Create an unbound API key on behalf of the user; the agent will use it to authenticate to the chat-api.
        let key_name = name
            .as_deref()
            .map(|n| format!("instance-{}", n))
            .unwrap_or_else(|| "instance".to_string());
        let (api_key, plaintext_key) = self
            .create_unbound_api_key(user_id, key_name, None, None)
            .await?;

        // Call Agent API which returns a stream of lifecycle events
        let mut rx = self
            .call_agent_api_create_streaming(
                &plaintext_key,
                &self.nearai_api_url,
                image,
                name.clone(),
                ssh_pubkey.clone(),
            )
            .await?;

        // Create a new channel to forward events and handle database writes
        let (tx, output_rx) = tokio::sync::mpsc::channel(10);
        let repo = Arc::clone(&self.repository);
        let api_key_id = api_key.id;

        // Spawn a task to process events
        tokio::spawn(async move {
            let mut created_event_processed = false;

            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => {
                        // Security: Only process the first "created" event to prevent duplicate instance creation
                        if !created_event_processed {
                            if let Some(stage) = event.get("stage").and_then(|s| s.as_str()) {
                                if stage == "created" {
                                    // Extract and save instance data to database
                                    if let Some(instance_data) = event.get("instance") {
                                        if let Err(e) = save_instance_from_event(
                                            repo.as_ref(),
                                            user_id,
                                            instance_data,
                                            &api_key_id,
                                            ssh_pubkey.as_deref(),
                                        )
                                        .await
                                        {
                                            tracing::error!(
                                                "Failed to save instance from created event: user_id={}, error={}",
                                                user_id,
                                                e
                                            );
                                            // Cleanup: Revoke the unbound API key if instance save fails
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
                                        // Mark as processed only after successful save
                                        created_event_processed = true;
                                    } else {
                                        // "created" event missing instance data - revoke key and error
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
                                // Duplicate "created" event detected; ignore to prevent duplicate instance creation
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

                        // Forward the event
                        if tx.send(Ok(event)).await.is_err() {
                            // Channel closed, client disconnected before instance was created
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
                        // Only cleanup if we haven't created the instance yet
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
    ) -> Option<AgentApiInstanceEnrichment> {
        let data = self.call_agent_api_get_instance(agent_api_name).await?;
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
    }

    async fn get_all_instance_enrichments_from_agent_api(
        &self,
    ) -> std::collections::HashMap<String, AgentApiInstanceEnrichment> {
        let response = match self.call_agent_api_list().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Agent API list failed, status enrichment skipped: {}", e);
                return std::collections::HashMap::new();
            }
        };
        let instances = match response.get("instances").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return std::collections::HashMap::new(),
        };
        let mut map = std::collections::HashMap::new();
        for inst in instances {
            if let Some(name) = inst.get("name").and_then(|v| v.as_str()) {
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

    async fn delete_instance(&self, instance_id: Uuid) -> anyhow::Result<()> {
        tracing::info!("Deleting instance: instance_id={}", instance_id);

        // Get instance details
        let instance = self
            .repository
            .get_instance(instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance not found"))?;

        // Call Agent API to terminate the instance. URL-encode instance name to prevent path
        // traversal (it can be derived from instance_name returned by the external Agent API).
        let encoded_name = urlencoding::encode(&instance.name);
        let delete_url = format!("{}/instances/{}", self.agent_api_base_url, encoded_name);
        let response = self
            .http_client
            .delete(&delete_url)
            .bearer_auth(&self.agent_api_token)
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

        // Call Agent API to restart the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let restart_url = format!(
            "{}/instances/{}/restart",
            self.agent_api_base_url, encoded_name
        );
        let response = self
            .http_client
            .post(&restart_url)
            .bearer_auth(&self.agent_api_token)
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

        // Call Agent API to stop the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let stop_url = format!(
            "{}/instances/{}/stop",
            self.agent_api_base_url, encoded_name
        );
        let response = self
            .http_client
            .post(&stop_url)
            .bearer_auth(&self.agent_api_token)
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

        // Call Agent API to start the instance
        let encoded_name = urlencoding::encode(&instance.name);
        let start_url = format!(
            "{}/instances/{}/start",
            self.agent_api_base_url, encoded_name
        );
        let response = self
            .http_client
            .post(&start_url)
            .bearer_auth(&self.agent_api_token)
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

    async fn record_usage(
        &self,
        api_key: &AgentApiKey,
        input_tokens: i64,
        output_tokens: i64,
        model_id: String,
        request_type: String,
        pricing: TokenPricing,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            "Recording usage: api_key_id={}, input_tokens={}, output_tokens={}",
            api_key.id,
            input_tokens,
            output_tokens
        );

        // Verify API key is bound to an instance
        let instance_id = api_key
            .instance_id
            .ok_or_else(|| anyhow!("API key is not bound to an instance"))?;

        let total_tokens = input_tokens + output_tokens;

        // Calculate costs
        let (input_cost, output_cost, total_cost) =
            pricing.calculate_cost(input_tokens, output_tokens);

        // Check spend limit
        if let Some(limit) = api_key.spend_limit {
            if let Ok(Some(balance)) = self.repository.get_instance_balance(instance_id).await {
                if balance.total_spent + total_cost > limit {
                    tracing::warn!(
                        "Spend limit exceeded: api_key_id={}, current={}, limit={}",
                        api_key.id,
                        balance.total_spent,
                        limit
                    );
                    return Err(anyhow!("Spend limit exceeded"));
                }
            }
        }

        // Create usage log entry
        let usage = UsageLogEntry {
            id: Uuid::new_v4(),
            user_id: api_key.user_id,
            instance_id,
            api_key_id: api_key.id,
            api_key_name: api_key.name.clone(),
            input_tokens,
            output_tokens,
            total_tokens,
            input_cost,
            output_cost,
            total_cost,
            model_id,
            request_type,
            created_at: Utc::now(),
        };

        // Log usage and update balance atomically in database transaction
        // This ensures both operations commit together or both rollback
        self.repository.log_usage_and_update_balance(usage).await?;

        tracing::info!(
            "Usage recorded successfully: api_key_id={}, total_cost={}",
            api_key.id,
            total_cost
        );

        Ok(())
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
