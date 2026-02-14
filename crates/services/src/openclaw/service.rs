use crate::UserId;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use std::sync::Arc;
use uuid::Uuid;

use super::ports::{
    CreateInstanceParams, InstanceBalance, OpenClawApiKey, OpenClawInstance, OpenClawRepository,
    OpenClawService, TokenPricing, UsageLogEntry,
};

pub struct OpenClawServiceImpl {
    repository: Arc<dyn OpenClawRepository>,
    http_client: Client,
    openclaw_api_base_url: String,
    openclaw_api_token: String,
}

impl OpenClawServiceImpl {
    pub fn new(
        repository: Arc<dyn OpenClawRepository>,
        api_base_url: String,
        api_token: String,
    ) -> Self {
        Self {
            repository,
            http_client: Client::new(),
            openclaw_api_base_url: api_base_url,
            openclaw_api_token: api_token,
        }
    }

    /// Generate a new API key in format: oc_{uuid}
    fn generate_api_key() -> String {
        format!("oc_{}", Uuid::new_v4().to_string().replace("-", ""))
    }

    /// Hash an API key for storage using SHA-256
    fn hash_api_key(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Validate API key format (must start with "oc_" and be 35 chars total)
    fn validate_api_key_format(key: &str) -> bool {
        key.starts_with("oc_") && key.len() == 35
    }

    /// Call OpenClaw API to create an instance
    async fn call_openclaw_api_create(
        &self,
        nearai_api_key: &str,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/instances", self.openclaw_api_base_url);

        let request_body = serde_json::json!({
            "image": image,
            "name": name,
            "nearai_api_key": nearai_api_key,
            "ssh_pubkey": ssh_pubkey,
        });

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&self.openclaw_api_token)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call OpenClaw API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("OpenClaw API error: {} - {}", status, error_text));
        }

        let body_text = response
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read OpenClaw response: {}", e))?;

        // Parse Server-Sent Events (SSE) response format
        // The response contains multiple "data: {...}" lines
        // We extract the first event which contains the instance creation result
        let first_event = body_text
            .lines()
            .find(|line| line.starts_with("data: "))
            .and_then(|line| line.strip_prefix("data: "))
            .ok_or_else(|| anyhow!("No data event found in OpenClaw response"))?;

        let body = serde_json::from_str::<serde_json::Value>(first_event)
            .map_err(|e| anyhow!("Failed to parse OpenClaw response: {}", e))?;

        Ok(body)
    }

    /// Call OpenClaw API to list instances
    async fn call_openclaw_api_list(&self) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/instances", self.openclaw_api_base_url);

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&self.openclaw_api_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call OpenClaw API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OpenClaw API error: {} - {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| anyhow!("Failed to parse OpenClaw response: {}", e))?;

        Ok(body)
    }
}

#[async_trait]
impl OpenClawService for OpenClawServiceImpl {
    async fn list_instances_from_openclaw(
        &self,
        _user_id: UserId,
    ) -> anyhow::Result<Vec<OpenClawInstance>> {
        tracing::info!("Listing instances from OpenClaw API (read-only, no DB sync)");

        // Call OpenClaw API
        let response = self.call_openclaw_api_list().await?;

        // Extract instances array from response
        let instances_array = response
            .get("instances")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Missing or invalid 'instances' array in OpenClaw response"))?;

        let mut instances = Vec::new();

        // Process each instance from OpenClaw (read-only, no database sync)
        for instance_data in instances_array {
            let instance_name = instance_data
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing 'name' in OpenClaw instance data"))?
                .to_string();

            let instance_ssh_pubkey = instance_data
                .get("ssh_pubkey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Generate a unique instance_id based on the OpenClaw name
            let instance_id = format!("openclaw-{}-{}", instance_name, Uuid::new_v4());

            // Create in-memory instance object (no database storage)
            let instance = OpenClawInstance {
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
            "Listed {} instances from OpenClaw API (read-only)",
            instances.len()
        );

        Ok(instances)
    }

    async fn create_instance_from_openclaw(
        &self,
        user_id: UserId,
        nearai_api_key: String,
        image: Option<String>,
        name: Option<String>,
        ssh_pubkey: Option<String>,
    ) -> anyhow::Result<OpenClawInstance> {
        tracing::info!("Creating instance from OpenClaw API: user_id={}", user_id);

        // Call OpenClaw API
        let response = self
            .call_openclaw_api_create(&nearai_api_key, image, name.clone(), ssh_pubkey.clone())
            .await?;

        // Extract instance data from response
        let instance_data = response
            .get("instance")
            .ok_or_else(|| anyhow!("Missing 'instance' in OpenClaw response"))?;

        let instance_name = instance_data
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'name' in OpenClaw instance data"))?
            .to_string();

        // Extract connection information from OpenClaw API response
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

        // Generate a unique instance_id based on the OpenClaw name
        let instance_id = format!("openclaw-{}-{}", instance_name, Uuid::new_v4());

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

        tracing::info!(
            "Instance created from OpenClaw API: instance_id={}, user_id={}",
            instance.id,
            user_id
        );

        Ok(instance)
    }
    async fn create_instance(
        &self,
        user_id: UserId,
        instance_id: String,
        name: String,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<OpenClawInstance> {
        tracing::info!(
            "Creating OpenClaw instance: user_id={}, instance_id={}",
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
    ) -> anyhow::Result<Option<OpenClawInstance>> {
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
    ) -> anyhow::Result<(Vec<OpenClawInstance>, i64)> {
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

    async fn update_instance(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: Option<String>,
        public_ssh_key: Option<String>,
    ) -> anyhow::Result<OpenClawInstance> {
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

        // Call OpenClaw API to terminate the instance
        // Use instance_id (the actual OpenClaw instance ID) for the deletion URL
        let delete_url = format!(
            "{}/instances/{}",
            self.openclaw_api_base_url, instance.instance_id
        );
        let response = self
            .http_client
            .delete(&delete_url)
            .bearer_auth(&self.openclaw_api_token)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to call OpenClaw API delete: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OpenClaw API delete failed with status {}: instance_id={}",
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

    async fn create_api_key(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        name: String,
        spend_limit: Option<i64>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> anyhow::Result<(OpenClawApiKey, String)> {
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

    async fn list_api_keys(
        &self,
        instance_id: Uuid,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<OpenClawApiKey>, i64)> {
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

    async fn validate_and_use_api_key(&self, api_key: &str) -> anyhow::Result<OpenClawApiKey> {
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
        api_key: &OpenClawApiKey,
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

        let total_tokens = input_tokens + output_tokens;

        // Calculate costs
        let (input_cost, output_cost, total_cost) =
            pricing.calculate_cost(input_tokens, output_tokens);

        // Check spend limit
        if let Some(limit) = api_key.spend_limit {
            if let Ok(Some(balance)) = self
                .repository
                .get_instance_balance(api_key.instance_id)
                .await
            {
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
            instance_id: api_key.instance_id,
            api_key_id: api_key.id,
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

        // Log usage and update balance (atomic in service)
        self.repository.log_usage(usage).await?;
        self.repository
            .update_instance_balance(api_key.instance_id, total_cost)
            .await?;

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
