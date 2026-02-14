use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::Stream, StreamExt};
use http::{HeaderMap, StatusCode};
use reqwest::Client;
use std::pin::Pin;

use super::ports::OpenClawInstance;

/// Proxy service for forwarding requests to OpenClaw instances
#[async_trait]
pub trait OpenClawProxyService: Send + Sync {
    /// Forward an HTTP request to an OpenClaw instance
    ///
    /// # Arguments
    /// * `instance` - The OpenClaw instance to forward to
    /// * `path` - The request path (e.g., "/v1/chat/completions")
    /// * `method` - The HTTP method (e.g., "POST")
    /// * `headers` - Request headers (Authorization will be replaced with instance token)
    /// * `body` - Request body as bytes
    ///
    /// # Returns
    /// A tuple of (status_code, response_headers, response_body_stream)
    async fn forward_request(
        &self,
        instance: &OpenClawInstance,
        path: &str,
        method: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<(
        StatusCode,
        HeaderMap,
        Pin<Box<dyn Stream<Item = anyhow::Result<Bytes>> + Send>>,
    )>;
}

/// OpenClaw request proxy implementation
pub struct OpenClawProxy {
    http_client: Client,
}

impl OpenClawProxy {
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
        }
    }
}

impl Default for OpenClawProxy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OpenClawProxyService for OpenClawProxy {
    async fn forward_request(
        &self,
        instance: &OpenClawInstance,
        path: &str,
        method: &str,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<(
        StatusCode,
        HeaderMap,
        Pin<Box<dyn Stream<Item = anyhow::Result<Bytes>> + Send>>,
    )> {
        // Validate instance has connection info
        let instance_url = instance
            .instance_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Instance missing instance_url"))?;
        let instance_token = instance
            .instance_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Instance missing instance_token"))?;

        // Build the full URL
        let url = format!("{}{}", instance_url, path);

        tracing::debug!(
            "Forwarding {} request to OpenClaw instance: instance_id={}, url={}",
            method,
            instance.id,
            url
        );

        // Replace Authorization header with instance token
        headers.remove("authorization");
        headers.insert(
            "authorization",
            format!("Bearer {}", instance_token)
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid instance token format"))?,
        );

        // Remove host header to let reqwest set it
        headers.remove("host");

        // Build the request
        let mut request_builder = match method.to_uppercase().as_str() {
            "GET" => self.http_client.get(&url),
            "POST" => self.http_client.post(&url),
            "PUT" => self.http_client.put(&url),
            "PATCH" => self.http_client.patch(&url),
            "DELETE" => self.http_client.delete(&url),
            "HEAD" => self.http_client.head(&url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Add headers
        for (name, value) in headers.iter() {
            request_builder = request_builder.header(name, value.clone());
        }

        // Add body if present
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }

        // Send the request
        let response = request_builder.send().await.map_err(|e| {
            tracing::error!(
                "Failed to forward request to OpenClaw instance: instance_id={}, error={}",
                instance.id,
                e
            );
            anyhow::anyhow!("Failed to forward request to OpenClaw instance: {}", e)
        })?;

        let status = response.status();
        let response_headers = response.headers().clone();

        // Create a stream of the response body
        let stream = response.bytes_stream();

        let stream = Box::pin(stream.map(|result| {
            result.map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))
        })) as Pin<Box<dyn Stream<Item = anyhow::Result<Bytes>> + Send>>;

        tracing::debug!(
            "Forwarded request to OpenClaw instance: instance_id={}, status={}",
            instance.id,
            status
        );

        Ok((status, response_headers, stream))
    }
}
