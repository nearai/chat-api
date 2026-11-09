use crate::logging::error_type;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::Stream, StreamExt};
use http::{HeaderMap, StatusCode};
use reqwest::Client;
use std::pin::Pin;

use super::ports::AgentInstance;
use super::url_guard;

/// Proxy service for forwarding requests to agent instances
#[async_trait]
pub trait AgentProxyService: Send + Sync {
    /// Forward an HTTP request to an agent instance
    ///
    /// # Arguments
    /// * `instance` - The agent instance to forward to
    /// * `path` - The request path (e.g., "/v1/chat/completions")
    /// * `method` - The HTTP method (e.g., "POST")
    /// * `headers` - Request headers (Authorization will be replaced with instance token)
    /// * `body` - Request body as bytes
    ///
    /// # Returns
    /// A tuple of (status_code, response_headers, response_body_stream)
    async fn forward_request(
        &self,
        instance: &AgentInstance,
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

/// Agent request proxy implementation
pub struct AgentProxy {
    http_client: Client,
}

impl AgentProxy {
    pub fn new() -> Self {
        // Create HTTP client with timeout to prevent indefinite hanging on unresponsive instances.
        // The guarded builder validates resolved addresses and redirect targets.
        let http_client = url_guard::guarded_client_builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build agent proxy HTTP client");

        Self { http_client }
    }
}

impl Default for AgentProxy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentProxyService for AgentProxy {
    async fn forward_request(
        &self,
        instance: &AgentInstance,
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

        // Validate the stored URL and append the request path to it
        let base_url = url_guard::validate_agent_url(instance_url, "instance_url")?;
        let url = url_guard::join_url_path(&base_url, path)?;

        tracing::debug!(
            "Forwarding {} request to agent instance: instance_id={}",
            method,
            instance.id
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
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url),
            "PUT" => self.http_client.put(url),
            "PATCH" => self.http_client.patch(url),
            "DELETE" => self.http_client.delete(url),
            "HEAD" => self.http_client.head(url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Whitelist of safe headers to forward to avoid header injection attacks.
        // Client-supplied forwarding headers are not trusted and are not forwarded.
        const SAFE_HEADERS: &[&str] = &[
            "content-type",
            "accept",
            "accept-encoding",
            "accept-language",
            "user-agent",
            "content-length",
            "x-request-id",
            "x-correlation-id",
        ];

        // Add headers (only forwarding whitelisted headers)
        for (name, value) in headers.iter() {
            let header_name_lower = name.to_string().to_lowercase();
            if SAFE_HEADERS.contains(&header_name_lower.as_str()) {
                request_builder = request_builder.header(name, value.clone());
            } else {
                tracing::debug!(
                    "Filtered out non-whitelisted header in proxy: {}",
                    header_name_lower
                );
            }
        }

        // Add body if present
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }

        // Send the request
        // Errors drop the URL: instance URLs may carry credentials.
        let response = request_builder.send().await.map_err(|e| {
            let e = e.without_url();
            tracing::error!(
                "Failed to forward request to agent instance: instance_id={}, error={}",
                instance.id,
                error_type(&e)
            );
            anyhow::anyhow!("Failed to forward request to agent instance: {}", e)
        })?;

        let status = response.status();
        let raw_headers = response.headers().clone();

        // Whitelist of safe response headers to avoid forwarding sensitive headers
        // (e.g. Set-Cookie) from a compromised or malicious agent instance
        const SAFE_RESPONSE_HEADERS: &[&str] = &[
            "content-type",
            "content-length",
            "content-disposition",
            "cache-control",
            "content-encoding",
        ];
        let mut response_headers = HeaderMap::new();
        for (name, value) in raw_headers.iter() {
            let name_lower = name.as_str().to_lowercase();
            if SAFE_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                response_headers.insert(name.clone(), value.clone());
            }
        }

        // Create a stream of the response body
        let stream = response.bytes_stream();

        let stream = Box::pin(stream.map(|result| {
            result.map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e.without_url()))
        })) as Pin<Box<dyn Stream<Item = anyhow::Result<Bytes>> + Send>>;

        tracing::debug!(
            "Forwarded request to agent instance: instance_id={}, status={}",
            instance.id,
            status
        );

        Ok((status, response_headers, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserId;
    use chrono::Utc;
    use uuid::Uuid;
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

    fn instance_with_url(instance_url: &str) -> AgentInstance {
        AgentInstance {
            id: Uuid::new_v4(),
            user_id: UserId(Uuid::new_v4()),
            instance_id: "agent-test".to_string(),
            name: "test".to_string(),
            public_ssh_key: None,
            instance_url: Some(instance_url.to_string()),
            instance_token: Some("instance-token".to_string()),
            dashboard_url: None,
            agent_api_base_url: None,
            service_type: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn forward_request_rejects_forbidden_instance_url() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let proxy = AgentProxy::new();
        for instance_url in [
            server.uri(),
            format!("{}/api?id=1&x=", server.uri()),
            server.uri().replace("127.0.0.1", "localhost"),
        ] {
            let result = proxy
                .forward_request(
                    &instance_with_url(&instance_url),
                    "/v1/instances/agent-test/backups",
                    "GET",
                    HeaderMap::new(),
                    Bytes::new(),
                )
                .await;
            assert!(result.is_err(), "{instance_url} should be rejected");
        }
        // MockServer verifies on drop that no request reached it.
    }

    #[tokio::test]
    async fn forward_request_errors_do_not_include_instance_url() {
        let proxy = AgentProxy::new();
        let result = proxy
            .forward_request(
                &instance_with_url("https://agent.invalid/?token=secret-instance-token"),
                "/v1/models",
                "GET",
                HeaderMap::new(),
                Bytes::new(),
            )
            .await;
        let message = format!("{:#}", result.err().expect("request should fail"));
        assert!(!message.contains("secret-instance-token"), "{message}");
        assert!(!message.contains("agent.invalid"), "{message}");
    }

    #[tokio::test]
    async fn forward_request_rejects_non_http_instance_url() {
        let proxy = AgentProxy::new();
        let result = proxy
            .forward_request(
                &instance_with_url("file:///etc/passwd"),
                "/v1/models",
                "GET",
                HeaderMap::new(),
                Bytes::new(),
            )
            .await;
        assert!(result.is_err());
    }
}
