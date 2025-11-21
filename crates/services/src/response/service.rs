use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method};

use super::ports::{CloudAPIProxyService, ProxyError, ProxyResponse};

/// Generic proxy service that forwards any request to Cloud API
pub struct CloudAPIProxy {
    api_key: String,
    base_url: String,
    http_client: reqwest::Client,
}

impl CloudAPIProxy {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://api.cloud.com/v1".to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }
}

#[async_trait]
impl CloudAPIProxyService for CloudAPIProxy {
    async fn forward_request(
        &self,
        method: Method,
        path: &str,
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<ProxyResponse, ProxyError> {
        // Ensure path doesn't start with a slash
        let clean_path = path.trim_start_matches('/');
        let url = format!("{}/{}", self.base_url, clean_path);

        tracing::info!("Cloud API Proxy: Forwarding request {} to {}", method, url);

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        tracing::debug!("Request body size: {} bytes", body_size);

        // Build the request
        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .header("Authorization", format!("Bearer {}", self.api_key));

        // Forward all headers from the client (except Authorization which we set above)
        headers.remove("authorization");
        headers.remove("host"); // Don't forward host header

        tracing::debug!("Forwarding {} header(s) to Cloud API", headers.len());
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        // Add body if present
        if let Some(body_bytes) = body {
            request_builder = request_builder.body(body_bytes);
        }

        // Send the request
        tracing::debug!("Sending request to Cloud API: {} {}", method, url);
        let response = request_builder.send().await.map_err(|e| {
            tracing::error!("Cloud API request failed for {} {}: {}", method, url, e);
            ProxyError::ApiError(e.to_string())
        })?;

        // Extract status and headers
        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        tracing::info!(
            "Cloud API Proxy: Received response from {} {} - status: {}",
            method,
            url,
            status
        );

        tracing::debug!("Response has {} header(s)", response_headers.len());

        // Get the body as a stream (don't buffer it)
        let body_stream = response.bytes_stream();

        Ok(ProxyResponse {
            status,
            headers: response_headers,
            body: Box::pin(body_stream),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_creation() {
        let service = CloudAPIProxy::new("test-api-key".to_string());
        assert_eq!(service.base_url, "https://api.cloud.com/v1");
    }

    #[tokio::test]
    async fn test_service_with_custom_base_url() {
        let service = CloudAPIProxy::new("test-api-key".to_string())
            .with_base_url("https://custom.api.com/v1".to_string());
        assert_eq!(service.base_url, "https://custom.api.com/v1");
    }
}
