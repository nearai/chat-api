use crate::vpc::VpcCredentialsService;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method};
use std::sync::Arc;
use std::time::Duration;

use super::ports::{OpenAIProxyService, ProxyError, ProxyResponse};

/// Generic proxy service that forwards any request to OpenAI's API
pub struct OpenAIProxy {
    vpc_service: Arc<dyn VpcCredentialsService>,
    base_url: String,
    http_client: reqwest::Client,
}

impl OpenAIProxy {
    pub fn new(vpc_service: Arc<dyn VpcCredentialsService>) -> Self {
        Self {
            vpc_service,
            base_url: "https://api.openai.com/v1".to_string(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("Failed to create HTTP client with timeout"),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }
}

#[async_trait]
impl OpenAIProxyService for OpenAIProxy {
    async fn forward_request(
        &self,
        method: Method,
        path: &str,
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<ProxyResponse, ProxyError> {
        // Get API key
        let api_key = self.vpc_service.get_api_key().await.map_err(|e| {
            tracing::error!("Failed to get API key: {}", e);
            ProxyError::ApiError("Failed to get API key".to_string())
        })?;

        // Ensure path doesn't start with a slash
        let clean_path = path.trim_start_matches('/');
        let url = format!("{}/{}", self.base_url, clean_path);

        tracing::info!("OpenAI Proxy: Forwarding request {}", method);

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        tracing::debug!("Request body size: {} bytes", body_size);

        // Build the request
        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .header("Authorization", format!("Bearer {}", api_key));

        // Forward all headers from the client (except Authorization which we set above)
        headers.remove("authorization");
        headers.remove("host"); // Don't forward host header

        // If no body is provided, remove content-related headers to avoid
        // the server waiting for body data that will never arrive
        if body.is_none() {
            headers.remove("content-length");
            headers.remove("content-type");
            headers.remove("transfer-encoding");
        }

        tracing::debug!("Forwarding {} header(s) to OpenAI", headers.len());
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        // Add body if present
        if let Some(body_bytes) = body {
            request_builder = request_builder.body(body_bytes);
        }

        // Send the request
        tracing::debug!("Sending request to OpenAI: {}", method);
        let response = request_builder.send().await.map_err(|e| {
            tracing::error!("OpenAI API request failed for {}: {}", method, e);
            ProxyError::ApiError(e.to_string())
        })?;

        // Extract status and headers
        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        tracing::info!(
            "OpenAI Proxy: Received response from {} - status: {}",
            method,
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

    async fn forward_multipart_request(
        &self,
        path: &str,
        mut headers: HeaderMap,
        form: reqwest::multipart::Form,
    ) -> Result<ProxyResponse, ProxyError> {
        // Get API key
        let api_key = self.vpc_service.get_api_key().await.map_err(|e| {
            // API key errors are system/config errors (not customer data), safe to log
            tracing::error!("Failed to get API key for multipart request: {}", e);
            ProxyError::ApiError("Failed to get API key".to_string())
        })?;

        // Ensure path doesn't start with a slash
        let clean_path = path.trim_start_matches('/');
        let url = format!("{}/{}", self.base_url, clean_path);

        tracing::info!("OpenAI Proxy: Forwarding multipart request");

        // Build the request with multipart form
        let mut request_builder = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key));

        // Forward headers (except Authorization and Content-Type which multipart handles)
        headers.remove("authorization");
        headers.remove("content-type"); // multipart will set this
        headers.remove("host"); // Don't forward host header

        tracing::debug!("Forwarding {} header(s) to OpenAI", headers.len());
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        // Add multipart form
        request_builder = request_builder.multipart(form);

        // Send the request
        tracing::debug!("Sending multipart request to OpenAI");
        let response = request_builder.send().await.map_err(|e| {
            tracing::error!("OpenAI API multipart request failed: {}", e);
            ProxyError::ApiError(e.to_string())
        })?;

        // Extract status and headers
        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        tracing::info!(
            "OpenAI Proxy: Received response from multipart request - status: {}",
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
    use crate::vpc::test_helpers::MockVpcCredentialsService;

    #[tokio::test]
    async fn test_service_creation() {
        let vpc_service = Arc::new(MockVpcCredentialsService::not_configured());
        let service = OpenAIProxy::new(vpc_service);
        assert_eq!(service.base_url, "https://api.openai.com/v1");
    }

    #[tokio::test]
    async fn test_service_with_custom_base_url() {
        let vpc_service = Arc::new(MockVpcCredentialsService::not_configured());
        let service =
            OpenAIProxy::new(vpc_service).with_base_url("https://custom.api.com/v1".to_string());
        assert_eq!(service.base_url, "https://custom.api.com/v1");
    }
}
