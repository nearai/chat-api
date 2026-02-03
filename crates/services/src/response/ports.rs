use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::Stream;
use http::{HeaderMap, Method};
use std::pin::Pin;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("API error: {0}")]
    ApiError(String),
}

/// Response from the proxy, containing status, headers, and body stream
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
}

#[async_trait]
pub trait OpenAIProxyService: Send + Sync {
    /// Forward an HTTP request to OpenAI's API and return the raw response.
    /// This is a generic proxy that works with any endpoint.
    ///
    /// # Arguments
    /// * `method` - HTTP method (GET, POST, DELETE, etc.)
    /// * `path` - The path after /v1 (e.g., "responses", "responses/{id}")
    /// * `headers` - Additional headers to forward (excluding Authorization)
    /// * `body` - Optional request body
    async fn forward_request(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<ProxyResponse, ProxyError>;

    /// Forward a multipart form request to OpenAI's API (e.g., for image uploads).
    /// This method handles multipart/form-data requests and returns the raw response.
    ///
    /// # Arguments
    /// * `path` - The path after /v1 (e.g., "images/edits")
    /// * `headers` - Additional headers to forward (excluding Authorization and Content-Type)
    /// * `form` - The multipart form data to send
    async fn forward_multipart_request(
        &self,
        path: &str,
        headers: HeaderMap,
        form: reqwest::multipart::Form,
    ) -> Result<ProxyResponse, ProxyError> {
        // Default implementation returns an error - implementers should override for multipart support
        let _ = (path, headers, form);
        Err(ProxyError::InvalidRequest(
            "This proxy service does not support multipart requests".to_string(),
        ))
    }
}
