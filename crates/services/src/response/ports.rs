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
}
