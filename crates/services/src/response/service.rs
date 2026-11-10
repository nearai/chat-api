use crate::logging::error_type;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method};

use super::ports::{OpenAIProxyService, ProxyError, ProxyResponse};

/// Generic proxy service that forwards any request to OpenAI's API
pub struct OpenAIProxy {
    api_key: String,
    base_url: String,
    http_client: reqwest::Client,
}

impl OpenAIProxy {
    /// Use the configured static key for every request, without a database lookup.
    pub fn new(api_key: String) -> anyhow::Result<Self> {
        if api_key.trim().is_empty() {
            tracing::error!(
                "OPENAI_API_KEY or OPENAI_API_KEY_FILE must contain a nonblank API key"
            );
            anyhow::bail!("OPENAI_API_KEY or OPENAI_API_KEY_FILE must contain a nonblank API key");
        }

        Ok(Self {
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
            http_client: reqwest::Client::new(),
        })
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }
}

fn validate_proxy_path(path: &str) -> Result<&str, ProxyError> {
    let clean_path = path.trim_start_matches('/');
    if clean_path.is_empty() {
        return Err(ProxyError::InvalidRequest(
            "Proxy path cannot be empty".to_string(),
        ));
    }

    if clean_path.contains('#') || clean_path.chars().any(char::is_control) {
        return Err(ProxyError::InvalidRequest(
            "Proxy path contains an unsafe delimiter".to_string(),
        ));
    }

    let path_part = clean_path
        .split_once('?')
        .map(|(path_part, _)| path_part)
        .unwrap_or(clean_path);

    validate_proxy_path_variant(path_part)?;

    let decoded = urlencoding::decode(path_part)
        .map_err(|_| ProxyError::InvalidRequest("Proxy path is not valid URL encoding".into()))?;
    if decoded.contains('%') {
        return Err(ProxyError::InvalidRequest(
            "Proxy path contains nested encoding".into(),
        ));
    }
    validate_proxy_path_variant(&decoded)?;

    Ok(clean_path)
}

fn validate_proxy_path_variant(path: &str) -> Result<(), ProxyError> {
    if path.contains('\\') {
        return Err(ProxyError::InvalidRequest(
            "Proxy path cannot contain backslashes".to_string(),
        ));
    }

    if path.contains('?') || path.contains('#') || path.chars().any(char::is_control) {
        return Err(ProxyError::InvalidRequest(
            "Proxy path contains an unsafe delimiter".to_string(),
        ));
    }

    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ProxyError::InvalidRequest(
                "Proxy path contains an unsafe path segment".to_string(),
            ));
        }
    }

    Ok(())
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
        let clean_path = validate_proxy_path(path)?;

        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), clean_path);

        tracing::info!(
            %method,
            "OpenAI Proxy: forwarding request"
        );

        let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
        tracing::debug!("Request body size: {} bytes", body_size);

        // Build the request
        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .bearer_auth(&self.api_key);

        // Forward all headers from the client (except Authorization which we set above)
        headers.remove("authorization");
        headers.remove("host"); // Don't forward host header
        headers.remove("cookie");
        headers.remove("x-org-id");
        headers.remove("x-workspace-id");

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
        tracing::debug!(
            %method,
            "Sending request to OpenAI"
        );
        let response = request_builder.send().await.map_err(|e| {
            tracing::error!(
                %method,
                error_type = error_type(&e),
                is_timeout = e.is_timeout(),
                is_connect = e.is_connect(),
                is_builder = e.is_builder(),
                status = e.status().map(|status| status.as_u16()),
                "OpenAI API request failed"
            );
            ProxyError::ApiError(e.to_string())
        })?;

        // Extract status and headers
        let status = response.status().as_u16();
        let response_headers = response.headers().clone();

        tracing::info!(
            %method,
            %status,
            "OpenAI Proxy: received response"
        );

        tracing::debug!("Response has {} header(s)", response_headers.len());

        // Stream the response body without buffering
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn rejects_missing_or_blank_static_key() {
        for key in ["", " ", "\n\t"] {
            let error = OpenAIProxy::new(key.into()).err().expect("key is required");

            assert_eq!(
                error.to_string(),
                "OPENAI_API_KEY or OPENAI_API_KEY_FILE must contain a nonblank API key"
            );
        }
    }

    #[tokio::test]
    async fn uses_static_key_and_does_not_retry_rejected_requests() {
        for status in [200, 401] {
            let upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(header("authorization", "Bearer configured-static-key"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&upstream)
                .await;

            let proxy = OpenAIProxy::new("configured-static-key".into())
                .unwrap()
                .with_base_url(format!("{}/v1", upstream.uri()));
            let mut headers = HeaderMap::new();
            headers.insert("authorization", "Bearer client-session".parse().unwrap());

            let response = proxy
                .forward_request(Method::POST, "chat/completions", headers, None)
                .await
                .unwrap();

            assert_eq!(response.status, status);
            assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn test_service_creation() {
        let service = OpenAIProxy::new("static-api-key".into()).unwrap();

        assert_eq!(service.base_url, "https://api.openai.com/v1");
    }

    #[tokio::test]
    async fn test_service_with_custom_base_url() {
        let service = OpenAIProxy::new("static-api-key".into())
            .unwrap()
            .with_base_url("https://custom.api.com/v1".to_string());

        assert_eq!(service.base_url, "https://custom.api.com/v1");
    }

    #[test]
    fn validate_proxy_path_allows_normal_paths_and_encoded_model_names() {
        assert_eq!(
            validate_proxy_path("chat/completions").unwrap(),
            "chat/completions"
        );
        assert_eq!(
            validate_proxy_path("/model/Qwen%2FQwen3.5-122B-A10B").unwrap(),
            "model/Qwen%2FQwen3.5-122B-A10B"
        );
        assert_eq!(
            validate_proxy_path("attestation/report?nonce=abc123").unwrap(),
            "attestation/report?nonce=abc123"
        );
    }

    #[test]
    fn validate_proxy_path_rejects_raw_traversal() {
        assert!(matches!(
            validate_proxy_path("signature/../files"),
            Err(ProxyError::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_proxy_path("signature/./files"),
            Err(ProxyError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_proxy_path_rejects_encoded_traversal() {
        for path in [
            "signature/..%2Ffiles",
            "signature/%2e%2e%2ffiles",
            "signature/%252e%252e%252ffiles",
            "signature/%2e%2e%5cfiles",
            "signature/%2e%2e%3Ftarget=files",
        ] {
            assert!(
                matches!(
                    validate_proxy_path(path),
                    Err(ProxyError::InvalidRequest(_))
                ),
                "path should be rejected: {path}"
            );
        }
    }

    #[test]
    fn validate_proxy_path_rejects_ambiguous_paths() {
        for path in [
            "",
            "files//content",
            "signature/..\\files",
            "files/abc#frag",
        ] {
            assert!(
                matches!(
                    validate_proxy_path(path),
                    Err(ProxyError::InvalidRequest(_))
                ),
                "path should be rejected: {path}"
            );
        }
    }
}
