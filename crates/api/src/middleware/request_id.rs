use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use http::{HeaderMap, HeaderName, HeaderValue};
use uuid::Uuid;

pub fn request_id_header_name() -> HeaderName {
    HeaderName::from_static("x-request-id")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestCorrelation {
    request_id: Uuid,
}

impl RequestCorrelation {
    pub const fn new(request_id: Uuid) -> Self {
        Self { request_id }
    }

    pub const fn request_id(self) -> Uuid {
        self.request_id
    }
}

pub async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response {
    let request_id = selected_request_id(req.headers());
    let request_id_value = request_id.to_string();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if let Ok(header_value) = HeaderValue::from_str(&request_id_value) {
        req.headers_mut()
            .insert(request_id_header_name(), header_value);
    }
    req.extensions_mut()
        .insert(RequestCorrelation::new(request_id));

    let mut response = next.run(req).await;
    if let Ok(header_value) = HeaderValue::from_str(&request_id_value) {
        response
            .headers_mut()
            .insert(request_id_header_name(), header_value);
    }
    tracing::debug!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        "request completed"
    );
    response
}

fn selected_request_id(headers: &HeaderMap) -> Uuid {
    headers
        .get(request_id_header_name())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::new_v4)
}

#[cfg(test)]
mod logging_macro_scan;
#[cfg(test)]
mod privacy_log_assertions;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware::from_fn, routing::post, Router};
    use std::io;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::Level;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogsWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogsWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut logs = self
                .0
                .lock()
                .expect("captured logs mutex should not poison");
            logs.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn writer(&self) -> CapturedLogsWriter {
            CapturedLogsWriter(Arc::clone(&self.0))
        }

        fn contents(&self) -> String {
            let logs = self
                .0
                .lock()
                .expect("captured logs mutex should not poison");
            String::from_utf8_lossy(&logs).into_owned()
        }
    }

    #[test]
    fn selected_request_id_reuses_valid_uuid() {
        let request_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            request_id_header_name(),
            HeaderValue::from_str(&request_id.to_string()).expect("uuid header is valid"),
        );

        assert_eq!(selected_request_id(&headers), request_id);
    }

    #[test]
    fn selected_request_id_replaces_invalid_uuid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            request_id_header_name(),
            HeaderValue::from_static("not-a-uuid"),
        );

        assert_ne!(selected_request_id(&headers).to_string(), "not-a-uuid");
    }

    #[tokio::test]
    async fn tracing_logs_exclude_customer_content() {
        privacy_log_assertions::assert_production_logs_exclude_forbidden_expressions();

        let logs = CapturedLogs::default();
        let writer_logs = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer_logs.writer())
            .finish();
        let request_id = Uuid::new_v4();
        let body = Body::from(
            r#"{"messages":[{"role":"user","content":"CHAT_PROMPT_SENTINEL"}],"api_key":"sk-chat-sentinel"}"#,
        );
        let app = Router::new()
            .route("/privacy-log-check", post(|| async { "ok" }))
            .layer(from_fn(request_id_middleware));

        let _subscriber_guard = tracing::subscriber::set_default(subscriber);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/privacy-log-check")
                    .header(request_id_header_name(), request_id.to_string())
                    .header("x-org-id", "spoofed-chat-org")
                    .header("authorization", "Bearer sk-chat-sentinel")
                    .body(body)
                    .expect("test request should build"),
            )
            .await
            .expect("test request should complete");

        assert_eq!(response.status().as_u16(), 200);
        let captured = logs.contents();
        assert!(captured.contains(&request_id.to_string()));
        assert!(captured.contains("method=POST"));
        assert!(captured.contains("path=/privacy-log-check"));
        assert!(captured.contains("status=200"));
        for forbidden in [
            "CHAT_PROMPT_SENTINEL",
            "sk-chat-sentinel",
            "spoofed-chat-org",
        ] {
            assert!(
                !captured.contains(forbidden),
                "captured logs must not contain {forbidden}; logs: {captured}"
            );
        }
    }
}
