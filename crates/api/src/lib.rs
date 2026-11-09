pub mod cloud_api;
pub mod common;
pub mod consts;
pub mod database_encryption;
pub mod encryption_key_resolver;
pub mod error;
pub mod middleware;
pub mod model_pricing;
pub mod models;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod static_files;
pub mod stripe_client_adapter;
pub mod tasks;
pub mod usage_parsing;
pub mod validation;
pub mod web_search_pricing;

pub use error::{ApiError, ApiErrorResponse};
pub use middleware::{auth_middleware, AuthState, AuthenticatedUser};
pub use models::*;
pub use openapi::ApiDoc;
pub use routes::create_router_with_cors;
pub use state::AppState;

use config::LoggingConfig;
use services::logging::error_type;
use tracing_subscriber::{filter::filter_fn, prelude::*, EnvFilter};

/// Dependency diagnostics can contain SQL bind values, HTTP headers, and URLs.
/// Apply this independently of EnvFilter so even trace-level configuration cannot
/// enable unaudited dependency events or spans.
fn application_log_target(target: &str) -> bool {
    matches!(
        target.split("::").next(),
        Some("api" | "task_worker" | "services" | "database" | "config" | "stripe_client")
    )
}

pub fn init_tracing_from_config(logging_config: &LoggingConfig) {
    let mut filter = logging_config.level.clone();
    for (module, level) in &logging_config.modules {
        filter.push_str(&format!(",{module}={level}"));
    }

    let env_filter = EnvFilter::try_new(&filter).unwrap_or_else(|_| {
        eprintln!("Invalid log filter. Falling back to info.");
        EnvFilter::new("info")
    });

    match logging_config.format.as_str() {
        "compact" => {
            if let Err(e) = tracing_subscriber::registry()
                .with(env_filter)
                .with(filter_fn(|metadata| {
                    application_log_target(metadata.target())
                }))
                .with(
                    tracing_subscriber::fmt::layer()
                        .compact()
                        .with_target(false)
                        .with_thread_ids(false)
                        .with_thread_names(false),
                )
                .try_init()
            {
                eprintln!(
                    "tracing already initialized: {e_type}",
                    e_type = error_type(&e)
                );
            }
        }
        "pretty" => {
            if let Err(e) = tracing_subscriber::registry()
                .with(env_filter)
                .with(filter_fn(|metadata| {
                    application_log_target(metadata.target())
                }))
                .with(tracing_subscriber::fmt::layer().pretty())
                .try_init()
            {
                eprintln!(
                    "tracing already initialized: {e_type}",
                    e_type = error_type(&e)
                );
            }
        }
        _ => {
            // Default to JSON for "json" or any unknown format
            if let Err(e) = tracing_subscriber::registry()
                .with(env_filter)
                .with(filter_fn(|metadata| {
                    application_log_target(metadata.target())
                }))
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false),
                )
                .try_init()
            {
                eprintln!(
                    "tracing already initialized: {e_type}",
                    e_type = error_type(&e)
                );
            }
        }
    }
}

#[cfg(test)]
fn random_key() -> [u8; 32] {
    use rand::{Rng, TryRngCore};
    rand::rngs::OsRng.unwrap_err().random()
}

#[cfg(test)]
mod logging_privacy_tests {
    use super::*;
    use services::{
        response::{ports::OpenAIProxyService, service::OpenAIProxy},
        vpc::test_helpers::MockVpcCredentialsService,
    };
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use tracing::instrument::WithSubscriber;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
            let writer = self.clone();
            tracing_subscriber::registry()
                .with(EnvFilter::new("trace,reqwest=trace,tokio_postgres=trace"))
                .with(filter_fn(|metadata| {
                    application_log_target(metadata.target())
                }))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(move || writer.clone()),
                )
        }

        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn dependency_events_and_spans_are_blocked_even_at_trace_level() {
        let logs = CapturedLogs::default();

        tracing::subscriber::with_default(logs.subscriber(), || {
            let span = tracing::info_span!(
                target: "reqwest::connect",
                "connection",
                url = "https://host/WEBHOOK_SECRET_SENTINEL"
            );
            let _entered = span.enter();

            tracing::warn!(target: "tokio_postgres::query", "SQL_VALUE_SENTINEL");
            tracing::error!(target: "reqwest::connect", "HTTP_TOKEN_SENTINEL");
            tracing::trace!(target: "api::routes", "application event retained");
            tracing::info!(target: "task_worker", "worker event retained");
        });

        let captured = logs.contents();
        assert!(captured.contains("application event retained"));
        assert!(captured.contains("worker event retained"));
        assert!(!captured.contains("SENTINEL"), "{captured}");
        assert!(!application_log_target("api_untrusted::client"));
    }

    #[tokio::test]
    async fn proxy_and_internal_errors_do_not_log_urls_or_error_payloads() {
        let logs = CapturedLogs::default();
        let proxy = OpenAIProxy::new(Arc::new(MockVpcCredentialsService::not_configured()))
            .with_base_url("http://[invalid-host".to_string());
        let error = anyhow::anyhow!("access_token=OAUTH_RESPONSE_SENTINEL")
            .context("https://dashboard.example/?token=DASHBOARD_TOKEN_SENTINEL");

        async {
            let response = ApiError::from(error);
            assert_eq!(response.status, http::StatusCode::INTERNAL_SERVER_ERROR);

            let result = proxy
                .forward_request(
                    http::Method::POST,
                    "responses?access_token=QUERY_TOKEN_SENTINEL",
                    http::HeaderMap::new(),
                    Some(bytes::Bytes::from_static(b"PRIVATE_PROMPT_SENTINEL")),
                )
                .await;

            assert!(result.is_err());
        }
        .with_subscriber(logs.subscriber())
        .await;

        let captured = logs.contents();
        assert!(captured.contains("Internal error"));
        assert!(captured.contains("OpenAI API request failed"));
        assert!(captured.contains("reqwest::error::Error"));
        assert!(!captured.contains("SENTINEL"), "{captured}");
        assert!(!captured.contains("invalid-host"), "{captured}");
    }
}
