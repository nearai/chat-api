//! HTTP metrics middleware for tracking request counts and latencies.
//!
//! This middleware records low-cardinality metrics for all HTTP requests:
//! - `chat_api.http.requests` - Count of HTTP requests by method, endpoint, status
//! - `chat_api.http.duration` - Histogram of request durations by method, endpoint

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use services::metrics::{
    consts::{
        get_environment, METRIC_HTTP_DURATION, METRIC_HTTP_REQUESTS, TAG_ENDPOINT, TAG_ENVIRONMENT,
        TAG_METHOD, TAG_STATUS_CODE,
    },
    MetricsServiceTrait,
};
use std::sync::Arc;
use std::time::Instant;

/// State for the metrics middleware
#[derive(Clone)]
pub struct MetricsState {
    pub metrics_service: Arc<dyn MetricsServiceTrait>,
}

/// Middleware that records HTTP request metrics
pub async fn http_metrics_middleware(
    State(state): State<MetricsState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = match req.method().as_str() {
        "CONNECT" | "DELETE" | "GET" | "HEAD" | "OPTIONS" | "PATCH" | "POST" | "PUT" | "TRACE" => {
            req.method().as_str()
        }
        _ => "OTHER",
    }
    .to_owned();
    let endpoint = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_owned();

    let response = next.run(req).await;
    let duration = start.elapsed();
    let status = response.status().as_u16();

    let environment = get_environment();

    let tags = [
        format!("{TAG_METHOD}:{method}"),
        format!("{TAG_ENDPOINT}:{endpoint}"),
        format!("{TAG_STATUS_CODE}:{status}"),
        format!("{TAG_ENVIRONMENT}:{environment}"),
    ];
    let tags_str: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();

    state
        .metrics_service
        .record_latency(METRIC_HTTP_DURATION, duration, &tags_str);
    state
        .metrics_service
        .record_count(METRIC_HTTP_REQUESTS, 1, &tags_str);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware::from_fn_with_state, routing::get, Router};
    use services::metrics::capturing::MetricValue;
    use services::metrics::{
        capturing::{CapturingMetricsService, RecordedMetric},
        consts::{METRIC_HTTP_DURATION, METRIC_HTTP_REQUESTS},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn recorded_metrics_for_request_with_method(
        method: &str,
        path: &str,
    ) -> Vec<RecordedMetric> {
        let metrics_service = Arc::new(CapturingMetricsService::new());
        let app = Router::new()
            .route(
                "/v1/conversations/{conversation_id}",
                get(|| async { "ok" }),
            )
            .layer(from_fn_with_state(
                MetricsState {
                    metrics_service: metrics_service.clone(),
                },
                http_metrics_middleware,
            ));

        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert!(response.status().is_success() || response.status().is_client_error());
        metrics_service.get_metrics()
    }

    async fn recorded_metrics_for_request(path: &str) -> Vec<RecordedMetric> {
        recorded_metrics_for_request_with_method("GET", path).await
    }

    fn endpoint_tag(metrics: &[RecordedMetric], name: &str) -> String {
        metrics
            .iter()
            .find(|metric| metric.name == name)
            .and_then(|metric| metric.tags.iter().find(|tag| tag.starts_with("endpoint:")))
            .cloned()
            .expect("HTTP metric should have an endpoint tag")
    }

    fn assert_common_tags(metrics: &[RecordedMetric], status: u16) {
        for metric in metrics {
            let mut tag_keys = metric
                .tags
                .iter()
                .map(|tag| {
                    tag.split_once(':')
                        .expect("metric tag should have a value")
                        .0
                })
                .collect::<Vec<_>>();
            tag_keys.sort_unstable();
            assert_eq!(
                tag_keys,
                ["endpoint", "environment", "method", "status_code"],
                "HTTP metric tag keys should match the Cloud API contract"
            );
            assert!(metric.tags.iter().any(|tag| tag == "method:GET"));
            assert!(metric
                .tags
                .iter()
                .any(|tag| tag == &format!("status_code:{status}")));
            assert!(metric
                .tags
                .iter()
                .any(|tag| tag.starts_with("environment:")));
        }
    }

    #[tokio::test]
    async fn matched_routes_use_route_template() {
        for path in ["/v1/conversations/first-id", "/v1/conversations/second-id"] {
            let metrics = recorded_metrics_for_request(path).await;

            assert_eq!(metrics.len(), 2);
            assert!(metrics.iter().any(|metric| {
                metric.name == METRIC_HTTP_DURATION
                    && matches!(metric.value, MetricValue::Latency(_))
            }));
            assert!(metrics.iter().any(|metric| {
                metric.name == METRIC_HTTP_REQUESTS && matches!(metric.value, MetricValue::Count(1))
            }));
            assert_common_tags(&metrics, 200);
            assert_eq!(
                endpoint_tag(&metrics, METRIC_HTTP_DURATION),
                "endpoint:/v1/conversations/{conversation_id}"
            );
            assert_eq!(
                endpoint_tag(&metrics, METRIC_HTTP_REQUESTS),
                "endpoint:/v1/conversations/{conversation_id}"
            );
            assert!(metrics
                .iter()
                .all(|metric| metric.tags.iter().all(|tag| !tag.contains(path))));
        }
    }

    #[tokio::test]
    async fn unmatched_routes_use_bounded_label() {
        for path in ["/.env", "/wp-admin/install.php"] {
            let metrics = recorded_metrics_for_request(path).await;

            assert_eq!(metrics.len(), 2);
            assert_common_tags(&metrics, 404);
            assert_eq!(
                endpoint_tag(&metrics, METRIC_HTTP_DURATION),
                "endpoint:unmatched"
            );
            assert_eq!(
                endpoint_tag(&metrics, METRIC_HTTP_REQUESTS),
                "endpoint:unmatched"
            );
            assert!(metrics
                .iter()
                .all(|metric| metric.tags.iter().all(|tag| !tag.contains(path))));
        }
    }

    #[tokio::test]
    async fn nonstandard_methods_use_bounded_label() {
        let metrics = recorded_metrics_for_request_with_method("KLFQ", "/health").await;

        assert_eq!(metrics.len(), 2);
        assert!(metrics.iter().all(|metric| {
            metric.tags.iter().any(|tag| tag == "method:OTHER")
                && metric.tags.iter().all(|tag| tag != "method:KLFQ")
        }));
    }

    #[tokio::test]
    async fn standard_methods_preserve_method_label() {
        for method in [
            "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
        ] {
            let metrics = recorded_metrics_for_request_with_method(method, "/health").await;
            let expected_tag = format!("method:{method}");

            assert_eq!(metrics.len(), 2);
            assert!(metrics
                .iter()
                .all(|metric| metric.tags.iter().any(|tag| tag == &expected_tag)));
        }
    }
}
