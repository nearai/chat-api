//! Metrics service for tracking usage and engagement metrics.
//!
//! This module provides a trait-based abstraction for recording metrics,
//! with implementations for:
//! - `CapturingMetricsService` for testing
//! - `MockMetricsService` for when metrics are disabled
//! - `OtlpMetricsService` for production use with OpenTelemetry OTLP export

pub mod capturing;
pub mod consts;

use async_trait::async_trait;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, MeterProvider as _},
    KeyValue,
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Trait for recording metrics.
///
/// This abstraction allows for different implementations:
/// - `CapturingMetricsService` for testing
/// - `MockMetricsService` for when metrics are disabled
/// - Future: `OtlpMetricsService` for production use with OpenTelemetry
#[async_trait]
pub trait MetricsServiceTrait: Send + Sync {
    /// Record a latency/duration metric
    fn record_latency(&self, name: &str, duration: Duration, tags: &[&str]);

    /// Record a count metric (increment counter)
    fn record_count(&self, name: &str, value: i64, tags: &[&str]);

    /// Record a histogram value
    fn record_histogram(&self, name: &str, value: f64, tags: &[&str]);
}

// Helper functions for creating properly formatted tags

/// Create a tag in the "key:value" format
pub fn tag(key: &str, value: impl std::fmt::Display) -> String {
    format!("{key}:{value}")
}

/// Create multiple tags from key-value pairs
pub fn tags(pairs: &[(&str, &str)]) -> Vec<String> {
    pairs.iter().map(|(k, v)| tag(k, v)).collect()
}

/// Mock implementation for when metrics collection is disabled.
/// All methods are no-ops.
pub struct MockMetricsService;

#[async_trait]
impl MetricsServiceTrait for MockMetricsService {
    fn record_latency(&self, _name: &str, _duration: Duration, _tags: &[&str]) {}
    fn record_count(&self, _name: &str, _value: i64, _tags: &[&str]) {}
    fn record_histogram(&self, _name: &str, _value: f64, _tags: &[&str]) {}
}

/// Logging metrics service that logs metrics to tracing.
/// Useful for debugging and development.
pub struct LoggingMetricsService;

#[async_trait]
impl MetricsServiceTrait for LoggingMetricsService {
    fn record_latency(&self, name: &str, duration: Duration, tags: &[&str]) {
        tracing::info!(
            metric_name = name,
            metric_type = "latency",
            duration_ms = duration.as_millis() as u64,
            tags = ?tags,
            "Recording latency metric"
        );
    }

    fn record_count(&self, name: &str, value: i64, tags: &[&str]) {
        tracing::info!(
            metric_name = name,
            metric_type = "count",
            value = value,
            tags = ?tags,
            "Recording count metric"
        );
    }

    fn record_histogram(&self, name: &str, value: f64, tags: &[&str]) {
        tracing::info!(
            metric_name = name,
            metric_type = "histogram",
            value = value,
            tags = ?tags,
            "Recording histogram metric"
        );
    }
}

/// OpenTelemetry OTLP metrics service for production use.
/// Exports metrics to an OTLP-compatible collector (e.g., Datadog Agent, Jaeger).
pub struct OtlpMetricsService {
    meter: Meter,
    // Cache instruments to avoid recreating them on every call
    latency_histograms: Mutex<HashMap<String, Histogram<u64>>>,
    counters: Mutex<HashMap<String, Counter<u64>>>,
    value_histograms: Mutex<HashMap<String, Histogram<f64>>>,
}

impl OtlpMetricsService {
    /// Create a new OtlpMetricsService from a MeterProvider.
    pub fn new(meter_provider: &SdkMeterProvider) -> Self {
        let meter = meter_provider.meter("chat-api");
        Self {
            meter,
            latency_histograms: Mutex::new(HashMap::new()),
            counters: Mutex::new(HashMap::new()),
            value_histograms: Mutex::new(HashMap::new()),
        }
    }

    /// Parse tags in "key:value" format into OpenTelemetry KeyValue pairs.
    fn parse_tags(tags: &[&str]) -> Vec<KeyValue> {
        tags.iter()
            .filter_map(|tag| {
                let parts: Vec<&str> = tag.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Some(KeyValue::new(parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[async_trait]
impl MetricsServiceTrait for OtlpMetricsService {
    fn record_latency(&self, name: &str, duration: Duration, tags: &[&str]) {
        let mut histograms = self.latency_histograms.lock().unwrap();
        let histogram = histograms.entry(name.to_string()).or_insert_with(|| {
            let description = match name {
                consts::METRIC_HTTP_DURATION => "HTTP request processing time",
                _ => "Latency measurement",
            };

            self.meter
                .u64_histogram(name.to_string())
                .with_description(description)
                .with_unit("ms")
                .build()
        });

        let kv_tags = Self::parse_tags(tags);
        histogram.record(duration.as_millis() as u64, &kv_tags);
    }

    fn record_count(&self, name: &str, value: i64, tags: &[&str]) {
        let mut counters = self.counters.lock().unwrap();
        let counter = counters.entry(name.to_string()).or_insert_with(|| {
            let description = match name {
                consts::METRIC_USER_SIGNUP => "User signups",
                consts::METRIC_USER_LOGIN => "User logins",
                consts::METRIC_RESPONSE_CREATED => "Response completions created",
                consts::METRIC_CONVERSATION_CREATED => "Conversations created",
                consts::METRIC_FILE_UPLOADED => "Files uploaded",
                consts::METRIC_HTTP_REQUESTS => "Total HTTP requests",
                _ => "Count",
            };

            self.meter
                .u64_counter(name.to_string())
                .with_description(description)
                .build()
        });

        let kv_tags = Self::parse_tags(tags);
        counter.add(value as u64, &kv_tags);
    }

    fn record_histogram(&self, name: &str, value: f64, tags: &[&str]) {
        let mut histograms = self.value_histograms.lock().unwrap();
        let histogram = histograms.entry(name.to_string()).or_insert_with(|| {
            self.meter
                .f64_histogram(name.to_string())
                .with_description("Value distribution")
                .build()
        });

        let kv_tags = Self::parse_tags(tags);
        histogram.record(value, &kv_tags);
    }
}
