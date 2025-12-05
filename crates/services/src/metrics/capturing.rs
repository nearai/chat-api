//! Capturing metrics service for testing purposes.
//!
//! This implementation captures all metrics in memory for assertions in tests.

use super::MetricsServiceTrait;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RecordedMetric {
    pub name: String,
    pub value: MetricValue,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum MetricValue {
    Latency(Duration),
    Count(i64),
    Histogram(f64),
}

pub struct CapturingMetricsService {
    pub metrics: std::sync::Mutex<Vec<RecordedMetric>>,
}

impl CapturingMetricsService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_metrics(&self) -> Vec<RecordedMetric> {
        self.metrics.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.metrics.lock().unwrap().clear();
    }

    /// Get count of metrics matching the given name
    pub fn count_by_name(&self, name: &str) -> usize {
        self.metrics
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.name == name)
            .count()
    }

    /// Get metrics matching the given name
    pub fn get_by_name(&self, name: &str) -> Vec<RecordedMetric> {
        self.metrics
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.name == name)
            .cloned()
            .collect()
    }
}

impl Default for CapturingMetricsService {
    fn default() -> Self {
        Self {
            metrics: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl MetricsServiceTrait for CapturingMetricsService {
    fn record_latency(&self, name: &str, duration: Duration, tags: &[&str]) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.push(RecordedMetric {
            name: name.to_string(),
            value: MetricValue::Latency(duration),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        });
    }

    fn record_count(&self, name: &str, value: i64, tags: &[&str]) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.push(RecordedMetric {
            name: name.to_string(),
            value: MetricValue::Count(value),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        });
    }

    fn record_histogram(&self, name: &str, value: f64, tags: &[&str]) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.push(RecordedMetric {
            name: name.to_string(),
            value: MetricValue::Histogram(value),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::consts::*;

    #[test]
    fn test_capturing_metrics_service() {
        let service = CapturingMetricsService::new();

        service.record_count(METRIC_USER_SIGNUP, 1, &["auth_method:google"]);
        service.record_count(
            METRIC_USER_LOGIN,
            1,
            &["auth_method:github", "is_new_user:false"],
        );
        service.record_latency(
            METRIC_HTTP_DURATION,
            Duration::from_millis(100),
            &["endpoint:/v1/responses"],
        );

        let metrics = service.get_metrics();
        assert_eq!(metrics.len(), 3);

        let signup_metrics = service.get_by_name(METRIC_USER_SIGNUP);
        assert_eq!(signup_metrics.len(), 1);
        assert!(signup_metrics[0]
            .tags
            .contains(&"auth_method:google".to_string()));
    }

    #[test]
    fn test_clear_metrics() {
        let service = CapturingMetricsService::new();
        service.record_count(METRIC_USER_SIGNUP, 1, &[]);
        assert_eq!(service.count_by_name(METRIC_USER_SIGNUP), 1);

        service.clear();
        assert_eq!(service.count_by_name(METRIC_USER_SIGNUP), 0);
    }
}
