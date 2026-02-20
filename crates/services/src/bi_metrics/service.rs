use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

use super::ports::*;

pub struct BiMetricsServiceImpl {
    repo: Arc<dyn BiMetricsRepository>,
}

impl BiMetricsServiceImpl {
    pub fn new(repo: Arc<dyn BiMetricsRepository>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl BiMetricsService for BiMetricsServiceImpl {
    async fn list_deployments(
        &self,
        filter: &DeploymentFilter,
    ) -> anyhow::Result<(Vec<DeploymentRecord>, i64)> {
        self.repo.list_deployments(filter).await
    }

    async fn get_deployment_summary(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<DeploymentSummary> {
        self.repo.get_deployment_summary(start_date, end_date).await
    }

    async fn get_status_history(
        &self,
        instance_id: Uuid,
        limit: i64,
    ) -> anyhow::Result<Vec<StatusChangeRecord>> {
        self.repo.get_status_history(instance_id, limit).await
    }

    async fn get_usage_aggregation(
        &self,
        filter: &UsageFilter,
    ) -> anyhow::Result<Vec<UsageAggregation>> {
        self.repo.get_usage_aggregation(filter).await
    }

    async fn get_top_consumers(
        &self,
        filter: &TopConsumerFilter,
    ) -> anyhow::Result<Vec<TopConsumer>> {
        self.repo.get_top_consumers(filter).await
    }
}
