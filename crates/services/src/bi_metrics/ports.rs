use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use crate::UserId;

/// A single deployment record for BI reporting.
/// Note: `name` is intentionally excluded to avoid exposing user-provided labels (per privacy policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub instance_id: String,
    pub instance_type: String, // openclaw | ironclaw
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Aggregate deployment counts grouped by type and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStatusCount {
    pub instance_type: String,
    pub status: String,
    pub count: i64,
}

/// Summary of deployments over a time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSummary {
    pub total_deployments: i64,
    pub counts_by_type_status: Vec<DeploymentStatusCount>,
    pub new_deployments_in_range: i64,
    pub deleted_in_range: i64,
}

/// A single status change event from the audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusChangeRecord {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub old_status: String,
    pub new_status: String,
    pub changed_at: DateTime<Utc>,
}

/// Grouping dimension for usage aggregation
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    Day,
    User,
    Instance,
    Model,
}

impl fmt::Display for UsageGroupBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageGroupBy::Day => write!(f, "day"),
            UsageGroupBy::User => write!(f, "user"),
            UsageGroupBy::Instance => write!(f, "instance"),
            UsageGroupBy::Model => write!(f, "model"),
        }
    }
}

/// A single row of aggregated usage data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAggregation {
    /// The grouping key value (date string, user_id, instance_id, or model_id)
    pub group_key: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub input_cost_nano: i64,
    pub output_cost_nano: i64,
    pub total_cost_nano: i64,
    pub request_count: i64,
}

/// Ranking dimension for top consumers
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageRankBy {
    Tokens,
    Cost,
}

impl fmt::Display for UsageRankBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageRankBy::Tokens => write!(f, "tokens"),
            UsageRankBy::Cost => write!(f, "cost"),
        }
    }
}

/// Grouping dimension for top consumers
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TopConsumerGroupBy {
    User,
    Instance,
}

impl fmt::Display for TopConsumerGroupBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TopConsumerGroupBy::User => write!(f, "user"),
            TopConsumerGroupBy::Instance => write!(f, "instance"),
        }
    }
}

/// A top consumer entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopConsumer {
    /// user_id or instance_id depending on group_by
    pub id: String,
    pub instance_type: Option<String>,
    pub total_tokens: i64,
    pub total_cost_nano: i64,
    pub request_count: i64,
}

/// Filter parameters for deployment queries
#[derive(Debug, Clone, Default)]
pub struct DeploymentFilter {
    pub instance_type: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

/// Filter parameters for usage queries
#[derive(Debug, Clone)]
pub struct UsageFilter {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub user_id: Option<UserId>,
    pub instance_id: Option<Uuid>,
    pub instance_type: Option<String>,
    pub group_by: UsageGroupBy,
    pub limit: i64,
}

/// Filter parameters for top consumer queries
#[derive(Debug, Clone)]
pub struct TopConsumerFilter {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub instance_type: Option<String>,
    pub rank_by: UsageRankBy,
    pub group_by: TopConsumerGroupBy,
    pub limit: i64,
}

/// Repository trait for BI metrics queries
#[async_trait]
pub trait BiMetricsRepository: Send + Sync {
    /// List deployments with optional filters
    async fn list_deployments(
        &self,
        filter: &DeploymentFilter,
    ) -> anyhow::Result<(Vec<DeploymentRecord>, i64)>;

    /// Get deployment summary counts
    async fn get_deployment_summary(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<DeploymentSummary>;

    /// Get status change history for a specific instance
    async fn get_status_history(
        &self,
        instance_id: Uuid,
        limit: i64,
    ) -> anyhow::Result<Vec<StatusChangeRecord>>;

    /// Get aggregated usage data
    async fn get_usage_aggregation(
        &self,
        filter: &UsageFilter,
    ) -> anyhow::Result<Vec<UsageAggregation>>;

    /// Get top consumers ranked by tokens or cost
    async fn get_top_consumers(
        &self,
        filter: &TopConsumerFilter,
    ) -> anyhow::Result<Vec<TopConsumer>>;
}

/// Service trait for BI metrics
#[async_trait]
pub trait BiMetricsService: Send + Sync {
    async fn list_deployments(
        &self,
        filter: &DeploymentFilter,
    ) -> anyhow::Result<(Vec<DeploymentRecord>, i64)>;

    async fn get_deployment_summary(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> anyhow::Result<DeploymentSummary>;

    async fn get_status_history(
        &self,
        instance_id: Uuid,
        limit: i64,
    ) -> anyhow::Result<Vec<StatusChangeRecord>>;

    async fn get_usage_aggregation(
        &self,
        filter: &UsageFilter,
    ) -> anyhow::Result<Vec<UsageAggregation>>;

    async fn get_top_consumers(
        &self,
        filter: &TopConsumerFilter,
    ) -> anyhow::Result<Vec<TopConsumer>>;
}
