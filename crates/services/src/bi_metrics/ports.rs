use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::user::ports::User;
use crate::UserId;

// ---- BI user list types (used only by GET /v1/admin/bi/users) ----

/// User with BI stats (subscription, agent count, spending, etc.)
#[derive(Debug, Clone)]
pub struct UserWithStats {
    pub user: User,
    pub subscription_status: Option<String>,
    pub subscription_price_id: Option<String>,
    pub agent_count: i64,
    pub total_spent_nano: i64,
    pub agent_spent_nano: i64,
    pub agent_token_usage: i64,
    pub last_activity_at: Option<DateTime<Utc>>,
    /// Total purchased+granted credits (nano-USD), from user_credits.total_nano_usd.
    pub purchased_credits_nano: i64,
    /// Spent portion of purchased credits (nano-USD), from user_credits.spent_nano_usd.
    /// Remaining = purchased_credits_nano - spent_purchased_credits_nano.
    pub spent_purchased_credits_nano: i64,
}

/// Filter for BI user list
#[derive(Debug, Clone, Default)]
pub struct ListUsersFilter {
    /// Filter by subscription status: "active", "trialing", or "none" for no subscription
    pub subscription_status: Option<String>,
    /// Filter by subscription plan name (e.g. "Pro", "Starter") or "none" for no subscription.
    /// Requires price_ids resolved from system config.
    pub subscription_plan_price_ids: Option<Vec<String>>,
    /// Filter by subscription plan = none (no subscription)
    pub subscription_plan_none: bool,
    /// Substring search on email and name (case-insensitive)
    pub search: Option<String>,
}

/// Sort options for BI user list
#[derive(Debug, Clone)]
pub struct ListUsersSort {
    pub sort_by: UsersSortBy,
    pub sort_order: UsersSortOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsersSortBy {
    CreatedAt,
    TotalSpentNano,
    AgentSpentNano,
    AgentTokenUsage,
    LastActivityAt,
    AgentCount,
    Email,
    Name,
    PurchasedCreditsNano,
    SpentPurchasedCreditsNano,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsersSortOrder {
    Asc,
    Desc,
}

impl Default for ListUsersSort {
    fn default() -> Self {
        Self {
            sort_by: UsersSortBy::CreatedAt,
            sort_order: UsersSortOrder::Desc,
        }
    }
}

// ---- BI metrics types ----

/// A single deployment record for BI reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DeploymentRecord {
    pub id: Uuid,
    pub user_id: UserId,
    /// User email from users table (for display in admin UI)
    pub user_email: Option<String>,
    /// User name from users table (for display in admin UI)
    pub user_name: Option<String>,
    /// User avatar URL from users table (for display in admin UI)
    pub user_avatar_url: Option<String>,
    /// Agent instance name (user-provided label). Exposed in BI for admin UI display; product decision to show for support and operations.
    pub name: Option<String>,
    pub instance_id: String,
    pub instance_type: String, // openclaw | ironclaw
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Total spend for this instance (nano USD) from usage events
    pub total_spent_nano: i64,
    /// Total tokens used for this instance from usage events
    pub total_tokens: i64,
}

/// Aggregate deployment counts grouped by type and status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DeploymentStatusCount {
    pub instance_type: String,
    pub status: String,
    pub count: i64,
}

/// Summary of deployments over a time range
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DeploymentSummary {
    pub total_deployments: i64,
    pub counts_by_type_status: Vec<DeploymentStatusCount>,
    pub new_deployments_in_range: i64,
    pub deleted_in_range: i64,
}

/// User count per subscription plan (plan name from system config, or "none")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UserSummaryPlanCount {
    pub plan: String,
    pub user_count: i64,
}

/// User count per agent count bucket (deployed agents = non-deleted instances)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UserSummaryAgentCountBucket {
    pub agent_count: i64,
    pub user_count: i64,
}

/// User distribution summary: counts by subscription plan and by deployed agent count
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UserSummary {
    pub by_subscription_plan: Vec<UserSummaryPlanCount>,
    pub by_agent_count: Vec<UserSummaryAgentCountBucket>,
}

/// A single status change event from the audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct StatusChangeRecord {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub old_status: String,
    pub new_status: String,
    /// User ID that initiated the change when known (null for system events).
    pub changed_by_user_id: Option<UserId>,
    /// User display name (or email fallback) for admin UI display.
    pub changed_by_user_name: Option<String>,
    /// User avatar URL for admin UI display when available.
    pub changed_by_user_avatar_url: Option<String>,
    /// Optional audit reason attached to the status change.
    pub change_reason: Option<String>,
    pub changed_at: DateTime<Utc>,
}

/// Grouping dimension for usage aggregation
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UsageAggregation {
    /// The grouping key value (date string, user_id, instance_id, or model_id)
    pub group_key: String,
    /// User email when group_by is user or instance (from users table)
    pub user_email: Option<String>,
    /// User name when group_by is user or instance (from users table)
    pub user_name: Option<String>,
    /// User avatar URL when group_by is user or instance (from users table)
    pub user_avatar_url: Option<String>,
    /// Agent type (openclaw/ironclaw) when group_by is instance
    pub instance_type: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub input_cost_nano: i64,
    pub output_cost_nano: i64,
    pub total_cost_nano: i64,
    pub request_count: i64,
    /// Count of distinct agent instances with usage (quantity > 0 or cost > 0) in this group. Present when group_by is day, model, or user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_agents_count: Option<i64>,
    /// Count of distinct users with usage in this group. Present when group_by is day or model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_users_count: Option<i64>,
}

/// Ranking dimension for top consumers
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TopConsumer {
    /// user_id or instance_id depending on group_by
    pub id: String,
    pub instance_type: Option<String>,
    /// User email when group_by is user, or instance owner when group_by is instance
    pub user_email: Option<String>,
    /// User name when group_by is user, or instance owner when group_by is instance
    pub user_name: Option<String>,
    /// User avatar URL when group_by is user, or instance owner when group_by is instance
    pub user_avatar_url: Option<String>,
    pub total_tokens: i64,
    pub total_cost_nano: i64,
    pub request_count: i64,
}

/// Sort field for deployment list
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum DeploymentsSortBy {
    #[default]
    CreatedAt,
    UpdatedAt,
    InstanceType,
    Status,
    UserEmail,
    UserName,
    Name,
    TotalSpentNano,
    TotalTokens,
}

impl FromStr for DeploymentsSortBy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created_at" => Ok(DeploymentsSortBy::CreatedAt),
            "updated_at" => Ok(DeploymentsSortBy::UpdatedAt),
            "instance_type" => Ok(DeploymentsSortBy::InstanceType),
            "status" => Ok(DeploymentsSortBy::Status),
            "user_email" => Ok(DeploymentsSortBy::UserEmail),
            "user_name" => Ok(DeploymentsSortBy::UserName),
            "name" => Ok(DeploymentsSortBy::Name),
            "total_spent_nano" => Ok(DeploymentsSortBy::TotalSpentNano),
            "total_tokens" => Ok(DeploymentsSortBy::TotalTokens),
            _ => Err(()),
        }
    }
}

/// Sort order for deployment list
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum DeploymentsSortOrder {
    Asc,
    #[default]
    Desc,
}

/// Filter parameters for deployment queries
#[derive(Debug, Clone)]
pub struct DeploymentFilter {
    pub instance_type: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub sort_by: DeploymentsSortBy,
    pub sort_order: DeploymentsSortOrder,
    pub limit: i64,
    pub offset: i64,
}

impl Default for DeploymentFilter {
    fn default() -> Self {
        Self {
            instance_type: None,
            status: None,
            start_date: None,
            end_date: None,
            search: None,
            sort_by: DeploymentsSortBy::default(),
            sort_order: DeploymentsSortOrder::default(),
            limit: 20,
            offset: 0,
        }
    }
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

    /// User summary: counts by subscription_price_id and by agent_count (raw, no plan name resolution)
    async fn get_user_summary(
        &self,
    ) -> anyhow::Result<(Vec<(Option<String>, i64)>, Vec<(i64, i64)>)>;

    /// List users with BI stats (subscription, agent count, spending). Used by GET /v1/admin/bi/users.
    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &ListUsersFilter,
        sort: &ListUsersSort,
    ) -> anyhow::Result<(Vec<UserWithStats>, u64)>;
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

    /// User distribution by subscription plan and by deployed agent count
    async fn get_user_summary(&self) -> anyhow::Result<UserSummary>;

    /// List users with BI stats. Used by GET /v1/admin/bi/users.
    async fn list_users_with_stats(
        &self,
        limit: i64,
        offset: i64,
        filter: &ListUsersFilter,
        sort: &ListUsersSort,
    ) -> anyhow::Result<(Vec<UserWithStats>, u64)>;
}
