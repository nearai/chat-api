//! Analytics repository traits and data structures.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::UserId;

/// Activity types tracked in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    Login,
    Signup,
    Response,
    Conversation,
    FileUpload,
}

impl ActivityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivityType::Login => "login",
            ActivityType::Signup => "signup",
            ActivityType::Response => "response",
            ActivityType::Conversation => "conversation",
            ActivityType::FileUpload => "file_upload",
        }
    }
}

impl std::fmt::Display for ActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Google,
    Github,
    Near,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Google => "google",
            AuthMethod::Github => "github",
            AuthMethod::Near => "near",
        }
    }
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Request to record a user activity
#[derive(Debug, Clone)]
pub struct RecordActivityRequest {
    pub user_id: UserId,
    pub activity_type: ActivityType,
    pub auth_method: Option<AuthMethod>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to increment a user's daily usage counts
#[derive(Debug, Clone)]
pub struct RecordDailyUsageRequest {
    pub user_id: UserId,
    pub usage_date: NaiveDate,
    pub request_increment: i64,
    pub token_increment: Option<i64>,
}

/// A single activity log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ActivityLogEntry {
    pub id: Uuid,
    pub user_id: UserId,
    pub activity_type: String,
    pub auth_method: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Summary of user metrics for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UserMetricsSummary {
    pub total_users: i64,
    pub new_users: i64,
    pub active_users: i64,
    pub total_logins: i64,
    pub total_signups: i64,
}

/// Breakdown of users by authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuthMethodBreakdown {
    pub auth_method: String,
    pub user_count: i64,
    pub login_count: i64,
    pub signup_count: i64,
}

/// Activity metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ActivityMetricsSummary {
    pub total_responses: i64,
    pub total_conversations: i64,
    pub total_file_uploads: i64,
}

/// Complete analytics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AnalyticsSummary {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub user_metrics: UserMetricsSummary,
    pub activity_metrics: ActivityMetricsSummary,
    pub by_auth_method: Vec<AuthMethodBreakdown>,
}

/// Snapshot of a user's usage for a single day.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DailyUsageSnapshot {
    pub user_id: UserId,
    pub usage_date: NaiveDate,
    pub request_count: i64,
    pub token_count: i64,
    pub updated_at: DateTime<Utc>,
}

impl DailyUsageSnapshot {
    pub fn zero(user_id: UserId, usage_date: NaiveDate) -> Self {
        Self {
            user_id,
            usage_date,
            request_count: 0,
            token_count: 0,
            updated_at: Utc::now(),
        }
    }
}

/// A user with their activity count (for top users query)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TopActiveUser {
    pub user_id: UserId,
    pub email: String,
    pub activity_count: i64,
    pub last_active: DateTime<Utc>,
}

/// Response for top active users query
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TopActiveUsersResponse {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub users: Vec<TopActiveUser>,
}

/// Repository trait for analytics operations
#[async_trait]
pub trait AnalyticsRepository: Send + Sync {
    /// Record a user activity
    async fn record_activity(&self, request: RecordActivityRequest) -> anyhow::Result<()>;

    /// Get analytics summary for a time period
    async fn get_analytics_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<AnalyticsSummary>;

    /// Get daily active users count
    async fn get_daily_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64>;

    /// Get weekly active users count (last 7 days from date)
    async fn get_weekly_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64>;

    /// Get monthly active users count (last 30 days from date)
    async fn get_monthly_active_users(&self, date: DateTime<Utc>) -> anyhow::Result<i64>;

    /// Get activity history for a user
    async fn get_user_activity(
        &self,
        user_id: UserId,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> anyhow::Result<Vec<ActivityLogEntry>>;

    /// Get top active users in a time period
    async fn get_top_active_users(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
    ) -> anyhow::Result<Vec<TopActiveUser>>;

    /// Increment a user's daily usage tally
    async fn record_daily_usage(&self, request: RecordDailyUsageRequest) -> anyhow::Result<()>;

    /// Read a user's usage totals for a specific day
    async fn get_user_daily_usage(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
    ) -> anyhow::Result<DailyUsageSnapshot>;
}

/// Error types for analytics operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum AnalyticsError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Thin trait for services like rate limiting that need daily usage counts.
#[async_trait]
pub trait DailyUsageStore: Send + Sync {
    async fn record_daily_usage(
        &self,
        request: RecordDailyUsageRequest,
    ) -> Result<(), AnalyticsError>;

    async fn get_user_daily_usage(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
    ) -> Result<DailyUsageSnapshot, AnalyticsError>;
}
