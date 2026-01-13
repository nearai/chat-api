//! Analytics repository traits and data structures.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    /// Activity type specifically for rate limiting purposes.
    /// This is used to track requests for quota/rate limit enforcement,
    /// separate from business analytics (which use Response, Conversation, etc.).
    RateLimitedRequest,
}

impl ActivityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivityType::Login => "login",
            ActivityType::Signup => "signup",
            ActivityType::Response => "response",
            ActivityType::Conversation => "conversation",
            ActivityType::FileUpload => "file_upload",
            ActivityType::RateLimitedRequest => "rate_limited_request",
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

/// Request to check usage limit and record activity if allowed
#[derive(Debug, Clone)]
pub struct CheckAndRecordActivityRequest {
    /// User ID for the activity
    pub user_id: UserId,
    /// Type of activity to check and record
    pub activity_type: ActivityType,
    /// Optional metadata for the activity
    pub metadata: Option<serde_json::Value>,
    /// Time window for the sliding window rate limit
    pub window: TimeWindow,
    /// Maximum number of activities allowed in the window
    pub limit: i64,
}

/// Result of checking and recording activity
#[derive(Debug, Clone)]
pub struct CheckAndRecordActivityResult {
    /// Current count of activities in the window after the check
    pub current_count: i64,
    /// Whether the activity was actually recorded (inserted into the database)
    pub was_recorded: bool,
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

    /// Check if usage is below limit and record activity if allowed.
    async fn check_and_record_activity(
        &self,
        request: CheckAndRecordActivityRequest,
    ) -> anyhow::Result<CheckAndRecordActivityResult>;

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
}

/// Error types for analytics operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum AnalyticsError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Time window for sliding window rate limiting (in days)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Number of days for the sliding window
    pub days: i32,
}

impl TimeWindow {
    /// Create a time window with specified number of days
    pub fn new(days: i32) -> Self {
        Self { days }
    }

    /// Day window (1 day)
    pub fn day() -> Self {
        Self { days: 1 }
    }

    /// Week window (7 days)
    pub fn week() -> Self {
        Self { days: 7 }
    }

    /// Month window (30 days)
    pub fn month() -> Self {
        Self { days: 30 }
    }
}
