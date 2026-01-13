//! Analytics service for tracking and querying user engagement metrics.
//!
//! This module provides database-backed analytics for tracking user signups,
//! logins, activity, and engagement metrics.

pub mod ports;

pub use ports::*;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::UserId;

/// Analytics service trait
#[async_trait]
pub trait AnalyticsServiceTrait: Send + Sync {
    /// Record a user activity
    async fn record_activity(&self, request: RecordActivityRequest) -> Result<(), AnalyticsError>;

    /// Atomically check if usage is below limit and record activity if allowed.
    ///
    /// This method:
    /// 1. Counts activities of the specified type in the sliding window
    /// 2. If below limit, inserts a new activity log entry
    /// 3. Returns the current count after the attempt and whether the activity was recorded
    ///
    /// Returns: (current_count, was_recorded)
    async fn check_and_record_activity(
        &self,
        user_id: UserId,
        activity_type: ActivityType,
        window: TimeWindow,
        limit: i64,
        metadata: Option<serde_json::Value>,
    ) -> Result<(i64, bool), AnalyticsError>;

    /// Get analytics summary for a time period
    async fn get_analytics_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<AnalyticsSummary, AnalyticsError>;

    /// Get daily active users count
    async fn get_daily_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError>;

    /// Get weekly active users count
    async fn get_weekly_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError>;

    /// Get monthly active users count
    async fn get_monthly_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError>;

    /// Get activity history for a user
    async fn get_user_activity(
        &self,
        user_id: UserId,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ActivityLogEntry>, AnalyticsError>;

    /// Get top active users in a time period
    async fn get_top_active_users(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopActiveUser>, AnalyticsError>;
}

/// Analytics service implementation
pub struct AnalyticsServiceImpl {
    repository: Arc<dyn AnalyticsRepository>,
}

impl AnalyticsServiceImpl {
    pub fn new(repository: Arc<dyn AnalyticsRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl AnalyticsServiceTrait for AnalyticsServiceImpl {
    async fn record_activity(&self, request: RecordActivityRequest) -> Result<(), AnalyticsError> {
        self.repository
            .record_activity(request)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn check_and_record_activity(
        &self,
        user_id: UserId,
        activity_type: ActivityType,
        window: TimeWindow,
        limit: i64,
        metadata: Option<serde_json::Value>,
    ) -> Result<(i64, bool), AnalyticsError> {
        self.repository
            .check_and_record_activity(user_id, activity_type, window, limit, metadata)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_analytics_summary(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<AnalyticsSummary, AnalyticsError> {
        self.repository
            .get_analytics_summary(start, end)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_daily_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError> {
        self.repository
            .get_daily_active_users(date)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_weekly_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError> {
        self.repository
            .get_weekly_active_users(date)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_monthly_active_users(&self, date: DateTime<Utc>) -> Result<i64, AnalyticsError> {
        self.repository
            .get_monthly_active_users(date)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_user_activity(
        &self,
        user_id: UserId,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ActivityLogEntry>, AnalyticsError> {
        self.repository
            .get_user_activity(user_id, limit, offset)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_top_active_users(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<TopActiveUser>, AnalyticsError> {
        self.repository
            .get_top_active_users(start, end, limit)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }
}
