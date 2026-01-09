//! Analytics service for tracking and querying user engagement metrics.
//!
//! This module provides database-backed analytics for tracking user signups,
//! logins, activity, and engagement metrics.

pub mod ports;

pub use ports::*;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use std::sync::Arc;

use crate::UserId;

/// Analytics service trait
#[async_trait]
pub trait AnalyticsServiceTrait: Send + Sync {
    /// Record a user activity
    async fn record_activity(&self, request: RecordActivityRequest) -> Result<(), AnalyticsError>;

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

#[async_trait]
impl DailyUsageStore for AnalyticsServiceImpl {
    async fn record_daily_usage(
        &self,
        request: RecordDailyUsageRequest,
    ) -> Result<(), AnalyticsError> {
        self.repository
            .record_daily_usage(request)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn get_user_daily_usage(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
    ) -> Result<DailyUsageSnapshot, AnalyticsError> {
        self.repository
            .get_user_daily_usage(user_id, usage_date)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }

    async fn increment_daily_usage_if_below_limit(
        &self,
        user_id: UserId,
        usage_date: NaiveDate,
        limit: i64,
    ) -> Result<(i64, bool), AnalyticsError> {
        self.repository
            .increment_daily_usage_if_below_limit(user_id, usage_date, limit)
            .await
            .map_err(|e| AnalyticsError::InternalError(e.to_string()))
    }
}
