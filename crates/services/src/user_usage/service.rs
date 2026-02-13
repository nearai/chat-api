use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;

use crate::UserId;

use super::ports::{UserUsageRepository, UserUsageService};

/// Default implementation of `UserUsageService` backed by a `UserUsageRepository`.
///
/// This implementation always holds a trait object repository (`Arc<dyn UserUsageRepository>`),
/// which keeps the service type simple to use from API code.
pub struct UserUsageServiceImpl {
    repo: Arc<dyn UserUsageRepository>,
}

impl UserUsageServiceImpl {
    pub fn new(repo: Arc<dyn UserUsageRepository>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl UserUsageService for UserUsageServiceImpl {
    async fn record_usage_event(
        &self,
        user_id: UserId,
        metric_key: &str,
        quantity: i64,
        cost_nano_usd: Option<i64>,
        model_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.repo
            .record_usage_event(user_id, metric_key, quantity, cost_nano_usd, model_id)
            .await
    }

    async fn get_token_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64> {
        self.repo
            .get_token_usage_sum(user_id, window_duration)
            .await
    }

    async fn get_cost_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64> {
        self.repo.get_cost_usage_sum(user_id, window_duration).await
    }

    async fn get_usage_by_user_id(
        &self,
        user_id: UserId,
    ) -> anyhow::Result<Option<super::ports::UserUsageSummary>> {
        self.repo.get_usage_by_user_id(user_id).await
    }

    async fn get_top_users_usage(
        &self,
        limit: i64,
        rank_by: super::ports::UsageRankBy,
    ) -> anyhow::Result<Vec<super::ports::UserUsageSummary>> {
        self.repo.get_top_users_usage(limit, rank_by).await
    }
}
