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
    async fn record_user_usage(
        &self,
        user_id: UserId,
        tokens_used: u64,
        cost_nano_usd: Option<i64>,
    ) -> anyhow::Result<()> {
        self.repo
            .record_user_usage(user_id, tokens_used, cost_nano_usd)
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
}
