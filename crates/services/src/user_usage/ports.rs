use async_trait::async_trait;
use chrono::Duration;

use crate::UserId;

/// Repository interface for per-user token and cost usage.
#[async_trait]
pub trait UserUsageRepository: Send + Sync {
    /// Record token and optional cost usage for a user (for rate limiting / billing).
    async fn record_user_usage(
        &self,
        user_id: UserId,
        tokens_used: u64,
        cost_nano_usd: Option<i64>,
    ) -> anyhow::Result<()>;

    /// Sum of tokens_used for the user in the sliding window.
    async fn get_token_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64>;

    /// Sum of cost_nano_usd for the user in the sliding window (NULL treated as 0).
    async fn get_cost_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64>;
}

/// Service interface for per-user token and cost usage.
#[async_trait]
pub trait UserUsageService: Send + Sync {
    async fn record_user_usage(
        &self,
        user_id: UserId,
        tokens_used: u64,
        cost_nano_usd: Option<i64>,
    ) -> anyhow::Result<()>;

    async fn get_token_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64>;

    async fn get_cost_usage_sum(
        &self,
        user_id: UserId,
        window_duration: Duration,
    ) -> anyhow::Result<i64>;
}
