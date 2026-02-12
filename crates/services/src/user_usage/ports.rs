use async_trait::async_trait;
use chrono::Duration;

use crate::UserId;

/// Metric keys for user_usage_event (matches DB constraint).
pub const METRIC_KEY_LLM_TOKENS: &str = "llm.tokens";
pub const METRIC_KEY_IMAGE_GENERATE: &str = "image.generate";
pub const METRIC_KEY_IMAGE_EDIT: &str = "image.edit";

/// Repository interface for per-user usage events (tokens, images, cost).
#[async_trait]
pub trait UserUsageRepository: Send + Sync {
    /// Record a usage event for rate limiting / billing.
    async fn record_usage_event(
        &self,
        user_id: UserId,
        metric_key: &str,
        quantity: i64,
        cost_nano_usd: Option<i64>,
        model_id: Option<&str>,
    ) -> anyhow::Result<()>;

    /// Sum of quantity for llm.tokens in the sliding window.
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

/// Service interface for per-user usage events.
#[async_trait]
pub trait UserUsageService: Send + Sync {
    async fn record_usage_event(
        &self,
        user_id: UserId,
        metric_key: &str,
        quantity: i64,
        cost_nano_usd: Option<i64>,
        model_id: Option<&str>,
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
