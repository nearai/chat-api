use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::UserId;

/// Per-user usage aggregate (all-time token sum, image count, and cost sum).
#[derive(Debug, Clone)]
pub struct UserUsageSummary {
    pub user_id: UserId,
    pub token_sum: i64,
    /// Sum of quantity for image.generate + image.edit (image count).
    pub image_num: i64,
    pub cost_nano_usd: i64,
}

/// Rank order for top usage listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageRankBy {
    Token,
    Cost,
}

/// Metric keys for user_usage_event (matches DB constraint).
pub const METRIC_KEY_LLM_TOKENS: &str = "llm.tokens";
pub const METRIC_KEY_IMAGE_GENERATE: &str = "image.generate";
pub const METRIC_KEY_IMAGE_EDIT: &str = "image.edit";

/// Parameters for recording a usage event with optional agent-specific fields.
#[derive(Debug, Clone)]
pub struct RecordUsageParams {
    pub user_id: UserId,
    pub metric_key: String,
    pub quantity: i64,
    pub cost_nano_usd: Option<i64>,
    pub model_id: Option<String>,
    pub instance_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
}

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

    /// Record a usage event with all fields (including agent-specific columns).
    async fn record_usage(&self, params: RecordUsageParams) -> anyhow::Result<()>;

    /// Record usage and update agent_balance atomically in a single transaction.
    async fn record_usage_and_update_balance(
        &self,
        params: RecordUsageParams,
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

    /// Usage for a single user (token sum, image count, cost).
    /// When start/end are Some, only events with created_at in [start, end) are included.
    /// When both are None, returns all-time usage.
    async fn get_usage_by_user_id(
        &self,
        user_id: UserId,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Option<UserUsageSummary>>;

    /// Top N users by usage, ordered by token_sum or cost_nano_usd.
    /// When start/end are Some, only events with created_at in [start, end) are included.
    async fn get_top_users_usage(
        &self,
        limit: i64,
        rank_by: UsageRankBy,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Vec<UserUsageSummary>>;
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

    /// Record a usage event with all fields (including agent-specific columns).
    async fn record_usage(&self, params: RecordUsageParams) -> anyhow::Result<()>;

    /// Record usage and update agent_balance atomically in a single transaction.
    async fn record_usage_and_update_balance(
        &self,
        params: RecordUsageParams,
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

    /// Usage for a single user. When start/end are Some, filters to [start, end). When both None, all-time.
    async fn get_usage_by_user_id(
        &self,
        user_id: UserId,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Option<UserUsageSummary>>;

    /// Top N users by usage, ordered by token or cost. Optional [start, end) time range.
    async fn get_top_users_usage(
        &self,
        limit: i64,
        rank_by: UsageRankBy,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Vec<UserUsageSummary>>;
}
