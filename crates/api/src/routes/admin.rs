use super::is_valid_service_type;
use crate::{
    consts::LIST_USERS_LIMIT_MAX, error::ApiError, middleware::AuthenticatedUser, models::*,
    state::AppState,
};
use axum::routing::post;
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Response,
    routing::{delete, get},
    Json, Router,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityLogEntry, AnalyticsSummary, TopActiveUsersResponse};
use services::bi_metrics::{
    DeploymentFilter, DeploymentRecord, DeploymentSummary, StatusChangeRecord, TopConsumer,
    TopConsumerFilter, TopConsumerGroupBy, UsageAggregation, UsageFilter, UsageGroupBy,
    UsageRankBy as BiUsageRankBy,
};

/// Maximum rows for BI usage aggregation queries.
const BI_USAGE_MAX_ROWS: i64 = 1000;
use services::model::ports::{UpdateModelParams, UpsertModelParams};
use services::user_usage::UsageRankBy;
use services::UserId;
use std::collections::HashMap;
use urlencoding::encode;
use uuid::Uuid;

/// Pagination query parameters
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Maximum number of items to return (default: 20, max: LIMIT_MAX)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl PaginationQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.limit < 1 {
            return Err(ApiError::bad_request(
                "limit is less than minimum value of 1",
            ));
        }

        if self.limit > LIST_USERS_LIMIT_MAX {
            return Err(ApiError::bad_request(format!(
                "limit exceeds maximum value of {}",
                LIST_USERS_LIMIT_MAX
            )));
        }

        if self.offset < 0 {
            return Err(ApiError::bad_request("offset cannot be negative"));
        }

        Ok(())
    }
}

fn default_limit() -> i64 {
    20
}

fn default_offset() -> i64 {
    0
}

/// Query parameters for admin list users (with filter and sort)
#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default = "default_offset")]
    pub offset: i64,
    /// Filter type: "subscription_status" or "subscription_plan"
    pub filter_by: Option<String>,
    /// Filter value. For subscription_status: active, canceled, past_due, none. For subscription_plan: plan name or none
    pub filter_value: Option<String>,
    /// Substring search on email and name (case-insensitive)
    pub q: Option<String>,
    /// Sort by: created_at, total_spent_nano, agent_spent_nano, agent_token_usage, last_activity_at, agent_count, email, name
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    /// Sort order: asc or desc
    #[serde(default = "default_sort_order")]
    pub sort_order: String,
}

fn default_sort_by() -> String {
    "created_at".to_string()
}

fn default_sort_order() -> String {
    "desc".to_string()
}

impl ListUsersQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        PaginationQuery {
            limit: self.limit,
            offset: self.offset,
        }
        .validate()?;

        if let (Some(ref fb), Some(ref fv)) = (&self.filter_by, &self.filter_value) {
            let fb = fb.trim();
            let fv = fv.trim();
            if !fb.is_empty() && !fv.is_empty() {
                match fb {
                    "subscription_status" => {
                        if ![
                            "active", "canceled", "past_due", "trialing", "unpaid", "none",
                        ]
                        .contains(&fv)
                        {
                            return Err(ApiError::bad_request(format!(
                                "invalid filter_value for subscription_status: {}",
                                fv
                            )));
                        }
                    }
                    "subscription_plan" => {
                        // Any non-empty value is ok (plan name or "none")
                    }
                    _ => {
                        return Err(ApiError::bad_request(format!(
                            "invalid filter_by: {}, must be subscription_status or subscription_plan",
                            fb
                        )));
                    }
                }
            }
        }

        if let Some(ref q) = self.q {
            if !q.trim().is_empty() && q.len() > 200 {
                return Err(ApiError::bad_request(
                    "search query exceeds maximum length of 200",
                ));
            }
        }

        let valid_sort_by = [
            "created_at",
            "total_spent_nano",
            "agent_spent_nano",
            "agent_token_usage",
            "last_activity_at",
            "agent_count",
            "email",
            "name",
        ];
        if !valid_sort_by.contains(&self.sort_by.as_str()) {
            return Err(ApiError::bad_request(format!(
                "invalid sort_by: {}, must be one of {:?}",
                self.sort_by, valid_sort_by
            )));
        }

        if self.sort_order != "asc" && self.sort_order != "desc" {
            return Err(ApiError::bad_request(format!(
                "invalid sort_order: {}, must be asc or desc",
                self.sort_order
            )));
        }

        Ok(())
    }
}

/// List users
///
/// Returns a paginated list of users. Requires admin authentication.
/// For user stats (subscription, agent count, spending, etc.) use /v1/admin/bi/users.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "Admin",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of items to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)")
    ),
    responses(
        (status = 200, description = "User list retrieved", body = UserListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_users(
    State(app_state): State<AppState>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<UserListResponse>, ApiError> {
    tracing::info!(
        "Listing users with limit={}, offset={}",
        params.limit,
        params.offset
    );

    params.validate()?;

    let (users, total) = app_state
        .user_service
        .list_users(params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    Ok(Json(UserListResponse {
        users: users.into_iter().map(Into::into).collect(),
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Implementation used by bi_list_users only (BI endpoint).
async fn list_users_bi_impl(
    app_state: &AppState,
    params: ListUsersQuery,
) -> Result<Json<AdminUserListResponse>, ApiError> {
    params.validate()?;

    let price_to_plan = build_price_id_to_plan_name(app_state).await?;
    // Build plan_name (lowercase for case-insensitive lookup) -> price_ids
    let plan_to_prices: std::collections::HashMap<String, Vec<String>> =
        price_to_plan
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, (pid, name)| {
                acc.entry(name.to_lowercase())
                    .or_default()
                    .push(pid.clone());
                acc
            });

    let (subscription_plan_price_ids, subscription_plan_none, subscription_status) = params
        .filter_by
        .as_ref()
        .zip(params.filter_value.as_ref())
        .map(|(fb, fv)| (fb.trim(), fv.trim()))
        .filter(|(fb, fv)| !fb.is_empty() && !fv.is_empty())
        .map(|(fb, fv)| {
            if fb.eq_ignore_ascii_case("subscription_status") {
                (None, false, Some(fv.to_string()))
            } else if fb.eq_ignore_ascii_case("subscription_plan") {
                if fv.eq_ignore_ascii_case("none") {
                    tracing::debug!("filter: subscription_plan=none (no subscription)");
                    (None, true, None)
                } else {
                    let price_ids = plan_to_prices
                        .get(&fv.to_lowercase())
                        .cloned()
                        .unwrap_or_default();
                    if price_ids.is_empty() {
                        tracing::warn!(
                            "filter: plan {:?} not found in system config (available: {:?}). Returning no users.",
                            fv,
                            plan_to_prices.keys().collect::<Vec<_>>()
                        );
                    } else {
                        tracing::debug!(
                            "filter: subscription_plan={:?} -> {} price_id(s): {:?}",
                            fv,
                            price_ids.len(),
                            price_ids
                        );
                    }
                    (Some(price_ids), false, None)
                }
            } else {
                (None, false, None)
            }
        })
        .unwrap_or((None, false, None));

    let filter = services::user::ports::AdminListUsersFilter {
        subscription_status,
        subscription_plan_price_ids,
        subscription_plan_none,
        search: params.q.as_ref().and_then(|q| {
            let t = q.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }),
    };

    let sort = services::user::ports::AdminListUsersSort {
        sort_by: match params.sort_by.as_str() {
            "created_at" => services::user::ports::AdminUsersSortBy::CreatedAt,
            "total_spent_nano" => services::user::ports::AdminUsersSortBy::TotalSpentNano,
            "agent_spent_nano" => services::user::ports::AdminUsersSortBy::AgentSpentNano,
            "agent_token_usage" => services::user::ports::AdminUsersSortBy::AgentTokenUsage,
            "last_activity_at" => services::user::ports::AdminUsersSortBy::LastActivityAt,
            "agent_count" => services::user::ports::AdminUsersSortBy::AgentCount,
            "email" => services::user::ports::AdminUsersSortBy::Email,
            "name" => services::user::ports::AdminUsersSortBy::Name,
            _ => services::user::ports::AdminUsersSortBy::CreatedAt,
        },
        sort_order: if params.sort_order == "asc" {
            services::user::ports::AdminUsersSortOrder::Asc
        } else {
            services::user::ports::AdminUsersSortOrder::Desc
        },
    };

    let (users, total) = app_state
        .user_service
        .list_users_with_stats(params.limit, params.offset, &filter, &sort)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list users: {}", e);
            ApiError::internal_server_error("Failed to list users")
        })?;

    let price_to_plan = build_price_id_to_plan_name(app_state).await?;

    let users: Vec<_> = users
        .into_iter()
        .map(|u| {
            let plan_name = u
                .subscription_price_id
                .as_ref()
                .and_then(|pid| price_to_plan.get(pid.as_str()).cloned())
                .or_else(|| {
                    if u.subscription_status.is_some() {
                        Some("Unknown".to_string())
                    } else {
                        None
                    }
                });
            AdminUserResponse::from_stats(u, plan_name)
        })
        .collect();

    Ok(Json(AdminUserListResponse {
        users,
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Build price_id -> plan_name map from system config subscription_plans
async fn build_price_id_to_plan_name(
    app_state: &AppState,
) -> Result<HashMap<String, String>, ApiError> {
    let config = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get system configs for plan resolution");
            ApiError::internal_server_error("Failed to resolve subscription plans")
        })?;

    let mut map = HashMap::new();
    if let Some(ref plans) = config.and_then(|c| c.subscription_plans) {
        for (plan_name, plan_config) in plans {
            for provider_config in plan_config.providers.values() {
                map.insert(provider_config.price_id.clone(), plan_name.clone());
            }
        }
    }
    Ok(map)
}

/// Query parameters for analytics endpoint
#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    /// Start of the time period (ISO 8601 timestamp)
    pub start: DateTime<Utc>,
    /// End of the time period (ISO 8601 timestamp)
    pub end: DateTime<Utc>,
}

/// Get analytics summary
///
/// Returns user metrics, activity metrics, and breakdown by auth method for a time period.
/// Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/analytics",
    tag = "Admin",
    params(
        ("start" = DateTime<Utc>, Query, description = "Start of time period (ISO 8601)"),
        ("end" = DateTime<Utc>, Query, description = "End of time period (ISO 8601)")
    ),
    responses(
        (status = 200, description = "Analytics retrieved", body = AnalyticsSummary),
        (status = 400, description = "Bad request - invalid date range", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_analytics(
    State(app_state): State<AppState>,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsSummary>, ApiError> {
    tracing::info!(
        "Getting analytics for period {} to {}",
        params.start,
        params.end
    );

    // Validate date range
    if params.start >= params.end {
        return Err(ApiError::bad_request("start date must be before end date"));
    }

    let analytics = app_state
        .analytics_service
        .get_analytics_summary(params.start, params.end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get analytics: {}", e);
            ApiError::internal_server_error("Failed to retrieve analytics")
        })?;

    Ok(Json(analytics))
}

/// Response for user activity endpoint
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserActivityResponse {
    pub user_id: UserId,
    pub activities: Vec<ActivityLogEntry>,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for top users endpoint
#[derive(Debug, Deserialize)]
pub struct TopUsersQuery {
    /// Start of the time period (ISO 8601 timestamp)
    pub start: DateTime<Utc>,
    /// End of the time period (ISO 8601 timestamp)
    pub end: DateTime<Utc>,
    /// Maximum number of users to return (default: 10)
    #[serde(default = "default_top_users_limit")]
    pub limit: i64,
}

fn default_top_users_limit() -> i64 {
    10
}

/// Get activity history for a specific user
///
/// Returns paginated activity log for a user. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/users/{user_id}/activity",
    tag = "Admin",
    params(
        ("user_id" = UserId, Path, description = "User ID"),
        ("limit" = Option<i64>, Query, description = "Maximum number of activities to return (default: 50)"),
        ("offset" = Option<i64>, Query, description = "Number of activities to skip (default: 0)")
    ),
    responses(
        (status = 200, description = "User activity retrieved", body = UserActivityResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_user_activity(
    State(app_state): State<AppState>,
    Path(user_id): Path<UserId>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<UserActivityResponse>, ApiError> {
    tracing::info!(
        "Getting activity for user {} with limit={}, offset={}",
        user_id,
        params.limit,
        params.offset
    );

    let activities = app_state
        .analytics_service
        .get_user_activity(user_id, Some(params.limit), Some(params.offset))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user activity: {}", e);
            ApiError::internal_server_error("Failed to retrieve user activity")
        })?;

    Ok(Json(UserActivityResponse {
        user_id,
        activities,
        limit: params.limit,
        offset: params.offset,
    }))
}

/// Admin endpoint: Set subscription for a user (for testing/manual management)
///
/// Allows admins to directly set a user's subscription without going through Stripe.
/// Useful for testing in production and manual subscription management.
/// Requires admin authentication.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/subscription",
    tag = "Admin",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    request_body = AdminSetSubscriptionRequest,
    responses(
        (status = 200, description = "Subscription set successfully", body = serde_json::Value),
        (status = 400, description = "Bad request - invalid plan or date", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_set_user_subscription(
    State(app_state): State<AppState>,
    Path(user_id): Path<UserId>,
    Json(request): Json<AdminSetSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::info!(
        "Admin: Setting subscription for user_id={}, provider={}, plan={}",
        user_id,
        request.provider,
        request.plan
    );

    // Parse the period end date
    let current_period_end = chrono::DateTime::parse_from_rfc3339(&request.current_period_end)
        .map_err(|_| ApiError::bad_request("Invalid current_period_end format (must be ISO 8601)"))?
        .with_timezone(&chrono::Utc);

    let subscription = app_state
        .subscription_service
        .admin_set_subscription(user_id, request.provider, request.plan, current_period_end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to set subscription for user_id={}: {}", user_id, e);
            match e {
                services::subscription::ports::SubscriptionError::InvalidPlan(msg) => {
                    ApiError::bad_request(msg)
                }
                services::subscription::ports::SubscriptionError::InvalidProvider(msg) => {
                    ApiError::bad_request(msg)
                }
                _ => ApiError::internal_server_error("Failed to set subscription"),
            }
        })?;

    Ok(Json(serde_json::to_value(&subscription).unwrap()))
}

/// Admin endpoint: Cancel all subscriptions for a user
///
/// Removes all subscriptions for a user. Useful for testing and manual management.
/// Requires admin authentication.
#[utoipa::path(
    delete,
    path = "/v1/admin/users/{user_id}/subscription",
    tag = "Admin",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Subscriptions cancelled successfully"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_cancel_user_subscriptions(
    State(app_state): State<AppState>,
    Path(user_id): Path<UserId>,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::info!("Admin: Canceling all subscriptions for user_id={}", user_id);

    app_state
        .subscription_service
        .admin_cancel_user_subscriptions(user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to cancel subscriptions for user_id={}: {}",
                user_id,
                e
            );
            ApiError::internal_server_error("Failed to cancel subscriptions")
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "All subscriptions cancelled"
    })))
}

/// Get top active users
///
/// Returns the most active users in a time period. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/analytics/top-users",
    tag = "Admin",
    params(
        ("start" = DateTime<Utc>, Query, description = "Start of time period (ISO 8601)"),
        ("end" = DateTime<Utc>, Query, description = "End of time period (ISO 8601)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of users to return (default: 10)")
    ),
    responses(
        (status = 200, description = "Top users retrieved", body = TopActiveUsersResponse),
        (status = 400, description = "Bad request - invalid date range", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_top_users(
    State(app_state): State<AppState>,
    Query(params): Query<TopUsersQuery>,
) -> Result<Json<TopActiveUsersResponse>, ApiError> {
    tracing::info!(
        "Getting top {} users for period {} to {}",
        params.limit,
        params.start,
        params.end
    );

    // Validate date range
    if params.start >= params.end {
        return Err(ApiError::bad_request("start date must be before end date"));
    }

    // Validate limit
    if params.limit < 1 || params.limit > 100 {
        return Err(ApiError::bad_request("limit must be between 1 and 100"));
    }

    let users = app_state
        .analytics_service
        .get_top_active_users(params.start, params.end, params.limit)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top users: {}", e);
            ApiError::internal_server_error("Failed to retrieve top users")
        })?;

    Ok(Json(TopActiveUsersResponse {
        period_start: params.start,
        period_end: params.end,
        users,
    }))
}

/// Response for top usage listing.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TopUsageResponse {
    pub users: Vec<crate::models::UserUsageResponse>,
    pub rank_by: String,
}

/// Query parameters for top usage endpoint.
#[derive(Debug, Deserialize)]
pub struct TopUsageQuery {
    /// Rank by "token" or "cost" (default: token)
    #[serde(default = "default_usage_rank_by")]
    pub rank_by: String,
    /// Maximum number of users to return (default: LIST_USERS_LIMIT_MAX)
    #[serde(default = "default_top_usage_limit")]
    pub limit: i64,
    /// Start of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub start: Option<DateTime<Utc>>,
    /// End of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub end: Option<DateTime<Utc>>,
}

fn default_usage_rank_by() -> String {
    "token".to_string()
}

fn default_top_usage_limit() -> i64 {
    LIST_USERS_LIMIT_MAX
}

/// Query parameters for usage by user ID (time range).
#[derive(Debug, Deserialize)]
pub struct UsageByUserQuery {
    /// Start of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub start: Option<DateTime<Utc>>,
    /// End of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub end: Option<DateTime<Utc>>,
}

/// Get usage for a single user by ID (all-time or within time range).
///
/// Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/usage/users/{user_id}",
    tag = "Admin",
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("start" = Option<DateTime<Utc>>, Query, description = "Start of time period (ISO 8601); use with end; interval [start, end)"),
        ("end" = Option<DateTime<Utc>>, Query, description = "End of time period (ISO 8601); use with start; interval [start, end)")
    ),
    responses(
        (status = 200, description = "Usage retrieved", body = crate::models::UserUsageResponse),
        (status = 400, description = "Bad request - start and end must be used together, start must be before end", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User has no usage or not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_usage_by_user_id(
    State(app_state): State<AppState>,
    Path(user_id): Path<UserId>,
    Query(params): Query<UsageByUserQuery>,
) -> Result<Json<UserUsageResponse>, ApiError> {
    let (start, end) = (params.start, params.end);
    if let (Some(s), Some(e)) = (start, end) {
        if s >= e {
            return Err(ApiError::bad_request("start must be before end"));
        }
    } else if start.is_some() || end.is_some() {
        return Err(ApiError::bad_request("start and end must be used together"));
    }

    let summary = app_state
        .user_usage_service
        .get_usage_by_user_id(user_id, start, end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get usage for user_id={}: {}", user_id, e);
            ApiError::internal_server_error("Failed to retrieve usage")
        })?;

    let summary = summary.ok_or_else(|| {
        tracing::info!("No usage found for user_id={}", user_id);
        ApiError::not_found("User has no usage or not found")
    })?;

    Ok(Json(crate::models::UserUsageResponse {
        user_id: summary.user_id,
        token_sum: summary.token_sum,
        image_num: summary.image_num,
        cost_nano_usd: summary.cost_nano_usd,
    }))
}

/// Get top N users by usage (all-time), ranked by token or cost.
///
/// Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/usage/top",
    tag = "Admin",
    params(
        ("rank_by" = Option<String>, Query, description = "Rank by 'token' or 'cost' (default: token)"),
        ("limit" = Option<i64>, Query, description = "Max users to return (default: 100)"),
        ("start" = Option<DateTime<Utc>>, Query, description = "Start of time period (ISO 8601); use with end; interval [start, end)"),
        ("end" = Option<DateTime<Utc>>, Query, description = "End of time period (ISO 8601); use with start; interval [start, end)")
    ),
    responses(
        (status = 200, description = "Top usage list", body = TopUsageResponse),
        (status = 400, description = "Bad request - invalid rank_by or limit", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_top_usage(
    State(app_state): State<AppState>,
    Query(params): Query<TopUsageQuery>,
) -> Result<Json<TopUsageResponse>, ApiError> {
    let rank_by = match params.rank_by.to_lowercase().as_str() {
        "token" => UsageRankBy::Token,
        "cost" => UsageRankBy::Cost,
        _ => return Err(ApiError::bad_request("rank_by must be 'token' or 'cost'")),
    };

    if params.limit < 1 || params.limit > LIST_USERS_LIMIT_MAX {
        return Err(ApiError::bad_request(format!(
            "limit must be between 1 and {}",
            LIST_USERS_LIMIT_MAX
        )));
    }

    let (start, end) = (params.start, params.end);
    if let (Some(s), Some(e)) = (start, end) {
        if s >= e {
            return Err(ApiError::bad_request("start must be before end"));
        }
    }

    let users = app_state
        .user_usage_service
        .get_top_users_usage(params.limit, rank_by, params.start, params.end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top usage: {}", e);
            ApiError::internal_server_error("Failed to retrieve top usage")
        })?;

    let rank_by_str = match rank_by {
        UsageRankBy::Token => "token",
        UsageRankBy::Cost => "cost",
    };

    Ok(Json(TopUsageResponse {
        users: users
            .into_iter()
            .map(|s| crate::models::UserUsageResponse {
                user_id: s.user_id,
                token_sum: s.token_sum,
                image_num: s.image_num,
                cost_nano_usd: s.cost_nano_usd,
            })
            .collect(),
        rank_by: rank_by_str.to_string(),
    }))
}

/// List all models with pagination
///
/// Returns a paginated list of all models. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/models",
    tag = "Admin",
    params(
        ("limit" = i64, Query, description = "Maximum number of items to return"),
        ("offset" = i64, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "List of models", body = ModelListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn list_models(
    State(app_state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<ModelListResponse>, ApiError> {
    pagination.validate()?;

    tracing::info!(
        "Listing models with limit={} and offset={}",
        pagination.limit,
        pagination.offset
    );

    let (models, total) = app_state
        .model_service
        .list_models(pagination.limit, pagination.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list models: {}", e);
            ApiError::internal_server_error("Failed to list models")
        })?;

    Ok(Json(ModelListResponse {
        models: models.into_iter().map(Into::into).collect(),
        limit: pagination.limit,
        offset: pagination.offset,
        total,
    }))
}

/// Batch create or update models
///
/// Creates new models or updates existing ones in batch. The request body should be a JSON object
/// where keys are model IDs and values are partial settings to update.
///
/// Example:
/// ```json
/// {
///   "gpt-4": { "public": true, "system_prompt": "..." },
///   "gpt-3.5": { "public": false }
/// }
/// ```
///
/// If a model doesn't exist, missing fields will use default values.
/// If a model exists, only provided fields will be updated.
/// Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/models",
    tag = "Admin",
    request_body = BatchUpsertModelsRequest,
    responses(
        (status = 200, description = "Models created or updated", body = Vec<ModelResponse>),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn batch_upsert_models(
    State(app_state): State<AppState>,
    Json(request): Json<BatchUpsertModelsRequest>,
) -> Result<Json<Vec<ModelResponse>>, ApiError> {
    if request.models.is_empty() {
        return Err(ApiError::bad_request("At least one model must be provided"));
    }

    tracing::info!("Batch upserting {} models", request.models.len());

    use services::model::ports::{ModelSettings, PartialModelSettings};

    let mut results = Vec::new();

    #[cfg(not(feature = "test"))]
    for model_id in request.models.keys() {
        ensure_proxy_model_exists(app_state.proxy_service.clone(), model_id).await?;
    }

    for (model_id, partial_settings) in request.models {
        if model_id.trim().is_empty() {
            return Err(ApiError::bad_request("model_id cannot be empty"));
        }

        // Validate system prompt length if provided
        if let Some(ref system_prompt) = partial_settings.system_prompt {
            if system_prompt.len() > crate::consts::SYSTEM_PROMPT_MAX_LEN {
                return Err(ApiError::bad_request(format!(
                    "System prompt for model '{}' exceeds maximum length of {} bytes",
                    model_id,
                    crate::consts::SYSTEM_PROMPT_MAX_LEN
                )));
            }
        }

        // Check if model exists
        let existing_model = app_state
            .model_service
            .get_model(&model_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to check if model exists: {}", e);
                ApiError::internal_server_error("Failed to check if model exists")
            })?;

        let model = if existing_model.is_some() {
            // Model exists: partial update
            let settings: PartialModelSettings = partial_settings.into();
            let params = UpdateModelParams {
                model_id: model_id.clone(),
                settings: Some(settings),
            };

            app_state
                .model_service
                .update_model(params)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to update model {}: {}", model_id, e);
                    ApiError::internal_server_error(format!("Failed to update model {}", model_id))
                })?
        } else {
            // Model doesn't exist: create with defaults + provided partial settings
            let default_settings = ModelSettings::default();
            let partial: PartialModelSettings = partial_settings.into();
            let full_settings = default_settings.into_updated(partial);

            let params = UpsertModelParams {
                model_id: model_id.clone(),
                settings: full_settings,
            };

            app_state
                .model_service
                .upsert_model(params)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create model {}: {}", model_id, e);
                    ApiError::internal_server_error(format!("Failed to create model {}", model_id))
                })?
        };

        // Invalidate cache immediately after each successful DB write
        // NOTE: This only invalidates cache on the current instance. In multi-instance deployments,
        // other instances may serve stale data for up to MODEL_SETTINGS_CACHE_TTL_SECS.
        {
            let mut cache = app_state.model_settings_cache.write().await;
            cache.remove(&model_id);
        }

        results.push(model.clone());
    }

    Ok(Json(results.into_iter().map(Into::into).collect()))
}

#[cfg(not(feature = "test"))]
async fn ensure_proxy_model_exists(
    proxy_service: std::sync::Arc<dyn services::response::ports::OpenAIProxyService>,
    model_id: &str,
) -> Result<(), ApiError> {
    let encoded_model_id = urlencoding::encode(model_id);
    let path = format!("model/{}", encoded_model_id);

    let response = proxy_service
        .forward_request(
            axum::http::Method::GET,
            &path,
            axum::http::HeaderMap::new(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify model '{}' via proxy: {}", model_id, e);
            ApiError::internal_server_error(format!(
                "Failed to verify existence of model '{}' with proxy",
                model_id
            ))
        })?;

    if (200..300).contains(&response.status) {
        Ok(())
    } else if response.status == 404 {
        tracing::warn!("Model '{}' not found via proxy", model_id);
        Err(ApiError::bad_request(format!(
            "Model '{}' does not exist in proxy service",
            model_id
        )))
    } else {
        tracing::error!(
            "Unexpected proxy status {} while checking model '{}'",
            response.status,
            model_id
        );
        Err(ApiError::internal_server_error(format!(
            "Failed to verify model '{}' with proxy",
            model_id
        )))
    }
}

/// Delete a model
///
/// Deletes a specific model and its settings. Requires admin authentication.
#[utoipa::path(
    delete,
    path = "/v1/admin/models/{model_id}",
    tag = "Admin",
    params(
        ("model_id" = String, Path, description = "Model identifier (e.g. gpt-4.1)")
    ),
    responses(
        (status = 204, description = "Model deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Model not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn delete_model(
    State(app_state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if model_id.trim().is_empty() {
        return Err(ApiError::bad_request("model_id cannot be empty"));
    }

    tracing::info!("Deleting model for model_id={}", model_id);

    let deleted = app_state
        .model_service
        .delete_model(&model_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete model: {}", e);
            ApiError::internal_server_error("Failed to delete model")
        })?;

    if !deleted {
        return Err(ApiError::not_found("Model not found"));
    }

    // Invalidate cache AFTER successful DB delete
    {
        let mut cache = app_state.model_settings_cache.write().await;
        cache.remove(&model_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke VPC credentials
///
/// Deletes the stored `vpc_api_key` from database and clears the in-memory VPC cache so the
/// next proxied request will request a new API key from the VPC.
#[utoipa::path(
    post,
    path = "/v1/admin/vpc/revoke",
    tag = "Admin",
    responses(
        (status = 204, description = "VPC credentials revoked"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn revoke_vpc_credentials(
    State(app_state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    tracing::info!("Admin revoked VPC credentials");

    app_state
        .vpc_credentials_service
        .revoke_credentials()
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke VPC credentials: {}", e);
            ApiError::internal_server_error("Failed to revoke VPC credentials")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Create or update system configs
///
/// Creates new system configs or updates existing ones. All fields in the request are optional.
/// If the configs don't exist, missing fields will use default values.
/// If the configs exist, only provided fields will be updated.
/// Requires admin authentication.
#[utoipa::path(
    patch,
    path = "/v1/admin/configs",
    tag = "Admin",
    request_body = UpsertSystemConfigsRequest,
    responses(
        (status = 200, description = "System configs created or updated", body = SystemConfigsResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn upsert_system_configs(
    State(app_state): State<AppState>,
    Json(request): Json<UpsertSystemConfigsRequest>,
) -> Result<Json<SystemConfigsResponse>, ApiError> {
    tracing::info!("Upserting system configs");

    #[cfg(not(feature = "test"))]
    if let Some(ref model_id) = request.default_model {
        ensure_proxy_model_exists(app_state.proxy_service.clone(), model_id).await?;
    }

    // Validate rate limit config if provided
    if let Some(ref rate_limit) = request.rate_limit {
        rate_limit.validate()?;
    }

    // Validate auto_route config if provided
    if let Some(ref auto_route) = request.auto_route {
        if auto_route.model.trim().is_empty() {
            return Err(ApiError::bad_request(
                "auto_route.model must not be empty".to_string(),
            ));
        }
        #[cfg(not(feature = "test"))]
        ensure_proxy_model_exists(app_state.proxy_service.clone(), &auto_route.model).await?;
        if let Some(t) = auto_route.temperature {
            if t < 0.0 {
                return Err(ApiError::bad_request(
                    "auto_route.temperature must be >= 0".to_string(),
                ));
            }
        }
        if let Some(p) = auto_route.top_p {
            if !(0.0..=1.0).contains(&p) {
                return Err(ApiError::bad_request(
                    "auto_route.top_p must be between 0 and 1".to_string(),
                ));
            }
        }
        if let Some(m) = auto_route.max_tokens {
            if m == 0 {
                return Err(ApiError::bad_request(
                    "auto_route.max_tokens must be > 0".to_string(),
                ));
            }
        }
    }

    let partial: services::system_configs::ports::PartialSystemConfigs =
        request.try_into().map_err(|e: String| {
            tracing::error!(error = %e, "Failed to convert rate limit config");
            ApiError::bad_request(format!("Invalid rate limit configuration: {}", e))
        })?;

    // Check if configs exist
    let existing_configs = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!("Failed to check if system configs exist: {}", e);
            ApiError::internal_server_error("Failed to check if system configs exist")
        })?;

    let updated = if existing_configs.is_some() {
        // Configs exist: partial update
        app_state
            .system_configs_service
            .update_configs(partial)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to update system configs");
                ApiError::internal_server_error("Failed to update system configs")
            })?
    } else {
        // Configs don't exist: create with defaults + provided partial configs
        use services::system_configs::ports::SystemConfigs;
        let default_configs = SystemConfigs::default();
        let full_configs = default_configs.into_updated(partial);

        app_state
            .system_configs_service
            .upsert_configs(full_configs)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to create system configs");
                ApiError::internal_server_error("Failed to create system configs")
            })?
    };

    // Hot reload: Update rate limit state with new config
    app_state
        .rate_limit_state
        .update_config(updated.rate_limit.clone())
        .await;

    // Invalidate system configs cache so auto-route picks up changes immediately
    {
        let mut cache = app_state.system_configs_cache.write().await;
        *cache = None;
    }

    Ok(Json(updated.into()))
}

/// Get full system configs (admin only, returns all fields including rate_limit)
#[utoipa::path(
    get,
    path = "/v1/admin/configs",
    tag = "Admin",
    responses(
        (status = 200, description = "Full system configs retrieved", body = Option<SystemConfigsResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_system_configs_admin(
    State(app_state): State<AppState>,
) -> Result<Json<Option<SystemConfigsResponse>>, ApiError> {
    tracing::info!("Getting full system configs (admin)");

    let config = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "Failed to get system configs");
            ApiError::internal_server_error("Failed to get system configs")
        })?;

    Ok(Json(config.map(Into::into)))
}

// ========== Admin Agent Endpoints ==========

/// Request body for admin creating instance for a user.
/// The chat-api creates an API key on behalf of the user and configures the agent to use it.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AdminCreateInstanceRequest {
    /// User ID to create the instance for
    pub user_id: Uuid,
    /// Image to use for the instance (optional)
    #[serde(default)]
    pub image: Option<String>,
    /// Instance name (optional)
    #[serde(default)]
    pub name: Option<String>,
    /// SSH public key (optional)
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
    /// Service type preset, e.g. "ironclaw" (optional)
    #[serde(default)]
    pub service_type: Option<String>,
}

/// Admin endpoint: List all agent instances (all users' instances)
#[utoipa::path(
    get,
    path = "/v1/admin/agents/instances",
    tag = "Admin",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of items to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)")
    ),
    responses(
        (status = 200, description = "All instances retrieved", body = PaginatedResponse<InstanceResponse>),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_list_all_instances(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<InstanceResponse>>, ApiError> {
    tracing::info!(
        "Admin: Listing all agent instances with limit={}, offset={}",
        params.limit,
        params.offset
    );

    params.validate()?;

    // Use DB (agent_instances) for correct user_id per instance
    let (instances, total) = app_state
        .agent_service
        .list_all_instances(params.limit, params.offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list all instances: error={}", e);
            ApiError::internal_server_error("Failed to list instances")
        })?;

    let items: Vec<InstanceResponse> = instances
        .into_iter()
        .map(crate::models::instance_response_for_admin)
        .collect();
    Ok(Json(PaginatedResponse {
        items,
        limit: params.limit,
        offset: params.offset,
        total,
    }))
}

/// Admin endpoint: Create an agent instance for a specific user
#[utoipa::path(
    post,
    path = "/v1/admin/agents/instances",
    tag = "Admin",
    request_body = AdminCreateInstanceRequest,
    responses(
        (status = 201, description = "Instance created for user", body = InstanceResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_create_instance(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(request): Json<AdminCreateInstanceRequest>,
) -> Result<(StatusCode, Json<InstanceResponse>), ApiError> {
    tracing::info!(
        "Admin: Creating agent instance for user_id={}",
        request.user_id
    );

    let user_id = services::UserId(request.user_id);
    app_state
        .user_repository
        .get_user(user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to check user existence: user_id={}, error={}",
                user_id,
                e
            );
            ApiError::internal_server_error("Failed to verify user")
        })?
        .ok_or_else(|| {
            tracing::warn!(
                "Admin attempted to create instance for non-existent user: user_id={}",
                user_id
            );
            ApiError::bad_request("User does not exist")
        })?;

    // Validate service_type if provided
    if let Some(service_type) = request.service_type.as_deref() {
        if !is_valid_service_type(service_type) {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_service_type",
                "Service type must be 'openclaw' or 'ironclaw'",
            ));
        }
    }

    let instance = app_state
        .agent_service
        .create_instance_from_agent_api(
            user_id,
            request.image,
            request.name,
            request.ssh_pubkey,
            request.service_type,
        )
        .await
        .map_err(|_| {
            tracing::error!(
                "Admin: Failed to create instance for user_id={}",
                request.user_id
            );
            ApiError::internal_server_error("Failed to create instance")
        })?;

    Ok((StatusCode::CREATED, Json(instance.into())))
}

/// Admin endpoint: Delete an agent instance
#[utoipa::path(
    delete,
    path = "/v1/admin/agents/instances/{id}",
    tag = "Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 204, description = "Instance deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_delete_instance(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Deleting instance: instance_id={}", instance_uuid);

    app_state
        .agent_service
        .delete_instance(instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to delete instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to delete instance")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Request body for admin creating API key on behalf of a user
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AdminCreateApiKeyRequest {
    /// User ID to create the API key for
    pub user_id: Uuid,
    /// Human-readable key name
    pub name: String,
    /// Optional spend limit in nano-dollars ($1.00 = 1,000,000,000 nano-dollars)
    pub spend_limit: Option<i64>,
    /// Optional expiration timestamp (RFC3339)
    pub expires_at: Option<String>,
}

/// Create an unbound API key on behalf of a user (pre-deployment key for agent setup)
#[utoipa::path(
    post,
    path = "/v1/admin/agents/keys",
    tag = "Admin",
    request_body = AdminCreateApiKeyRequest,
    responses(
        (status = 200, description = "API key created", body = CreateApiKeyResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_create_unbound_api_key(
    State(app_state): State<AppState>,
    Extension(_admin): Extension<AuthenticatedUser>,
    Json(request): Json<AdminCreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    let user_id = services::UserId(request.user_id);
    tracing::info!(
        "Admin: Creating unbound API key on behalf of user_id={}",
        user_id
    );

    // Verify target user exists
    app_state
        .user_repository
        .get_user(user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to check user existence: user_id={}, error={}",
                user_id,
                e
            );
            ApiError::internal_server_error("Failed to verify user")
        })?
        .ok_or_else(|| {
            tracing::warn!(
                "Admin attempted to create API key for non-existent user: user_id={}",
                user_id
            );
            ApiError::bad_request("User does not exist")
        })?;

    let (api_key, plaintext_key) = app_state
        .agent_service
        .create_unbound_api_key(
            user_id,
            request.name.clone(),
            request.spend_limit,
            request.expires_at.as_ref().and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create unbound API key: error={}", e);
            ApiError::internal_server_error("Failed to create API key")
        })?;

    Ok(Json(CreateApiKeyResponse {
        id: api_key.id.to_string(),
        name: api_key.name,
        api_key: plaintext_key,
        spend_limit: api_key.spend_limit.map(|s| s.to_string()),
        expires_at: api_key.expires_at.map(|dt| dt.to_rfc3339()),
        created_at: api_key.created_at.to_rfc3339(),
    }))
}

/// Bind an unbound API key to an instance
#[utoipa::path(
    post,
    path = "/v1/admin/agents/keys/{key_id}/bind-instance",
    tag = "Admin",
    params(("key_id" = String, Path, description = "API key ID")),
    request_body = BindApiKeyRequest,
    responses(
        (status = 200, description = "API key bound", body = ApiKeyResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Key or instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_bind_api_key_to_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(key_id): Path<String>,
    Json(request): Json<BindApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    let key_uuid =
        Uuid::parse_str(&key_id).map_err(|_| ApiError::bad_request("Invalid key ID format"))?;

    let instance_uuid = Uuid::parse_str(&request.instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!(
        "Admin: Binding API key to instance: key_id={}, instance_id={}, admin_user_id={}",
        key_uuid,
        instance_uuid,
        user.user_id
    );

    let api_key = app_state
        .agent_service
        .admin_bind_api_key_to_instance(key_uuid, instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!("Failed to bind API key: key_id={}, error={}", key_uuid, e);
            match e.to_string().as_str() {
                msg if msg.contains("not found") => ApiError::not_found(msg),
                msg if msg.contains("Access denied") => ApiError::forbidden(msg),
                msg if msg.contains("already bound") => ApiError::bad_request(msg),
                _ => ApiError::internal_server_error("Failed to bind API key"),
            }
        })?;

    Ok(Json(ApiKeyResponse::from(api_key)))
}

/// TEMPORARY: Admin-only endpoint to sync instance status from Agent API.
/// Remove when automated sync is in place.
#[utoipa::path(
    post,
    path = "/v1/admin/agents/instances/sync-status",
    tag = "Admin",
    responses(
        (status = 200, description = "Sync completed", body = SyncAgentStatusResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_sync_agent_status(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
) -> Result<Json<SyncAgentStatusResponse>, ApiError> {
    tracing::info!("Admin: Syncing agent instance status from Agent API");

    let result = app_state
        .agent_service
        .sync_all_instance_statuses()
        .await
        .map_err(|e| {
            tracing::error!("Failed to sync agent instance status: {}", e);
            ApiError::internal_server_error("Failed to sync instance status")
        })?;

    Ok(Json(SyncAgentStatusResponse {
        synced: result.synced,
        updated: result.updated,
        skipped: result.skipped,
        not_found: result.not_found,
        error_skipped: result.error_skipped,
        errors: result.errors,
    }))
}

/// Response for sync agent status endpoint
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SyncAgentStatusResponse {
    pub synced: u32,
    pub updated: u32,
    pub skipped: u32,
    pub not_found: u32,
    /// Instances skipped because their manager API call failed
    pub error_skipped: u32,
    pub errors: Vec<String>,
}

/// Create a backup of an agent instance
#[utoipa::path(
    post,
    path = "/v1/admin/agents/instances/{id}/backup",
    tag = "Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Backup created"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_create_backup(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Creating backup: instance_id={}", instance_uuid);

    let instance = app_state
        .agent_repository
        .get_instance(instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to fetch instance")
        })?
        .ok_or_else(|| ApiError::not_found("Instance not found"))?;

    let encoded_instance_id = encode(&instance.instance_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/backup", encoded_instance_id),
            "POST",
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to forward request: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to create backup")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

/// List backups for an agent instance
#[utoipa::path(
    get,
    path = "/v1/admin/agents/instances/{id}/backups",
    tag = "Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Backups retrieved"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_list_backups(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Listing backups: instance_id={}", instance_uuid);

    let instance = app_state
        .agent_repository
        .get_instance(instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to fetch instance")
        })?
        .ok_or_else(|| ApiError::not_found("Instance not found"))?;

    let encoded_instance_id = encode(&instance.instance_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/backups", encoded_instance_id),
            "GET",
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to forward request: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to list backups")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

/// Get backup details for an agent instance
#[utoipa::path(
    get,
    path = "/v1/admin/agents/instances/{id}/backups/{backup_id}",
    tag = "Admin",
    params(
        ("id" = String, Path, description = "Instance ID"),
        ("backup_id" = String, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup details retrieved"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance or backup not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_get_backup(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path((instance_id, backup_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    if backup_id.contains("..") || backup_id.contains("/") || backup_id.contains("\\") {
        return Err(ApiError::bad_request("Invalid backup ID format"));
    }

    tracing::info!(
        "Admin: Getting backup: instance_id={}, backup_id={}",
        instance_uuid,
        backup_id
    );

    let instance = app_state
        .agent_repository
        .get_instance(instance_uuid)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to fetch instance")
        })?
        .ok_or_else(|| ApiError::not_found("Instance not found"))?;

    let encoded_instance_id = encode(&instance.instance_id);
    let encoded_backup_id = encode(&backup_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!(
                "/v1/instances/{}/backups/{}",
                encoded_instance_id, encoded_backup_id
            ),
            "GET",
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to forward request: instance_id={}, backup_id={}, error={}",
                instance_uuid,
                backup_id,
                e
            );
            ApiError::internal_server_error("Failed to get backup")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

// =============================================================================
// BI Metrics endpoints
// =============================================================================

/// Query parameters for BI deployment list
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BiDeploymentQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default = "default_offset")]
    pub offset: i64,
    #[serde(rename = "type")]
    pub instance_type: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Query parameters for BI deployment summary
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BiSummaryQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Query parameters for BI usage aggregation
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BiUsageQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub user_id: Option<Uuid>,
    pub instance_id: Option<Uuid>,
    #[serde(rename = "type")]
    pub instance_type: Option<String>,
    #[serde(default = "default_group_by")]
    pub group_by: UsageGroupBy,
}

fn default_group_by() -> UsageGroupBy {
    UsageGroupBy::Day
}

/// Query parameters for BI top consumers
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BiTopConsumersQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    #[serde(rename = "type")]
    pub instance_type: Option<String>,
    #[serde(default = "default_bi_rank_by")]
    pub rank_by: BiUsageRankBy,
    #[serde(default = "default_top_group_by")]
    pub group_by: TopConsumerGroupBy,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_bi_rank_by() -> BiUsageRankBy {
    BiUsageRankBy::Cost
}

fn default_top_group_by() -> TopConsumerGroupBy {
    TopConsumerGroupBy::Instance
}

/// Response types for BI endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BiDeploymentListResponse {
    pub deployments: Vec<DeploymentRecord>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BiUsageResponse {
    pub data: Vec<UsageAggregation>,
    pub group_by: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BiTopConsumersResponse {
    pub consumers: Vec<TopConsumer>,
    pub rank_by: String,
    pub group_by: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BiStatusHistoryResponse {
    pub instance_id: Uuid,
    pub history: Vec<StatusChangeRecord>,
}

/// Validate optional date range: start_date must be before end_date when both are provided.
fn validate_date_range(
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> Result<(), ApiError> {
    if let (Some(s), Some(e)) = (start, end) {
        if s >= e {
            return Err(ApiError::bad_request("start_date must be before end_date"));
        }
    }
    Ok(())
}

/// Validate optional string filter length to prevent memory abuse.
const MAX_FILTER_LEN: usize = 100;

fn validate_string_filter(name: &str, value: &Option<String>) -> Result<(), ApiError> {
    if let Some(ref v) = value {
        if v.len() > MAX_FILTER_LEN {
            return Err(ApiError::bad_request(format!(
                "{name} filter exceeds maximum length of {MAX_FILTER_LEN}"
            )));
        }
    }
    Ok(())
}

/// List users with BI stats (BI). Same response as /v1/admin/users. Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/users",
    tag = "Admin",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of items to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
        ("filter_by" = Option<String>, Query, description = "Filter type: subscription_status or subscription_plan"),
        ("filter_value" = Option<String>, Query, description = "Filter value. For subscription_status: active, canceled, past_due, none. For subscription_plan: plan name or none"),
        ("q" = Option<String>, Query, description = "Substring search on email and name (case-insensitive)"),
        ("sort_by" = Option<String>, Query, description = "Sort by: created_at, total_spent_nano, agent_spent_nano, agent_token_usage, last_activity_at, agent_count, email, name"),
        ("sort_order" = Option<String>, Query, description = "Sort order: asc or desc")
    ),
    responses(
        (status = 200, description = "User list with stats", body = AdminUserListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_list_users(
    State(app_state): State<AppState>,
    Query(params): Query<ListUsersQuery>,
) -> Result<Json<AdminUserListResponse>, ApiError> {
    tracing::info!(
        "BI: Listing users with limit={}, offset={}, filter_by={:?}, filter_value={:?}, q={:?}, sort_by={}, sort_order={}",
        params.limit,
        params.offset,
        params.filter_by,
        params.filter_value,
        params.q,
        params.sort_by,
        params.sort_order
    );
    list_users_bi_impl(&app_state, params).await
}

/// List deployments with optional filters (BI). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/deployments",
    tag = "Admin",
    params(BiDeploymentQuery),
    responses(
        (status = 200, description = "Deployment list", body = BiDeploymentListResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_list_deployments(
    State(app_state): State<AppState>,
    Query(params): Query<BiDeploymentQuery>,
) -> Result<Json<BiDeploymentListResponse>, ApiError> {
    validate_string_filter("type", &params.instance_type)?;
    validate_string_filter("status", &params.status)?;
    validate_date_range(params.start_date, params.end_date)?;

    let filter = DeploymentFilter {
        instance_type: params.instance_type,
        status: params.status,
        start_date: params.start_date,
        end_date: params.end_date,
        limit: params.limit.clamp(1, 100),
        offset: params.offset.max(0),
    };

    let (deployments, total) = app_state
        .bi_metrics_service
        .list_deployments(&filter)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list deployments for BI: {}", e);
            ApiError::internal_server_error("Failed to list deployments")
        })?;

    Ok(Json(BiDeploymentListResponse {
        deployments,
        total,
        limit: filter.limit,
        offset: filter.offset,
    }))
}

/// Get deployment summary counts (BI). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/deployments/summary",
    tag = "Admin",
    params(BiSummaryQuery),
    responses(
        (status = 200, description = "Deployment summary", body = DeploymentSummary),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_deployment_summary(
    State(app_state): State<AppState>,
    Query(params): Query<BiSummaryQuery>,
) -> Result<Json<DeploymentSummary>, ApiError> {
    validate_date_range(params.start_date, params.end_date)?;

    let summary = app_state
        .bi_metrics_service
        .get_deployment_summary(params.start_date, params.end_date)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get deployment summary: {}", e);
            ApiError::internal_server_error("Failed to get deployment summary")
        })?;

    Ok(Json(summary))
}

/// Query parameters for BI status history
#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BiStatusHistoryQuery {
    #[serde(default = "default_status_history_limit")]
    pub limit: i64,
}

fn default_status_history_limit() -> i64 {
    100
}

/// Get status change history for a deployment (BI). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/deployments/{id}/status-history",
    tag = "Admin",
    params(
        ("id" = String, Path, description = "Instance ID (UUID)"),
        BiStatusHistoryQuery
    ),
    responses(
        (status = 200, description = "Status change history", body = BiStatusHistoryResponse),
        (status = 400, description = "Bad request - invalid instance ID", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_status_history(
    State(app_state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<BiStatusHistoryQuery>,
) -> Result<Json<BiStatusHistoryResponse>, ApiError> {
    let instance_uuid =
        Uuid::parse_str(&id).map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    let limit = params.limit.clamp(1, 1000);

    let history = app_state
        .bi_metrics_service
        .get_status_history(instance_uuid, limit)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get status history: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to get status history")
        })?;

    Ok(Json(BiStatusHistoryResponse {
        instance_id: instance_uuid,
        history,
    }))
}

/// Get aggregated usage data (BI). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/usage",
    tag = "Admin",
    params(BiUsageQuery),
    responses(
        (status = 200, description = "Aggregated usage data", body = BiUsageResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_usage(
    State(app_state): State<AppState>,
    Query(params): Query<BiUsageQuery>,
) -> Result<Json<BiUsageResponse>, ApiError> {
    validate_string_filter("type", &params.instance_type)?;
    validate_date_range(params.start_date, params.end_date)?;

    let filter = UsageFilter {
        start_date: params.start_date,
        end_date: params.end_date,
        user_id: params.user_id.map(UserId::from),
        instance_id: params.instance_id,
        instance_type: params.instance_type,
        group_by: params.group_by,
        limit: BI_USAGE_MAX_ROWS,
    };

    let data = app_state
        .bi_metrics_service
        .get_usage_aggregation(&filter)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get usage aggregation: {}", e);
            ApiError::internal_server_error("Failed to get usage data")
        })?;

    Ok(Json(BiUsageResponse {
        data,
        group_by: filter.group_by.to_string(),
    }))
}

/// Get top consumers ranked by tokens or cost (BI). Requires admin authentication.
#[utoipa::path(
    get,
    path = "/v1/admin/bi/usage/top",
    tag = "Admin",
    params(BiTopConsumersQuery),
    responses(
        (status = 200, description = "Top consumers", body = BiTopConsumersResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - Admin access required", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn bi_top_consumers(
    State(app_state): State<AppState>,
    Query(params): Query<BiTopConsumersQuery>,
) -> Result<Json<BiTopConsumersResponse>, ApiError> {
    validate_string_filter("type", &params.instance_type)?;
    validate_date_range(params.start_date, params.end_date)?;

    let filter = TopConsumerFilter {
        start_date: params.start_date,
        end_date: params.end_date,
        instance_type: params.instance_type,
        rank_by: params.rank_by,
        group_by: params.group_by,
        limit: params.limit.clamp(1, 100),
    };

    let consumers = app_state
        .bi_metrics_service
        .get_top_consumers(&filter)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top consumers: {}", e);
            ApiError::internal_server_error("Failed to get top consumers")
        })?;

    Ok(Json(BiTopConsumersResponse {
        consumers,
        rank_by: filter.rank_by.to_string(),
        group_by: filter.group_by.to_string(),
    }))
}

/// Create admin router with all admin routes (requires admin authentication)
pub fn create_admin_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users))
        .route("/users/{user_id}/activity", get(get_user_activity))
        .route(
            "/users/{user_id}/subscription",
            post(admin_set_user_subscription).delete(admin_cancel_user_subscriptions),
        )
        .route("/models", get(list_models).patch(batch_upsert_models))
        .route("/models/{model_id}", delete(delete_model))
        .route("/vpc/revoke", post(revoke_vpc_credentials))
        .route(
            "/configs",
            get(get_system_configs_admin).patch(upsert_system_configs),
        )
        .route("/analytics", get(get_analytics))
        .route("/analytics/top-users", get(get_top_users))
        .route("/usage/users/{user_id}", get(get_usage_by_user_id))
        .route("/usage/top", get(get_top_usage))
        // Admin agent routes
        .nest(
            "/agents",
            Router::new()
                .route(
                    "/instances",
                    get(admin_list_all_instances).post(admin_create_instance),
                )
                .route("/instances/sync-status", post(admin_sync_agent_status))
                .route("/instances/{id}", delete(admin_delete_instance))
                .route("/instances/{id}/backup", post(admin_create_backup))
                .route("/instances/{id}/backups", get(admin_list_backups))
                .route("/instances/{id}/backups/{backup_id}", get(admin_get_backup))
                .route("/keys", post(admin_create_unbound_api_key))
                .route(
                    "/keys/{key_id}/bind-instance",
                    post(admin_bind_api_key_to_instance),
                ),
        )
        // BI metrics routes
        .nest(
            "/bi",
            Router::new()
                .route("/users", get(bi_list_users))
                .route("/deployments", get(bi_list_deployments))
                .route("/deployments/summary", get(bi_deployment_summary))
                .route("/deployments/{id}/status-history", get(bi_status_history))
                .route("/usage", get(bi_usage))
                .route("/usage/top", get(bi_top_consumers)),
        )
}
