use crate::{error::ApiError, middleware::AuthenticatedUser, models::*, state::AppState};
use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use services::user::ports::AccountDeletionError;
/// Get current user
///
/// Returns the profile of the currently authenticated user, including their linked OAuth accounts.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "Users",
    responses(
        (status = 200, description = "Current user profile", body = UserProfileResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_current_user(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserProfileResponse>, ApiError> {
    tracing::info!("Getting user profile for user: {}", user.user_id);

    let profile = app_state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user profile: {}", e);
            ApiError::user_profile_error()
        })?;

    Ok(Json(profile.into()))
}

/// Delete current user account
///
/// Deletes the authenticated user's direct PII/account rows after verifying they have no active
/// subscriptions and no running/provisioning/error instances.
#[utoipa::path(
    delete,
    path = "/v1/users/me",
    tag = "Users",
    responses(
        (status = 204, description = "User account deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 409, description = "Account cannot be deleted until subscriptions are inactive and instances are stopped", body = crate::error::ApiErrorResponse),
        (status = 502, description = "Failed to delete upstream chat history", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn delete_current_user(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<StatusCode, ApiError> {
    tracing::warn!("Deleting current user account: user_id={}", user.user_id);

    app_state
        .user_service
        .validate_account_deletion_preconditions(user.user_id)
        .await
        .map_err(account_deletion_error_to_api_error)?;

    let conversation_ids = app_state
        .user_service
        .list_owned_conversation_ids(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to list conversations for account deletion: user_id={}, error={:#}",
                user.user_id,
                e
            );
            ApiError::internal_server_error("Failed to prepare account deletion")
        })?;

    let mut cloud_deleted_conversation_ids = Vec::with_capacity(conversation_ids.len());
    for conversation_id in conversation_ids {
        app_state
            .conversation_service
            .delete_conversation_from_provider(&conversation_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to delete conversation from Cloud API during account deletion: user_id={}, conversation_id={}, error={}",
                    user.user_id,
                    conversation_id,
                    e
                );
                ApiError::bad_gateway("Failed to delete chat history")
                    .with_details(format!("Cloud API conversation cleanup failed for {conversation_id}"))
            })?;
        cloud_deleted_conversation_ids.push(conversation_id);
    }

    app_state
        .user_service
        .delete_account(user.user_id, &cloud_deleted_conversation_ids)
        .await
        .map_err(account_deletion_error_to_api_error)?;

    Ok(StatusCode::NO_CONTENT)
}

fn account_deletion_error_to_api_error(e: AccountDeletionError) -> ApiError {
    match e {
        AccountDeletionError::UserNotFound => ApiError::not_found("User not found"),
        AccountDeletionError::ActiveSubscriptions { count } => ApiError::conflict(format!(
            "Cannot delete account while {count} active subscription(s) exist"
        )),
        AccountDeletionError::InstancesNotStopped { count, statuses } => ApiError::conflict(
            format!("Cannot delete account while {count} instance(s) are not stopped"),
        )
        .with_details(format!(
            "Blocking instance statuses: {}",
            statuses.join(", ")
        )),
        AccountDeletionError::ConversationCleanupIncomplete { conversation_ids } => {
            ApiError::conflict("Cannot delete account until chat history is cleaned up")
                .with_details(format!(
                    "Missing Cloud API cleanup for conversation(s): {}",
                    conversation_ids.join(", ")
                ))
        }
        AccountDeletionError::Internal(err) => {
            tracing::error!("Failed to delete account: {:#}", err);
            ApiError::internal_server_error("Failed to delete account")
        }
    }
}

/// Query parameters for usage time range.
#[derive(Debug, Deserialize)]
pub struct UsageTimeRangeQuery {
    /// Start of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub start: Option<DateTime<Utc>>,
    /// End of the time period (ISO 8601). When set, both start and end must be set; interval is [start, end).
    pub end: Option<DateTime<Utc>>,
}

/// Get current user's usage (all-time or within time range).
///
/// Returns the authenticated user's own usage. No admin required.
/// Without start/end, returns all-time usage.
#[utoipa::path(
    get,
    path = "/v1/users/me/usage",
    tag = "Users",
    params(
        ("start" = Option<DateTime<Utc>>, Query, description = "Start of time period (ISO 8601); use with end; interval [start, end)"),
        ("end" = Option<DateTime<Utc>>, Query, description = "End of time period (ISO 8601); use with start; interval [start, end)")
    ),
    responses(
        (status = 200, description = "Current user usage", body = UserUsageResponse),
        (status = 400, description = "Bad request - start and end must be used together, start must be before end", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "No usage recorded", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_my_usage(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<UsageTimeRangeQuery>,
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
        .get_usage_by_user_id(user.user_id, start, end)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get usage for user_id={}: {}", user.user_id, e);
            ApiError::internal_server_error("Failed to retrieve usage")
        })?;

    let summary = summary.ok_or_else(|| {
        tracing::info!("No usage found for user_id={}", user.user_id);
        ApiError::not_found("No usage recorded")
    })?;

    Ok(Json(UserUsageResponse {
        user_id: summary.user_id,
        token_sum: summary.token_sum,
        image_num: summary.image_num,
        cost_nano_usd: summary.cost_nano_usd,
    }))
}

/// Get user settings
///
/// Retrieves the settings for the currently authenticated user.
#[utoipa::path(
    get,
    path = "/v1/users/me/settings",
    tag = "Users",
    responses(
        (status = 200, description = "User settings retrieved", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn get_user_settings(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Getting user settings for user: {}", user.user_id);

    let content = app_state
        .user_settings_service
        .get_settings(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user settings: {}", e);
            ApiError::internal_server_error("Failed to get user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Update user settings
///
/// Fully updates the settings for the currently authenticated user.
#[utoipa::path(
    post,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UpdateUserSettingsRequest,
    responses(
        (status = 200, description = "User settings updated", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_user_settings(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UpdateUserSettingsRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!("Fully updating user settings for user: {}", user.user_id);

    request.validate()?;

    let content = services::user::ports::UserSettingsContent {
        notification: request.notification,
        system_prompt: request.system_prompt,
        web_search: request.web_search,
        appearance: request.appearance.into(),
    };

    let content = app_state
        .user_settings_service
        .update_settings(user.user_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user settings: {}", e);
            ApiError::internal_server_error("Failed to update user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Update user settings
///
/// Partially updates the settings for the currently authenticated user.
#[utoipa::path(
    patch,
    path = "/v1/users/me/settings",
    tag = "Users",
    request_body = UpdateUserSettingsPartiallyRequest,
    responses(
        (status = 200, description = "User settings updated", body = UserSettingsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
pub async fn update_user_settings_partially(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UpdateUserSettingsPartiallyRequest>,
) -> Result<Json<UserSettingsResponse>, ApiError> {
    tracing::info!(
        "Partially updating user settings for user: {}",
        user.user_id
    );

    request.validate()?;

    let content = services::user::ports::PartialUserSettingsContent {
        notification: request.notification,
        system_prompt: request.system_prompt,
        web_search: request.web_search,
        appearance: request.appearance.map(Into::into),
    };

    let content = app_state
        .user_settings_service
        .update_settings_partially(user.user_id, content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user settings: {}", e);
            ApiError::internal_server_error("Failed to update user settings")
        })?;

    Ok(Json(UserSettingsResponse {
        user_id: user.user_id,
        content: content.into(),
    }))
}

/// Create user router with all routes (requires authentication)
pub fn create_user_router() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_current_user).delete(delete_current_user))
        .route("/me/usage", get(get_my_usage))
        .route("/me/settings", get(get_user_settings))
        .route("/me/settings", post(update_user_settings))
        .route("/me/settings", patch(update_user_settings_partially))
}
