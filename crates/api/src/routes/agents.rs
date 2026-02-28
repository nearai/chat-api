use super::is_valid_service_type;
use crate::{error::ApiError, middleware::AuthenticatedUser, models::*, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for user creating their own instance.
/// The chat-api creates an API key on behalf of the user and configures the agent to use it.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct CreateInstanceRequest {
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

/// Helper to create SSE streaming response for instance creation
async fn create_instance_streaming_response(
    app_state: AppState,
    user_id: services::UserId,
    image: Option<String>,
    name: Option<String>,
    ssh_pubkey: Option<String>,
    service_type: Option<String>,
    max_allowed: u64,
) -> Result<Response, ApiError> {
    let rx = app_state
        .agent_service
        .create_instance_from_agent_api_streaming(
            user_id,
            image,
            name,
            ssh_pubkey,
            service_type,
            max_allowed,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to start instance creation stream: {}", e);
            ApiError::internal_server_error("Failed to start instance creation")
        })?;

    use futures::stream::StreamExt;
    use tokio_stream::wrappers::ReceiverStream;

    let stream = ReceiverStream::new(rx)
        .then(|event_result| async move {
            match event_result {
                Ok(event) => {
                    if let Ok(json_str) = serde_json::to_string(&event) {
                        Ok(axum::body::Bytes::from(format!("data: {}\n\n", json_str)))
                    } else {
                        Err(axum::Error::new(anyhow::anyhow!(
                            "Failed to serialize event"
                        )))
                    }
                }
                Err(e) => {
                    tracing::error!("Error in instance creation stream: {}", e);
                    let error_json =
                        serde_json::json!({"error": "Instance creation failed"}).to_string();
                    Ok(axum::body::Bytes::from(format!("data: {}\n\n", error_json)))
                }
            }
        })
        .chain(futures::stream::once(async {
            Ok(axum::body::Bytes::from("data: [DONE]\n\n"))
        }));

    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .header("x-accel-buffering", "no")
        .body(body)
        .map_err(|e| {
            tracing::error!("Failed to build SSE response: {}", e);
            ApiError::internal_server_error("Failed to construct response")
        })
}

/// Create a new agent instance.
///
/// Agent instance limits are enforced for all users to prevent resource exhaustion:
/// - Subscribed users: plan limit from subscription_plans config
/// - Unsubscribed users: no instances allowed (active subscription required)
///
/// Supports two response modes via content negotiation:
/// - Accept: text/event-stream → Returns SSE stream of lifecycle events
/// - Accept: application/json (default) → Returns 201 with complete InstanceResponse
#[utoipa::path(
    post,
    path = "/v1/agents/instances",
    tag = "Agents",
    request_body = CreateInstanceRequest,
    responses(
        (status = 200, description = "Instance creation stream (SSE)"),
        (status = 201, description = "Instance created", body = InstanceResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 402, description = "Payment required - instance limit exceeded for plan", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn create_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    Json(request): Json<CreateInstanceRequest>,
) -> Result<Response, ApiError> {
    tracing::info!("Creating agent instance: user_id={}", user.user_id);

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

    // Get user's active subscriptions
    let subscriptions = app_state
        .subscription_service
        .get_user_subscriptions(user.user_id, true)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch subscriptions: user_id={}, error={}",
                user.user_id,
                e
            );
            ApiError::internal_server_error("Failed to check subscription")
        })?;

    // Get system configs for subscription plans
    let system_configs = app_state
        .system_configs_service
        .get_configs()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch system configs: user_id={}, error={}",
                user.user_id,
                e
            );
            ApiError::internal_server_error("Failed to check plan limits")
        })?;

    // Limit: plan max if subscribed, else 0 (active subscription required).
    let max_allowed: u64 = match (subscriptions.first(), system_configs.as_ref()) {
        (Some(sub), Some(configs)) => configs
            .subscription_plans
            .as_ref()
            .and_then(|plans| plans.get(&sub.plan))
            .map(|plan| {
                plan.agent_instances
                    .as_ref()
                    .map(|l| l.max)
                    .unwrap_or(u64::MAX)
            })
            .unwrap_or(0),
        _ => 0,
    };

    // Enforce the limit
    let (_, total) = app_state
        .agent_service
        .list_instances(user.user_id, 1, 0)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to count instances: user_id={}, error={}",
                user.user_id,
                e
            );
            ApiError::internal_server_error("Failed to check instance count")
        })?;

    let current_count = total as u64;
    if current_count >= max_allowed {
        tracing::warn!(
            "Agent instance limit exceeded: user_id={}, current={}, max={}",
            user.user_id,
            current_count,
            max_allowed
        );
        return Err(ApiError::new(
            axum::http::StatusCode::PAYMENT_REQUIRED,
            "payment_required",
            format!(
                "Agent instance limit of {} exceeded for your plan",
                max_allowed
            ),
        ));
    }

    // Content negotiation: SSE streaming or JSON response
    // Use get_all to handle multiple Accept headers per HTTP spec
    let wants_stream = headers.get_all("accept").iter().any(|v| {
        v.to_str()
            .map(|s| s.contains("text/event-stream"))
            .unwrap_or(false)
    });

    if wants_stream {
        create_instance_streaming_response(
            app_state,
            user.user_id,
            request.image,
            request.name,
            request.ssh_pubkey,
            request.service_type,
            max_allowed,
        )
        .await
    } else {
        let instance = app_state
            .agent_service
            .create_instance_from_agent_api(
                user.user_id,
                request.image,
                request.name,
                request.ssh_pubkey,
                request.service_type,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to create instance: user_id={}, error={}",
                    user.user_id,
                    e
                );
                ApiError::internal_server_error("Failed to create instance")
            })?;

        Ok((
            StatusCode::CREATED,
            Json::<InstanceResponse>(instance.into()),
        )
            .into_response())
    }
}

/// List user's agent instances
#[utoipa::path(
    get,
    path = "/v1/agents/instances",
    tag = "Agents",
    params(
        ("limit" = i64, Query, description = "Maximum items to return"),
        ("offset" = i64, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "Instances retrieved", body = PaginatedResponse<InstanceResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn list_instances(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<InstanceResponse>>, ApiError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);

    tracing::debug!(
        "Listing instances for user: user_id={}, limit={}, offset={}",
        user.user_id,
        limit,
        offset
    );

    // Get instances for the authenticated user from database
    let (instances, total) = app_state
        .agent_service
        .list_instances(user.user_id, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to list instances: user_id={}, error={}",
                user.user_id,
                e
            );
            ApiError::internal_server_error("Failed to list instances")
        })?;

    let enrichment_map = app_state
        .agent_service
        .get_instance_enrichments(&instances)
        .await;

    let paginated: Vec<InstanceResponse> = instances
        .into_iter()
        .map(|inst| {
            let enrichment = enrichment_map.get(&inst.name);
            crate::models::instance_response_with_enrichment(inst, enrichment)
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items: paginated,
        limit,
        offset,
        total,
    }))
}

/// Get a specific agent instance
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance retrieved", body = InstanceResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn get_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Json<InstanceResponse>, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Getting instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
    );

    let instance = app_state
        .agent_service
        .get_instance(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to get instance")
        })?
        .ok_or_else(|| ApiError::not_found("Instance not found"))?;

    let enrichment = app_state
        .agent_service
        .get_instance_enrichment_from_agent_api(
            &instance.name,
            instance.agent_api_base_url.as_deref(),
        )
        .await;

    Ok(Json(crate::models::instance_response_with_enrichment(
        instance,
        enrichment.as_ref(),
    )))
}

/// Create an API key for an instance
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/keys",
    tag = "Agents",
    request_body = CreateApiKeyRequest,
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 201, description = "API key created", body = CreateApiKeyResponse),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn create_api_key(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!(
        "Creating API key: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
    );

    // Parse expiration if provided
    let expires_at = if let Some(expires_str) = request.expires_at {
        Some(
            DateTime::parse_from_rfc3339(&expires_str)
                .map_err(|_| ApiError::bad_request("Invalid expiration timestamp format"))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let (api_key, plaintext_key) = app_state
        .agent_service
        .create_api_key(
            instance_uuid,
            user.user_id,
            request.name,
            request.spend_limit,
            expires_at,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to create API key: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to create API key")
        })?;

    let response = CreateApiKeyResponse {
        id: api_key.id.to_string(),
        name: api_key.name,
        api_key: plaintext_key,
        spend_limit: api_key.spend_limit.map(format_nano_dollars),
        expires_at: api_key.expires_at.map(|e| e.to_rfc3339()),
        created_at: api_key.created_at.to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// List API keys for an instance
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/keys",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID"),
        ("limit" = i64, Query, description = "Maximum items to return"),
        ("offset" = i64, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "API keys retrieved", body = PaginatedResponse<ApiKeyResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn list_api_keys(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<ApiKeyResponse>>, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);

    let (keys, total) = app_state
        .agent_service
        .list_api_keys(instance_uuid, user.user_id, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to list API keys: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to list API keys")
        })?;

    Ok(Json(PaginatedResponse {
        items: keys.into_iter().map(Into::into).collect(),
        limit,
        offset,
        total,
    }))
}

/// Revoke an API key
#[utoipa::path(
    delete,
    path = "/v1/agents/keys/{key_id}",
    tag = "Agents",
    params(
        ("key_id" = String, Path, description = "API Key ID")
    ),
    responses(
        (status = 204, description = "API key revoked"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "API key not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn revoke_api_key(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(key_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let api_key_uuid =
        Uuid::parse_str(&key_id).map_err(|_| ApiError::bad_request("Invalid API key ID format"))?;

    tracing::info!(
        "Revoking API key: api_key_id={}, user_id={}",
        api_key_uuid,
        user.user_id
    );

    app_state
        .agent_service
        .revoke_api_key(api_key_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to revoke API key: api_key_id={}, error={}",
                api_key_uuid,
                e
            );
            ApiError::internal_server_error("Failed to revoke API key")
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get instance usage history
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/usage",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID"),
        ("start_date" = Option<String>, Query, description = "Start date (ISO 8601)"),
        ("end_date" = Option<String>, Query, description = "End date (ISO 8601)"),
        ("limit" = i64, Query, description = "Maximum items to return"),
        ("offset" = i64, Query, description = "Number of items to skip")
    ),
    responses(
        (status = 200, description = "Usage retrieved", body = PaginatedResponse<UsageResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn get_instance_usage(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
    Query(params): Query<UsageQueryParams>,
) -> Result<Json<PaginatedResponse<UsageResponse>>, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    // Parse optional date parameters
    let start_date = if let Some(start_str) = params.start_date {
        Some(
            DateTime::parse_from_rfc3339(&start_str)
                .map_err(|_| ApiError::bad_request("Invalid start_date format"))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let end_date = if let Some(end_str) = params.end_date {
        Some(
            DateTime::parse_from_rfc3339(&end_str)
                .map_err(|_| ApiError::bad_request("Invalid end_date format"))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let (usage, total) = app_state
        .agent_service
        .get_instance_usage(
            instance_uuid,
            user.user_id,
            start_date,
            end_date,
            limit,
            offset,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get usage: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to get usage")
        })?;

    Ok(Json(PaginatedResponse {
        items: usage.into_iter().map(Into::into).collect(),
        limit,
        offset,
        total,
    }))
}

/// Get instance balance
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/balance",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Balance retrieved", body = BalanceResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn get_instance_balance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Getting balance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
    );

    let balance = app_state
        .agent_service
        .get_instance_balance(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get balance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to get balance")
        })?
        .ok_or_else(|| ApiError::not_found("Balance not found"))?;

    Ok(Json(balance.into()))
}

/// Pagination query parameters
#[derive(serde::Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Create agent router with all routes (requires authentication for user routes)
pub fn create_agent_router() -> Router<AppState> {
    Router::new()
        .route("/instances", post(create_instance))
        .route("/instances", get(list_instances))
        .route("/instances/{id}", get(get_instance))
        .route("/instances/{id}/keys", post(create_api_key))
        .route("/instances/{id}/keys", get(list_api_keys))
        .route("/keys/{key_id}", delete(revoke_api_key))
        .route("/instances/{id}/usage", get(get_instance_usage))
        .route("/instances/{id}/balance", get(get_instance_balance))
        .route("/instances/{id}/start", post(start_instance))
        .route("/instances/{id}/stop", post(stop_instance))
        .route("/instances/{id}/restart", post(restart_instance))
        .route("/instances/{id}/upgrade", post(upgrade_instance))
        .route(
            "/instances/{id}/upgrade-available",
            get(check_upgrade_available),
        )
        .route("/instances/{id}", delete(delete_instance))
}

/// Delete an agent instance (user must own it)
#[utoipa::path(
    delete,
    path = "/v1/agents/instances/{id}",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 204, description = "Instance deleted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn delete_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Deleting instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

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

/// Start an agent instance
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/start",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance started"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn start_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Starting instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    // Verify ownership
    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

    app_state
        .agent_service
        .start_instance(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to start instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to start instance")
        })?;

    Response::builder()
        .status(StatusCode::OK)
        .body(axum::body::Body::empty())
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

/// Stop an agent instance
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/stop",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance stopped"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn stop_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Stopping instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    // Verify ownership
    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

    app_state
        .agent_service
        .stop_instance(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to stop instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to stop instance")
        })?;

    Response::builder()
        .status(StatusCode::OK)
        .body(axum::body::Body::empty())
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

/// Restart an agent instance
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/restart",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance restarted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn restart_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Restarting instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    // Verify ownership
    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

    app_state
        .agent_service
        .restart_instance(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to restart instance: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to restart instance")
        })?;

    Response::builder()
        .status(StatusCode::OK)
        .body(axum::body::Body::empty())
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

/// Upgrade an agent instance to the latest image
#[utoipa::path(
    post,
    path = "/v1/agents/instances/{id}/upgrade",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "SSE stream of upgrade progress"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn upgrade_instance(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Upgrading instance: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

    let rx = app_state
        .agent_service
        .upgrade_instance_stream(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to start upgrade stream: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to upgrade instance")
        })?;

    use futures::stream::StreamExt;
    use tokio_stream::wrappers::ReceiverStream;

    let stream = ReceiverStream::new(rx).then(|chunk_result| async move {
        match chunk_result {
            Ok(bytes) => Ok::<_, anyhow::Error>(bytes),
            Err(e) => {
                tracing::error!("Error in upgrade stream: {}", e);
                let error_json = serde_json::json!({
                    "error": "Upgrade failed",
                    "code": "UPGRADE_STREAM_ERROR"
                })
                .to_string();
                Ok(axum::body::Bytes::from(format!("data: {}\n\n", error_json)))
            }
        }
    });

    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .header("x-accel-buffering", "no")
        .body(body)
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

/// Check if an upgrade is available for an agent instance
#[utoipa::path(
    get,
    path = "/v1/agents/instances/{id}/upgrade-available",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Upgrade availability info", body = crate::routes::agents::UpgradeAvailabilityResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - not your instance", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn check_upgrade_available(
    State(app_state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::debug!(
        "Checking upgrade availability: instance_id={}, user_id={}",
        instance_uuid,
        user.user_id
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

    if instance.user_id != user.user_id {
        return Err(ApiError::forbidden("This instance does not belong to you"));
    }

    let upgrade_info = app_state
        .agent_service
        .check_upgrade_available(instance_uuid, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to check upgrade availability: instance_id={}, error={}",
                instance_uuid,
                e
            );
            ApiError::internal_server_error("Failed to check upgrade availability")
        })?;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&UpgradeAvailabilityResponse {
                has_upgrade: upgrade_info.has_upgrade,
                current_image: upgrade_info.current_image,
                latest_image: upgrade_info.latest_image,
            })
            .map_err(|_| ApiError::internal_server_error("Failed to serialize response"))?,
        ))
        .map_err(|_| ApiError::internal_server_error("Failed to construct response"))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UpgradeAvailabilityResponse {
    pub has_upgrade: bool,
    pub current_image: Option<String>,
    pub latest_image: String,
}
