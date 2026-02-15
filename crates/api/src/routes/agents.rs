use crate::{error::ApiError, middleware::AuthenticatedUser, models::*, state::AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::DateTime;
use urlencoding::encode;
use uuid::Uuid;

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

    let paginated: Vec<InstanceResponse> = instances.into_iter().map(Into::into).collect();

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

    Ok(Json(instance.into()))
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

    let encoded_instance_id = encode(&instance.instance_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/start", encoded_instance_id),
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
            ApiError::internal_server_error("Failed to start instance")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
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

    let encoded_instance_id = encode(&instance.instance_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/stop", encoded_instance_id),
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
            ApiError::internal_server_error("Failed to stop instance")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
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

    let encoded_instance_id = encode(&instance.instance_id);
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/restart", encoded_instance_id),
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
            ApiError::internal_server_error("Failed to restart instance")
        })?;

    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}
