use crate::{
    error::ApiError,
    middleware::{AuthenticatedApiKey, AuthenticatedUser},
    models::*,
    state::AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::DateTime;
use uuid::Uuid;

/// List user's OpenClaw instances
#[utoipa::path(
    get,
    path = "/v1/openclaw/instances",
    tag = "OpenClaw",
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

/// Get a specific OpenClaw instance
#[utoipa::path(
    get,
    path = "/v1/openclaw/instances/{id}",
    tag = "OpenClaw",
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

/// Request body for admin creating instance for a user
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AdminCreateInstanceRequest {
    /// User ID to create the instance for
    pub user_id: Uuid,
    /// OpenClaw API key for authentication
    pub nearai_api_key: String,
    /// Image to use for the instance (optional)
    #[serde(default)]
    pub image: Option<String>,
    /// Instance name (optional)
    #[serde(default)]
    pub name: Option<String>,
    /// SSH public key (optional)
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
}

/// Admin endpoint: Create an OpenClaw instance for a specific user
#[utoipa::path(
    post,
    path = "/v1/admin/openclaw/instances",
    tag = "OpenClaw Admin",
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
        "Admin: Creating OpenClaw instance for user_id={}",
        request.user_id
    );

    let instance = app_state
        .agent_service
        .create_instance_from_openclaw(
            services::UserId(request.user_id),
            request.nearai_api_key,
            request.image,
            request.name,
            request.ssh_pubkey,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Admin: Failed to create instance for user_id={}: error={}",
                request.user_id,
                e
            );
            ApiError::internal_server_error("Failed to create instance")
        })?;

    Ok((StatusCode::CREATED, Json(instance.into())))
}

/// Admin endpoint: Delete an OpenClaw instance
#[utoipa::path(
    delete,
    path = "/v1/admin/openclaw/instances/{id}",
    tag = "OpenClaw Admin",
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

/// Create an API key for an instance
#[utoipa::path(
    post,
    path = "/v1/openclaw/instances/{id}/keys",
    tag = "OpenClaw",
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
    path = "/v1/openclaw/instances/{id}/keys",
    tag = "OpenClaw",
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
    path = "/v1/openclaw/keys/{key_id}",
    tag = "OpenClaw",
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
    path = "/v1/openclaw/instances/{id}/usage",
    tag = "OpenClaw",
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
    path = "/v1/openclaw/instances/{id}/balance",
    tag = "OpenClaw",
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

/// Admin endpoint: List all OpenClaw instances (all users' instances)
#[utoipa::path(
    get,
    path = "/v1/admin/openclaw/instances",
    tag = "OpenClaw Admin",
    responses(
        (status = 200, description = "All instances retrieved", body = Vec<InstanceResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_list_all_instances(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<InstanceResponse>>, ApiError> {
    tracing::info!("Admin: Listing all OpenClaw instances");

    // Call OpenClaw API to get all instances
    let instances = app_state
        .agent_service
        .list_instances_from_openclaw(_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list all instances: error={}", e);
            ApiError::internal_server_error("Failed to list instances")
        })?;

    let response: Vec<InstanceResponse> = instances.into_iter().map(Into::into).collect();
    Ok(Json(response))
}

/// OpenClaw chat completions endpoint - routes requests to OpenClaw instances
/// Requires OpenClaw API key authentication
#[utoipa::path(
    post,
    path = "/v1/openclaw/chat/completions",
    tag = "OpenClaw",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Chat completion response"),
        (status = 400, description = "Bad request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("api_key" = []))
)]
pub async fn openclaw_chat_completions(
    State(app_state): State<AppState>,
    Extension(api_key): Extension<AuthenticatedApiKey>,
    body: Bytes,
) -> Result<Response, ApiError> {
    tracing::info!(
        "OpenClaw chat completions: user_id={}, instance_id={}, api_key_id={}",
        api_key.api_key_info.user_id,
        api_key.instance.id,
        api_key.api_key_info.id
    );

    // Forward request to instance
    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &api_key.instance,
            "/v1/chat/completions",
            "POST",
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to forward chat completions request: instance_id={}, error={}",
                api_key.instance.id,
                e
            );
            ApiError::internal_server_error("Failed to forward request to OpenClaw instance")
        })?;

    // TODO: Add usage tracking for streaming responses
    // For now, just forward the response
    let response_body = axum::body::Body::from_stream(body_stream);
    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}

/// Create OpenClaw router with all routes (requires authentication for user routes)
pub fn create_openclaw_router() -> Router<AppState> {
    Router::new()
        .route("/instances", get(list_instances))
        .route("/instances/{id}", get(get_instance))
        .route("/instances/{id}/keys", post(create_api_key))
        .route("/instances/{id}/keys", get(list_api_keys))
        .route("/keys/{key_id}", delete(revoke_api_key))
        .route("/instances/{id}/usage", get(get_instance_usage))
        .route("/instances/{id}/balance", get(get_instance_balance))
}

/// Start an OpenClaw instance
#[utoipa::path(
    post,
    path = "/v1/admin/openclaw/instances/{id}/start",
    tag = "OpenClaw Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance started"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_start_instance(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Starting instance: instance_id={}", instance_uuid);

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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/start", instance.instance_id),
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

/// Stop an OpenClaw instance
#[utoipa::path(
    post,
    path = "/v1/admin/openclaw/instances/{id}/stop",
    tag = "OpenClaw Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance stopped"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_stop_instance(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Stopping instance: instance_id={}", instance_uuid);

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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/stop", instance.instance_id),
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

/// Restart an OpenClaw instance
#[utoipa::path(
    post,
    path = "/v1/admin/openclaw/instances/{id}/restart",
    tag = "OpenClaw Admin",
    params(
        ("id" = String, Path, description = "Instance ID")
    ),
    responses(
        (status = 200, description = "Instance restarted"),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden - admin only", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Instance not found", body = crate::error::ApiErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ApiErrorResponse)
    ),
    security(("session_token" = []))
)]
pub async fn admin_restart_instance(
    State(app_state): State<AppState>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(instance_id): Path<String>,
) -> Result<Response, ApiError> {
    let instance_uuid = Uuid::parse_str(&instance_id)
        .map_err(|_| ApiError::bad_request("Invalid instance ID format"))?;

    tracing::info!("Admin: Restarting instance: instance_id={}", instance_uuid);

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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/restart", instance.instance_id),
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

/// Create a backup of an OpenClaw instance
#[utoipa::path(
    post,
    path = "/v1/admin/openclaw/instances/{id}/backup",
    tag = "OpenClaw Admin",
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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/backup", instance.instance_id),
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

/// List backups for an OpenClaw instance
#[utoipa::path(
    get,
    path = "/v1/admin/openclaw/instances/{id}/backups",
    tag = "OpenClaw Admin",
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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!("/v1/instances/{}/backups", instance.instance_id),
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

/// Get backup details for an OpenClaw instance
#[utoipa::path(
    get,
    path = "/v1/admin/openclaw/instances/{id}/backups/{backup_id}",
    tag = "OpenClaw Admin",
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

    // SECURITY: Validate backup_id to prevent path traversal attacks
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

    let (status, headers, body_stream) = app_state
        .agent_proxy_service
        .forward_request(
            &instance,
            &format!(
                "/v1/instances/{}/backups/{}",
                instance.instance_id, backup_id
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

/// Create admin OpenClaw router (admin-only routes)
pub fn create_admin_openclaw_router() -> Router<AppState> {
    Router::new()
        .route("/instances", post(admin_create_instance))
        .route("/instances", get(admin_list_all_instances))
        .route("/instances/{id}", delete(admin_delete_instance))
        .route("/instances/{id}/start", post(admin_start_instance))
        .route("/instances/{id}/stop", post(admin_stop_instance))
        .route("/instances/{id}/restart", post(admin_restart_instance))
        .route("/instances/{id}/backup", post(admin_create_backup))
        .route("/instances/{id}/backups", get(admin_list_backups))
        .route("/instances/{id}/backups/{backup_id}", get(admin_get_backup))
}
