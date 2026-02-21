use crate::consts::{LIST_FILES_LIMIT_MAX, MAX_REQUEST_BODY_SIZE, MAX_RESPONSE_BODY_SIZE};
use crate::middleware::auth::{AuthenticatedApiKey, AuthenticatedUser};
use crate::usage_parsing::{
    parse_chat_completion_usage_from_bytes, parse_response_usage_from_bytes,
    UsageTrackingStreamChatCompletions, UsageTrackingStreamResponseCompleted,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::{Duration, Utc};
use flate2::read::GzDecoder;
use futures::stream;
use http::{header::CONTENT_LENGTH, HeaderValue};
use multer::Multipart;
use near_api::{Account, AccountId, NetworkConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use services::analytics::{ActivityType, RecordActivityRequest};
use services::consts::MODEL_PUBLIC_DEFAULT;
use services::conversation::ports::{
    ConversationError, SharePermission, ShareRecipient, ShareRecipientKind, ShareTarget,
};
use services::file::ports::FileError;
use services::metrics::consts::{
    METRIC_CONVERSATION_CREATED, METRIC_FILE_UPLOADED, METRIC_RESPONSE_CREATED,
};
use services::response::ports::ProxyResponse;
use services::user::ports::{BanType, OAuthProvider};
use services::UserId;
use std::io::Read;
use utoipa::ToSchema;
use uuid::Uuid;

/// Minimum required NEAR balance (1 NEAR in yoctoNEAR: 10^24)
const MIN_NEAR_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

/// Duration of user ban after NEAR balance check fails (in seconds)
const NEAR_BALANCE_BAN_DURATION_SECS: i64 = 60 * 60;

/// Duration to cache NEAR balance checks in memory (in seconds)
const NEAR_BALANCE_CACHE_TTL_SECS: i64 = 5 * 60;

/// Duration to cache model settings needed by /v1/responses in memory (in seconds)
const MODEL_SETTINGS_CACHE_TTL_SECS: i64 = 60;

/// Auto-routing: target model and default parameters for `model: "auto"` requests
pub const AUTO_ROUTE_MODEL: &str = "zai-org/GLM-5-FP8";
pub const AUTO_ROUTE_TEMPERATURE: f64 = 1.0;
pub const AUTO_ROUTE_TOP_P: f64 = 0.95;
pub const AUTO_ROUTE_MAX_TOKENS: u64 = 4096;

/// Error message when a user is banned
pub const USER_BANNED_ERROR_MESSAGE: &str =
    "Access temporarily restricted. Please try again later.";

/// Error message when subscription is required but user has none
pub const SUBSCRIPTION_REQUIRED_ERROR_MESSAGE: &str =
    "Active subscription required. Please subscribe to continue.";

/// Error message when monthly token limit is exceeded
pub const MONTHLY_TOKEN_LIMIT_EXCEEDED_MESSAGE: &str =
    "Monthly token limit exceeded. Upgrade your plan or wait for the next billing period.";

/// OpenAPI tag constants for API documentation
mod openapi_tags {
    pub const CONVERSATIONS: &str = "Conversations";
    pub const SHARE_GROUPS: &str = "Share Groups";
    pub const FILES: &str = "Files";
    pub const PROXY: &str = "Proxy";
}

/// OpenAPI error description constants for API documentation
mod openapi_errors {
    pub const BAD_REQUEST: &str = "Bad request";
    pub const UNAUTHORIZED: &str = "Unauthorized";
    pub const ACCESS_DENIED: &str = "Access denied";
    pub const CONVERSATION_NOT_FOUND: &str = "Conversation not found";
    pub const SHARE_GROUP_NOT_FOUND: &str = "Share group not found";
    pub const CONVERSATION_OR_SHARE_NOT_FOUND: &str = "Conversation or share not found";
    pub const OPENAI_API_ERROR: &str = "OpenAI API error";
}

use openapi_errors::*;
use openapi_tags::*;

/// Create router for conversation read routes that work with optional authentication
/// These routes can be accessed by both authenticated users and unauthenticated users
/// (for publicly shared conversations)
pub fn create_optional_auth_router() -> Router<crate::state::AppState> {
    Router::new()
        .route("/v1/conversations/{conversation_id}", get(get_conversation))
        .route(
            "/v1/conversations/{conversation_id}/items",
            get(list_conversation_items),
        )
}

/// Create the unified API router with all v1 proxy and API routes.
///
/// Route groups and their middleware:
/// - Chat completions, images, responses: dual auth + subscription + rate limited
/// - Model list, models, signature: dual auth only (not rate limited)
/// - Conversations, share groups, files: session auth only
pub fn create_api_router(
    rate_limit_state: crate::middleware::RateLimitState,
    dual_auth_state: crate::middleware::DualAuthState,
    auth_state: crate::middleware::AuthState,
    subscription_state: crate::middleware::SubscriptionState,
) -> Router<crate::state::AppState> {
    // Dual auth + subscription + rate limited: chat completions, images, responses
    let llm_proxy_router = Router::new()
        .route("/v1/chat/completions", post(proxy_chat_completions))
        .route("/v1/images/generations", post(proxy_image_generations))
        .route("/v1/images/edits", post(proxy_image_edits))
        .route("/v1/responses", post(proxy_responses))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state.clone(),
            crate::middleware::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            subscription_state,
            crate::middleware::subscription_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            dual_auth_state.clone(),
            crate::middleware::dual_auth_middleware,
        ));

    // Dual auth only (not rate limited): model list, models, signature
    let models_proxy_router = Router::new()
        .route("/v1/model/list", get(proxy_model_list))
        .route("/v1/models", get(proxy_models))
        .route("/v1/signature/{chat_id}", get(proxy_signature))
        .layer(axum::middleware::from_fn_with_state(
            dual_auth_state,
            crate::middleware::dual_auth_middleware,
        ));

    // Session auth only: conversations, share groups, files
    let conversations_router = Router::new()
        .route(
            "/v1/conversations",
            post(create_conversation).get(list_conversations),
        )
        .route(
            "/v1/conversations/{conversation_id}",
            post(update_conversation).delete(delete_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/shares",
            post(create_conversation_share).get(list_conversation_shares),
        )
        .route(
            "/v1/conversations/{conversation_id}/shares/{share_id}",
            delete(delete_conversation_share),
        )
        .route(
            "/v1/conversations/{conversation_id}/items",
            post(create_conversation_items),
        )
        .route(
            "/v1/conversations/{conversation_id}/pin",
            post(pin_conversation).delete(unpin_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/archive",
            post(archive_conversation).delete(unarchive_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/clone",
            post(clone_conversation),
        );

    let share_groups_router = Router::new()
        .route(
            "/v1/share-groups",
            post(create_share_group).get(list_share_groups),
        )
        .route(
            "/v1/share-groups/{group_id}",
            patch(update_share_group).delete(delete_share_group),
        )
        .route("/v1/shared-with-me", get(list_shared_with_me));

    let files_router = Router::new()
        .route("/v1/files", post(upload_file).get(list_files))
        .route("/v1/files/{file_id}", get(get_file).delete(delete_file))
        .route("/v1/files/{file_id}/content", get(get_file_content));

    let session_auth_routes = Router::new()
        .merge(conversations_router)
        .merge(share_groups_router)
        .merge(files_router)
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            crate::middleware::auth_middleware,
        ));

    Router::new()
        .merge(llm_proxy_router)
        .merge(models_proxy_router)
        .merge(session_auth_routes)
}

/// Type of resource to track in the response
enum TrackableResource {
    /// New conversation - records metrics
    Conversation,
    /// Updated conversation - tracks in DB but does NOT record metrics
    ConversationUpdate,
    File,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ShareRecipientPayload {
    pub kind: ShareRecipientKind,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ShareTargetPayload {
    Direct {
        recipients: Vec<ShareRecipientPayload>,
    },
    Group {
        group_id: Uuid,
    },
    Organization {
        email_pattern: String,
    },
    Public,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateConversationShareRequest {
    pub permission: SharePermission,
    pub target: ShareTargetPayload,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConversationShareResponse {
    pub id: Uuid,
    pub conversation_id: String,
    pub permission: SharePermission,
    pub share_type: String,
    pub recipient: Option<ShareRecipientPayload>,
    pub group_id: Option<Uuid>,
    pub org_email_pattern: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OwnerInfo {
    pub user_id: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConversationSharesListResponse {
    pub is_owner: bool,
    pub can_share: bool,
    /// Whether the user can send messages (has write access)
    pub can_write: bool,
    pub shares: Vec<ConversationShareResponse>,
    /// Owner information for displaying author names on messages
    pub owner: Option<OwnerInfo>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateShareGroupRequest {
    pub name: String,
    pub members: Vec<ShareRecipientPayload>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateShareGroupRequest {
    pub name: Option<String>,
    pub members: Option<Vec<ShareRecipientPayload>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareGroupResponse {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<ShareRecipientPayload>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ShareRecipientPayload> for ShareRecipient {
    fn from(payload: ShareRecipientPayload) -> Self {
        ShareRecipient {
            kind: payload.kind,
            value: payload.value,
        }
    }
}

impl From<ShareRecipient> for ShareRecipientPayload {
    fn from(recipient: ShareRecipient) -> Self {
        ShareRecipientPayload {
            kind: recipient.kind,
            value: recipient.value,
        }
    }
}

fn to_share_response(
    share: services::conversation::ports::ConversationShare,
) -> ConversationShareResponse {
    ConversationShareResponse {
        id: share.id,
        conversation_id: share.conversation_id,
        permission: share.permission,
        share_type: share.share_type.as_str().to_string(),
        recipient: share.recipient.map(ShareRecipientPayload::from),
        group_id: share.group_id,
        org_email_pattern: share.org_email_pattern,
        created_at: share.created_at,
        updated_at: share.updated_at,
    }
}

fn to_share_group_response(group: services::conversation::ports::ShareGroup) -> ShareGroupResponse {
    ShareGroupResponse {
        id: group.id,
        name: group.name,
        members: group
            .members
            .into_iter()
            .map(ShareRecipientPayload::from)
            .collect(),
        created_at: group.created_at,
        updated_at: group.updated_at,
    }
}

/// Raw query parameters for listing files
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ListFilesParams {
    pub after: Option<String>,
    pub limit: Option<i64>,
    pub order: Option<String>,
    pub purpose: Option<String>,
}

/// Validated and normalized list files parameters
#[derive(Debug)]
pub struct ValidatedListFilesParams {
    pub after: Option<String>,
    pub limit: i64,
    pub order: String,
    pub purpose: Option<String>,
}

impl ListFilesParams {
    /// Validate query parameters and return normalized values (with defaults applied)
    fn validate(self) -> Result<ValidatedListFilesParams, (StatusCode, Json<ErrorResponse>)> {
        // Apply default values
        let limit = self.limit.unwrap_or(LIST_FILES_LIMIT_MAX);
        if !(1..=LIST_FILES_LIMIT_MAX).contains(&limit) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid limit parameter. Must be between 1 and {}",
                        LIST_FILES_LIMIT_MAX
                    ),
                }),
            ));
        }

        let order = self.order.unwrap_or_else(|| "desc".to_string());
        if order != "asc" && order != "desc" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid order parameter. Must be 'asc' or 'desc'".to_string(),
                }),
            ));
        }

        Ok(ValidatedListFilesParams {
            after: self.after,
            limit,
            order,
            purpose: self.purpose,
        })
    }
}

/// Create a conversation - forwards to OpenAI and tracks in DB
#[utoipa::path(
    post,
    path = "/v1/conversations",
    tag = CONVERSATIONS,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Conversation created successfully", body = serde_json::Value),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn create_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "create_conversation called for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Extract body
    let body_bytes = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to read request body for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Failed to read request body: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::debug!(
        "create_conversation request body size: {} bytes for user_id={}",
        body_bytes.len(),
        user.user_id
    );

    if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
        tracing::debug!("Request body: {}", body_str);
    }

    tracing::debug!(
        "Forwarding conversation creation request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            "conversations",
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation creation for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    handle_trackable_response(
        &state,
        &user,
        proxy_response,
        TrackableResource::Conversation,
    )
    .await
}

/// Update a conversation - validates user access then forwards to OpenAI and updates tracking
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to update")
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Conversation updated successfully", body = serde_json::Value),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn update_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "update_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    // Validate user has access to the conversation
    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    // Extract body
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "update_conversation request body size: {} bytes for user_id={}",
        body_bytes.len(),
        user.user_id
    );

    if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
        tracing::debug!("Request body: {}", body_str);
    }

    tracing::debug!(
        "Forwarding conversation update request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            &format!("conversations/{conversation_id}"),
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation update for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    // Track the updated conversation (don't fail the request if tracking fails)
    // Use ConversationUpdate to avoid recording metrics for updates
    handle_trackable_response(
        &state,
        &user,
        proxy_response,
        TrackableResource::ConversationUpdate,
    )
    .await
}

/// List all conversations for the authenticated user (fetches details from OpenAI client)
#[utoipa::path(
    get,
    path = "/v1/conversations",
    tag = CONVERSATIONS,
    responses(
        (status = 200, description = "List of conversations retrieved successfully", body = Vec<serde_json::Value>),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn list_conversations(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Response, Response> {
    tracing::info!("list_conversations called for user_id={}", user.user_id);

    let conversations = state
        .conversation_service
        .list_conversations(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to list conversations for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to list conversations: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Retrieved {} conversations for user_id={}",
        conversations.len(),
        user.user_id
    );

    Ok(Json(conversations).into_response())
}

/// Get a conversation - validates user access or public share and fetches details via service/OpenAI
/// Works with optional authentication - authenticated users get their access checked,
/// unauthenticated users can only access publicly shared conversations
///
/// # Authentication
/// This endpoint supports **optional authentication**:
/// - **With authentication**: Returns conversation if user owns it or has been granted access via sharing
/// - **Without authentication**: Returns conversation only if it has been publicly shared
///
/// This allows public sharing of conversations while maintaining access control for private conversations.
#[utoipa::path(
    get,
    path = "/v1/conversations/{conversation_id}",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to retrieve")
    ),
    responses(
        (status = 200, description = "Conversation retrieved successfully", body = serde_json::Value),
        (status = 403, description = "Access denied - conversation not accessible to this user or not publicly shared"),
        (status = 404, description = CONVERSATION_NOT_FOUND)
    ),
    security(
        (), // Optional - no auth required for publicly shared conversations
        ("session_token" = []) // Optional - session token for authenticated access
    )
)]
async fn get_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<Option<AuthenticatedUser>>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    tracing::info!(
        "get_conversation called for user_id={:?}, conversation_id={}",
        user.as_ref().map(|u| u.user_id),
        conversation_id
    );

    // Check user access OR public share access
    validate_conversation_access_optional_auth(
        &state,
        user.as_ref(),
        &conversation_id,
        SharePermission::Read,
    )
    .await?;

    let conversation =
        fetch_conversation_from_proxy(&state, &conversation_id, headers.clone()).await?;

    Ok(Json(conversation))
}

/// Delete a conversation for the authenticated user
#[utoipa::path(
    delete,
    path = "/v1/conversations/{conversation_id}",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to delete")
    ),
    responses(
        (status = 200, description = "Conversation deleted successfully", body = serde_json::Value),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn delete_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
) -> Result<Response, Response> {
    tracing::info!(
        "delete_conversation called for user_id={}, conversation_id={}",
        user.user_id,
        conversation_id
    );

    validate_owner_conversation(&state, &user, &conversation_id).await?;

    // Delete from DB and OpenAI
    let deleted = state
        .conversation_service
        .delete_conversation(&conversation_id, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to delete conversation {} for user_id={}: {}",
                conversation_id,
                user.user_id,
                e
            );

            let (status, msg) = match e {
                ConversationError::NotFound => {
                    (StatusCode::NOT_FOUND, "Conversation not found".to_string())
                }
                ConversationError::ApiError(msg) => {
                    (StatusCode::BAD_GATEWAY, format!("OpenAI API error: {msg}"))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to delete conversation".to_string(),
                ),
            };

            (status, Json(ErrorResponse { error: msg })).into_response()
        })?;

    Ok(Json(deleted).into_response())
}

/// Create a share for a conversation
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}/shares",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to share")
    ),
    request_body = CreateConversationShareRequest,
    responses(
        (status = 200, description = "Share(s) created successfully", body = Vec<ConversationShareResponse>),
        (status = 400, description = "Bad request - invalid recipients or empty list", body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn create_conversation_share(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    Json(request): Json<CreateConversationShareRequest>,
) -> Result<Json<Vec<ConversationShareResponse>>, Response> {
    let target = match request.target {
        ShareTargetPayload::Direct { recipients } => {
            if recipients.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Recipients list cannot be empty".to_string(),
                    }),
                )
                    .into_response());
            }

            // Validate all recipients before processing
            for recipient in &recipients {
                crate::validation::validate_share_recipient(&recipient.kind, &recipient.value)
                    .map_err(|error| {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: format!(
                                    "Invalid {} recipient '{}': {}",
                                    match recipient.kind {
                                        ShareRecipientKind::Email => "email",
                                        ShareRecipientKind::NearAccount => "NEAR account",
                                    },
                                    recipient.value,
                                    error
                                ),
                            }),
                        )
                            .into_response()
                    })?;
            }

            ShareTarget::Direct(
                recipients
                    .into_iter()
                    .map(ShareRecipient::from)
                    .collect::<Vec<_>>(),
            )
        }
        ShareTargetPayload::Group { group_id } => ShareTarget::Group(group_id),
        ShareTargetPayload::Organization { email_pattern } => {
            let validated_pattern = crate::validation::validate_org_email_pattern(&email_pattern)
                .map_err(|error| {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response()
            })?;

            ShareTarget::Organization(validated_pattern)
        }
        ShareTargetPayload::Public => ShareTarget::Public,
    };

    let shares = state
        .conversation_share_service
        .create_share(user.user_id, &conversation_id, request.permission, target)
        .await
        .map_err(map_share_error)?;

    // Record share activity in analytics
    if let Err(e) = state
        .analytics_service
        .record_activity(RecordActivityRequest {
            user_id: user.user_id,
            activity_type: ActivityType::Share,
            auth_method: None,
            metadata: Some(serde_json::json!({
                "conversation_id": conversation_id,
                "share_count": shares.len(),
                "permission": request.permission.as_str(),
            })),
        })
        .await
    {
        tracing::warn!("Failed to record analytics for share creation: {}", e);
    }

    Ok(Json(
        shares
            .into_iter()
            .map(to_share_response)
            .collect::<Vec<_>>(),
    ))
}

/// List all shares for a conversation
#[utoipa::path(
    get,
    path = "/v1/conversations/{conversation_id}/shares",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to list shares for")
    ),
    responses(
        (status = 200, description = "List of shares retrieved successfully", body = ConversationSharesListResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn list_conversation_shares(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
) -> Result<Json<ConversationSharesListResponse>, Response> {
    // Get the actual owner of the conversation from the database
    let owner_id = state
        .conversation_service
        .get_conversation_owner(&conversation_id)
        .await
        .map_err(map_share_error)?;

    // Check if current user is the owner
    let is_owner = owner_id.map(|o| o == user.user_id).unwrap_or(false);

    // Check if user has write access (owner OR shared with write permission)
    let has_write_access = is_owner
        || state
            .conversation_share_service
            .ensure_access(&conversation_id, user.user_id, SharePermission::Write)
            .await
            .is_ok();

    // Get owner info for displaying author names on messages
    let owner_info = if let Some(owner_user_id) = owner_id {
        state
            .user_service
            .get_user_profile(owner_user_id)
            .await
            .ok()
            .map(|profile| OwnerInfo {
                user_id: owner_user_id.to_string(),
                name: profile.user.name,
            })
    } else {
        None
    };

    // List shares - owners and users with write access can see shares
    let shares = if has_write_access {
        if let Some(owner_user_id) = owner_id {
            state
                .conversation_share_service
                .list_shares(owner_user_id, &conversation_id)
                .await
                .map_err(map_share_error)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(Json(ConversationSharesListResponse {
        is_owner,
        can_share: has_write_access,
        can_write: has_write_access,
        shares: shares.into_iter().map(to_share_response).collect(),
        owner: owner_info,
    }))
}

/// Delete a share for a conversation
#[utoipa::path(
    delete,
    path = "/v1/conversations/{conversation_id}/shares/{share_id}",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation"),
        ("share_id" = Uuid, Path, description = "ID of the share to delete")
    ),
    responses(
        (status = 204, description = "Share deleted successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_OR_SHARE_NOT_FOUND, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn delete_conversation_share(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((conversation_id, share_id)): Path<(String, Uuid)>,
) -> Result<Response, Response> {
    state
        .conversation_share_service
        .delete_share(user.user_id, &conversation_id, share_id)
        .await
        .map_err(map_share_error)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Create a share group
#[utoipa::path(
    post,
    path = "/v1/share-groups",
    tag = SHARE_GROUPS,
    request_body = CreateShareGroupRequest,
    responses(
        (status = 200, description = "Share group created successfully", body = ShareGroupResponse),
        (status = 400, description = "Bad request - empty name or members", body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn create_share_group(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<CreateShareGroupRequest>,
) -> Result<Json<ShareGroupResponse>, Response> {
    if request.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Group name cannot be empty".to_string(),
            }),
        )
            .into_response());
    }

    if request.members.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Group must include at least one member".to_string(),
            }),
        )
            .into_response());
    }

    // Validate all members before processing
    for member in &request.members {
        crate::validation::validate_share_recipient(&member.kind, &member.value).map_err(
            |error| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!(
                            "Invalid {} member '{}': {}",
                            match member.kind {
                                ShareRecipientKind::Email => "email",
                                ShareRecipientKind::NearAccount => "NEAR account",
                            },
                            member.value,
                            error
                        ),
                    }),
                )
                    .into_response()
            },
        )?;
    }

    let members = request
        .members
        .into_iter()
        .map(ShareRecipient::from)
        .collect();

    let group = state
        .conversation_share_service
        .create_group(user.user_id, &request.name, members)
        .await
        .map_err(map_share_error)?;

    Ok(Json(to_share_group_response(group)))
}

/// List all share groups for the authenticated user
#[utoipa::path(
    get,
    path = "/v1/share-groups",
    tag = SHARE_GROUPS,
    responses(
        (status = 200, description = "List of share groups retrieved successfully", body = Vec<ShareGroupResponse>),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn list_share_groups(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<ShareGroupResponse>>, Response> {
    // Get user profile to extract email and NEAR accounts for membership matching
    let user_profile = state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get user profile: {}", e),
                }),
            )
                .into_response()
        })?;

    // Build member identifiers from user's email and linked NEAR accounts
    let mut member_identifiers = vec![ShareRecipient {
        kind: ShareRecipientKind::Email,
        value: user_profile.user.email.to_lowercase(),
    }];

    // Add NEAR accounts from linked accounts
    for account in &user_profile.linked_accounts {
        if account.provider == services::user::ports::OAuthProvider::Near {
            member_identifiers.push(ShareRecipient {
                kind: ShareRecipientKind::NearAccount,
                value: account.provider_user_id.clone(),
            });
        }
    }

    let groups = state
        .conversation_share_service
        .list_accessible_groups(user.user_id, &member_identifiers)
        .await
        .map_err(map_share_error)?;

    Ok(Json(
        groups
            .into_iter()
            .map(to_share_group_response)
            .collect::<Vec<_>>(),
    ))
}

/// Update a share group
#[utoipa::path(
    patch,
    path = "/v1/share-groups/{group_id}",
    tag = SHARE_GROUPS,
    params(
        ("group_id" = Uuid, Path, description = "ID of the share group to update")
    ),
    request_body = UpdateShareGroupRequest,
    responses(
        (status = 200, description = "Share group updated successfully", body = ShareGroupResponse),
        (status = 400, description = "Bad request - empty name or members", body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = SHARE_GROUP_NOT_FOUND, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn update_share_group(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<UpdateShareGroupRequest>,
) -> Result<Json<ShareGroupResponse>, Response> {
    if matches!(request.name.as_deref(), Some(name) if name.trim().is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Group name cannot be empty".to_string(),
            }),
        )
            .into_response());
    }

    if matches!(request.members.as_ref(), Some(members) if members.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Group members cannot be empty".to_string(),
            }),
        )
            .into_response());
    }

    // Validate all members before processing
    if let Some(ref members) = request.members {
        for member in members {
            crate::validation::validate_share_recipient(&member.kind, &member.value).map_err(
                |error| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: format!(
                                "Invalid {} member '{}': {}",
                                match member.kind {
                                    ShareRecipientKind::Email => "email",
                                    ShareRecipientKind::NearAccount => "NEAR account",
                                },
                                member.value,
                                error
                            ),
                        }),
                    )
                        .into_response()
                },
            )?;
        }
    }

    let members = request.members.map(|members| {
        members
            .into_iter()
            .map(ShareRecipient::from)
            .collect::<Vec<_>>()
    });

    let group = state
        .conversation_share_service
        .update_group(user.user_id, group_id, request.name, members)
        .await
        .map_err(map_share_error)?;

    Ok(Json(to_share_group_response(group)))
}

/// Delete a share group
#[utoipa::path(
    delete,
    path = "/v1/share-groups/{group_id}",
    tag = SHARE_GROUPS,
    params(
        ("group_id" = Uuid, Path, description = "ID of the share group to delete")
    ),
    responses(
        (status = 204, description = "Share group deleted successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = SHARE_GROUP_NOT_FOUND, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn delete_share_group(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(group_id): Path<Uuid>,
) -> Result<Response, Response> {
    state
        .conversation_share_service
        .delete_group(user.user_id, group_id)
        .await
        .map_err(map_share_error)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Serialize, ToSchema)]
pub struct SharedConversationInfo {
    conversation_id: String,
    permission: SharePermission,
    /// Conversation title (None if fetch failed)
    title: Option<String>,
    /// Conversation created_at timestamp (None if fetch failed)
    created_at: Option<i64>,
    /// Error message if conversation details couldn't be fetched
    error: Option<String>,
}

/// Maximum concurrent requests when fetching conversation details
const SHARED_CONVERSATIONS_FETCH_CONCURRENCY: usize = 10;

/// List conversations shared with the authenticated user
#[utoipa::path(
    get,
    path = "/v1/shared-with-me",
    tag = SHARE_GROUPS,
    responses(
        (status = 200, description = "List of shared conversations retrieved successfully", body = Vec<SharedConversationInfo>),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn list_shared_with_me(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Result<Json<Vec<SharedConversationInfo>>, Response> {
    let shared = state
        .conversation_share_service
        .list_shared_with_me(user.user_id)
        .await
        .map_err(map_share_error)?;

    if shared.is_empty() {
        return Ok(Json(vec![]));
    }

    // Fetch conversation details with concurrency limit
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        SHARED_CONVERSATIONS_FETCH_CONCURRENCY,
    ));

    let fetch_tasks: Vec<_> = shared
        .into_iter()
        .map(|(conversation_id, permission)| {
            let state = state.clone();
            let headers = headers.clone();
            let semaphore = semaphore.clone();

            async move {
                let _permit = semaphore.acquire().await;
                let result = fetch_conversation_from_proxy(&state, &conversation_id, headers).await;

                match result {
                    Ok(conversation) => {
                        let title = conversation
                            .get("metadata")
                            .and_then(|m| m.get("title"))
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string());
                        let created_at = conversation.get("created_at").and_then(|c| c.as_i64());

                        SharedConversationInfo {
                            conversation_id,
                            permission,
                            title,
                            created_at,
                            error: None,
                        }
                    }
                    Err(_) => SharedConversationInfo {
                        conversation_id,
                        permission,
                        title: None,
                        created_at: None,
                        error: Some("Failed to fetch conversation details".to_string()),
                    },
                }
            }
        })
        .collect();

    let results = futures::future::join_all(fetch_tasks).await;

    Ok(Json(results))
}

/// Create items in a conversation
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}/items",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to add items to")
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Items created successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn create_conversation_items(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "create_conversation_items called for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    // Fetch user profile for author metadata
    let user_profile = state.user_service.get_user_profile(user.user_id).await.ok();
    let author_name = user_profile.as_ref().and_then(|p| p.user.name.clone());

    // Extract body
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "create_conversation_items request body size: {} bytes for user_id={}",
        body_bytes.len(),
        user.user_id
    );

    // Parse and modify body to inject author metadata
    // This allows shared conversations to show who sent each message.
    // Author tracking is handled by cloud-api.
    let modified_body =
        if let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            // Inject author metadata
            let mut metadata = body_json
                .get("metadata")
                .and_then(|m| m.as_object())
                .cloned()
                .unwrap_or_default();

            metadata.insert(
                "author_id".to_string(),
                serde_json::Value::String(user.user_id.to_string()),
            );
            if let Some(name) = author_name.as_ref() {
                metadata.insert(
                    "author_name".to_string(),
                    serde_json::Value::String(name.clone()),
                );
            }
            body_json["metadata"] = serde_json::Value::Object(metadata);

            serde_json::to_vec(&body_json).unwrap_or_else(|_| body_bytes.to_vec())
        } else {
            body_bytes.to_vec()
        };

    // Set content-length header to match modified body
    // usize::to_string() only produces ASCII digits, which are always valid for HeaderValue
    let content_length = HeaderValue::from_str(&modified_body.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    tracing::debug!(
        "Forwarding conversation items creation request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            &format!("conversations/{conversation_id}/items"),
            headers.clone(),
            Some(Bytes::from(modified_body)),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation items creation for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// List conversation items - works with optional authentication
/// Authenticated users get their access checked, unauthenticated users can only access public conversations
///
/// # Authentication
/// This endpoint supports **optional authentication**:
/// - **With authentication**: Returns items if user owns the conversation or has been granted access via sharing
/// - **Without authentication**: Returns items only if the conversation has been publicly shared
///
/// This allows public sharing of conversation content while maintaining access control for private conversations.
#[utoipa::path(
    get,
    path = "/v1/conversations/{conversation_id}/items",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to list items from")
    ),
    responses(
        (status = 200, description = "Conversation items retrieved successfully"),
        (status = 403, description = "Access denied - conversation not accessible to this user or not publicly shared"),
        (status = 404, description = CONVERSATION_NOT_FOUND)
    ),
    security(
        (), // Optional - no auth required for publicly shared conversations
        ("session_token" = []) // Optional - session token for authenticated access
    )
)]
async fn list_conversation_items(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<Option<AuthenticatedUser>>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "list_conversation_items called for user_id={:?}, conversation_id={}",
        user.as_ref().map(|u| u.user_id),
        conversation_id
    );

    // Check user access OR public share access
    validate_conversation_access_optional_auth(
        &state,
        user.as_ref(),
        &conversation_id,
        SharePermission::Read,
    )
    .await?;

    tracing::debug!(
        "Forwarding conversation items list request to OpenAI for user_id={:?}",
        user.as_ref().map(|u| u.user_id)
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::GET,
            &format!("conversations/{conversation_id}/items"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("OpenAI API error during conversation items list: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Pin a conversation
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}/pin",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to pin")
    ),
    responses(
        (status = 200, description = "Conversation pinned successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn pin_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "pin_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    tracing::debug!(
        "Forwarding conversation pin request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            &format!("conversations/{conversation_id}/pin"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation pin for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Unpin a conversation
#[utoipa::path(
    delete,
    path = "/v1/conversations/{conversation_id}/pin",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to unpin")
    ),
    responses(
        (status = 200, description = "Conversation unpinned successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn unpin_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "unpin_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    tracing::debug!(
        "Forwarding conversation unpin request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::DELETE,
            &format!("conversations/{conversation_id}/pin"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation unpin for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Archive a conversation
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}/archive",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to archive")
    ),
    responses(
        (status = 200, description = "Conversation archived successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn archive_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "archive_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    tracing::debug!(
        "Forwarding conversation archive request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            &format!("conversations/{conversation_id}/archive"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation archive for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Unarchive a conversation
#[utoipa::path(
    delete,
    path = "/v1/conversations/{conversation_id}/archive",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to unarchive")
    ),
    responses(
        (status = 200, description = "Conversation unarchived successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn unarchive_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "unarchive_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    validate_user_conversation(&state, &user, &conversation_id, SharePermission::Write).await?;

    tracing::debug!(
        "Forwarding conversation unarchive request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::DELETE,
            &format!("conversations/{conversation_id}/archive"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation unarchive for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Clone a conversation
#[utoipa::path(
    post,
    path = "/v1/conversations/{conversation_id}/clone",
    tag = CONVERSATIONS,
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to clone")
    ),
    responses(
        (status = 200, description = "Conversation cloned successfully", body = serde_json::Value),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = CONVERSATION_NOT_FOUND, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn clone_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "clone_conversation called for user_id={}, session_id={}, conversation_id={}",
        user.user_id,
        user.session_id,
        conversation_id
    );

    // Validate user has access to the source conversation OR it's publicly shared
    // (read access is sufficient for cloning)
    validate_user_or_public_conversation(&state, &user, &conversation_id, SharePermission::Read)
        .await?;

    tracing::debug!(
        "Forwarding conversation clone request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            &format!("conversations/{conversation_id}/clone"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during conversation clone for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    handle_trackable_response(
        &state,
        &user,
        proxy_response,
        TrackableResource::Conversation,
    )
    .await
}

/// Upload a file - forwards to OpenAI and tracks in DB
#[utoipa::path(
    post,
    path = "/v1/files",
    tag = FILES,
    request_body(content = Vec<u8>, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "File uploaded successfully", body = crate::models::FileGetResponse),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn upload_file(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "upload_file called for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Extract body
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "upload_file request body size: {} bytes for user_id={}",
        body_bytes.len(),
        user.user_id
    );

    tracing::debug!(
        "Forwarding file upload request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::POST, "files", headers.clone(), Some(body_bytes))
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during file upload for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    handle_trackable_response(&state, &user, proxy_response, TrackableResource::File).await
}

/// List all files for the authenticated user (fetches details from OpenAI)
#[utoipa::path(
    get,
    path = "/v1/files",
    tag = FILES,
    params(
        ("after" = Option<String>, Query, description = "File ID to start listing after"),
        ("limit" = Option<i64>, Query, description = "Maximum number of files to return"),
        ("order" = Option<String>, Query, description = "Sort order: 'asc' or 'desc'"),
        ("purpose" = Option<String>, Query, description = "Filter by file purpose")
    ),
    responses(
        (status = 200, description = "List of files retrieved successfully", body = crate::models::FileListResponse),
        (status = 400, description = "Bad request - invalid query parameters", body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 404, description = "File not found", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn list_files(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    axum::extract::Query(params): axum::extract::Query<ListFilesParams>,
) -> Result<Json<crate::models::FileListResponse>, Response> {
    tracing::info!("list_files called for user_id={}", user.user_id);

    // Validate and normalize query parameters
    let validated = params.validate().map_err(|e| e.into_response())?;

    let (files, has_more) = state
        .file_service
        .list_files(
            user.user_id,
            validated.after.clone(),
            validated.limit,
            &validated.order,
            validated.purpose.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to list files for user_id={}: {}", user.user_id, e);
            let (status, error) = match e {
                FileError::NotFound => (StatusCode::NOT_FOUND, "File not found".to_string()),
                FileError::ApiError(msg) => {
                    (StatusCode::BAD_GATEWAY, format!("OpenAI API error: {msg}"))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to list files: {e}"),
                ),
            };
            (status, Json(ErrorResponse { error })).into_response()
        })?;

    // Extract first and last file IDs
    let first_id = files.first().map(|f| f.id.clone());
    let last_id = files.last().map(|f| f.id.clone());

    let response = crate::models::FileListResponse {
        object: "list".to_string(),
        data: files.into_iter().map(From::from).collect(),
        first_id,
        last_id,
        has_more,
    };

    Ok(Json(response))
}

/// Get a file - validates user access and fetches from OpenAI
#[utoipa::path(
    get,
    path = "/v1/files/{file_id}",
    tag = FILES,
    params(
        ("file_id" = String, Path, description = "ID of the file to retrieve")
    ),
    responses(
        (status = 200, description = "File retrieved successfully", body = crate::models::FileGetResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 404, description = "File not found", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn get_file(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(file_id): Path<String>,
) -> Result<Json<crate::models::FileGetResponse>, Response> {
    tracing::info!(
        "get_file called for user_id={}, file_id={}",
        user.user_id,
        file_id
    );

    let file = state
        .file_service
        .get_file(&file_id, user.user_id)
        .await
        .map_err(|e| {
            let (status, error) = match e {
                FileError::NotFound => (StatusCode::NOT_FOUND, "File not found".to_string()),
                FileError::ApiError(msg) => {
                    (StatusCode::BAD_GATEWAY, format!("OpenAI API error: {msg}"))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to get file: {e}"),
                ),
            };

            (status, Json(ErrorResponse { error })).into_response()
        })?;

    Ok(Json(file.into()))
}

/// Delete a file - validates user access, deletes from OpenAI and DB
#[utoipa::path(
    delete,
    path = "/v1/files/{file_id}",
    tag = FILES,
    params(
        ("file_id" = String, Path, description = "ID of the file to delete")
    ),
    responses(
        (status = 200, description = "File deleted successfully", body = serde_json::Value),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 404, description = "File not found", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn delete_file(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(file_id): Path<String>,
) -> Result<Response, Response> {
    tracing::info!(
        "delete_file called for user_id={}, file_id={}",
        user.user_id,
        file_id
    );

    // Delete from DB and OpenAI
    let deleted = state
        .file_service
        .delete_file(&file_id, user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to delete file {} for user_id={}: {}",
                file_id,
                user.user_id,
                e
            );
            let (status, error_msg) = match e {
                FileError::NotFound => (StatusCode::NOT_FOUND, "File not found".to_string()),
                FileError::ApiError(msg) => {
                    (StatusCode::BAD_GATEWAY, format!("OpenAI API error: {msg}"))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to delete file: {e}"),
                ),
            };
            (status, Json(ErrorResponse { error: error_msg })).into_response()
        })?;

    Ok(Json(deleted).into_response())
}

/// Get file content - validates user access and fetches content from OpenAI
#[utoipa::path(
    get,
    path = "/v1/files/{file_id}/content",
    tag = FILES,
    params(
        ("file_id" = String, Path, description = "ID of the file to get content for")
    ),
    responses(
        (status = 200, description = "File content retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = ACCESS_DENIED, body = ErrorResponse),
        (status = 404, description = "File not found", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn get_file_content(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "get_file_content called for user_id={}, file_id={}",
        user.user_id,
        file_id
    );

    validate_user_file(&state, &user, &file_id).await?;

    tracing::debug!(
        "Forwarding file content request to OpenAI for user_id={}",
        user.user_id
    );

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::GET,
            &format!("files/{file_id}/content"),
            headers.clone(),
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error during file content get for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Proxy responses endpoint - forwards to OpenAI with model settings and author metadata injection
#[utoipa::path(
    post,
    path = "/v1/responses",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Response created successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned or model not available", body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_responses(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_responses: POST /v1/responses for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Check if user is currently banned before proceeding
    ensure_user_not_banned(&state, &user).await?;

    // Trigger an asynchronous NEAR balance check. This does NOT block the current request:
    // if the balance is too low, a ban will be created and will affect subsequent requests.
    spawn_near_balance_check(&state, &user);

    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    // Parsed JSON body (if applicable)
    let mut body_json: Option<serde_json::Value> = None;
    // Optional system prompt resolved from model settings
    let mut model_system_prompt: Option<String> = None;
    // Model id from request body, if present
    let mut model_id_from_body: Option<String> = None;
    // Whether model settings came from cache
    let mut model_settings_cache_hit: Option<bool> = None;

    tracing::debug!(
        "Extracted request body: {} bytes for POST /v1/responses",
        body_bytes.len()
    );

    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            tracing::debug!("Request body content: {}", body_str);
        }

        // Try to parse JSON body once for further processing (model visibility + system prompt)
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => {
                body_json = Some(v);
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse /responses request body as JSON for user_id={}: {}",
                    user.user_id,
                    e
                );
            }
        }
    }

    // If a conversation ID is provided, this is a write operation on an existing conversation.
    // Enforce that the caller has write access (owner OR shared with write permission).
    if let Some(ref body) = body_json {
        if let Some(conversation_id) = body
            .get("conversation")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            validate_user_conversation(&state, &user, conversation_id, SharePermission::Write)
                .await?;
        }
    }

    // Enforce model-level visibility based on settings if a model is specified
    if let Some(ref body) = body_json {
        if let Some(model_id) = body.get("model").and_then(|v| v.as_str()) {
            model_id_from_body = Some(model_id.to_string());

            // Use shared helper function to get model settings with caching
            match get_model_settings_with_cache(&state, model_id, user.user_id).await {
                Ok((prompt, cache_hit)) => {
                    model_system_prompt = prompt;
                    model_settings_cache_hit = cache_hit;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // Fetch user profile to inject author metadata into messages
    let user_profile = state.user_service.get_user_profile(user.user_id).await.ok();

    // Modify request body to inject system prompt and/or author metadata
    let modified_body_bytes = if let Some(mut body) = body_json {
        // Inject model-level system prompt if present
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            let new_instructions = match body.get("instructions").and_then(|v| v.as_str()) {
                Some(existing) if !existing.is_empty() => {
                    format!("{system_prompt}\n\n{existing}")
                }
                _ => system_prompt.clone(),
            };
            body["instructions"] = serde_json::Value::String(new_instructions);
        }

        // Inject author metadata with user info
        // This allows shared conversations to show who sent each message.
        // Author tracking is handled by cloud-api.
        if let Some(profile) = user_profile {
            let mut metadata = body
                .get("metadata")
                .and_then(|m| m.as_object())
                .cloned()
                .unwrap_or_default();

            metadata.insert(
                "author_id".to_string(),
                serde_json::Value::String(user.user_id.to_string()),
            );
            if let Some(name) = profile.user.name.as_ref() {
                metadata.insert(
                    "author_name".to_string(),
                    serde_json::Value::String(name.clone()),
                );
            }

            body["metadata"] = serde_json::Value::Object(metadata);

            // OpenAI requires `store: true` when `metadata` is present for some models.
            body["store"] = serde_json::Value::Bool(true);
        }

        match serde_json::to_vec(&body) {
            Ok(serialized) => Bytes::from(serialized),
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to modify request body".to_string(),
                    }),
                )
                    .into_response())
            }
        }
    } else {
        body_bytes
    };

    // Set content-length header
    // usize::to_string() only produces ASCII digits, which are always valid for HeaderValue
    let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    // Track conversation from the request
    tracing::debug!("POST to /responses detected, attempting to track conversation");
    if let Err(e) =
        track_conversation_from_request(&state, user.user_id, &modified_body_bytes).await
    {
        tracing::error!(
            "Failed to track conversation for user {} from /responses: {}",
            user.user_id,
            e
        );
        // Don't fail the request if conversation tracking fails
    }

    tracing::debug!(
        "Forwarding POST /v1/responses to OpenAI for user_id={}",
        user.user_id
    );

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            "responses",
            headers.clone(),
            Some(modified_body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for POST /v1/responses (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for POST /v1/responses (user_id={})",
        proxy_response.status,
        user.user_id
    );

    // Record metrics for successful responses
    if (200..300).contains(&proxy_response.status) {
        state
            .metrics_service
            .record_count(METRIC_RESPONSE_CREATED, 1, &[]);

        // Record analytics in database
        if let Err(e) = state
            .analytics_service
            .record_activity(RecordActivityRequest {
                user_id: user.user_id,
                activity_type: ActivityType::Response,
                auth_method: None,
                metadata: model_id_from_body.as_ref().map(|model_id| {
                    let mut meta = serde_json::Map::new();
                    meta.insert(
                        "model_id".to_string(),
                        serde_json::Value::String(model_id.clone()),
                    );
                    if let Some(hit) = model_settings_cache_hit {
                        meta.insert(
                            "model_settings_cache_hit".to_string(),
                            serde_json::Value::Bool(hit),
                        );
                    }
                    serde_json::Value::Object(meta)
                }),
            })
            .await
        {
            tracing::warn!("Failed to record analytics for response creation: {}", e);
        }
    }

    // Wrap the response stream: record usage (token/cost)
    tracing::debug!(
        "proxy_responses: upstream status={}, content_type={:?}, is_streaming={}",
        proxy_response.status,
        proxy_response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        is_streaming_response(&proxy_response.headers),
    );

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else if is_streaming_response(&proxy_response.headers) {
        let mut usage_stream = UsageTrackingStreamResponseCompleted::new(
            proxy_response.body,
            state.user_usage_service.clone(),
            state.model_pricing_cache.clone(),
            user.user_id,
        );
        if let Some(Extension(api_key)) = &api_key_ext {
            usage_stream = usage_stream
                .with_agent_ids(api_key.api_key_info.instance_id, api_key.api_key_info.id);
        }
        Body::from_stream(usage_stream)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Upstream stream error for user_id={}: {}", user.user_id, e);
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        // For non-streaming responses, decompress (if gzipped) before parsing usage.
        let usage_bytes =
            decompress_if_gzipped(&bytes, &proxy_response.headers).unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to decompress non-stream response for user_id={}: {}",
                    user.user_id,
                    e
                );
                bytes.to_vec()
            });
        // Fire-and-forget: record usage in background to avoid blocking on pricing fetch + DB write
        let state_clone = state.clone();
        let user_id = user.user_id;
        let usage_bytes_clone = usage_bytes.clone();
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_response_usage_from_body(&state_clone, user_id, &usage_bytes_clone, api_key_opt)
                .await;
        });
        Body::from(bytes)
    };

    build_response(proxy_response.status, proxy_response.headers, response_body).await
}

/// Ensure that if the authenticated user logged in with NEAR (has a NEAR-linked account),
/// their on-chain balance is at least 1 NEAR before allowing expensive /v1/responses calls.
async fn ensure_near_balance_for_near_user(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
) -> Result<(), Response> {
    // Fetch user profile to inspect linked OAuth accounts
    let profile = state
        .user_service
        .get_user_profile(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get user profile for NEAR balance check (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to verify NEAR balance".to_string(),
                }),
            )
                .into_response()
        })?;

    // Find a linked NEAR account (provider_user_id stores the NEAR account ID)
    let near_account_id = profile
        .linked_accounts
        .iter()
        .find(|acc| acc.provider == OAuthProvider::Near)
        .map(|acc| acc.provider_user_id.clone());

    // If the user does not have a NEAR-linked account, skip the balance check
    let Some(account_id_str) = near_account_id else {
        return Ok(());
    };

    tracing::info!(
        "Checking NEAR balance for user_id={} account_id={} (with cache)",
        user.user_id,
        account_id_str
    );

    // First, check in-memory cache to avoid frequent RPC calls
    {
        let cache = state.near_balance_cache.read().await;
        if let Some(entry) = cache.get(&account_id_str) {
            let age = Utc::now().signed_duration_since(entry.last_checked_at);
            if age.num_seconds() >= 0 && age.num_seconds() < NEAR_BALANCE_CACHE_TTL_SECS {
                tracing::debug!(
                    "Using cached NEAR balance for account '{}' (age={}s, balance={} yoctoNEAR)",
                    account_id_str,
                    age.num_seconds(),
                    entry.balance
                );

                // We only treat cached values as authoritative if they meet the minimum balance.
                // Low cached balances are ignored here so we can re-check on-chain after bans expire.
                if entry.balance >= MIN_NEAR_BALANCE {
                    return Ok(());
                }
            }
        }
    }

    // Parse NEAR account ID
    let account_id: AccountId = account_id_str.parse().map_err(|e| {
        tracing::error!(
            "Invalid NEAR account id '{}' for user_id={}: {}",
            account_id_str,
            user.user_id,
            e
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Invalid NEAR account id for user".to_string(),
            }),
        )
            .into_response()
    })?;

    let account = Account(account_id);

    let network_config = NetworkConfig::from_rpc_url("near", state.near_rpc_url.clone());

    let info = account
        .view()
        .fetch_from(&network_config)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch NEAR account info for account_id='{}': {}",
                account_id_str,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch NEAR account info".to_string(),
                }),
            )
                .into_response()
        })?;

    let balance = info.data.amount.as_yoctonear();

    tracing::info!(
        "NEAR balance for account '{}' (user_id={}): {} yoctoNEAR",
        account_id_str,
        user.user_id,
        balance
    );

    if balance < MIN_NEAR_BALANCE {
        tracing::warn!(
            "NEAR balance too low for user_id={} account_id={} balance={} (required >= {})",
            user.user_id,
            account_id_str,
            balance,
            MIN_NEAR_BALANCE
        );

        // Ban user for a fixed duration when NEAR balance check fails
        if let Err(e) = state
            .user_service
            .ban_user_for_duration(
                user.user_id,
                BanType::NearBalanceLow,
                Some(format!(
                    "NEAR balance {} is below required minimum {}",
                    balance, MIN_NEAR_BALANCE
                )),
                Duration::seconds(NEAR_BALANCE_BAN_DURATION_SECS),
            )
            .await
        {
            tracing::error!(
                "Failed to create NEAR balance ban for user_id={}: {}",
                user.user_id,
                e
            );
        }

        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: USER_BANNED_ERROR_MESSAGE.to_string(),
            }),
        )
            .into_response())
    } else {
        let mut cache = state.near_balance_cache.write().await;
        cache.insert(
            account_id_str.clone(),
            crate::state::NearBalanceCacheEntry {
                last_checked_at: Utc::now(),
                balance,
            },
        );
        Ok(())
    }
}

/// Ensure the authenticated user is not currently banned
async fn ensure_user_not_banned(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
) -> Result<(), Response> {
    let is_banned = state
        .user_service
        .has_active_ban(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to check user ban status for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to verify user ban status".to_string(),
                }),
            )
                .into_response()
        })?;

    if is_banned {
        tracing::warn!("Blocked request for banned user_id={}", user.user_id);
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: USER_BANNED_ERROR_MESSAGE.to_string(),
            }),
        )
            .into_response());
    }

    Ok(())
}

/// Spawn an asynchronous NEAR balance check task.
///
/// This function is fire-and-forget: it does not affect the current request's outcome.
/// If the user's NEAR balance is found to be insufficient, a ban will be created and
/// subsequent requests will be blocked by `ensure_user_not_banned`.
fn spawn_near_balance_check(state: &crate::state::AppState, user: &AuthenticatedUser) {
    let state = state.clone();
    let user = user.clone();

    tokio::spawn(async move {
        if let Err(resp) = ensure_near_balance_for_near_user(&state, &user).await {
            tracing::debug!(
                "Asynchronous NEAR balance check completed with status={} for user_id={}",
                resp.status(),
                user.user_id
            );
        }
    });
}

/// Proxy model list endpoint - returns list of available models with public flags
#[utoipa::path(
    get,
    path = "/v1/model/list",
    tag = PROXY,
    responses(
        (status = 200, description = "Model list retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_model_list(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_model_list: GET /v1/model/list for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, "model/list", headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for GET /v1/model/list (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for GET /v1/model/list (user_id={})",
        proxy_response.status,
        user.user_id
    );

    // If upstream returned non-success, just proxy as-is
    if !(200..300).contains(&proxy_response.status) {
        return build_response(
            proxy_response.status,
            proxy_response.headers,
            Body::from_stream(proxy_response.body),
        )
        .await;
    }

    // Buffer body into bytes
    let proxy_body = Body::from_stream(proxy_response.body);
    let body_bytes: Bytes = to_bytes(proxy_body, MAX_RESPONSE_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to read model list response body for user_id={}: {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to read response body: {e}"),
                }),
            )
                .into_response()
        })?;

    // Try to parse JSON
    let mut body_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Failed to parse model list JSON for user_id={}: {}, returning original body",
                user.user_id,
                e
            );
            return build_response(
                proxy_response.status,
                proxy_response.headers,
                Body::from(body_bytes),
            )
            .await;
        }
    };

    let models_opt = body_json.get_mut("models").and_then(|v| v.as_array_mut());

    let Some(models_array) = models_opt else {
        tracing::debug!("No 'models' array found in model list response, returning original body");
        return Response::builder()
            .status(StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::OK))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&body_json).unwrap_or_else(|_| body_bytes.to_vec()),
            ))
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to build response: {e}"),
                    }),
                )
                    .into_response()
            });
    };

    // Collect all model IDs for batch settings lookup
    let mut model_ids: Vec<String> = Vec::new();
    for model in models_array.iter() {
        if let Some(model_id) = model.get("modelId").and_then(|v| v.as_str()) {
            model_ids.push(model_id.to_string());
        }
    }

    // Batch fetch settings for all models from the admin models table
    let settings_map = state
        .model_service
        .get_models_by_ids(&model_ids.iter().map(|s| s.as_str()).collect::<Vec<&str>>())
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to batch load model settings for model list: {}, defaulting all public={}",
                e,
                MODEL_PUBLIC_DEFAULT
            );
            std::collections::HashMap::new()
        });

    // Attach `public` flag to each model based on its stored settings
    let mut decorated_models = Vec::new();
    for mut model in std::mem::take(models_array) {
        let public_flag = model
            .get("modelId")
            .and_then(|v| v.as_str())
            .and_then(|id| settings_map.get(id).map(|m| m.settings.public))
            .unwrap_or(MODEL_PUBLIC_DEFAULT);

        if let Some(obj) = model.as_object_mut() {
            obj.insert("public".to_string(), serde_json::Value::Bool(public_flag));
        }

        decorated_models.push(model);
    }

    *body_json
        .get_mut("models")
        .expect("Models key must exist after previous check") =
        serde_json::Value::Array(decorated_models);

    let filtered_bytes = serde_json::to_vec(&body_json).unwrap_or_else(|e| {
        tracing::error!(
            "Failed to serialize filtered model list JSON: {}, returning original body",
            e
        );
        body_bytes.to_vec()
    });

    Response::builder()
        .status(StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::OK))
        .header("content-type", "application/json")
        .body(Body::from(filtered_bytes))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to build response: {e}"),
                }),
            )
                .into_response()
        })
}

/// Proxy signature endpoint - forwards signature requests to OpenAI
#[utoipa::path(
    get,
    path = "/v1/signature/{chat_id}",
    tag = PROXY,
    params(
        ("chat_id" = String, Path, description = "Chat ID to get signature for")
    ),
    responses(
        (status = 200, description = "Signature retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = OPENAI_API_ERROR, body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_signature(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(chat_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_signature: GET /v1/signature/{} for user_id={}, session_id={}",
        chat_id,
        user.user_id,
        user.session_id
    );

    let path = format!("signature/{}", chat_id);

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, &path, headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for GET /v1/signature/{} (user_id={}): {}",
                chat_id,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from OpenAI: status={} for GET /v1/signature/{} (user_id={})",
        proxy_response.status,
        chat_id,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Helper function to get model settings with caching support.
/// Returns (system_prompt, cache_hit) if model is found and public.
/// Validates model visibility and populates cache if needed.
async fn get_model_settings_with_cache(
    state: &crate::state::AppState,
    model_id: &str,
    user_id: services::UserId,
) -> Result<(Option<String>, Option<bool>), Response> {
    let mut model_system_prompt: Option<String> = None;
    let mut model_settings_cache_hit: Option<bool> = None;

    // 1) Try cache first
    {
        let cache = state.model_settings_cache.read().await;
        if let Some(entry) = cache.get(model_id) {
            let age = Utc::now().signed_duration_since(entry.last_checked_at);
            if age.num_seconds() >= 0 && age.num_seconds() < MODEL_SETTINGS_CACHE_TTL_SECS {
                model_settings_cache_hit = Some(true);

                if !entry.public {
                    tracing::warn!(
                        "Blocking request for non-public model '{}' from user {} (cache)",
                        model_id,
                        user_id
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "This model is not available".to_string(),
                        }),
                    )
                        .into_response());
                }

                model_system_prompt = entry.system_prompt.clone();
            }
        }
    }

    // 2) Cache miss or expired: fetch from DB/service and populate cache
    if model_settings_cache_hit.is_none() {
        model_settings_cache_hit = Some(false);
        match state.model_service.get_model(model_id).await {
            Ok(Some(model)) => {
                // Populate cache
                {
                    let mut cache = state.model_settings_cache.write().await;
                    cache.insert(
                        model_id.to_string(),
                        crate::state::ModelSettingsCacheEntry {
                            last_checked_at: Utc::now(),
                            exists: true,
                            public: model.settings.public,
                            system_prompt: model.settings.system_prompt.clone(),
                        },
                    );
                }

                if !model.settings.public {
                    tracing::warn!(
                        "Blocking request for non-public model '{}' from user {}",
                        model_id,
                        user_id
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "This model is not available".to_string(),
                        }),
                    )
                        .into_response());
                }

                model_system_prompt = model.settings.system_prompt.clone();
            }
            Ok(None) => {
                // Model not in admin DB - allow by default per MODEL_PUBLIC_DEFAULT
                // Cache with defaults to avoid repeated DB hits
                {
                    let mut cache = state.model_settings_cache.write().await;
                    cache.insert(
                        model_id.to_string(),
                        crate::state::ModelSettingsCacheEntry {
                            last_checked_at: Utc::now(),
                            exists: false, // Not in DB but allowed with defaults
                            public: MODEL_PUBLIC_DEFAULT, // true by default
                            system_prompt: None,
                        },
                    );
                }

                // Continue with defaults
                model_system_prompt = None;
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to get model".to_string(),
                    }),
                )
                    .into_response())
            }
        }
    }

    Ok((model_system_prompt, model_settings_cache_hit))
}

/// Prepares chat completions request body with optional model system prompt injection.
async fn prepare_chat_completions_body(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    body_bytes: Bytes,
) -> Result<Bytes, Response> {
    let mut body_json: Option<serde_json::Value> = None;
    let mut model_system_prompt: Option<String> = None;

    let mut auto_routed = false;

    if !body_bytes.is_empty() {
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => {
                body_json = Some(v);

                // Route "auto" model to the configured target with recommended defaults
                if let Some(body) = body_json.as_mut() {
                    if body.get("model").and_then(|v| v.as_str()) == Some("auto") {
                        tracing::info!("Auto-routing model: user_id={}", user.user_id);
                        body["model"] = json!(AUTO_ROUTE_MODEL);
                        if body.get("temperature").is_none_or(|v| v.is_null()) {
                            body["temperature"] = json!(AUTO_ROUTE_TEMPERATURE);
                        }
                        if body.get("top_p").is_none_or(|v| v.is_null()) {
                            body["top_p"] = json!(AUTO_ROUTE_TOP_P);
                        }
                        if body.get("max_tokens").is_none_or(|v| v.is_null()) {
                            body["max_tokens"] = json!(AUTO_ROUTE_MAX_TOKENS);
                        }
                        auto_routed = true;
                    }
                }

                if let Some(model_id) = body_json
                    .as_ref()
                    .and_then(|b| b.get("model"))
                    .and_then(|v| v.as_str())
                {
                    match get_model_settings_with_cache(state, model_id, user.user_id).await {
                        Ok((prompt, _)) => model_system_prompt = prompt,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse request body as JSON for chat/completions (user_id={}): {}",
                    user.user_id,
                    e
                );
            }
        }
    }

    let modified_body_bytes = if let Some(mut body) = body_json {
        let mut modified = false;
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
                let has_system_message = messages
                    .iter()
                    .any(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"));
                if !has_system_message {
                    let system_msg = json!({ "role": "system", "content": system_prompt });
                    messages.insert(0, system_msg);
                    modified = true;
                } else if let Some(first_system_idx) = messages
                    .iter()
                    .position(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"))
                {
                    let first_system = &mut messages[first_system_idx];
                    if let Some(content_str) = first_system.get("content").and_then(|c| c.as_str())
                    {
                        first_system["content"] = serde_json::Value::String(format!(
                            "{}\n\n{}",
                            system_prompt, content_str
                        ));
                        modified = true;
                    } else if let Some(content_arr) = first_system
                        .get_mut("content")
                        .and_then(|c| c.as_array_mut())
                    {
                        content_arr.insert(0, json!({ "type": "text", "text": system_prompt }));
                        modified = true;
                    } else {
                        first_system["content"] =
                            serde_json::Value::String(system_prompt.to_string());
                        modified = true;
                    }
                }
            } else {
                body["messages"] = json!([{ "role": "system", "content": system_prompt }]);
                modified = true;
            }
        }
        if modified || auto_routed {
            serde_json::to_vec(&body).map(Bytes::from).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to modify request body".to_string(),
                    }),
                )
                    .into_response()
            })
        } else {
            Ok(body_bytes)
        }
    } else {
        Ok(body_bytes)
    }?;
    Ok(modified_body_bytes)
}

/// Configuration for proxying POST requests to cloud-api endpoints (no usage tracking).
/// Used by proxy_post_to_cloud_api for future POST endpoints that do not need usage tracking.
#[allow(dead_code)]
struct ProxyEndpointConfig {
    /// Path for the proxy service (e.g., "chat/completions")
    endpoint_path: &'static str,
    /// Full path for logging (e.g., "/v1/chat/completions")
    endpoint_full_path: &'static str,
    /// Whether to set the content-length header (false for multipart/form-data)
    set_content_length: bool,
    /// Whether to enable model system prompt injection
    enable_model_prompt: bool,
}

/// Shared helper for proxying POST requests to cloud-api endpoints (no usage tracking).
/// Use dedicated handlers (proxy_chat_completions, proxy_image_*) for endpoints that track usage.
///
/// Handles: ban check, NEAR check, body extraction, optional model prompt injection, forward, response.
#[allow(dead_code)]
async fn proxy_post_to_cloud_api(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    mut headers: HeaderMap,
    request: Request,
    config: ProxyEndpointConfig,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_post_to_cloud_api: POST {} for user_id={}, session_id={}",
        config.endpoint_full_path,
        user.user_id,
        user.session_id
    );

    // Check if user is currently banned before proceeding
    ensure_user_not_banned(state, user).await?;

    // Trigger an asynchronous NEAR balance check
    spawn_near_balance_check(state, user);

    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "Extracted request body: {} bytes for POST {}",
        body_bytes.len(),
        config.endpoint_full_path
    );

    // Parse JSON body and handle model settings if enabled
    let mut body_json: Option<serde_json::Value> = None;
    let mut model_system_prompt: Option<String> = None;

    if config.enable_model_prompt && !body_bytes.is_empty() {
        // Try to parse JSON body for model settings lookup
        match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            Ok(v) => {
                body_json = Some(v);

                // Extract model ID and get model settings
                if let Some(model_id) = body_json
                    .as_ref()
                    .and_then(|b| b.get("model"))
                    .and_then(|v| v.as_str())
                {
                    match get_model_settings_with_cache(state, model_id, user.user_id).await {
                        Ok((prompt, _cache_hit)) => {
                            model_system_prompt = prompt;
                            // Cache hit/miss is tracked via analytics in proxy_responses, not needed here
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Failed to parse request body as JSON for POST {} (user_id={}): {}",
                    config.endpoint_full_path,
                    user.user_id,
                    e
                );
            }
        }
    }

    // Inject system prompt into request body if present
    let modified_body_bytes = if let Some(mut body) = body_json {
        let mut modified = false;

        // For chat completions, inject system prompt as a system message
        if let Some(system_prompt) = model_system_prompt.as_ref() {
            if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
                // Check if there's already a system message
                let has_system_message = messages
                    .iter()
                    .any(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"));

                if !has_system_message {
                    // Prepend system message at the beginning
                    let system_msg = json!({
                        "role": "system",
                        "content": system_prompt
                    });
                    messages.insert(0, system_msg);
                    modified = true;
                } else {
                    // If system message exists, prepend to the first system message's content
                    if let Some(first_system_idx) = messages
                        .iter()
                        .position(|msg| msg.get("role").and_then(|r| r.as_str()) == Some("system"))
                    {
                        let first_system = &mut messages[first_system_idx];

                        // Handle string content
                        if let Some(content_str) =
                            first_system.get("content").and_then(|c| c.as_str())
                        {
                            let new_content = format!("{system_prompt}\n\n{content_str}");
                            first_system["content"] = serde_json::Value::String(new_content);
                            modified = true;
                        }
                        // Handle array content format (for multimodal)
                        else if let Some(content_arr) = first_system
                            .get_mut("content")
                            .and_then(|c| c.as_array_mut())
                        {
                            // Prepend text content to the array efficiently
                            content_arr.insert(
                                0,
                                json!({
                                    "type": "text",
                                    "text": system_prompt
                                }),
                            );
                            modified = true;
                        }
                        // If content is missing or in unexpected format, replace with system prompt
                        else {
                            first_system["content"] =
                                serde_json::Value::String(system_prompt.to_string());
                            modified = true;
                        }
                    }
                }
            } else {
                // No messages array - create one with system message
                body["messages"] = json!([{
                    "role": "system",
                    "content": system_prompt
                }]);
                modified = true;
            }
        }

        if modified {
            match serde_json::to_vec(&body) {
                Ok(serialized) => Bytes::from(serialized),
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to modify request body".to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    // Set content-length header if requested (skip for multipart/form-data)
    if config.set_content_length {
        let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
            .expect("usize to string conversion always produces valid HeaderValue");
        headers.insert(CONTENT_LENGTH, content_length);
    }

    // Forward the request to cloud-api
    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            config.endpoint_path,
            headers.clone(),
            Some(modified_body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                config.endpoint_full_path,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for POST {} (user_id={})",
        proxy_response.status,
        config.endpoint_full_path,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Proxy chat completions endpoint - OpenAI-compatible chat completions with model system prompt injection and usage tracking.
#[utoipa::path(
    post,
    path = "/v1/chat/completions",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Chat completion created successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned or model not available", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_chat_completions(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "chat/completions";
    const ENDPOINT_FULL_PATH: &str = "/v1/chat/completions";

    tracing::info!(
        "proxy_chat_completions: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    let body_bytes = extract_body_bytes(request).await?;
    tracing::debug!(
        "Extracted request body: {} bytes for POST {}",
        body_bytes.len(),
        ENDPOINT_FULL_PATH
    );

    let modified_body_bytes = prepare_chat_completions_body(&state, &user, body_bytes).await?;
    let content_length = HeaderValue::from_str(&modified_body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(modified_body_bytes.clone()),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for POST {} (user_id={})",
        proxy_response.status,
        ENDPOINT_FULL_PATH,
        user.user_id
    );

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else if is_streaming_response(&proxy_response.headers) {
        let mut usage_stream = UsageTrackingStreamChatCompletions::new(
            proxy_response.body,
            state.user_usage_service.clone(),
            state.model_pricing_cache.clone(),
            user.user_id,
        );
        if let Some(Extension(api_key)) = &api_key_ext {
            usage_stream = usage_stream
                .with_agent_ids(api_key.api_key_info.instance_id, api_key.api_key_info.id);
        }
        Body::from_stream(usage_stream)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        let usage_bytes =
            decompress_if_gzipped(&bytes, &proxy_response.headers).unwrap_or_else(|e| {
                tracing::error!(
                    "Failed to decompress non-stream response for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                bytes.to_vec()
            });
        // Return the original upstream bytes so they remain consistent with any forwarded content-encoding headers.
        let state_clone = state.clone();
        let user_id = user.user_id;
        let request_body = modified_body_bytes.clone();
        let response_body = usage_bytes.clone();
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_chat_usage_from_body(
                &state_clone,
                user_id,
                &request_body,
                &response_body,
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy image generation to cloud-api (OpenAI-compatible endpoint) with usage tracking.
#[utoipa::path(
    post,
    path = "/v1/images/generations",
    tag = PROXY,
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Image generation request processed successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_image_generations(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    mut headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "images/generations";
    const ENDPOINT_FULL_PATH: &str = "/v1/images/generations";

    tracing::info!(
        "proxy_image_generations: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    let body_bytes = extract_body_bytes(request).await?;
    // Parse request JSON: model is required; n is optional, default 1.
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        tracing::error!(
            "Failed to parse image generations request body as JSON for user_id={}: {}",
            user.user_id,
            e
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid JSON body for image generations request".to_string(),
            }),
        )
            .into_response()
    })?;

    let image_request_model = body_json
        .get("model")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            tracing::error!(
                "Missing or invalid `model` in image generations request for user_id={}",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "`model` is required for image generations".to_string(),
                }),
            )
                .into_response()
        })?
        .to_string();

    let image_count: u32 = match body_json.get("n") {
        None => 1,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                tracing::error!(
                    "Invalid `n` (must be positive integer) in image generations request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response()
            })?;
            if n == 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response());
            }
            u32::try_from(n).map_err(|_| {
                tracing::error!(
                    "`n` out of range in image generations request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer within valid range".to_string(),
                    }),
                )
                    .into_response()
            })?
        }
    };

    let content_length = HeaderValue::from_str(&body_bytes.len().to_string())
        .expect("usize to string conversion always produces valid HeaderValue");
    headers.insert(CONTENT_LENGTH, content_length);

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        // Use image_count and model from the request to compute cost; we don't depend on response body shape.
        let state_clone = state.clone();
        let user_id = user.user_id;
        let model = image_request_model.clone();
        let qty = image_count as i64;
        let mk = services::user_usage::METRIC_KEY_IMAGE_GENERATE;
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_image_usage(
                &state_clone,
                user_id,
                mk,
                qty,
                Some(model.as_str()),
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy image edits to cloud-api (OpenAI-compatible endpoint) with usage tracking.
/// Note: This endpoint accepts multipart/form-data.
#[utoipa::path(
    post,
    path = "/v1/images/edits",
    tag = PROXY,
    request_body(content = Vec<u8>, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Image edit request processed successfully"),
        (status = 400, description = BAD_REQUEST, body = ErrorResponse),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 403, description = "Forbidden - user banned", body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_image_edits(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    api_key_ext: Option<Extension<AuthenticatedApiKey>>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    const ENDPOINT_PATH: &str = "images/edits";
    const ENDPOINT_FULL_PATH: &str = "/v1/images/edits";

    tracing::info!(
        "proxy_image_edits: POST {} for user_id={}, session_id={}",
        ENDPOINT_FULL_PATH,
        user.user_id,
        user.session_id
    );

    ensure_user_not_banned(&state, &user).await?;
    spawn_near_balance_check(&state, &user);

    // Read full multipart body as bytes (to keep original formdata for forwarding).
    let body_bytes = extract_body_bytes(request).await?;

    // Parse Content-Type to extract boundary.
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!(
                "Missing or invalid Content-Type for image edits request (user_id={})",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Content-Type header with multipart boundary is required".to_string(),
                }),
            )
                .into_response()
        })?;

    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix("boundary=")
                .map(|b| b.trim_matches('"').to_string())
        })
        .ok_or_else(|| {
            tracing::error!(
                "Missing boundary in Content-Type for image edits request (user_id={})",
                user.user_id
            );
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "multipart/form-data boundary is required".to_string(),
                }),
            )
                .into_response()
        })?;

    // Use multer to parse multipart fields from the raw bytes, without modifying them.
    let body_for_multipart = body_bytes.clone();
    let stream = stream::once(async move { Ok::<Bytes, std::io::Error>(body_for_multipart) });
    let mut multipart = Multipart::new(stream, boundary);

    let mut request_model: Option<String> = None;
    let mut request_n: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!(
            "Failed to parse multipart field for image edits (user_id={}): {}",
            user.user_id,
            e
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid multipart/form-data body for image edits".to_string(),
            }),
        )
            .into_response()
    })? {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("model") => {
                let text = field.text().await.map_err(|e| {
                    tracing::error!(
                        "Failed to read `model` field in image edits request (user_id={}): {}",
                        user.user_id,
                        e
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "Invalid `model` field in image edits request".to_string(),
                        }),
                    )
                        .into_response()
                })?;
                request_model = Some(text);
            }
            Some("n") => {
                let text = field.text().await.map_err(|e| {
                    tracing::error!(
                        "Failed to read `n` field in image edits request (user_id={}): {}",
                        user.user_id,
                        e
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "Invalid `n` field in image edits request".to_string(),
                        }),
                    )
                        .into_response()
                })?;
                request_n = Some(text);
            }
            _ => {
                // Other fields: we don't need to inspect, but they remain in body_bytes for forwarding.
            }
        }
    }

    let request_model = request_model.ok_or_else(|| {
        tracing::error!(
            "Missing `model` field in image edits request for user_id={}",
            user.user_id
        );
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "`model` is required for image edits".to_string(),
            }),
        )
            .into_response()
    })?;

    // n is optional, default 1; if present must be a positive integer
    let image_count: u32 = match request_n.as_deref() {
        None | Some("") => 1,
        Some(s) => {
            let n: u64 = s.trim().parse().map_err(|_| {
                tracing::error!(
                    "Invalid `n` (must be positive integer) in image edits request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response()
            })?;
            if n == 0 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer".to_string(),
                    }),
                )
                    .into_response());
            }
            u32::try_from(n).map_err(|_| {
                tracing::error!(
                    "`n` out of range in image edits request for user_id={}",
                    user.user_id
                );
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "`n` must be a positive integer within valid range".to_string(),
                    }),
                )
                    .into_response()
            })?
        }
    };

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::POST,
            ENDPOINT_PATH,
            headers.clone(),
            Some(body_bytes),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for POST {} (user_id={}): {}",
                ENDPOINT_FULL_PATH,
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    let response_body = if !(200..300).contains(&proxy_response.status) {
        Body::from_stream(proxy_response.body)
    } else {
        let bytes = match collect_stream_to_bytes(proxy_response.body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "Upstream stream error for user_id={} on {}: {}",
                    user.user_id,
                    ENDPOINT_FULL_PATH,
                    e
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: "Failed to read response body".to_string(),
                    }),
                )
                    .into_response());
            }
        };
        let state_clone = state.clone();
        let user_id = user.user_id;
        let model = request_model.clone();
        let mk = services::user_usage::METRIC_KEY_IMAGE_EDIT;
        let qty = image_count as i64;
        let api_key_opt = api_key_ext.map(|Extension(key)| key);
        tokio::spawn(async move {
            record_image_usage(
                &state_clone,
                user_id,
                mk,
                qty,
                Some(model.as_str()),
                api_key_opt,
            )
            .await;
        });
        Body::from(bytes)
    };

    build_response(
        proxy_response.status,
        proxy_response.headers.clone(),
        response_body,
    )
    .await
}

/// Proxy models list to cloud-api (OpenAI-compatible endpoint: GET /v1/models)
#[utoipa::path(
    get,
    path = "/v1/models",
    tag = PROXY,
    responses(
        (status = 200, description = "Models list retrieved successfully"),
        (status = 401, description = UNAUTHORIZED, body = ErrorResponse),
        (status = 502, description = "Cloud API error", body = ErrorResponse)
    ),
    security(
        ("session_token" = [])
    )
)]
async fn proxy_models(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_models: GET /v1/models for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    // Forward the request to cloud-api
    let proxy_response = state
        .proxy_service
        .forward_request(Method::GET, "models", headers.clone(), None)
        .await
        .map_err(|e| {
            tracing::error!(
                "Cloud API error for GET /v1/models (user_id={}): {}",
                user.user_id,
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Cloud API error: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::info!(
        "Received response from cloud-api: status={} for GET /v1/models (user_id={})",
        proxy_response.status,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
}

/// Helper function to handle response: buffer, parse, and track resource
async fn handle_trackable_response(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    proxy_response: ProxyResponse,
    resource_type: TrackableResource,
) -> Result<Response, Response> {
    let status = proxy_response.status;
    let response_headers = proxy_response.headers;

    tracing::debug!("Response headers: {:?}", response_headers);

    // Buffer the response to extract the resource ID
    let proxy_body = Body::from_stream(proxy_response.body);
    let body_bytes: Bytes = to_bytes(proxy_body, MAX_RESPONSE_BODY_SIZE)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to read response: {e}"),
                }),
            )
                .into_response()
        })?;

    if !(200..300).contains(&status) {
        return build_response(status, response_headers, Body::from(body_bytes)).await;
    }

    // If successful, parse response and track resource (don't fail request if tracking fails)

    let decompressed_bytes =
        decompress_if_gzipped(&body_bytes, &response_headers).unwrap_or_else(|e| {
            tracing::error!(
                "Failed to decompress response for user_id={}: {}",
                user.user_id,
                e
            );
            body_bytes.to_vec()
        });

    let Ok(response_json) = serde_json::from_slice::<serde_json::Value>(&decompressed_bytes) else {
        return build_response(status, response_headers, Body::from(body_bytes)).await;
    };

    let Some(id) = response_json
        .get("id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
    else {
        return build_response(status, response_headers, Body::from(body_bytes)).await;
    };

    match resource_type {
        TrackableResource::Conversation => {
            if let Err(e) = state
                .conversation_service
                .track_conversation(&id, user.user_id)
                .await
            {
                tracing::error!(
                    "Failed to track conversation {} for user {}: {}",
                    id,
                    user.user_id,
                    e
                );
            }

            // Record metrics for conversation creation
            state
                .metrics_service
                .record_count(METRIC_CONVERSATION_CREATED, 1, &[]);

            // Record analytics in database
            if let Err(e) = state
                .analytics_service
                .record_activity(RecordActivityRequest {
                    user_id: user.user_id,
                    activity_type: ActivityType::Conversation,
                    auth_method: None,
                    metadata: Some(serde_json::json!({ "conversation_id": id })),
                })
                .await
            {
                tracing::warn!(
                    "Failed to record analytics for conversation creation: {}",
                    e
                );
            }
        }
        TrackableResource::ConversationUpdate => {
            // Track conversation in DB but do NOT record metrics (this is an update, not creation)
            if let Err(e) = state
                .conversation_service
                .track_conversation(&id, user.user_id)
                .await
            {
                tracing::error!(
                    "Failed to track conversation update {} for user {}: {}",
                    id,
                    user.user_id,
                    e
                );
            }
        }
        TrackableResource::File => {
            match serde_json::from_value::<services::file::ports::FileData>(response_json) {
                Ok(file_data) => {
                    if let Err(e) = state.file_service.track_file(file_data, user.user_id).await {
                        tracing::error!(
                            "Failed to track file {} for user {}: {}",
                            id,
                            user.user_id,
                            e
                        );
                    }

                    // Record metrics for file upload
                    state
                        .metrics_service
                        .record_count(METRIC_FILE_UPLOADED, 1, &[]);

                    // Record analytics in database
                    if let Err(e) = state
                        .analytics_service
                        .record_activity(RecordActivityRequest {
                            user_id: user.user_id,
                            activity_type: ActivityType::FileUpload,
                            auth_method: None,
                            metadata: Some(serde_json::json!({ "file_id": id })),
                        })
                        .await
                    {
                        tracing::warn!("Failed to record analytics for file upload: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to parse file data from response for user {}: {}",
                        user.user_id,
                        e
                    );
                }
            }
        }
    }

    build_response(status, response_headers, Body::from(body_bytes)).await
}

async fn build_response(status: u16, headers: HeaderMap, body: Body) -> Result<Response, Response> {
    // Build the response
    let mut response = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));

    // Copy headers from OpenAI response
    if let Some(response_headers) = response.headers_mut() {
        for (key, value) in headers.iter() {
            // Skip certain headers that shouldn't be forwarded:
            // - transfer-encoding: hyper handles this
            // - connection: hop-by-hop header
            // - content-length: may be incorrect if we modified the body (e.g., injecting author metadata)
            //   hyper will calculate the correct content-length automatically
            if key != "transfer-encoding" && key != "connection" && key != "content-length" {
                response_headers.insert(key, value.clone());
            }
        }
    }

    response.body(body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to build response: {e}"),
            }),
        )
            .into_response()
    })
}

/// Track a conversation from a response creation request
async fn track_conversation_from_request(
    state: &crate::state::AppState,
    user_id: UserId,
    body: &Bytes,
) -> anyhow::Result<()> {
    tracing::debug!(
        "Attempting to track conversation from /responses request for user_id={}",
        user_id
    );

    // Parse the request body to extract conversation_id if present
    #[derive(Deserialize)]
    struct ResponseRequest {
        conversation: Option<String>,
    }

    if let Ok(req) = serde_json::from_slice::<ResponseRequest>(body) {
        if let Some(conversation_id) = req.conversation {
            tracing::info!(
                "Found conversation_id={} in /responses request for user_id={}, tracking...",
                conversation_id,
                user_id
            );

            state
                .conversation_service
                .track_conversation(&conversation_id, user_id)
                .await?;

            tracing::info!(
                "Successfully tracked conversation {} from /responses for user_id={}",
                conversation_id,
                user_id
            );
        } else {
            tracing::debug!(
                "No conversation_id found in /responses request body for user_id={}",
                user_id
            );
        }
    } else {
        tracing::debug!(
            "Failed to parse /responses request body for user_id={}",
            user_id
        );
    }

    Ok(())
}

async fn validate_user_conversation(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    conversation_id: &str,
    required_permission: SharePermission,
) -> Result<(), Response> {
    state
        .conversation_share_service
        .ensure_access(conversation_id, user.user_id, required_permission)
        .await
        .map_err(map_share_error)
}

/// Validate user has access OR the conversation is publicly shared
async fn validate_user_or_public_conversation(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    conversation_id: &str,
    required_permission: SharePermission,
) -> Result<(), Response> {
    // First check regular access
    let user_access = state
        .conversation_share_service
        .ensure_access(conversation_id, user.user_id, required_permission)
        .await;

    if user_access.is_ok() {
        return Ok(());
    }

    // If no user access, check if publicly shared
    state
        .conversation_share_service
        .get_public_access_by_conversation_id(conversation_id, required_permission)
        .await
        .map(|_| ())
        .map_err(map_share_error)
}

/// Validate conversation access with optional authentication
/// - If user is authenticated: check their access (owner, shared, or public)
/// - If user is not authenticated: only check if publicly shared
async fn validate_conversation_access_optional_auth(
    state: &crate::state::AppState,
    user: Option<&AuthenticatedUser>,
    conversation_id: &str,
    required_permission: SharePermission,
) -> Result<(), Response> {
    if let Some(user) = user {
        // User is authenticated - check their access or public share
        validate_user_or_public_conversation(state, user, conversation_id, required_permission)
            .await
    } else {
        // User is not authenticated - only public share is allowed
        state
            .conversation_share_service
            .get_public_access_by_conversation_id(conversation_id, required_permission)
            .await
            .map(|_| ())
            .map_err(map_share_error)
    }
}

async fn validate_owner_conversation(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    conversation_id: &str,
) -> Result<(), Response> {
    state
        .conversation_service
        .access_conversation(conversation_id, user.user_id)
        .await
        .map_err(|e| {
            let (status, error) = match e {
                ConversationError::NotFound => {
                    (StatusCode::NOT_FOUND, "Conversation not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to get conversation: {}", e),
                ),
            };

            (status, Json(ErrorResponse { error })).into_response()
        })
}

fn map_share_error(error: ConversationError) -> Response {
    let (status, message) = match error {
        ConversationError::NotFound => {
            (StatusCode::NOT_FOUND, "Conversation not found".to_string())
        }
        ConversationError::AccessDenied => (StatusCode::FORBIDDEN, "Access denied".to_string()),
        ConversationError::ApiError(msg) => (StatusCode::BAD_GATEWAY, msg),
        ConversationError::DatabaseError(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to access conversation: {msg}"),
        ),
        ConversationError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
    };

    (status, Json(ErrorResponse { error: message })).into_response()
}

async fn fetch_conversation_from_proxy(
    state: &crate::state::AppState,
    conversation_id: &str,
    headers: HeaderMap,
) -> Result<serde_json::Value, Response> {
    fn bad_gateway(message: impl Into<String>) -> Response {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: message.into(),
            }),
        )
            .into_response()
    }

    let proxy_response = state
        .proxy_service
        .forward_request(
            Method::GET,
            &format!("conversations/{conversation_id}"),
            headers,
            None,
        )
        .await
        .map_err(|e| bad_gateway(format!("OpenAI API error: {e}")))?;

    let status = StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() {
        let reason = status
            .canonical_reason()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        return Err(bad_gateway(format!(
            "OpenAI API returned status {}{reason}",
            status.as_u16()
        )));
    }

    let proxy_body = Body::from_stream(proxy_response.body);
    let body_bytes: Bytes = to_bytes(proxy_body, MAX_RESPONSE_BODY_SIZE)
        .await
        .map_err(|e| bad_gateway(format!("Failed to read response: {e}")))?;

    let conversation: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| bad_gateway(format!("Failed to parse JSON: {e}")))?;

    Ok(conversation)
}

async fn validate_user_file(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    file_id: &str,
) -> Result<(), Response> {
    state
        .file_service
        .access_file(file_id, user.user_id)
        .await
        .map_err(|e| {
            let (status, error) = match e {
                FileError::NotFound => (StatusCode::NOT_FOUND, "File not found".to_string()),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to get file: {}", e),
                ),
            };

            (status, Json(ErrorResponse { error })).into_response()
        })
}

/// Extract body bytes from a request
async fn extract_body_bytes(request: Request) -> Result<Bytes, Response> {
    tracing::debug!("Extracting body bytes from request");
    let result = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read request body: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Failed to read request body: {e}"),
                }),
            )
                .into_response()
        })?;

    tracing::debug!(
        "Successfully extracted {} bytes from request body",
        result.len()
    );
    Ok(result)
}

/// Decompress gzip-encoded bytes if needed
fn decompress_if_gzipped(bytes: &[u8], headers: &HeaderMap) -> Result<Vec<u8>, std::io::Error> {
    // Check if content-encoding is gzip
    if let Some(encoding) = headers.get("content-encoding") {
        if let Ok(encoding_str) = encoding.to_str() {
            if encoding_str.contains("gzip") {
                tracing::debug!("Response is gzip-encoded, decompressing...");
                let mut decoder = GzDecoder::new(bytes);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                tracing::debug!(
                    "Decompressed {} bytes to {} bytes",
                    bytes.len(),
                    decompressed.len()
                );
                return Ok(decompressed);
            }
        }
    }

    // Not gzipped, return as-is
    Ok(bytes.to_vec())
}

/// Returns true if response headers indicate a streaming (SSE) response.
fn is_streaming_response(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false)
}

/// Record image usage (metric_key + quantity; cost from model pricing × quantity).
/// Used for /v1/images/generations (image.generate, quantity=n) and /v1/images/edits (image.edit, quantity=1).
async fn record_image_usage(
    state: &crate::state::AppState,
    user_id: UserId,
    metric_key: &str,
    quantity: i64,
    model_name: Option<&str>,
    api_key_ext: Option<AuthenticatedApiKey>,
) {
    if quantity <= 0 {
        return;
    }
    let cost_nano_usd = if let Some(model) = model_name {
        state
            .model_pricing_cache
            .get_pricing(model)
            .await
            .map(|p| p.cost_nano_usd_for_images(quantity as u32))
            .unwrap_or(0)
    } else {
        0
    };

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "request_type": "image_generation",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: metric_key.to_string(),
        quantity,
        cost_nano_usd: Some(cost_nano_usd),
        model_id: model_name.map(|s| s.to_string()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!(
            "Failed to record image usage for user_id={}: {}",
            user_id,
            e
        );
    }
}

/// Record token and cost usage from parsed **chat completions** response body.
/// Returns true if usage was recorded.
async fn record_chat_usage_from_body(
    state: &crate::state::AppState,
    user_id: UserId,
    request_body: &[u8],
    response_body: &[u8],
    api_key_ext: Option<AuthenticatedApiKey>,
) -> bool {
    let Some(usage) = parse_chat_completion_usage_from_bytes(response_body) else {
        return false;
    };
    if usage.total_tokens == 0 {
        return false;
    }

    // Extract request model name from request body
    let request_model = serde_json::from_slice::<serde_json::Value>(request_body)
        .ok()
        .and_then(|v| {
            v.get("model")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| usage.model.clone());

    let pricing = state.model_pricing_cache.get_pricing(&request_model).await;
    let cost_nano_usd = pricing
        .as_ref()
        .map(|p| p.cost_nano_usd(usage.input_tokens, usage.output_tokens));

    let input_cost = pricing
        .as_ref()
        .map(|p| usage.input_tokens as i64 * p.input_nano_per_token)
        .unwrap_or(0);
    let output_cost = pricing
        .as_ref()
        .map(|p| usage.output_tokens as i64 * p.output_nano_per_token)
        .unwrap_or(0);

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "input_tokens": usage.input_tokens as i64,
        "output_tokens": usage.output_tokens as i64,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "request_type": "chat_completion",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: services::user_usage::METRIC_KEY_LLM_TOKENS.to_string(),
        quantity: usage.total_tokens as i64,
        cost_nano_usd,
        model_id: Some(usage.model.clone()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!("Failed to record usage for user_id={}: {}", user_id, e);
        return false;
    }

    true
}

/// Record token and cost usage from parsed **/v1/responses** body.
/// Returns true if usage was recorded.
async fn record_response_usage_from_body(
    state: &crate::state::AppState,
    user_id: UserId,
    body: &[u8],
    api_key_ext: Option<AuthenticatedApiKey>,
) -> bool {
    let Some(usage) = parse_response_usage_from_bytes(body) else {
        return false;
    };
    if usage.total_tokens == 0 {
        return false;
    }

    let pricing = state.model_pricing_cache.get_pricing(&usage.model).await;
    let cost_nano_usd = pricing
        .as_ref()
        .map(|p| p.cost_nano_usd(usage.input_tokens, usage.output_tokens));

    let input_cost = pricing
        .as_ref()
        .map(|p| usage.input_tokens as i64 * p.input_nano_per_token)
        .unwrap_or(0);
    let output_cost = pricing
        .as_ref()
        .map(|p| usage.output_tokens as i64 * p.output_nano_per_token)
        .unwrap_or(0);

    let (instance_id, api_key_id) = api_key_ext
        .as_ref()
        .map(|ak| (ak.api_key_info.instance_id, Some(ak.api_key_info.id)))
        .unwrap_or((None, None));

    let details = serde_json::json!({
        "input_tokens": usage.input_tokens as i64,
        "output_tokens": usage.output_tokens as i64,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "request_type": "response",
    });

    let params = services::user_usage::RecordUsageParams {
        user_id,
        metric_key: services::user_usage::METRIC_KEY_LLM_TOKENS.to_string(),
        quantity: usage.total_tokens as i64,
        cost_nano_usd,
        model_id: Some(usage.model.clone()),
        instance_id,
        api_key_id,
        details: Some(details),
    };

    let result = if instance_id.is_some() {
        state
            .user_usage_service
            .record_usage_and_update_balance(params)
            .await
    } else {
        state.user_usage_service.record_usage(params).await
    };

    if let Err(e) = result {
        tracing::warn!("Failed to record usage for user_id={}: {}", user_id, e);
        return false;
    }

    true
}

/// Collect a stream into bytes. Returns the first stream error instead of silently truncating.
async fn collect_stream_to_bytes(
    stream: impl futures::Stream<Item = Result<Bytes, reqwest::Error>>,
) -> Result<Bytes, reqwest::Error> {
    use futures::StreamExt;

    let mut collected = Vec::new();
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        match result {
            Ok(bytes) => collected.extend_from_slice(&bytes),
            Err(e) => return Err(e),
        }
    }

    Ok(Bytes::from(collected))
}
