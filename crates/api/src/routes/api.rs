use crate::consts::{LIST_FILES_LIMIT_MAX, MAX_REQUEST_BODY_SIZE, MAX_RESPONSE_BODY_SIZE};
use crate::middleware::auth::AuthenticatedUser;
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
use http::{HeaderName, HeaderValue};
use near_api::{Account, AccountId, NetworkConfig};
use serde::{Deserialize, Serialize};
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
use sha2::{Digest, Sha256};
use std::io::Read;
use uuid::Uuid;

/// Minimum required NEAR balance (1 NEAR in yoctoNEAR: 10^24)
const MIN_NEAR_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

/// Duration of user ban after NEAR balance check fails (in seconds)
const NEAR_BALANCE_BAN_DURATION_SECS: i64 = 60 * 60;

/// Duration to cache NEAR balance checks in memory (in seconds)
const NEAR_BALANCE_CACHE_TTL_SECS: i64 = 5 * 60;

/// Duration to cache model settings needed by /v1/responses in memory (in seconds)
const MODEL_SETTINGS_CACHE_TTL_SECS: i64 = 60;

/// Error message when a user is banned
pub const USER_BANNED_ERROR_MESSAGE: &str =
    "Access temporarily restricted. Please try again later.";

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

/// Create the OpenAI API proxy router (requires authentication)
pub fn create_api_router(
    rate_limit_state: crate::middleware::RateLimitState,
) -> Router<crate::state::AppState> {
    // Conversation routes that require authentication
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

    let responses_router = Router::new()
        .route("/v1/responses", post(proxy_responses))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            crate::middleware::rate_limit_middleware,
        ));

    let proxy_router = Router::new()
        .route("/v1/model/list", get(proxy_model_list))
        .route("/v1/signature/{chat_id}", get(proxy_signature));

    Router::new()
        .merge(conversations_router)
        .merge(share_groups_router)
        .merge(files_router)
        .merge(responses_router)
        .merge(proxy_router)
}

/// Type of resource to track in the response
enum TrackableResource {
    /// New conversation - records metrics
    Conversation,
    /// Updated conversation - tracks in DB but does NOT record metrics
    ConversationUpdate,
    File,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareRecipientPayload {
    pub kind: ShareRecipientKind,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateConversationShareRequest {
    pub permission: SharePermission,
    pub target: ShareTargetPayload,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct OwnerInfo {
    pub user_id: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConversationSharesListResponse {
    pub is_owner: bool,
    pub can_share: bool,
    /// Whether the user can send messages (has write access)
    pub can_write: bool,
    pub shares: Vec<ConversationShareResponse>,
    /// Owner information for displaying author names on messages
    pub owner: Option<OwnerInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateShareGroupRequest {
    pub name: String,
    pub members: Vec<ShareRecipientPayload>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateShareGroupRequest {
    pub name: Option<String>,
    pub members: Option<Vec<ShareRecipientPayload>>,
}

#[derive(Debug, Serialize)]
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
#[derive(Serialize, Deserialize, Debug)]
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
    tag = "Conversations",
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to retrieve")
    ),
    responses(
        (status = 200, description = "Conversation retrieved successfully", body = serde_json::Value),
        (status = 403, description = "Access denied - conversation not accessible to this user or not publicly shared"),
        (status = 404, description = "Conversation not found")
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

#[derive(Serialize)]
struct SharedConversationInfo {
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

async fn create_conversation_items(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
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
    // NOTE: We inject metadata into the request AND store it in the database (below).
    // This dual approach ensures author info is available even if OpenAI doesn't preserve
    // custom metadata fields. When listing items, we retrieve from DB via inject_author_metadata().
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

    // For successful responses, collect the body to extract response_id and store author info
    if (200..300).contains(&proxy_response.status) {
        let response_bytes = collect_stream_to_bytes(proxy_response.body).await;

        // Try to extract response_id from the response and store author info
        if let Ok(response_json) = serde_json::from_slice::<serde_json::Value>(&response_bytes) {
            if let Some(response_id) = response_json
                .get("response_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            {
                let repo = state.response_author_repository.clone();
                let conv_id = conversation_id.clone();
                let uid = user.user_id;
                let author = author_name.clone();

                // Store author info asynchronously
                tokio::spawn(async move {
                    if let Err(e) = repo
                        .store_author(&conv_id, &response_id, uid.into(), author.as_deref())
                        .await
                    {
                        tracing::warn!("Failed to store response author: {}", e);
                    }
                });
            }
        }

        build_response(
            proxy_response.status,
            proxy_response.headers,
            Body::from(response_bytes),
        )
        .await
    } else {
        build_response(
            proxy_response.status,
            proxy_response.headers,
            Body::from_stream(proxy_response.body),
        )
        .await
    }
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
    tag = "Conversations",
    params(
        ("conversation_id" = String, Path, description = "ID of the conversation to list items from")
    ),
    responses(
        (status = 200, description = "Conversation items retrieved successfully"),
        (status = 403, description = "Access denied - conversation not accessible to this user or not publicly shared"),
        (status = 404, description = "Conversation not found")
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

    // Collect response body to inject author metadata
    let body_bytes = collect_stream_to_bytes(proxy_response.body).await;

    // Try to inject author metadata into the response
    let final_body = match inject_author_metadata(&state, &conversation_id, body_bytes).await {
        Ok(modified_bytes) => Body::from(modified_bytes),
        Err(original_bytes) => Body::from(original_bytes),
    };

    build_response(proxy_response.status, proxy_response.headers, final_body).await
}

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

async fn proxy_responses(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
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

    // Enforce model-level visibility based on settings if a model is specified
    if let Some(ref body) = body_json {
        if let Some(model_id) = body.get("model").and_then(|v| v.as_str()) {
            model_id_from_body = Some(model_id.to_string());

            // 1) Try cache first
            {
                let cache = state.model_settings_cache.read().await;
                if let Some(entry) = cache.get(model_id) {
                    let age = Utc::now().signed_duration_since(entry.last_checked_at);
                    if age.num_seconds() >= 0 && age.num_seconds() < MODEL_SETTINGS_CACHE_TTL_SECS {
                        model_settings_cache_hit = Some(true);

                        if !entry.public {
                            tracing::warn!(
                                "Blocking response request for non-public model '{}' from user {} (cache)",
                                model_id,
                                user.user_id
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
                                "Blocking response request for non-public model '{}' from user {}",
                                model_id,
                                user.user_id
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
                        // Cache with defaults to avoid repeated DB hits, let OpenAI validate model existence
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

                        // Continue with defaults - let OpenAI validate model existence
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
        }
    }

    // Fetch user profile to inject author metadata into messages
    let user_profile = state.user_service.get_user_profile(user.user_id).await.ok();

    // Save conversation_id and author_name for response author tracking
    // (before body_json and user_profile are consumed)
    let conversation_id_for_author = body_json
        .as_ref()
        .and_then(|b| b.get("conversation"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let author_name_for_tracking = user_profile.as_ref().and_then(|p| p.user.name.clone());

    tracing::info!(
        "create_response: conversation_id_for_author={:?}, author_name={:?}, user_id={}",
        conversation_id_for_author,
        author_name_for_tracking,
        user.user_id
    );

    // Modify request body to inject system prompt and/or author metadata
    let modified_body_bytes = if let Some(mut body) = body_json {
        // Inject model-level system prompt if present
        if let Some(system_prompt) = model_system_prompt.clone() {
            let new_instructions = match body.get("instructions").and_then(|v| v.as_str()) {
                Some(existing) if !existing.is_empty() => {
                    format!("{system_prompt}\n\n{existing}")
                }
                _ => system_prompt,
            };
            body["instructions"] = serde_json::Value::String(new_instructions);
        }

        // Inject author metadata with user info
        // This allows shared conversations to show who sent each message
        // NOTE: We inject metadata into the request AND store it in the database (see response stream wrapper below).
        // This dual approach ensures author info is available even if OpenAI doesn't preserve
        // custom metadata fields. When listing items, we retrieve from DB via inject_author_metadata().
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
    match HeaderValue::from_str(&modified_body_bytes.len().to_string()) {
        Ok(header_value) => {
            headers.insert("content-length", header_value);
        }
        Err(e) => {
            tracing::error!("Failed to create content-length header value: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to set content-length header".to_string(),
                }),
            )
                .into_response());
        }
    }

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

    // Access model system prompt cache during proxy response handling (for observability/debugging).
    // We DO NOT expose the prompt itself; we only attach a stable hash + cache hit indicator.
    let mut proxy_headers = proxy_response.headers.clone();
    if let Some(ref model_id) = model_id_from_body {
        let cached_prompt_opt = {
            let cache = state.model_settings_cache.read().await;
            cache.get(model_id).and_then(|e| {
                if e.exists {
                    e.system_prompt.clone()
                } else {
                    None
                }
            })
        };

        if let Some(prompt) = cached_prompt_opt {
            let mut hasher = Sha256::new();
            hasher.update(prompt.as_bytes());
            let prompt_hash = format!("{:x}", hasher.finalize());

            let _ = proxy_headers.insert(
                HeaderName::from_static("x-nearai-model-system-prompt-sha256"),
                HeaderValue::from_str(&prompt_hash)
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            );
        }

        if let Some(hit) = model_settings_cache_hit {
            let _ = proxy_headers.insert(
                HeaderName::from_static("x-nearai-model-settings-cache"),
                HeaderValue::from_static(if hit { "hit" } else { "miss" }),
            );
        }
    }

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

    // Wrap the response stream to extract response_id and store author info
    let response_body = if let Some(conv_id) = conversation_id_for_author.as_ref() {
        if (200..300).contains(&proxy_response.status) {
            let repo = state.response_author_repository.clone();
            let user_id = user.user_id;
            let author = author_name_for_tracking;

            tracing::info!(
                "create_response: Using AuthorTrackingStream for conv_id={}, user_id={}, author={:?}",
                conv_id,
                user_id,
                author
            );

            let wrapped_stream = AuthorTrackingStream::new(
                proxy_response.body,
                repo,
                conv_id.clone(),
                user_id,
                author,
            );
            Body::from_stream(wrapped_stream)
        } else {
            tracing::info!(
                "create_response: NOT using AuthorTrackingStream - conv_id={:?}, status={}",
                conversation_id_for_author,
                proxy_response.status
            );
            Body::from_stream(proxy_response.body)
        }
    } else {
        tracing::info!(
            "create_response: NOT using AuthorTrackingStream - conv_id={:?}, status={}",
            conversation_id_for_author,
            proxy_response.status
        );
        Body::from_stream(proxy_response.body)
    };

    build_response(proxy_response.status, proxy_headers, response_body).await
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

/// Stream wrapper that extracts response_id from SSE events and stores author info
use database::repositories::ResponseAuthorRepository;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Try to extract response_id from SSE data text
fn try_extract_response_id(text: &str) -> Option<String> {
    // Look for response_id in SSE data
    // Format: data: {"type":"response.created","response":{"id":"resp_xxx",...},...}
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(response_id) = json
                    .get("response")
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                {
                    return Some(response_id.to_string());
                }
            }
        }
    }
    None
}

struct AuthorTrackingStream<S> {
    inner: S,
    buffer: String,
    response_id_found: bool,
    repo: std::sync::Arc<ResponseAuthorRepository>,
    conversation_id: String,
    user_id: UserId,
    author_name: Option<String>,
}

impl<S> AuthorTrackingStream<S> {
    fn new(
        inner: S,
        repo: std::sync::Arc<ResponseAuthorRepository>,
        conversation_id: String,
        user_id: UserId,
        author_name: Option<String>,
    ) -> Self {
        Self {
            inner,
            buffer: String::new(),
            response_id_found: false,
            repo,
            conversation_id,
            user_id,
            author_name,
        }
    }
}

impl<S, E> Stream for AuthorTrackingStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Try to extract response_id if not found yet
                if !self.response_id_found {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        self.buffer.push_str(text);

                        if let Some(response_id) = try_extract_response_id(&self.buffer) {
                            self.response_id_found = true;

                            // Store author info asynchronously
                            let repo = self.repo.clone();
                            let conv_id = self.conversation_id.clone();
                            let user_id = self.user_id;
                            let author = self.author_name.clone();

                            tokio::spawn(async move {
                                tracing::info!(
                                    "Storing author for response_id={}, conversation_id={}, user_id={}, author_name={:?}",
                                    response_id, conv_id, user_id, author
                                );
                                if let Err(e) = repo
                                    .store_author(
                                        &conv_id,
                                        &response_id,
                                        user_id.into(),
                                        author.as_deref(),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to store response author: {}", e);
                                }
                            });
                        }
                    }
                }

                Poll::Ready(Some(Ok(bytes)))
            }
            other => other,
        }
    }
}

/// Collect a stream into bytes
async fn collect_stream_to_bytes(
    stream: impl futures::Stream<Item = Result<Bytes, reqwest::Error>>,
) -> Bytes {
    use futures::StreamExt;

    let mut collected = Vec::new();
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        if let Ok(bytes) = result {
            collected.extend_from_slice(&bytes);
        }
    }

    Bytes::from(collected)
}

/// Inject author metadata into conversation items response
/// Returns Ok(modified_bytes) on success, Err(original_bytes) on failure
/// Only injects author info for messages that have explicit records in response_authors table
async fn inject_author_metadata(
    state: &crate::state::AppState,
    conversation_id: &str,
    body_bytes: Bytes,
) -> Result<Bytes, Bytes> {
    // Parse the response as JSON
    let mut json: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|_| body_bytes.clone())?;

    // Get authors for this conversation from the database
    let authors = state
        .response_author_repository
        .get_authors_for_conversation(conversation_id)
        .await
        .unwrap_or_default();

    tracing::info!(
        "inject_author_metadata: conversation_id={}, found {} stored authors: {:?}",
        conversation_id,
        authors.len(),
        authors.keys().collect::<Vec<_>>()
    );

    if authors.is_empty() {
        // No stored authors, return original response
        return Err(body_bytes);
    }

    // Navigate to the data array containing items
    let items = json
        .get_mut("data")
        .and_then(|d| d.as_array_mut())
        .ok_or_else(|| body_bytes.clone())?;

    let mut modified = false;

    for item in items.iter_mut() {
        // Skip items that already have author_id in metadata
        if item
            .get("metadata")
            .and_then(|m| m.get("author_id"))
            .is_some()
        {
            continue;
        }

        // Get the response_id from each item
        let response_id = item.get("response_id").and_then(|v| v.as_str());

        if let Some(resp_id) = response_id {
            // Only inject author info if we have an explicit record
            if let Some(author) = authors.get(resp_id) {
                // Ensure metadata object exists
                if item.get("metadata").is_none() {
                    item["metadata"] = serde_json::json!({});
                }

                if let Some(metadata) = item.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                    metadata.insert(
                        "author_id".to_string(),
                        serde_json::Value::String(author.user_id.to_string()),
                    );
                    if let Some(name) = &author.author_name {
                        metadata.insert(
                            "author_name".to_string(),
                            serde_json::Value::String(name.clone()),
                        );
                    }
                    modified = true;
                }
            }
        }
    }

    if modified {
        serde_json::to_vec(&json)
            .map(Bytes::from)
            .map_err(|_| body_bytes)
    } else {
        Err(body_bytes)
    }
}
