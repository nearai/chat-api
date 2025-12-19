use crate::consts::{LIST_FILES_LIMIT_MAX, MODEL_PUBLIC_DEFAULT};
use crate::middleware::auth::AuthenticatedUser;
use axum::{
    body::Body,
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use chrono::{Duration, Utc};
use flate2::read::GzDecoder;
use futures::TryStreamExt;
use near_api::{Account, AccountId, NetworkConfig};
use serde::{Deserialize, Serialize};
use services::analytics::{ActivityType, RecordActivityRequest};
use services::conversation::ports::ConversationError;
use services::file::ports::FileError;
use services::metrics::consts::{
    METRIC_CONVERSATION_CREATED, METRIC_FILE_UPLOADED, METRIC_RESPONSE_CREATED,
};
use services::response::ports::ProxyResponse;
use services::user::ports::{BanType, OAuthProvider};
use services::UserId;
use std::io::Read;

const NEAR_BAN_ERROR_MESSAGE: &str =
    "User is temporarily banned from using this feature; please try again later";

/// Minimum required NEAR balance (1 NEAR in yoctoNEAR: 10^24)
const MIN_NEAR_BALANCE: u128 = 1_000_000_000_000_000_000_000_000;

/// Duration of user ban after NEAR balance check fails (in seconds)
const NEAR_BALANCE_BAN_DURATION_SECS: i64 = 60 * 60;

/// Duration to cache NEAR balance checks in memory (in seconds)
const NEAR_BALANCE_CACHE_TTL_SECS: i64 = 5 * 60;

/// Create the OpenAI API proxy router
pub fn create_api_router(
    rate_limit_state: crate::middleware::RateLimitState,
) -> Router<crate::state::AppState> {
    let conversations_router = Router::new()
        .route("/v1/conversations", post(create_conversation))
        .route("/v1/conversations", get(list_conversations))
        .route("/v1/conversations/{conversation_id}", get(get_conversation))
        .route(
            "/v1/conversations/{conversation_id}",
            post(update_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}",
            delete(delete_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/items",
            post(create_conversation_items),
        )
        .route(
            "/v1/conversations/{conversation_id}/items",
            get(list_conversation_items),
        )
        .route(
            "/v1/conversations/{conversation_id}/pin",
            post(pin_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/pin",
            delete(unpin_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/archive",
            post(archive_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/archive",
            delete(unarchive_conversation),
        )
        .route(
            "/v1/conversations/{conversation_id}/clone",
            post(clone_conversation),
        );

    let files_router = Router::new()
        .route("/v1/files", post(upload_file))
        .route("/v1/files", get(list_files))
        .route("/v1/files/{file_id}", get(get_file))
        .route("/v1/files/{file_id}", delete(delete_file))
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
    let body_bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
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
    validate_user_conversation(&state, &user, &conversation_id).await?;

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

/// Get a conversation - validates user access and fetches details via service/OpenAI
async fn get_conversation(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    tracing::info!(
        "get_conversation called for user_id={}, conversation_id={}",
        user.user_id,
        conversation_id
    );

    let conversation = state
        .conversation_service
        .get_conversation(&conversation_id, user.user_id)
        .await
        .map_err(|e| {
            let (status, error) = match e {
                ConversationError::NotFound => {
                    (StatusCode::NOT_FOUND, "Conversation not found".to_string())
                }
                ConversationError::ApiError(msg) => {
                    (StatusCode::BAD_GATEWAY, format!("OpenAI API error: {msg}"))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get conversation".to_string(),
                ),
            };

            (status, Json(ErrorResponse { error })).into_response()
        })?;

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

    validate_user_conversation(&state, &user, &conversation_id).await?;

    // Extract body
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "create_conversation_items request body size: {} bytes for user_id={}",
        body_bytes.len(),
        user.user_id
    );

    if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
        tracing::debug!("Request body: {}", body_str);
    }

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
            Some(body_bytes),
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

async fn list_conversation_items(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    tracing::info!(
        "list_conversation_items called for user_id={}, session_id={}",
        user.user_id,
        user.session_id
    );

    validate_user_conversation(&state, &user, &conversation_id).await?;

    tracing::debug!(
        "Forwarding conversation items list request to OpenAI for user_id={}",
        user.user_id
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
            tracing::error!(
                "OpenAI API error during conversation items list for user_id={}: {}",
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

    validate_user_conversation(&state, &user, &conversation_id).await?;

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

    validate_user_conversation(&state, &user, &conversation_id).await?;

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

    validate_user_conversation(&state, &user, &conversation_id).await?;

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

    validate_user_conversation(&state, &user, &conversation_id).await?;

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

    // Validate user has access to the source conversation
    validate_user_conversation(&state, &user, &conversation_id).await?;

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
            match state.model_service.get_model(model_id).await {
                Ok(Some(model)) => {
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
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Model not found".to_string(),
                        }),
                    )
                        .into_response())
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

    // If we have a model-level system prompt, inject or prepend it into the request as `instructions`.
    let modified_body_bytes =
        if let (Some(mut body), Some(system_prompt)) = (body_json, model_system_prompt.clone()) {
            // If client already provided instructions, prepend model system prompt with two newlines.
            let new_instructions = match body.get("instructions").and_then(|v| v.as_str()) {
                Some(existing) if !existing.is_empty() => {
                    format!("{system_prompt}\n\n{existing}")
                }
                _ => system_prompt,
            };

            body["instructions"] = serde_json::Value::String(new_instructions);

            match serde_json::to_vec(&body) {
                Ok(serialized) => Bytes::from(serialized),
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to modify instructions".to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        } else {
            body_bytes
        };

    headers.append(
        "content-length",
        modified_body_bytes.len().to_string().parse().unwrap(),
    );

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
                metadata: None,
            })
            .await
        {
            tracing::warn!("Failed to record analytics for response creation: {}", e);
        }
    }

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
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
                error: NEAR_BAN_ERROR_MESSAGE.to_string(),
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
                error: NEAR_BAN_ERROR_MESSAGE.to_string(),
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
    let body_bytes: Bytes = proxy_response
        .body
        .try_collect::<Vec<_>>()
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
        })?
        .into_iter()
        .flatten()
        .collect();

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
        .await.unwrap_or_else(|e| {
        tracing::warn!(
                "Failed to batch load model settings for model list: {}, defaulting all public=false",
                e
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
        .expect("models key must exist after previous check") =
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
    // Collect the stream into bytes
    let body_bytes: Bytes = proxy_response
        .body
        .try_collect::<Vec<_>>()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to read response: {e}"),
                }),
            )
                .into_response()
        })?
        .into_iter()
        .flatten()
        .collect();

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
            // Skip certain headers that shouldn't be forwarded
            if key != "transfer-encoding" && key != "connection" {
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
    let result = axum::body::to_bytes(request.into_body(), usize::MAX)
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
