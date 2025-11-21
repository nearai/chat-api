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
use flate2::read::GzDecoder;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use services::conversation::ports::ConversationError;
use services::response::ports::ProxyResponse;
use services::UserId;
use std::io::Read;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Create the OpenAI API proxy router
pub fn create_api_router() -> Router<crate::state::AppState> {
    // IMPORTANT: Specific routes MUST be in the same Router and registered BEFORE catch-all routes
    // Axum matches routes in order within a router
    Router::new()
        // Specific conversation endpoints (handle these before catch-all)
        .route("/v1/conversations", post(create_conversation))
        .route("/v1/conversations", get(list_conversations))
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
        )
        // Catch-all proxy for all other OpenAI endpoints
        .route("/v1/{*path}", post(proxy_handler))
        .route("/v1/{*path}", get(proxy_handler))
        .route("/v1/{*path}", delete(proxy_handler))
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

    handle_conversation_response(&state, &user, proxy_response).await
}

/// Helper function to handle conversation response: buffer, parse, and track conversation
async fn handle_conversation_response(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    proxy_response: ProxyResponse,
) -> Result<Response, Response> {
    let status = proxy_response.status;
    let response_headers = proxy_response.headers;

    tracing::debug!("Response headers: {:?}", response_headers);

    // Buffer the response to extract the conversation ID
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

    // If successful, parse response and track conversation
    if (200..300).contains(&status) {
        let decompressed_bytes = match decompress_if_gzipped(&body_bytes, &response_headers) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    "Failed to decompress response for user_id={}: {}",
                    user.user_id,
                    e
                );
                body_bytes.to_vec()
            }
        };

        if let Ok(response_json) = serde_json::from_slice::<serde_json::Value>(&decompressed_bytes)
        {
            tracing::debug!("Response JSON parsed successfully");
            if let Some(conversation_id) = response_json.get("id").and_then(|v| v.as_str()) {
                // Track conversation in database
                tracing::debug!("Tracking conversation {} in database", conversation_id);
                if let Err(e) = state
                    .conversation_service
                    .track_conversation(conversation_id, user.user_id)
                    .await
                {
                    tracing::error!(
                        "Failed to track conversation {} for user {}: {}",
                        conversation_id,
                        user.user_id,
                        e
                    );
                    // Don't fail the request if tracking fails
                } else {
                    tracing::info!(
                        "Successfully tracked conversation {} in database for user_id={}",
                        conversation_id,
                        user.user_id
                    );
                }
            } else {
                tracing::warn!(
                    "No conversation ID found in OpenAI response for user_id={}",
                    user.user_id
                );
            }
        } else {
            tracing::warn!(
                "Failed to parse OpenAI response as JSON for user_id={}",
                user.user_id
            );
            if let Ok(text) = String::from_utf8(decompressed_bytes.clone()) {
                tracing::debug!("Response body: {}", text);
            }
        }
    } else {
        tracing::warn!(
            "Returned non-success status {} for user_id={}",
            status,
            user.user_id
        );
    }

    build_response(status, response_headers, Body::from(body_bytes)).await
}

/// List all conversations for the authenticated user (fetches details from OpenAI client)
async fn list_conversations(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<serde_json::Value>>, Response> {
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

    Ok(Json(conversations))
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

    handle_conversation_response(&state, &user, proxy_response).await
}

/// Generic proxy handler that forwards all requests to OpenAI
async fn proxy_handler(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, Response> {
    tracing::info!(
        "proxy_handler: {} /v1/{} for user_id={}, session_id={}",
        method,
        path,
        user.user_id,
        user.session_id
    );

    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    tracing::debug!(
        "Extracted request body: {} bytes for {} /v1/{}",
        body_bytes.len(),
        method,
        path
    );

    if !body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            tracing::debug!("Request body content: {}", body_str);
        }
    }

    // Track conversation if this is a POST to /responses
    if method == Method::POST && path == "responses" {
        tracing::debug!("POST to /responses detected, attempting to track conversation");
        if let Err(e) = track_conversation_from_request(&state, user.user_id, &body_bytes).await {
            tracing::error!(
                "Failed to track conversation for user {} from /responses: {}",
                user.user_id,
                e
            );
            // Don't fail the request if conversation tracking fails
        }
    }

    tracing::debug!(
        "Forwarding {} /v1/{} to OpenAI for user_id={}",
        method,
        path,
        user.user_id
    );

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(method.clone(), &path, headers.clone(), Some(body_bytes))
        .await
        .map_err(|e| {
            tracing::error!(
                "OpenAI API error for {} /v1/{} (user_id={}): {}",
                method,
                path,
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
        "Received response from OpenAI: status={} for {} /v1/{} (user_id={})",
        proxy_response.status,
        method,
        path,
        user.user_id
    );

    build_response(
        proxy_response.status,
        proxy_response.headers,
        Body::from_stream(proxy_response.body),
    )
    .await
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

async fn validate_user_conversation(
    state: &crate::state::AppState,
    user: &AuthenticatedUser,
    conversation_id: &str,
) -> Result<(), Response> {
    match state
        .conversation_service
        .get_conversation(conversation_id, user.user_id)
        .await
    {
        Ok(_) => Ok(()),
        Err(ConversationError::NotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Conversation not found".to_string(),
            }),
        )
            .into_response()),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get conversation".to_string(),
            }),
        )
            .into_response()),
    }
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
