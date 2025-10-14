use axum::{
    body::Body,
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use services::UserId;

use crate::middleware::auth::AuthenticatedUser;

#[derive(Serialize, Deserialize)]
pub struct ConversationResponse {
    pub id: String,
    pub title: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Create the OpenAI API proxy router
pub fn create_api_router() -> Router<crate::state::AppState> {
    Router::new()
        // Specific handlers for conversation endpoints (track in DB)
        .route("/v1/conversations", post(create_conversation))
        .route("/v1/conversations", get(list_conversations))
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
    // Extract body
    let body_bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Failed to read request body: {}", e),
                }),
            )
                .into_response()
        })?;

    // Forward to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(Method::POST, "conversations", headers, Some(body_bytes))
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {}", e),
                }),
            )
                .into_response()
        })?;

    let status = proxy_response.status;
    let response_headers = proxy_response.headers;

    // For conversation creation, we need to buffer the response to extract the conversation ID
    // Collect the stream into bytes
    let body_bytes: Bytes = proxy_response
        .body
        .try_collect::<Vec<_>>()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to read response: {}", e),
                }),
            )
                .into_response()
        })?
        .into_iter()
        .flatten()
        .collect();

    // If successful, parse response and track conversation
    if status >= 200 && status < 300 {
        if let Ok(response_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if let Some(conversation_id) = response_json.get("id").and_then(|v| v.as_str()) {
                // Track conversation in database
                if let Err(e) = state
                    .conversation_service
                    .track_conversation(conversation_id, user.user_id, None)
                    .await
                {
                    tracing::warn!("Failed to track conversation {}: {}", conversation_id, e);
                    // Don't fail the request if tracking fails
                }
            }
        }
    }

    // Build response
    let mut response_builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));

    if let Some(headers_map) = response_builder.headers_mut() {
        for (key, value) in response_headers.iter() {
            if key != "transfer-encoding" && key != "connection" {
                headers_map.insert(key, value.clone());
            }
        }
    }

    response_builder.body(Body::from(body_bytes)).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to build response: {}", e),
            }),
        )
            .into_response()
    })
}

/// List all conversations for the authenticated user (from local DB)
async fn list_conversations(
    State(state): State<crate::state::AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<ConversationResponse>>, Response> {
    let conversations = state
        .conversation_service
        .list_conversations(user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to list conversations: {}", e),
                }),
            )
                .into_response()
        })?;

    Ok(Json(
        conversations
            .into_iter()
            .map(|c| ConversationResponse {
                id: c.id,
                title: c.title,
                created_at: c.created_at.to_rfc3339(),
                updated_at: c.updated_at.to_rfc3339(),
            })
            .collect(),
    ))
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
    // Extract body bytes
    let body_bytes = extract_body_bytes(request).await?;

    // Track conversation if this is a POST to /responses
    if method == Method::POST && path == "responses" {
        if let Err(e) = track_conversation_from_request(&state, user.user_id, &body_bytes).await {
            tracing::warn!("Failed to track conversation: {}", e);
            // Don't fail the request if conversation tracking fails
        }
    }

    // Forward the request to OpenAI
    let proxy_response = state
        .proxy_service
        .forward_request(method, &path, headers, Some(body_bytes))
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("OpenAI API error: {}", e),
                }),
            )
                .into_response()
        })?;

    // Build the response
    let mut response = Response::builder()
        .status(StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::OK));

    // Copy headers from OpenAI response
    if let Some(response_headers) = response.headers_mut() {
        for (key, value) in proxy_response.headers.iter() {
            // Skip certain headers that shouldn't be forwarded
            if key != "transfer-encoding" && key != "connection" {
                response_headers.insert(key, value.clone());
            }
        }
    }

    // Convert the stream to an axum Body for streaming support
    let stream = proxy_response
        .body
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let body = Body::from_stream(stream);

    response.body(body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to build response: {}", e),
            }),
        )
            .into_response()
    })
}

/// Extract body bytes from a request
async fn extract_body_bytes(request: Request) -> Result<Bytes, Response> {
    axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Failed to read request body: {}", e),
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
    // Parse the request body to extract conversation_id if present
    #[derive(Deserialize)]
    struct ResponseRequest {
        conversation: Option<String>,
    }

    if let Ok(req) = serde_json::from_slice::<ResponseRequest>(body) {
        if let Some(conversation_id) = req.conversation {
            state
                .conversation_service
                .track_conversation(&conversation_id, user_id, None)
                .await?;
        }
    }

    Ok(())
}
