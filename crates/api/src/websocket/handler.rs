use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::{IntoResponse, Response},
};
use chrono::Utc;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use services::conversation::ports::SharePermission;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::{state::AppState, websocket::WebSocketMessage};

/// Query parameters for WebSocket connection
#[derive(Debug, Deserialize)]
pub struct WebSocketQuery {
    /// Auth token (required since WebSocket can't use Authorization header)
    token: String,
}

/// WebSocket handler for real-time conversation updates
///
/// Clients connect to `/v1/ws/conversations/{conversation_id}?token=<auth_token>` to receive
/// real-time updates for a specific conversation. The handler:
///
/// 1. Authenticates the user via the token query parameter
/// 2. Verifies the user has at least read access to the conversation
/// 3. Upgrades the HTTP connection to WebSocket
/// 4. Subscribes to conversation updates via the ConnectionManager
/// 5. Forwards messages to the client until they disconnect
///
/// Note: WebSocket connections can't use Authorization headers, so the token is passed
/// as a query parameter.
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(conversation_id): Path<String>,
    Query(query): Query<WebSocketQuery>,
) -> Result<Response, Response> {
    // Authenticate the token
    let user = authenticate_websocket_token(&query.token, &state)
        .await
        .map_err(|e| {
            tracing::warn!("WebSocket auth failed: {:?}", e);
            crate::error::ApiError::unauthorized("Invalid or expired token").into_response()
        })?;

    tracing::info!(
        "WebSocket connection request: user_id={}, conversation_id={}",
        user.user_id,
        conversation_id
    );

    // Verify user has at least read access to this conversation
    state
        .conversation_share_service
        .ensure_access(&conversation_id, user.user_id, SharePermission::Read)
        .await
        .map_err(|e| {
            tracing::warn!(
                "WebSocket access denied: user_id={}, conversation_id={}, error={:?}",
                user.user_id,
                conversation_id,
                e
            );
            crate::error::ApiError::forbidden("Access denied to this conversation").into_response()
        })?;

    tracing::info!(
        "WebSocket access granted: user_id={}, conversation_id={}",
        user.user_id,
        conversation_id
    );

    // Upgrade the connection to WebSocket
    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, state.connection_manager.clone(), conversation_id, user.user_id)
    }))
}

/// Handle the WebSocket connection after upgrade
async fn handle_socket(
    socket: WebSocket,
    connection_manager: Arc<crate::websocket::ConnectionManager>,
    conversation_id: String,
    user_id: services::UserId,
) {
    tracing::info!(
        "WebSocket connected: user_id={}, conversation_id={}",
        user_id,
        conversation_id
    );

    // Subscribe to conversation updates
    let mut receiver = connection_manager.subscribe(&conversation_id).await;

    // Split the socket into sender and receiver
    let (mut sender, mut socket_receiver) = socket.split();

    // Handle incoming messages from client (ping/pong, close, etc.)
    let conversation_id_clone = conversation_id.clone();
    let client_handler = tokio::spawn(async move {
        while let Some(msg) = socket_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Handle client messages (e.g., ping)
                    if let Ok(ws_msg) = serde_json::from_str::<WebSocketMessage>(&text) {
                        match ws_msg {
                            WebSocketMessage::Ping => {
                                tracing::debug!(
                                    "Received ping from client: conversation_id={}",
                                    conversation_id_clone
                                );
                            }
                            _ => {
                                tracing::debug!(
                                    "Received message from client: conversation_id={}, type={:?}",
                                    conversation_id_clone,
                                    std::mem::discriminant(&ws_msg)
                                );
                            }
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    tracing::debug!(
                        "Received WebSocket ping: conversation_id={}",
                        conversation_id_clone
                    );
                    // Axum handles pong automatically
                    let _ = data; // Silence unused warning
                }
                Ok(Message::Close(_)) => {
                    tracing::info!(
                        "Client requested close: conversation_id={}",
                        conversation_id_clone
                    );
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "WebSocket receive error: conversation_id={}, error={:?}",
                        conversation_id_clone,
                        e
                    );
                    break;
                }
                _ => {}
            }
        }
    });

    // Forward broadcast messages to the client
    let conversation_id_clone = conversation_id.clone();
    let broadcast_handler = tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(msg) => {
                    // Serialize and send the message
                    match serde_json::to_string(&msg) {
                        Ok(json) => {
                            if let Err(e) = sender.send(Message::Text(json.into())).await {
                                tracing::warn!(
                                    "Failed to send WebSocket message: conversation_id={}, error={:?}",
                                    conversation_id_clone,
                                    e
                                );
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to serialize WebSocket message: conversation_id={}, error={:?}",
                                conversation_id_clone,
                                e
                            );
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        "WebSocket client lagged, skipped {} messages: conversation_id={}",
                        n,
                        conversation_id_clone
                    );
                    // Continue receiving - client will miss some messages
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(
                        "Broadcast channel closed: conversation_id={}",
                        conversation_id_clone
                    );
                    break;
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = client_handler => {
            tracing::debug!("Client handler completed: conversation_id={}", conversation_id);
        }
        _ = broadcast_handler => {
            tracing::debug!("Broadcast handler completed: conversation_id={}", conversation_id);
        }
    }

    // Unsubscribe from the conversation
    connection_manager.unsubscribe(&conversation_id).await;

    tracing::info!(
        "WebSocket disconnected: user_id={}, conversation_id={}",
        user_id,
        conversation_id
    );
}

/// Authenticated user for WebSocket connections
struct WebSocketUser {
    user_id: services::UserId,
}

/// Authenticate a WebSocket connection using the token from query params
async fn authenticate_websocket_token(
    token: &str,
    state: &AppState,
) -> Result<WebSocketUser, crate::error::ApiError> {
    // Validate token format
    if !token.starts_with("sess_") || token.len() != 37 {
        return Err(crate::error::ApiError::invalid_token());
    }

    // Hash the token
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    // Look up the session
    let session = state
        .session_repository
        .get_session_by_token_hash(token_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get session: {}", e);
            crate::error::ApiError::internal_server_error("Authentication failed")
        })?
        .ok_or_else(|| crate::error::ApiError::session_not_found())?;

    // Check expiration
    if session.expires_at < Utc::now() {
        return Err(crate::error::ApiError::session_expired());
    }

    Ok(WebSocketUser {
        user_id: session.user_id,
    })
}
