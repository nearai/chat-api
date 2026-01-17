use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Message types that can be sent over WebSocket
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum WebSocketMessage {
    /// New items were added to a conversation
    #[serde(rename = "new_items")]
    NewItems {
        conversation_id: String,
        /// JSON array of conversation items
        items: serde_json::Value,
    },
    /// A response stream has completed (used to notify other users to refresh)
    #[serde(rename = "response_created")]
    ResponseCreated {
        conversation_id: String,
        /// The response_id of the completed response (if available)
        response_id: Option<String>,
    },
    /// User is typing in a conversation
    #[serde(rename = "typing")]
    Typing {
        conversation_id: String,
        user_id: String,
        user_name: Option<String>,
    },
    /// Ping message for keep-alive
    #[serde(rename = "ping")]
    Ping,
    /// Pong response for keep-alive
    #[serde(rename = "pong")]
    Pong,
}

/// Channel info for a conversation
struct ConversationChannel {
    sender: broadcast::Sender<WebSocketMessage>,
    /// Track number of active subscribers to clean up unused channels
    #[allow(dead_code)]
    subscriber_count: usize,
}

/// Manages WebSocket connections and message broadcasting for conversations
#[derive(Default)]
pub struct ConnectionManager {
    /// Map of conversation_id -> broadcast channel
    channels: Arc<RwLock<HashMap<String, ConversationChannel>>>,
}

impl ConnectionManager {
    /// Create a new ConnectionManager
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to updates for a specific conversation
    /// Returns a receiver that will receive messages broadcast to this conversation
    pub async fn subscribe(
        &self,
        conversation_id: &str,
    ) -> broadcast::Receiver<WebSocketMessage> {
        let mut channels = self.channels.write().await;

        // Get or create channel for this conversation
        let channel = channels.entry(conversation_id.to_string()).or_insert_with(|| {
            // Buffer up to 100 messages (dropped if subscriber is too slow)
            let (sender, _) = broadcast::channel(100);
            ConversationChannel {
                sender,
                subscriber_count: 0,
            }
        });

        channel.subscriber_count += 1;
        channel.sender.subscribe()
    }

    /// Unsubscribe from a conversation (decrement subscriber count)
    /// Channels are not immediately cleaned up - they'll be reused if another subscriber connects
    pub async fn unsubscribe(&self, conversation_id: &str) {
        let mut channels = self.channels.write().await;

        if let Some(channel) = channels.get_mut(conversation_id) {
            channel.subscriber_count = channel.subscriber_count.saturating_sub(1);

            // Clean up channel if no subscribers remain
            if channel.subscriber_count == 0 {
                channels.remove(conversation_id);
            }
        }
    }

    /// Broadcast a message to all subscribers of a conversation
    /// Returns the number of receivers that received the message
    pub async fn broadcast(&self, conversation_id: &str, message: WebSocketMessage) -> usize {
        let channels = self.channels.read().await;

        if let Some(channel) = channels.get(conversation_id) {
            // send() returns the number of receivers, or error if no receivers
            match channel.sender.send(message) {
                Ok(count) => count,
                Err(_) => 0, // No receivers
            }
        } else {
            0
        }
    }

    /// Broadcast new items to a conversation
    pub async fn broadcast_new_items(
        &self,
        conversation_id: &str,
        items: serde_json::Value,
    ) -> usize {
        self.broadcast(
            conversation_id,
            WebSocketMessage::NewItems {
                conversation_id: conversation_id.to_string(),
                items,
            },
        )
        .await
    }

    /// Broadcast a typing indicator
    pub async fn broadcast_typing(
        &self,
        conversation_id: &str,
        user_id: &str,
        user_name: Option<String>,
    ) -> usize {
        self.broadcast(
            conversation_id,
            WebSocketMessage::Typing {
                conversation_id: conversation_id.to_string(),
                user_id: user_id.to_string(),
                user_name,
            },
        )
        .await
    }

    /// Broadcast that a response has been created (stream completed)
    /// This notifies other users to refresh their conversation data
    pub async fn broadcast_response_created(
        &self,
        conversation_id: &str,
        response_id: Option<&str>,
    ) -> usize {
        self.broadcast(
            conversation_id,
            WebSocketMessage::ResponseCreated {
                conversation_id: conversation_id.to_string(),
                response_id: response_id.map(|s| s.to_string()),
            },
        )
        .await
    }

    /// Get the number of active channels (for monitoring)
    #[allow(dead_code)]
    pub async fn active_channels_count(&self) -> usize {
        self.channels.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscribe_and_broadcast() {
        let manager = ConnectionManager::new();
        let conv_id = "test-conv-1";

        // Subscribe
        let mut receiver = manager.subscribe(conv_id).await;

        // Broadcast
        let items = serde_json::json!([{"id": "item-1", "content": "test"}]);
        let count = manager.broadcast_new_items(conv_id, items.clone()).await;
        assert_eq!(count, 1);

        // Receive
        let msg = receiver.try_recv().unwrap();
        match msg {
            WebSocketMessage::NewItems {
                conversation_id,
                items: received_items,
            } => {
                assert_eq!(conversation_id, conv_id);
                assert_eq!(received_items, items);
            }
            _ => panic!("Expected NewItems message"),
        }
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let manager = ConnectionManager::new();
        let conv_id = "test-conv-2";

        // Subscribe multiple receivers
        let mut receiver1 = manager.subscribe(conv_id).await;
        let mut receiver2 = manager.subscribe(conv_id).await;

        // Broadcast
        let count = manager
            .broadcast_typing(conv_id, "user-1", Some("Alice".to_string()))
            .await;
        assert_eq!(count, 2);

        // Both should receive
        assert!(receiver1.try_recv().is_ok());
        assert!(receiver2.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_to_nonexistent_channel() {
        let manager = ConnectionManager::new();

        // Broadcast to non-existent channel should not panic
        let count = manager
            .broadcast_new_items("nonexistent", serde_json::json!([]))
            .await;
        assert_eq!(count, 0);
    }
}
