/// API definitions for the DHT web socket API
// copy pasted from libp2p-rust-dht's websocketmessage.rs file
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsyncWebSocketDomoMessage {
    Volatile {
        value: serde_json::Value,
    },
    Persistent {
        value: serde_json::Value,
        topic_name: String,
        topic_uuid: String,
        deleted: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncWebSocketDomoRequest {
    RequestGetAll,
    RequestGetTopicName {
        topic_name: String,
    },
    RequestGetTopicUUID {
        topic_name: String,
        topic_uuid: String,
    },
    RequestDeleteTopicUUID {
        topic_name: String,
        topic_uuid: String,
    },
    RequestPubMessage {
        value: serde_json::Value,
    },
    RequestPostTopicUUID {
        topic_name: String,
        topic_uuid: String,
        value: serde_json::Value,
    },
    Response {
        value: serde_json::Value,
    },
}
