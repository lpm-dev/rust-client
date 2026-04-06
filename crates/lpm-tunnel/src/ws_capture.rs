//! WebSocket connection and frame capture types.
//!
//! Used by the inspector to display WebSocket traffic alongside HTTP requests.
//! Each WebSocket connection has a lifecycle (upgrade → frames → close) and
//! multiple bidirectional frames.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A captured WebSocket event — either a connection lifecycle event or a frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    /// WebSocket connection established (upgrade succeeded).
    Connected {
        /// Connection ID (matches the tunnel relay's connection ID).
        connection_id: String,
        /// The WebSocket URL path (e.g., "/_next/webpack-hmr").
        url: String,
        /// Request headers from the upgrade request.
        headers: HashMap<String, String>,
        /// Timestamp (ISO 8601).
        timestamp: String,
    },
    /// A single WebSocket frame (in either direction).
    Frame {
        /// Connection ID this frame belongs to.
        connection_id: String,
        /// Direction of the frame.
        direction: FrameDirection,
        /// Frame data. Text frames are UTF-8 strings; binary frames are base64-encoded.
        data: String,
        /// Whether this is a binary frame.
        is_binary: bool,
        /// Size of the frame data in bytes (before base64 encoding).
        size: usize,
        /// Timestamp (ISO 8601).
        timestamp: String,
    },
    /// WebSocket connection closed.
    Closed {
        /// Connection ID.
        connection_id: String,
        /// Reason for closure (if available).
        reason: Option<String>,
        /// Timestamp (ISO 8601).
        timestamp: String,
    },
}

/// Direction of a WebSocket frame relative to the local dev server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameDirection {
    /// Frame from the remote client → local dev server (inbound).
    Inbound,
    /// Frame from the local dev server → remote client (outbound).
    Outbound,
}

impl WsEvent {
    /// Get the connection ID regardless of event type.
    pub fn connection_id(&self) -> &str {
        match self {
            Self::Connected { connection_id, .. }
            | Self::Frame { connection_id, .. }
            | Self::Closed { connection_id, .. } => connection_id,
        }
    }

    /// Get the timestamp regardless of event type.
    pub fn timestamp(&self) -> &str {
        match self {
            Self::Connected { timestamp, .. }
            | Self::Frame { timestamp, .. }
            | Self::Closed { timestamp, .. } => timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_event_serde_roundtrip_connected() {
        let event = WsEvent::Connected {
            connection_id: "ws_1".to_string(),
            url: "/_next/webpack-hmr".to_string(),
            headers: HashMap::from([("upgrade".to_string(), "websocket".to_string())]),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"connected\""));
        let parsed: WsEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id(), "ws_1");
    }

    #[test]
    fn ws_event_serde_roundtrip_frame() {
        let event = WsEvent::Frame {
            connection_id: "ws_1".to_string(),
            direction: FrameDirection::Inbound,
            data: "{\"type\":\"ping\"}".to_string(),
            is_binary: false,
            size: 15,
            timestamp: "2026-04-06T12:00:01Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"direction\":\"inbound\""));
        let parsed: WsEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id(), "ws_1");
    }

    #[test]
    fn ws_event_serde_roundtrip_closed() {
        let event = WsEvent::Closed {
            connection_id: "ws_1".to_string(),
            reason: Some("normal closure".to_string()),
            timestamp: "2026-04-06T12:05:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: WsEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id(), "ws_1");
    }

    #[test]
    fn connection_id_accessor() {
        let connected = WsEvent::Connected {
            connection_id: "c1".to_string(),
            url: "/ws".to_string(),
            headers: HashMap::new(),
            timestamp: String::new(),
        };
        assert_eq!(connected.connection_id(), "c1");

        let frame = WsEvent::Frame {
            connection_id: "c2".to_string(),
            direction: FrameDirection::Outbound,
            data: String::new(),
            is_binary: false,
            size: 0,
            timestamp: String::new(),
        };
        assert_eq!(frame.connection_id(), "c2");
    }
}
