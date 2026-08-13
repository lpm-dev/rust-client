//! WebSocket connection and frame capture types.
//!
//! Used by the inspector to display WebSocket traffic alongside HTTP requests.
//! Each WebSocket connection has a lifecycle (upgrade → frames → close) and
//! multiple bidirectional frames.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const WS_CAPTURE_PREVIEW_BYTES: usize = 64 * 1024;

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
        /// Whether `data` is a bounded preview of a larger frame.
        #[serde(default)]
        truncated: bool,
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
    /// Build a frame event without retaining an unbounded frame payload.
    pub fn captured_frame(
        connection_id: String,
        direction: FrameDirection,
        bytes: &[u8],
        is_binary: bool,
        timestamp: String,
    ) -> Self {
        let preview_len = bytes.len().min(WS_CAPTURE_PREVIEW_BYTES);
        let preview = &bytes[..preview_len];
        let data = if is_binary {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, preview)
        } else {
            String::from_utf8_lossy(preview).into_owned()
        };
        Self::Frame {
            connection_id,
            direction,
            data,
            is_binary,
            size: bytes.len(),
            truncated: preview_len < bytes.len(),
            timestamp,
        }
    }

    /// Estimated heap bytes retained by this event.
    pub fn retained_size_bytes(&self) -> usize {
        match self {
            Self::Connected {
                connection_id,
                url,
                headers,
                timestamp,
            } => {
                connection_id.capacity()
                    + url.capacity()
                    + timestamp.capacity()
                    + headers
                        .iter()
                        .map(|(name, value)| name.capacity() + value.capacity())
                        .sum::<usize>()
            }
            Self::Frame {
                connection_id,
                data,
                timestamp,
                ..
            } => connection_id.capacity() + data.capacity() + timestamp.capacity(),
            Self::Closed {
                connection_id,
                reason,
                timestamp,
            } => {
                connection_id.capacity()
                    + reason.as_ref().map_or(0, String::capacity)
                    + timestamp.capacity()
            }
        }
    }

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
            truncated: false,
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
            truncated: false,
            timestamp: String::new(),
        };
        assert_eq!(frame.connection_id(), "c2");
    }

    #[test]
    fn captured_frame_bounds_preview_and_preserves_original_size() {
        let payload = vec![b'x'; 1024 * 1024];

        let event = WsEvent::captured_frame(
            "c1".to_string(),
            FrameDirection::Inbound,
            &payload,
            false,
            String::new(),
        );

        let WsEvent::Frame {
            data,
            size,
            truncated,
            ..
        } = event
        else {
            panic!("expected frame event");
        };
        assert_eq!(size, payload.len());
        assert!(truncated);
        assert!(data.len() <= WS_CAPTURE_PREVIEW_BYTES);
    }

    #[test]
    fn captured_binary_frame_encodes_only_the_bounded_preview() {
        let payload = vec![0xff; 1024 * 1024];

        let event = WsEvent::captured_frame(
            "c1".to_string(),
            FrameDirection::Outbound,
            &payload,
            true,
            String::new(),
        );

        let WsEvent::Frame {
            data,
            size,
            truncated,
            ..
        } = event
        else {
            panic!("expected frame event");
        };
        assert_eq!(size, payload.len());
        assert!(truncated);
        assert!(data.len() <= WS_CAPTURE_PREVIEW_BYTES.div_ceil(3) * 4);
    }
}
