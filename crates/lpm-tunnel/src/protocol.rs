//! Tunnel protocol message definitions.
//!
//! Defines the JSON messages exchanged between the LPM CLI (tunnel client)
//! and the tunnel relay server over WebSocket.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent from client to relay.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Initial handshake: authenticate and request a tunnel domain.
    #[serde(rename = "hello")]
    Hello {
        /// LPM auth token.
        token: String,
        /// Requested domain (Pro/Org only, None for random).
        /// Wire format uses "subdomain" for backward compat with relay Worker.
        #[serde(rename = "subdomain")]
        domain: Option<String>,
        /// Local port being tunneled.
        local_port: u16,
    },

    /// Response to a proxied HTTP request.
    #[serde(rename = "http_response")]
    HttpResponse {
        /// Request ID (matches the incoming HttpRequest).
        id: String,
        /// HTTP status code.
        status: u16,
        /// Response headers.
        headers: HashMap<String, String>,
        /// Response body (base64-encoded for binary safety).
        body: String,
    },

    /// WebSocket frame from local server back to the remote client.
    #[serde(rename = "ws_frame")]
    WebSocketFrame {
        /// Connection ID.
        id: String,
        /// Frame data (base64-encoded).
        data: String,
        /// Whether this is a binary frame.
        is_binary: bool,
    },

    /// WebSocket close event from local server back to the remote client.
    #[serde(rename = "ws_close")]
    WebSocketClose {
        /// Connection ID.
        id: String,
        /// Close code, if known.
        code: Option<u16>,
        /// Close reason, if provided.
        reason: Option<String>,
    },

    /// Keepalive ping.
    #[serde(rename = "ping")]
    Ping,
}

/// Messages sent from relay to client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Handshake response: assigned domain and tunnel URL.
    #[serde(rename = "hello")]
    Hello {
        /// Assigned domain (may be full domain or bare subdomain from old relays).
        /// Wire format uses "subdomain" for backward compat with relay Worker.
        #[serde(rename = "subdomain")]
        domain: String,
        /// Full tunnel URL (e.g., `https://abc123.t.lpm.dev`).
        tunnel_url: String,
        /// Session ID for reconnection.
        session_id: String,
    },

    /// Incoming HTTP request to be proxied to localhost.
    #[serde(rename = "http_request")]
    HttpRequest {
        /// Unique request ID.
        id: String,
        /// HTTP method (GET, POST, etc.).
        method: String,
        /// Request URL path (e.g., `/api/users`).
        url: String,
        /// Request headers.
        headers: HashMap<String, String>,
        /// Request body (base64-encoded).
        body: String,
    },

    /// WebSocket upgrade request from a remote client.
    #[serde(rename = "ws_upgrade")]
    WebSocketUpgrade {
        /// Connection ID.
        id: String,
        /// Upgrade URL path.
        url: String,
        /// Upgrade request headers.
        headers: HashMap<String, String>,
    },

    /// WebSocket frame from remote client.
    #[serde(rename = "ws_frame")]
    WebSocketFrame {
        /// Connection ID.
        id: String,
        /// Frame data (base64-encoded).
        data: String,
        /// Whether this is a binary frame.
        is_binary: bool,
    },

    /// WebSocket close event from remote client.
    #[serde(rename = "ws_close")]
    WebSocketClose {
        /// Connection ID.
        id: String,
        /// Close code, if known.
        code: Option<u16>,
        /// Close reason, if provided.
        reason: Option<String>,
    },

    /// Keepalive pong.
    #[serde(rename = "pong")]
    Pong,

    /// Error from the relay.
    #[serde(rename = "error")]
    Error {
        /// Error message.
        message: String,
        /// Error code (e.g., "auth_failed", "rate_limited", "plan_required").
        code: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_client_hello() {
        let msg = ClientMessage::Hello {
            token: "lpm_test123".to_string(),
            domain: None,
            local_port: 3000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"local_port\":3000"));
    }

    #[test]
    fn deserialize_server_hello() {
        let json = r#"{
			"type": "hello",
			"subdomain": "abc123",
			"tunnel_url": "https://abc123.t.lpm.dev",
			"session_id": "sess_001"
		}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Hello {
                domain,
                tunnel_url,
                session_id,
            } => {
                assert_eq!(domain, "abc123");
                assert_eq!(tunnel_url, "https://abc123.t.lpm.dev");
                assert_eq!(session_id, "sess_001");
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn deserialize_server_http_request() {
        let json = r#"{
			"type": "http_request",
			"id": "req_001",
			"method": "POST",
			"url": "/api/webhook",
			"headers": {"content-type": "application/json"},
			"body": "eyJ0ZXN0IjogdHJ1ZX0="
		}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::HttpRequest {
                id, method, url, ..
            } => {
                assert_eq!(id, "req_001");
                assert_eq!(method, "POST");
                assert_eq!(url, "/api/webhook");
            }
            _ => panic!("expected HttpRequest"),
        }
    }

    #[test]
    fn serialize_client_http_response() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let msg = ClientMessage::HttpResponse {
            id: "req_001".to_string(),
            status: 200,
            headers,
            body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"ok"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"http_response\""));
        assert!(json.contains("\"status\":200"));
    }

    #[test]
    fn roundtrip_ping_pong() {
        let ping = serde_json::to_string(&ClientMessage::Ping).unwrap();
        assert!(ping.contains("\"type\":\"ping\""));

        let pong_json = r#"{"type":"pong"}"#;
        let pong: ServerMessage = serde_json::from_str(pong_json).unwrap();
        matches!(pong, ServerMessage::Pong);
    }

    #[test]
    fn websocket_close_roundtrip() {
        let msg = ClientMessage::WebSocketClose {
            id: "ws_001".to_string(),
            code: Some(1001),
            reason: Some("going away".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"ws_close\""));
        assert!(json.contains("\"code\":1001"));

        let server_msg: ServerMessage = serde_json::from_str(&json).unwrap();
        match server_msg {
            ServerMessage::WebSocketClose { id, code, reason } => {
                assert_eq!(id, "ws_001");
                assert_eq!(code, Some(1001));
                assert_eq!(reason.as_deref(), Some("going away"));
            }
            _ => panic!("expected WebSocketClose"),
        }
    }

    // ── Finding #2: domain field uses "subdomain" on the wire ──

    #[test]
    fn client_hello_domain_serializes_as_subdomain() {
        let msg = ClientMessage::Hello {
            token: "tok".to_string(),
            domain: Some("acme.lpm.llc".to_string()),
            local_port: 3000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains("\"subdomain\":\"acme.lpm.llc\""),
            "domain field must serialize as 'subdomain' on the wire: {json}"
        );
    }

    #[test]
    fn server_hello_subdomain_deserializes_to_domain() {
        let json = r#"{
			"type": "hello",
			"subdomain": "acme.lpm.llc",
			"tunnel_url": "https://acme.lpm.llc",
			"session_id": "sess_002"
		}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Hello { domain, .. } => {
                assert_eq!(domain, "acme.lpm.llc");
            }
            _ => panic!("expected Hello"),
        }
    }
}
