//! WebSocket tunnel client for exposing localhost to the internet via LPM.
//!
//! Connects to the LPM tunnel relay service, which assigns a public URL
//! (e.g., `https://acme-api.lpm.llc`) and proxies HTTP requests to the local port.
//!
//! Supports multiple base domains (lpm.fyi, lpm.llc).
//! Free users get ephemeral random domains on lpm.fyi.
//! Pro/Org users can claim persistent domains on any available base domain.

pub mod client;
pub mod protocol;
pub mod proxy;
pub mod webhook;
pub mod webhook_buffer;
pub mod webhook_log;
pub mod webhook_replay;
pub mod webhook_signature;

/// Active tunnel session information.
#[derive(Debug, Clone)]
pub struct TunnelSession {
    /// The public tunnel URL (e.g., `https://acme-api.lpm.llc`).
    pub tunnel_url: String,
    /// The full domain (e.g., `acme-api.lpm.llc`).
    pub domain: String,
    /// Session ID for reconnection.
    pub session_id: String,
    /// Local port being tunneled.
    pub local_port: u16,
}

/// Default tunnel relay URL.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.lpm.fyi/connect";

/// Known base domains for tunnel subdomains.
/// Used for validation and backward compatibility (bare subdomain → append default).
pub const DEFAULT_BASE_DOMAIN: &str = "lpm.fyi";
