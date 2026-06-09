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
pub mod relay;
pub mod webhook;
pub mod webhook_buffer;
pub mod webhook_log;
pub mod webhook_replay;
pub mod webhook_signature;
pub mod ws_capture;

pub use relay::resolve_relay_url;

/// Plan and relay limits advertised by the tunnel service.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunnelLimitMetadata {
    /// Maximum simultaneously open tunnels for the account.
    #[serde(default)]
    pub max_concurrent: Option<u64>,
    /// Per-session request limit per minute. Zero means unlimited.
    #[serde(default)]
    pub request_rate_limit_per_minute: Option<u64>,
    /// Global relay request limit per minute per source IP.
    #[serde(default)]
    pub per_ip_rate_limit_per_minute: Option<u64>,
    /// Maximum inbound request body size accepted by the relay.
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    /// Number of custom tunnel domains the account can claim.
    #[serde(default)]
    pub max_custom_domains: Option<u64>,
    /// Whether tunnel-auth headers are available for the account.
    #[serde(default)]
    pub tunnel_auth_available: Option<bool>,
}

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
    /// Account plan used by the relay for this session.
    pub plan: Option<String>,
    /// Base domain used by the assigned tunnel domain.
    pub base_domain: Option<String>,
    /// Assignment source: random, account default, or claimed custom domain.
    pub domain_kind: Option<String>,
    /// Epoch milliseconds when the relay will close the session.
    pub session_expires_at: Option<u64>,
    /// Maximum session lifetime in milliseconds. None means uncapped or not advertised.
    pub session_max_ms: Option<u64>,
    /// Relay limits applied to this session.
    pub limits: Option<TunnelLimitMetadata>,
}

/// Default tunnel relay URL. Override per-process with the
/// `LPM_TUNNEL_RELAY` environment variable, or per-user with the
/// `tunnel.relay-url` key in `~/.lpm/config.toml`. See
/// [`resolve_relay_url`].
pub const DEFAULT_RELAY_URL: &str = "wss://relay.lpm.fyi/connect";

/// Known base domains for tunnel subdomains.
/// Used for validation and backward compatibility (bare subdomain → append default).
pub const DEFAULT_BASE_DOMAIN: &str = "lpm.fyi";
