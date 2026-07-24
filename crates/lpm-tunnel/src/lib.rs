//! WebSocket tunnel client for exposing a verified local endpoint via LPM.
//!
//! Connects to the LPM tunnel relay service, which assigns a public URL
//! (e.g., `https://acme-api.lpm.llc`) and proxies HTTP requests to the endpoint.
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

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub use relay::resolve_relay_url;

pub(crate) fn validate_forward_target(
    target: &lpm_common::LocalTarget,
) -> Result<(), lpm_common::LpmError> {
    if target.port == 0 {
        return Err(lpm_common::LpmError::Tunnel(
            "local target port must be between 1 and 65535".to_string(),
        ));
    }
    if !target.is_loopback() {
        return Err(lpm_common::LpmError::Tunnel(format!(
            "refusing to forward a tunnel to non-loopback target {}",
            target.url()
        )));
    }
    if target.scheme == lpm_common::LocalScheme::Https {
        return Err(lpm_common::LpmError::Tunnel(
            "tunnels and webhook replay require a plain HTTP child endpoint; disable framework HTTPS and let LPM terminate TLS with `lpm dev --https`"
                .to_string(),
        ));
    }
    Ok(())
}

/// Plan and relay limits advertised by the tunnel service.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TunnelLimitMetadata {
    /// Maximum simultaneously open tunnels for the account.
    #[serde(default)]
    pub max_concurrent: Option<u64>,
    /// Account-wide request limit per minute across every active tunnel.
    #[serde(default)]
    pub request_rate_limit_per_minute: Option<u64>,
    /// Request limit per minute for one source IP within this account.
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

/// Account-wide request usage advertised by the tunnel service.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TunnelUsageMetadata {
    /// Requests admitted during the current usage period.
    #[serde(default)]
    pub accepted_requests: Option<u64>,
    /// Requests included in the current plan/seat allowance.
    #[serde(default)]
    pub included_requests: Option<u64>,
    /// Requests above the included allowance.
    #[serde(default)]
    pub overage_requests: Option<u64>,
    /// Whether requests continue into proportional overage.
    #[serde(default)]
    pub overage_enabled: Option<bool>,
    /// Whether the allowance is currently a hard stop.
    #[serde(default)]
    pub hard_limit: Option<bool>,
    /// Inclusive ISO-8601 usage-period start.
    #[serde(default)]
    pub period_start: Option<String>,
    /// Exclusive ISO-8601 usage-period end.
    #[serde(default)]
    pub period_end: Option<String>,
    /// Request quantity represented by one advertised overage unit.
    #[serde(default)]
    pub overage_unit_requests: Option<u64>,
    /// Price of one overage unit in cents.
    #[serde(default)]
    pub overage_unit_price_cents: Option<u64>,
    /// Current estimated overage charge in cents.
    #[serde(default)]
    pub estimated_overage_cents: Option<f64>,
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
    /// Local endpoint port being tunneled.
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
