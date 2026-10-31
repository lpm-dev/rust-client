//! WebSocket tunnel client for exposing a verified local endpoint via LPM.
//!
//! Connects to the LPM tunnel relay service, which assigns a public URL
//! (e.g., `https://acme-api.lpm.llc`) and proxies HTTP requests to the endpoint.
//!
//! Supports multiple base domains (lpm.fyi, lpm.llc). Tunnels need a Pro or
//! organization plan; Pro and organization accounts can claim persistent
//! domains on any available base domain.

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

pub use relay::{resolve_relay_url, resolve_relay_url_from_config_value};

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

/// Point later connections at the loopback family that just accepted one,
/// unless the endpoint changed since `attempted` was read.
pub(crate) fn adopt_loopback_sibling(
    live_target: &std::sync::RwLock<lpm_common::LocalTarget>,
    attempted: &lpm_common::LocalTarget,
    sibling: lpm_common::LocalTarget,
) {
    let mut current = live_target
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *current == *attempted {
        tracing::debug!("local endpoint answered on {}", sibling.url());
        *current = sibling;
    }
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

/// What a usage report given to the usage callback reflects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageUpdate {
    /// The usage the relay reported when the tunnel connected.
    Connected,
    /// An allowance or overage threshold notice from the relay.
    Notice,
    /// A request the relay admitted for this tunnel. The count is the
    /// relay's account-wide one when it sends one; an older relay's leaves
    /// this tunnel's tally on top of its last report, missing the account's
    /// other tunnels.
    Admitted,
}

/// The account usage a tunnel shows, kept current between relay reports.
#[derive(Debug, Clone)]
pub(crate) struct UsageTracker {
    usage: TunnelUsageMetadata,
    period_end: Option<chrono::DateTime<chrono::Utc>>,
}

impl UsageTracker {
    pub(crate) fn new(usage: TunnelUsageMetadata) -> Self {
        let period_end = usage
            .period_end
            .as_deref()
            .and_then(|end| chrono::DateTime::parse_from_rfc3339(end).ok())
            .map(|end| end.with_timezone(&chrono::Utc));
        Self { usage, period_end }
    }

    pub(crate) fn usage(&self) -> &TunnelUsageMetadata {
        &self.usage
    }

    /// Counts a request the relay admitted, given the account total it
    /// reported with the request, if any.
    pub(crate) fn record_admission(
        &mut self,
        reported: Option<u64>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        if self.period_end.is_some_and(|end| now >= end) {
            // The relay's count starts over in a period it hasn't described yet.
            self.period_end = None;
            self.usage.period_start = None;
            self.usage.period_end = None;
            self.usage.accepted_requests = Some(0);
        }
        let current = self.usage.accepted_requests.unwrap_or(0);
        // Requests admitted together can arrive in either order, so within a
        // period the count only moves forward.
        let accepted = reported.map_or(current.saturating_add(1), |reported| reported.max(current));
        if Some(accepted) == self.usage.accepted_requests {
            return;
        }
        self.usage.accepted_requests = Some(accepted);
        self.usage.overage_requests = self
            .usage
            .included_requests
            .map(|included| accepted.saturating_sub(included));
        self.usage.estimated_overage_cents = None;
    }
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
    /// Assignment source: the account's default domain or a claimed domain.
    pub domain_kind: Option<String>,
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

mod http_stream;

#[cfg(test)]
mod usage_tracker_tests {
    use super::*;

    fn usage(accepted: u64, period_end: &str) -> TunnelUsageMetadata {
        TunnelUsageMetadata {
            accepted_requests: Some(accepted),
            included_requests: Some(100),
            overage_requests: Some(accepted.saturating_sub(100)),
            overage_enabled: Some(true),
            period_start: Some("2026-10-01T00:00:00Z".into()),
            period_end: Some(period_end.into()),
            estimated_overage_cents: Some(12.0),
            ..TunnelUsageMetadata::default()
        }
    }

    fn at(timestamp: &str) -> chrono::DateTime<chrono::Utc> {
        timestamp.parse().unwrap()
    }

    #[test]
    fn an_admission_takes_the_account_total_the_relay_reports() {
        let mut tracker = UsageTracker::new(usage(99, "2026-11-01T00:00:00Z"));

        tracker.record_admission(Some(104), at("2026-10-30T12:00:00Z"));

        let usage = tracker.usage();
        assert_eq!(usage.accepted_requests, Some(104));
        assert_eq!(usage.overage_requests, Some(4));
        assert_eq!(usage.estimated_overage_cents, None);
    }

    #[test]
    fn an_admission_without_a_reported_total_adds_one() {
        let mut tracker = UsageTracker::new(usage(99, "2026-11-01T00:00:00Z"));

        tracker.record_admission(None, at("2026-10-30T12:00:00Z"));
        tracker.record_admission(None, at("2026-10-30T12:00:01Z"));

        assert_eq!(tracker.usage().accepted_requests, Some(101));
        assert_eq!(tracker.usage().overage_requests, Some(1));
    }

    #[test]
    fn an_earlier_admission_arriving_late_does_not_lower_the_count() {
        let mut tracker = UsageTracker::new(usage(10, "2026-11-01T00:00:00Z"));

        tracker.record_admission(Some(12), at("2026-10-30T12:00:00Z"));
        tracker.record_admission(Some(11), at("2026-10-30T12:00:00Z"));

        assert_eq!(tracker.usage().accepted_requests, Some(12));
    }

    #[test]
    fn a_count_already_shown_keeps_the_overage_estimate() {
        let mut tracker = UsageTracker::new(usage(120, "2026-11-01T00:00:00Z"));

        tracker.record_admission(Some(120), at("2026-10-30T12:00:00Z"));

        assert_eq!(tracker.usage().estimated_overage_cents, Some(12.0));
    }

    #[test]
    fn the_count_starts_over_once_the_period_ends() {
        let mut reported = UsageTracker::new(usage(5_000, "2026-11-01T00:00:00Z"));
        let mut tallied = reported.clone();

        reported.record_admission(Some(3), at("2026-11-01T00:00:00Z"));
        reported.record_admission(Some(2), at("2026-11-01T00:00:01Z"));
        tallied.record_admission(None, at("2026-11-01T00:00:05Z"));

        assert_eq!(reported.usage().accepted_requests, Some(3));
        assert_eq!(reported.usage().overage_requests, Some(0));
        assert_eq!(reported.usage().period_end, None);
        assert_eq!(tallied.usage().accepted_requests, Some(1));
    }
}
