//! Relay URL resolution and per-host TOFU pin storage.
//!
//! The relay endpoint that the CLI connects to is configurable so that
//! local development against a custom worker, regional relays, and any
//! future migration of `relay.lpm.fyi` work without a CLI release.
//!
//! Resolution precedence ([`resolve_relay_url`]):
//!
//! 1. `LPM_TUNNEL_RELAY` env var — wins over everything. Per-process,
//!    matches the conventional shape of the rest of the LPM env-var
//!    surface (`LPM_TOKEN`, `LPM_RESOLVER`, …).
//! 2. `~/.lpm/config.toml` `tunnel.relay-url` — per-user persistent
//!    override. Lives under a nested `[tunnel]` table so the key set
//!    can grow (`tunnel.pin-host`, `tunnel.no-pin`, …) without
//!    polluting the top-level namespace shared with `save-prefix`,
//!    `linker`, etc.
//! 3. [`crate::DEFAULT_RELAY_URL`] (`wss://relay.lpm.fyi/connect`).
//!
//! TOFU certificate pins are now stored **per host** under
//! `~/.lpm/relay-pins/<host>` (e.g. `relay.lpm.fyi`). A single global
//! `~/.lpm/relay-pin` file from earlier versions is still consulted —
//! see [`tofu_pin_path_for_host`] and [`legacy_tofu_pin_path`].

use std::path::{Path, PathBuf};

/// Resolve the WebSocket relay URL the CLI should connect to.
///
/// Precedence: `LPM_TUNNEL_RELAY` env > `~/.lpm/config.toml`
/// `tunnel.relay-url` > [`crate::DEFAULT_RELAY_URL`]. Returns the
/// fully-qualified `wss://...` (or `ws://...` for local dev) URL ready
/// to hand to [`crate::client::TunnelOptions`].
///
/// Whitespace is trimmed and empty values are ignored — an env var
/// accidentally set to `""` falls through to the next tier rather than
/// silently breaking the tunnel. Bad TOML in `~/.lpm/config.toml` falls
/// through to the default with a debug log; we never abort the tunnel
/// for a malformed user config (the install pipeline has its own
/// stricter loader if we ever add one).
pub fn resolve_relay_url() -> String {
    if let Ok(val) = std::env::var("LPM_TUNNEL_RELAY")
        && !val.trim().is_empty()
    {
        let trimmed = val.trim().to_string();
        return accept_relay_override(&trimmed, "LPM_TUNNEL_RELAY");
    }

    if let Some(home) = dirs::home_dir() {
        let path = home.join(".lpm").join("config.toml");
        if let Some(val) = read_relay_url_from_config(&path) {
            return accept_relay_override(&val, "~/.lpm/config.toml tunnel.relay-url");
        }
    }

    crate::DEFAULT_RELAY_URL.to_string()
}

/// Gate a relay-URL override and log its use.
///
/// The tunnel attaches the LPM bearer token to the WebSocket connect
/// request (M8 finding); a hijacked override could redirect the
/// bearer to an attacker-controlled WebSocket server. Accept only
/// `wss://` (any host — legitimate self-hosted production relay) or
/// `ws://` on a loopback host (local dev). Anything else falls back
/// to the default with a `warn` so the operator sees the rejection.
/// Honoured overrides also emit a `warn` so an unexpected redirect
/// shows up in operator logs.
fn accept_relay_override(raw: &str, origin: &str) -> String {
    if relay_url_is_accepted(raw) {
        tracing::warn!(
            origin = origin,
            override_url = %raw,
            "tunnel relay endpoint override honoured — confirm this is expected",
        );
        return raw.to_string();
    }
    tracing::warn!(
        origin = origin,
        override_url = %raw,
        "rejecting tunnel relay override: only wss:// (any host) or ws:// (loopback host) accepted; \
         falling back to default to avoid leaking the LPM bearer to an unexpected endpoint",
    );
    crate::DEFAULT_RELAY_URL.to_string()
}

/// Accept `wss://` overrides (any host) or `ws://` overrides only
/// when the host is a loopback address. Anything else is refused.
fn relay_url_is_accepted(url: &str) -> bool {
    let (scheme, rest) = match url.split_once("://") {
        Some(pair) => pair,
        None => return false,
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return false;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "wss" => true,
        "ws" => is_loopback_host(host),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    false
}

/// Best-effort TOML lookup for `tunnel.relay-url`. Missing file →
/// `None`; malformed TOML or unexpected types → `None` (with a debug
/// log) so a broken config never wedges the tunnel — the resolver just
/// falls through to the default.
fn read_relay_url_from_config(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("relay config read failed at {}: {e}", path.display());
            return None;
        }
    };
    let parsed: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("relay config parse failed at {}: {e}", path.display());
            return None;
        }
    };
    let trimmed = parsed
        .get("tunnel")
        .and_then(|t| t.get("relay-url"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    Some(trimmed.to_string())
}

/// Path to the per-host TOFU pin file (`~/.lpm/relay-pins/<host>`).
///
/// `host` is the relay's hostname (e.g. `relay.lpm.fyi`) — the same
/// value rustls passes the certificate verifier as `ServerName`. Pin
/// storage is keyed by host so multiple relays (regional endpoints,
/// staging, local dev) can each have their own pin without colliding,
/// and so re-pointing the CLI at a new relay never silently inherits
/// a pin for a different server.
pub fn tofu_pin_path_for_host(host: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".lpm").join("relay-pins").join(host))
}

/// Path to the legacy single-file TOFU pin (`~/.lpm/relay-pin`).
///
/// Earlier versions stored exactly one pin globally, regardless of which
/// relay the CLI was connecting to. New installations only write to the
/// per-host layout, but we still consult this path on the
/// canonically-default relay (`relay.lpm.fyi`) to avoid forcing every
/// existing user to delete their pin file when they upgrade.
pub fn legacy_tofu_pin_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".lpm").join("relay-pin"))
}

/// Hostname of the canonical default relay
/// (`wss://relay.lpm.fyi/connect`). The legacy `~/.lpm/relay-pin` file
/// is treated as a pin for this host only — connecting to any other
/// host always uses the per-host layout.
pub const DEFAULT_RELAY_HOST: &str = "relay.lpm.fyi";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Process-global env mutations are inherently racy across parallel
    /// tests. Serialize the few tests that touch `LPM_TUNNEL_RELAY` /
    /// `HOME` under a mutex so they don't trample each other.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `LPM_TUNNEL_RELAY` set → wins over everything else. The test must
    /// also clear `HOME` so a developer's real `~/.lpm/config.toml`
    /// doesn't leak into the resolution path.
    #[test]
    fn env_var_wins_over_config_and_default() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        // Write a config that would otherwise be honored.
        let cfg = home.path().join(".lpm").join("config.toml");
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(
            &cfg,
            "[tunnel]\nrelay-url = \"wss://from-config/connect\"\n",
        )
        .unwrap();

        // SAFETY: env mutation is process-global; the env_lock above
        // serializes against other tests in this module that touch the
        // same vars, and no production code depends on these being
        // unset in this test context.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("LPM_TUNNEL_RELAY", "wss://from-env/connect");
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::remove_var("HOME");
        }

        assert_eq!(got, "wss://from-env/connect");
    }

    /// `LPM_TUNNEL_RELAY` set to whitespace falls through — protects
    /// against scripts that accidentally `export LPM_TUNNEL_RELAY=""`.
    #[test]
    fn empty_env_var_falls_through() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("LPM_TUNNEL_RELAY", "   ");
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::remove_var("HOME");
        }
        assert_eq!(got, crate::DEFAULT_RELAY_URL);
    }

    /// No env var, but `~/.lpm/config.toml` has `tunnel.relay-url`.
    #[test]
    fn config_value_wins_over_default() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        let cfg = home.path().join(".lpm").join("config.toml");
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(
            &cfg,
            "[tunnel]\nrelay-url = \"wss://from-config/connect\"\n",
        )
        .unwrap();

        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::set_var("HOME", home.path());
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("HOME");
        }

        assert_eq!(got, "wss://from-config/connect");
    }

    /// Coexistence: other top-level keys (`save-prefix`, `linker`, …)
    /// must not break the `[tunnel]` table lookup. Real configs mix
    /// many readers' keys.
    #[test]
    fn config_value_under_other_top_level_keys() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        let cfg = home.path().join(".lpm").join("config.toml");
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(
            &cfg,
            "save-prefix = \"^\"\nlinker = \"isolated\"\n[tunnel]\nrelay-url = \"wss://from-config/connect\"\n",
        )
        .unwrap();

        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::set_var("HOME", home.path());
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("HOME");
        }

        assert_eq!(got, "wss://from-config/connect");
    }

    /// Malformed `~/.lpm/config.toml` must NOT abort the tunnel — the
    /// resolver falls through to the default and the user can still
    /// connect. The same posture as `is_localhost_relay` etc: stay
    /// permissive on this path so a typo in an unrelated key never
    /// wedges connectivity.
    #[test]
    fn malformed_config_falls_through_to_default() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        let cfg = home.path().join(".lpm").join("config.toml");
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(&cfg, "this is not valid toml === [[[[").unwrap();

        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::set_var("HOME", home.path());
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("HOME");
        }

        assert_eq!(got, crate::DEFAULT_RELAY_URL);
    }

    /// No env, no config file → built-in default.
    #[test]
    fn default_when_nothing_set() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::remove_var("LPM_TUNNEL_RELAY");
            std::env::set_var("HOME", home.path());
        }
        let got = resolve_relay_url();
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(got, crate::DEFAULT_RELAY_URL);
    }

    /// Per-host pin path is rooted under `~/.lpm/relay-pins/`. The host
    /// segment is preserved verbatim — pin files are 1:1 with the
    /// hostname rustls verified.
    #[test]
    fn per_host_pin_path_layout() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let path = tofu_pin_path_for_host("relay.lpm.fyi").unwrap();
        unsafe {
            std::env::remove_var("HOME");
        }
        assert!(
            path.ends_with(Path::new(".lpm/relay-pins/relay.lpm.fyi")),
            "unexpected pin path layout: {}",
            path.display()
        );
    }

    /// Legacy global pin path is unchanged from earlier versions —
    /// still `~/.lpm/relay-pin` (no `s`, no subdirectory) — so existing
    /// installs keep working.
    #[test]
    fn legacy_pin_path_unchanged() {
        let _g = env_lock();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let path = legacy_tofu_pin_path().unwrap();
        unsafe {
            std::env::remove_var("HOME");
        }
        assert!(
            path.ends_with(Path::new(".lpm/relay-pin")),
            "legacy path must not regress: {}",
            path.display()
        );
    }

    /// M8 — `wss://` overrides on any host are accepted (legitimate
    /// self-hosted production relay).
    #[test]
    fn relay_url_is_accepted_for_wss_any_host() {
        assert!(relay_url_is_accepted("wss://relay.lpm.fyi/connect"));
        assert!(relay_url_is_accepted("wss://self-hosted.example/connect"));
    }

    /// M8 — `ws://` overrides are accepted ONLY for loopback hosts;
    /// `ws://attacker.example` is the leak shape and must be rejected.
    #[test]
    fn relay_url_is_accepted_for_ws_loopback_only() {
        assert!(relay_url_is_accepted("ws://localhost:8787/connect"));
        assert!(relay_url_is_accepted("ws://127.0.0.1:8787/connect"));
        assert!(relay_url_is_accepted("ws://[::1]:8787/connect"));
        assert!(!relay_url_is_accepted("ws://attacker.example/connect"));
        assert!(!relay_url_is_accepted("ws://relay.lpm.fyi/connect"));
    }

    #[test]
    fn relay_url_rejects_unsupported_schemes() {
        assert!(!relay_url_is_accepted("http://relay.lpm.fyi/connect"));
        assert!(!relay_url_is_accepted("https://relay.lpm.fyi/connect"));
        assert!(!relay_url_is_accepted("ftp://relay.lpm.fyi/connect"));
        assert!(!relay_url_is_accepted("not a url"));
        assert!(!relay_url_is_accepted(""));
    }

    /// End-to-end: a rejected override falls back to the default URL
    /// so the LPM bearer never gets sent to the attacker host.
    #[test]
    fn accept_relay_override_falls_back_on_rejected_url() {
        assert_eq!(
            accept_relay_override("ws://attacker.example/connect", "test"),
            crate::DEFAULT_RELAY_URL,
            "non-loopback ws:// override must NOT steer the connect",
        );
    }

    /// And the positive path: an accepted override IS used.
    #[test]
    fn accept_relay_override_honors_accepted_url() {
        assert_eq!(
            accept_relay_override("wss://self-hosted.example/connect", "test"),
            "wss://self-hosted.example/connect",
            "wss:// override must steer the connect",
        );
    }
}
