use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Transport used by a verified local development endpoint.
pub enum LocalScheme {
    /// Plain HTTP, with `ws` used for WebSocket upgrades.
    Http,
    /// HTTPS, with `wss` used for WebSocket upgrades.
    Https,
}

impl LocalScheme {
    /// Return the HTTP scheme name.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Return the matching WebSocket scheme name.
    #[inline]
    pub fn websocket(self) -> &'static str {
        match self {
            Self::Http => "ws",
            Self::Https => "wss",
        }
    }
}

impl fmt::Display for LocalScheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Verified loopback endpoint owned by a launched local development server.
pub struct LocalTarget {
    /// HTTP transport advertised by the child.
    pub scheme: LocalScheme,
    /// Concrete loopback address that accepted a connection.
    pub address: IpAddr,
    /// Listening TCP port.
    pub port: u16,
    /// Path prefix advertised by the child, normalized to start with `/`.
    #[serde(default = "default_base_path")]
    pub base_path: String,
    /// Whether `address` is only the first family to try. Set when the user
    /// named a port but no address: a listener on either `127.0.0.1` or `::1`
    /// is then the endpoint, as it is for `localhost:<port>` in a browser.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any_loopback_family: bool,
}

impl LocalTarget {
    /// Construct an IPv4 loopback target with a `/` base path.
    pub fn loopback(scheme: LocalScheme, port: u16) -> Self {
        Self {
            scheme,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            base_path: default_base_path(),
            any_loopback_family: false,
        }
    }

    /// Construct a target for a port whose listener may be on either loopback
    /// family, trying `127.0.0.1` before `::1`.
    pub fn loopback_port(scheme: LocalScheme, port: u16) -> Self {
        Self {
            any_loopback_family: true,
            ..Self::loopback(scheme, port)
        }
    }

    /// The same endpoint on the other loopback family (`127.0.0.1` ↔ `::1`),
    /// when [`any_loopback_family`](Self::any_loopback_family) allows it.
    pub fn loopback_sibling(&self) -> Option<Self> {
        if !self.any_loopback_family {
            return None;
        }
        let address = match self.address {
            IpAddr::V4(Ipv4Addr::LOCALHOST) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            _ => return None,
        };
        Some(Self {
            address,
            ..self.clone()
        })
    }

    /// Replace and normalize the target's base path.
    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = normalize_base_path(base_path.into());
        self
    }

    /// Return whether the target address is loopback-scoped.
    #[inline]
    pub fn is_loopback(&self) -> bool {
        self.address.is_loopback()
    }

    /// Format the address and port as an HTTP authority.
    pub fn authority(&self) -> String {
        match self.address {
            IpAddr::V4(address) => format!("{address}:{}", self.port),
            IpAddr::V6(address) => format!("[{address}]:{}", self.port),
        }
    }

    /// Format the complete local endpoint URL.
    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.base_path)
    }

    /// Format a WebSocket URL for a request path under this target.
    pub fn websocket_url(&self, path: &str) -> String {
        format!(
            "{}://{}{}",
            self.scheme.websocket(),
            self.authority(),
            self.upstream_path(path)
        )
    }

    /// Prefix a request path with the advertised base path without duplicating it.
    pub fn upstream_path(&self, request_path: &str) -> String {
        if self.base_path == "/" {
            return normalize_base_path(request_path.to_string());
        }
        let base_path = self.base_path.trim_end_matches('/');
        let request_path = normalize_base_path(request_path.to_string());
        if request_path == base_path
            || request_path
                .strip_prefix(base_path)
                .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('?'))
        {
            return request_path;
        }
        format!("{base_path}{request_path}")
    }
}

fn default_base_path() -> String {
    "/".to_string()
}

fn normalize_base_path(path: String) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return default_base_path();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_target_formats_an_http_url() {
        let target = LocalTarget::loopback(LocalScheme::Http, 5173);

        assert_eq!(target.url(), "http://127.0.0.1:5173/");
        assert_eq!(target.websocket_url("/hmr"), "ws://127.0.0.1:5173/hmr");
    }

    #[test]
    fn ipv6_target_brackets_its_authority() {
        let target = LocalTarget {
            scheme: LocalScheme::Https,
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 8443,
            base_path: "/app".to_string(),
            any_loopback_family: false,
        };

        assert_eq!(target.url(), "https://[::1]:8443/app");
        assert!(target.is_loopback());
    }

    #[test]
    fn port_only_target_alternates_between_the_loopback_families() {
        let target = LocalTarget::loopback_port(LocalScheme::Http, 4321).with_base_path("/app");

        let sibling = target.loopback_sibling().unwrap();

        assert_eq!(sibling.url(), "http://[::1]:4321/app");
        assert!(sibling.any_loopback_family);
        assert_eq!(sibling.loopback_sibling(), Some(target));
    }

    #[test]
    fn a_verified_or_unusual_loopback_address_has_no_sibling() {
        let verified = LocalTarget::loopback(LocalScheme::Http, 4321);
        let mut unusual = LocalTarget::loopback_port(LocalScheme::Http, 4321);
        unusual.address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        assert_eq!(verified.loopback_sibling(), None);
        assert_eq!(unusual.loopback_sibling(), None);
    }

    #[test]
    fn a_verified_target_serializes_without_the_family_flag() {
        let verified =
            serde_json::to_value(LocalTarget::loopback(LocalScheme::Http, 5173)).unwrap();
        let port_only =
            serde_json::to_value(LocalTarget::loopback_port(LocalScheme::Http, 5173)).unwrap();

        assert!(verified.get("anyLoopbackFamily").is_none(), "{verified}");
        assert_eq!(port_only["anyLoopbackFamily"], true);
        assert_eq!(
            serde_json::from_value::<LocalTarget>(verified).unwrap(),
            LocalTarget::loopback(LocalScheme::Http, 5173)
        );
    }

    #[test]
    fn upstream_path_prefixes_root_requests_without_duplicating_the_base() {
        let target = LocalTarget::loopback(LocalScheme::Http, 5173).with_base_path("/app/");

        assert_eq!(target.upstream_path("/"), "/app/");
        assert_eq!(
            target.upstream_path("/assets/main.js"),
            "/app/assets/main.js"
        );
        assert_eq!(
            target.upstream_path("/app/assets/main.js"),
            "/app/assets/main.js"
        );
        assert_eq!(target.upstream_path("/application"), "/app/application");
    }
}
