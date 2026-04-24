//! Upstream routing policy for package metadata fetches.
//!
//! Phase 49 (preplan §3, §5.4): `@lpm.dev/*` packages ALWAYS route via the
//! LPM Worker (auth + batch endpoint + cost attribution). For everything
//! else, [`RouteMode`] picks between the LPM Worker proxy and a direct
//! fetch from `registry.npmjs.org`.
//!
//! The shipped default is [`RouteMode::Direct`] — Phase 49's whole point
//! is to stop paying Cloudflare for 100 %-free npm traffic. [`RouteMode::Proxy`]
//! exists as an undocumented debug escape hatch via the `LPM_NPM_ROUTE`
//! env var; it is NOT a user-facing knob.

/// How the rust-client routes npm-scoped package fetches.
///
/// `@lpm.dev/*` packages are unaffected by this setting — they always
/// route through the LPM Worker for auth + batched cost attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMode {
    /// Fetch non-`@lpm.dev/*` packages via the LPM Worker proxy. Preserves
    /// the pre-Phase-49 routing shape. Undocumented escape hatch.
    Proxy,

    /// Fetch non-`@lpm.dev/*` packages direct from `registry.npmjs.org`.
    /// The shipped default per preplan §3 — stops the double hop
    /// `client → CF Worker → npm`.
    #[default]
    Direct,
}

/// The concrete upstream selected for a single package.
///
/// Produced by [`RouteMode::route_for_package`]. Walker dispatch + the
/// provider's escape-hatch fetch both branch on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRoute {
    /// Fetch via the LPM Worker (auth + `batch-metadata-deep` endpoint).
    LpmWorker,

    /// Fetch direct from `registry.npmjs.org` (no Worker hop).
    NpmDirect,
}

impl RouteMode {
    /// Pick the upstream for a specific package name.
    ///
    /// `@lpm.dev/*` always goes to the Worker — LPM packages need the
    /// authenticated batch path and their fetches are attributed. Anything
    /// else follows `self`.
    pub fn route_for_package(self, name: &str) -> UpstreamRoute {
        if name.starts_with("@lpm.dev/") {
            UpstreamRoute::LpmWorker
        } else {
            match self {
                RouteMode::Proxy => UpstreamRoute::LpmWorker,
                RouteMode::Direct => UpstreamRoute::NpmDirect,
            }
        }
    }

    /// Read the mode from `LPM_NPM_ROUTE`, falling back to the default.
    ///
    /// Valid values: `"direct"`, `"proxy"`. Anything else (including
    /// unset) yields the default. This is an undocumented debug escape
    /// hatch; do not advertise it in user-facing docs.
    pub fn from_env_or_default() -> Self {
        match std::env::var("LPM_NPM_ROUTE").as_deref() {
            Ok("proxy") => RouteMode::Proxy,
            Ok("direct") => RouteMode::Direct,
            _ => RouteMode::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_direct() {
        assert_eq!(RouteMode::default(), RouteMode::Direct);
    }

    #[test]
    fn lpm_packages_always_route_to_worker() {
        // Regardless of mode, @lpm.dev/* goes to the Worker.
        assert_eq!(
            RouteMode::Direct.route_for_package("@lpm.dev/acme.util"),
            UpstreamRoute::LpmWorker
        );
        assert_eq!(
            RouteMode::Proxy.route_for_package("@lpm.dev/acme.util"),
            UpstreamRoute::LpmWorker
        );
    }

    #[test]
    fn npm_direct_mode_skips_worker() {
        assert_eq!(
            RouteMode::Direct.route_for_package("react"),
            UpstreamRoute::NpmDirect
        );
        assert_eq!(
            RouteMode::Direct.route_for_package("@types/node"),
            UpstreamRoute::NpmDirect
        );
    }

    #[test]
    fn npm_proxy_mode_routes_via_worker() {
        assert_eq!(
            RouteMode::Proxy.route_for_package("react"),
            UpstreamRoute::LpmWorker
        );
        assert_eq!(
            RouteMode::Proxy.route_for_package("@types/node"),
            UpstreamRoute::LpmWorker
        );
    }

    #[test]
    fn env_var_parsing() {
        // Safe to mutate process env in a single-threaded unit test.
        // We set and unset the variable around each assertion to keep
        // the test self-contained; parallel test runs share the process
        // env but each assertion sets its own value first.
        // SAFETY: tests set/clear env vars; single-threaded unit test context.
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "direct") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::Direct);
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "proxy") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::Proxy);
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "garbage") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::default());
        unsafe { std::env::remove_var("LPM_NPM_ROUTE") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::default());
    }
}
