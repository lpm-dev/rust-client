//! Upstream routing policy for package metadata fetches.
//!
//! Phase 49 (preplan §3, §5.4): `@lpm.dev/*` packages ALWAYS route via
//! the LPM Worker (auth + batch endpoint + cost attribution). For
//! everything else, [`RouteMode`] picks between the LPM Worker proxy
//! and a direct fetch from `registry.npmjs.org`.
//!
//! The shipped default is [`RouteMode::Direct`] — Phase 49's whole
//! point is to stop paying Cloudflare for 100%-free npm traffic.
//! [`RouteMode::Proxy`] exists as an undocumented debug escape hatch
//! via the `LPM_NPM_ROUTE` env var; it is NOT a user-facing knob.
//!
//! ## Phase 58 — Custom registries via `.npmrc`
//!
//! [`RouteTable`] wraps `RouteMode` plus a parsed [`crate::NpmrcConfig`]
//! so `.npmrc`-declared private/internal registries become first-class
//! routing destinations. When a package matches an npmrc-declared
//! `@scope:registry=...` or the default `registry=...` overrides
//! npmjs.org, [`RouteTable::route_for_package`] emits
//! [`UpstreamRoute::Custom`] carrying the destination URL plus any
//! origin-scoped auth.
//!
//! Day-3 plumbing: types + RouteTable + lpm-registry-side dispatch.
//! Day-4 wiring: lpm-resolver (walker, greedy) + lpm-cli (install,
//! install_global) consume `RouteTable` instead of `RouteMode`.

use std::path::Path;
use std::sync::Arc;

use crate::npmrc::{NpmrcConfig, RegistryAuth, RegistryTarget};

/// How the rust-client routes npm-scoped package fetches.
///
/// `@lpm.dev/*` packages are unaffected by this setting — they always
/// route through the LPM Worker for auth + batched cost attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMode {
    /// Fetch non-`@lpm.dev/*` packages via the LPM Worker proxy.
    /// Preserves the pre-Phase-49 routing shape. Undocumented escape
    /// hatch.
    Proxy,

    /// Fetch non-`@lpm.dev/*` packages direct from
    /// `registry.npmjs.org`. The shipped default per preplan §3 —
    /// stops the double hop `client → CF Worker → npm`.
    #[default]
    Direct,
}

/// The concrete upstream selected for a single package.
///
/// Produced by [`RouteMode::route_for_package`] (2-arm) or
/// [`RouteTable::route_for_package`] (3-arm). Walker dispatch + the
/// provider's escape-hatch fetch both branch on this.
///
/// **Drop of `Copy`**: the `Custom` variant carries `RegistryTarget`
/// (`Arc<str>` base URL) and an optional `RegistryAuth` (a
/// `SecretString`-bearing newtype), neither of which is `Copy`. The
/// rest of the enum is still cheap to clone — `Arc::clone` for the
/// target, `SecretString::clone` for the auth (one ref-bump on each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamRoute {
    /// Fetch via the LPM Worker (auth + `batch-metadata-deep` endpoint).
    LpmWorker,

    /// Fetch direct from `registry.npmjs.org` (no Worker hop).
    NpmDirect,

    /// Fetch from a custom npm-compatible registry declared in
    /// `.npmrc` (Phase 58). `target.base_url` is the canonicalized
    /// registry root; `auth` is the origin-scoped credential to attach,
    /// if any. The dispatcher MUST verify auth's origin matches the
    /// destination URL's host before sending — defense-in-depth against
    /// cross-origin token leaks.
    Custom {
        target: RegistryTarget,
        auth: Option<RegistryAuth>,
    },
}

impl RouteMode {
    /// Pick the upstream for a specific package name.
    ///
    /// `@lpm.dev/*` always goes to the Worker — LPM packages need the
    /// authenticated batch path and their fetches are attributed.
    /// Anything else follows `self`. **Never emits
    /// [`UpstreamRoute::Custom`]** — that requires the npmrc-aware
    /// [`RouteTable::route_for_package`].
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

/// Composite routing decision: env-driven [`RouteMode`] plus the
/// disk-discovered [`NpmrcConfig`].
///
/// Phase 58 day-3: this is the type the resolver/CLI threads through
/// dispatch instead of `RouteMode`. Day-3 ships the data layer +
/// `lpm-registry`-side dispatch only; day-4 wires the rest.
///
/// `npmrc` is `Arc`-shared so cloning a `RouteTable` (e.g., one per
/// dispatcher task) is one ref-bump, not a HashMap clone.
#[derive(Debug, Clone)]
pub struct RouteTable {
    mode: RouteMode,
    npmrc: Arc<NpmrcConfig>,
}

impl RouteTable {
    /// Build a `RouteTable` from explicit components — used by tests
    /// and by callers that already have a parsed `NpmrcConfig` in hand.
    pub fn new(mode: RouteMode, npmrc: NpmrcConfig) -> Self {
        Self {
            mode,
            npmrc: Arc::new(npmrc),
        }
    }

    /// Build a `RouteTable` with no `.npmrc` configuration — equivalent
    /// to today's `RouteMode`-only routing. Convenience for callers
    /// that haven't yet been migrated to the npmrc-aware path.
    pub fn from_mode_only(mode: RouteMode) -> Self {
        Self::new(mode, NpmrcConfig::default())
    }

    /// Production builder: read `RouteMode` from env, walk the four
    /// `.npmrc` layers (system → user → project) anchored at `cwd`,
    /// and finalize.
    pub fn from_env_and_filesystem(cwd: &Path) -> Self {
        let mode = RouteMode::from_env_or_default();
        let npmrc = NpmrcConfig::load_from_filesystem(cwd);
        Self::new(mode, npmrc)
    }

    /// Pick the upstream for a specific package name.
    ///
    /// Resolution order (preplan §3.4):
    /// 1. `@lpm.dev/*` → `LpmWorker` (unchanged invariant; LPM packages
    ///    always go through the Worker for auth + batch + attribution).
    /// 2. `@scope/foo` and `npmrc.scope_registries[@scope]` exists →
    ///    `Custom { target, auth }`.
    /// 3. `npmrc.default_registry` is `Some(target)` → `Custom { … }`.
    /// 4. Else → fall back to `mode.route_for_package(name)` (existing
    ///    2-arm `LpmWorker`/`NpmDirect` behavior).
    ///
    /// Auth lookup uses the **destination URL's origin**, not the
    /// package's scope. If the user has `@mycompany:registry=https://X/`
    /// AND `//X/:_authToken=...`, the token is attached to fetches
    /// of `@mycompany/foo`. If they have a scope mapping with no auth,
    /// the request goes anonymous — npm parity.
    pub fn route_for_package(&self, name: &str) -> UpstreamRoute {
        if name.starts_with("@lpm.dev/") {
            return UpstreamRoute::LpmWorker;
        }
        if let Some(target) = self.npmrc.target_for_package(name) {
            let auth = self.npmrc.auth_for_url(&target.base_url).cloned();
            return UpstreamRoute::Custom {
                target: target.clone(),
                auth,
            };
        }
        self.mode.route_for_package(name)
    }

    /// Non-fatal warnings raised during npmrc parse + walker discovery.
    /// Callers (e.g., `lpm install`) dump these via `output::warn`
    /// before resolution starts.
    pub fn npmrc_warnings(&self) -> &[String] {
        &self.npmrc.warnings
    }

    /// Fatal errors raised during npmrc parse (currently: missing env
    /// vars in `${VAR}` interpolation). Callers must surface these and
    /// exit non-zero before any network — npm errors here too, so we
    /// match.
    pub fn npmrc_errors(&self) -> &[String] {
        &self.npmrc.errors
    }

    /// Borrow the underlying `RouteMode`. Useful for code paths that
    /// haven't been npmrc-aware-ified yet.
    pub fn mode(&self) -> RouteMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npmrc::NpmrcConfig;

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
        // the test self-contained; parallel test runs share the
        // process env but each assertion sets its own value first.
        // SAFETY: tests set/clear env vars; single-threaded unit-test
        // context.
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "direct") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::Direct);
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "proxy") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::Proxy);
        unsafe { std::env::set_var("LPM_NPM_ROUTE", "garbage") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::default());
        unsafe { std::env::remove_var("LPM_NPM_ROUTE") };
        assert_eq!(RouteMode::from_env_or_default(), RouteMode::default());
    }

    // ---- RouteTable tests (Phase 58 day-3) ----

    fn no_env(_name: &str) -> Option<String> {
        None
    }

    #[test]
    fn route_table_lpm_packages_always_route_to_worker() {
        // Even with a default-registry override in npmrc, @lpm.dev/*
        // bypasses everything and goes straight to the Worker. This
        // is the load-bearing invariant from Phase 49 — LPM packages
        // require auth + batched attribution that npm-compatible
        // registries don't provide.
        let npmrc = NpmrcConfig::parse("registry=https://npm.internal/\n", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        assert_eq!(
            table.route_for_package("@lpm.dev/acme.util"),
            UpstreamRoute::LpmWorker
        );
    }

    #[test]
    fn route_table_falls_back_to_route_mode_when_no_npmrc() {
        // Empty npmrc → behavior identical to RouteMode::route_for_package.
        let table = RouteTable::from_mode_only(RouteMode::Direct);
        assert_eq!(table.route_for_package("react"), UpstreamRoute::NpmDirect);
        let table = RouteTable::from_mode_only(RouteMode::Proxy);
        assert_eq!(table.route_for_package("react"), UpstreamRoute::LpmWorker);
    }

    #[test]
    fn route_table_uses_default_registry_from_npmrc() {
        let npmrc = NpmrcConfig::parse("registry=https://npm.internal/\n", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        match table.route_for_package("react") {
            UpstreamRoute::Custom { target, auth } => {
                assert_eq!(target.base_url.as_ref(), "https://npm.internal");
                assert!(auth.is_none(), "no auth set in npmrc");
            }
            other => panic!("expected Custom route, got {other:?}"),
        }
    }

    #[test]
    fn route_table_uses_scope_registry_from_npmrc() {
        let npmrc = NpmrcConfig::parse(
            "@mycompany:registry=https://npm.internal/\n",
            "test",
            &no_env,
        );
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        // Scoped package → custom registry.
        match table.route_for_package("@mycompany/foo") {
            UpstreamRoute::Custom { target, .. } => {
                assert_eq!(target.base_url.as_ref(), "https://npm.internal");
            }
            other => panic!("expected Custom for scoped pkg, got {other:?}"),
        }
        // Unscoped package → falls through to RouteMode (Direct → NpmDirect).
        assert_eq!(table.route_for_package("react"), UpstreamRoute::NpmDirect);
        // Other scope → falls through.
        assert_eq!(
            table.route_for_package("@types/node"),
            UpstreamRoute::NpmDirect
        );
    }

    #[test]
    fn route_table_attaches_origin_matched_auth() {
        // Default registry + matching auth → Custom carries the auth.
        let content = concat!(
            "registry=https://npm.internal/\n",
            "//npm.internal/:_authToken=ABC123\n",
        );
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        match table.route_for_package("react") {
            UpstreamRoute::Custom { target, auth } => {
                assert_eq!(target.base_url.as_ref(), "https://npm.internal");
                let auth = auth.expect("auth should be present");
                match auth {
                    RegistryAuth::Bearer { token: s, .. } => {
                        use secrecy::ExposeSecret;
                        assert_eq!(s.expose_secret(), "ABC123");
                    }
                    other => panic!("expected Bearer, got {other:?}"),
                }
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn route_table_no_auth_for_unmatched_origin() {
        // npmrc has a scope mapping to internal AND an auth token for
        // ANOTHER host. Custom route emitted, but auth must be None.
        let content = concat!(
            "@mycompany:registry=https://npm.internal/\n",
            "//unrelated.example/:_authToken=XYZ\n",
        );
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        match table.route_for_package("@mycompany/foo") {
            UpstreamRoute::Custom { auth, .. } => {
                assert!(
                    auth.is_none(),
                    "auth from a different origin must NOT be attached"
                );
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn route_table_npmrc_warnings_and_errors_surfaced() {
        let content = concat!(
            "cafile=/etc/ssl/cert.pem\n",      // deferred-feature warning
            "//host/:_authToken=${MISSING}\n", // env-interp error
        );
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc);
        assert_eq!(table.npmrc_warnings().len(), 1);
        assert!(table.npmrc_warnings()[0].contains("Phase 58.1"));
        assert_eq!(table.npmrc_errors().len(), 1);
        assert!(table.npmrc_errors()[0].contains("MISSING"));
    }
}
