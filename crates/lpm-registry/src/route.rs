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
    /// Build a `RouteTable` from explicit components.
    ///
    /// Returns `Err(NpmrcLoadErrors)` if `npmrc` has any **fatal**
    /// errors (currently: missing env vars referenced via `${VAR}`).
    /// This is the type-system enforcement of the "no install proceeds
    /// with broken `.npmrc`" contract — Gemini day-3 review Finding 2.
    /// A side-channel `npmrc_errors()` accessor on a constructed
    /// `RouteTable` would still leave the check up to "remember to
    /// look"; making this `Result`-typed makes the contract impossible
    /// to silently bypass.
    ///
    /// Non-fatal `warnings` (cafile, strict-ssl, etc.) are still
    /// available via [`Self::npmrc_warnings`] on the successfully-
    /// constructed table — those are advisory.
    pub fn new(mode: RouteMode, npmrc: NpmrcConfig) -> Result<Self, NpmrcLoadErrors> {
        if !npmrc.errors.is_empty() {
            return Err(NpmrcLoadErrors {
                errors: npmrc.errors.clone(),
            });
        }
        Ok(Self {
            mode,
            npmrc: Arc::new(npmrc),
        })
    }

    /// Build a `RouteTable` with no `.npmrc` configuration — equivalent
    /// to today's `RouteMode`-only routing. Infallible (empty npmrc has
    /// no errors). Convenience for callers that don't need `.npmrc`
    /// support, and for tests.
    pub fn from_mode_only(mode: RouteMode) -> Self {
        Self {
            mode,
            npmrc: Arc::new(NpmrcConfig::default()),
        }
    }

    /// Production builder: read `RouteMode` from env, walk the four
    /// `.npmrc` layers (system → user → project) anchored at `cwd`,
    /// and finalize. Returns `Err` if any layer raised a fatal parse
    /// error (e.g., `${MISSING_VAR}` interpolation). The caller is
    /// expected to surface the error and exit non-zero before any
    /// network — npm errors here too, so we match.
    pub fn from_env_and_filesystem(cwd: &Path) -> Result<Self, NpmrcLoadErrors> {
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

    /// Phase 58.1 — TLS overrides parsed from `.npmrc` (`cafile=` / `ca=`
    /// extra roots and `strict-ssl=false`). Callers thread this into
    /// [`RegistryClient::with_tls_overrides`](crate::client::RegistryClient::with_tls_overrides)
    /// once at install start, before any network is touched.
    ///
    /// Returns a borrow of the merged `TlsOverrides` from the loaded
    /// `.npmrc` layers. Empty / `default()` when no `.npmrc` exists.
    pub fn tls_overrides(&self) -> &crate::npmrc::TlsOverrides {
        &self.npmrc.tls
    }

    /// Look up auth for a request URL we're about to send. Delegates
    /// to the wrapped [`NpmrcConfig::auth_for_url`] — origin-matched
    /// (host + port), scheme-agnostic per npm convention.
    ///
    /// Used by tarball-download call sites in install.rs to pair the
    /// destination URL with the correct credential before calling
    /// `RegistryClient::download_tarball_to_file_with_auth` (Phase 58
    /// day-4.5 fix). The metadata path goes through
    /// `RouteTable::route_for_package` which embeds the auth in the
    /// `Custom` arm; tarball URLs come from resolved metadata and so
    /// need this lookup separately.
    pub fn auth_for_url(&self, url: &str) -> Option<&RegistryAuth> {
        self.npmrc.auth_for_url(url)
    }

    /// Borrow the underlying `RouteMode`. Useful for code paths that
    /// haven't been npmrc-aware-ified yet.
    pub fn mode(&self) -> RouteMode {
        self.mode
    }
}

/// Fatal `.npmrc` parse errors that block `RouteTable` construction.
/// Surfaced by [`RouteTable::new`] / [`RouteTable::from_env_and_filesystem`]
/// when the user's config has unrecoverable problems (currently:
/// `${VAR}` references where the env var is unset — npm errors here
/// too).
///
/// CLI callers should `output::error` each line and exit non-zero
/// before any resolution work begins. The `Display` impl renders one
/// error per line.
#[derive(Debug)]
pub struct NpmrcLoadErrors {
    pub errors: Vec<String>,
}

impl std::fmt::Display for NpmrcLoadErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors.len() == 1 {
            write!(f, "{}", self.errors[0])
        } else {
            for (i, e) in self.errors.iter().enumerate() {
                if i > 0 {
                    writeln!(f)?;
                }
                write!(f, "{e}")?;
            }
            Ok(())
        }
    }
}

impl std::error::Error for NpmrcLoadErrors {}

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
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
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
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
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
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
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
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
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
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
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
    fn route_table_new_fails_fast_on_fatal_npmrc_error() {
        // Gemini day-3 review Finding 2: a `.npmrc` with `${MISSING}`
        // env interpolation must NOT yield a usable RouteTable. The
        // type system enforces this — `new` returns `Err` so a caller
        // CAN'T forget to check for errors.
        let content = "//host/:_authToken=${MISSING}\n";
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let err = RouteTable::new(RouteMode::Direct, npmrc)
            .expect_err("missing env var must block construction");
        assert_eq!(err.errors.len(), 1);
        assert!(err.errors[0].contains("MISSING"));
        // Display impl renders the single error inline.
        let rendered = format!("{err}");
        assert!(rendered.contains("MISSING"));
    }

    #[test]
    fn route_table_new_collects_multiple_fatal_errors() {
        // Two missing env vars on different lines — both surfaced in
        // one `Err`. Caller surfaces all so the user fixes them in one
        // edit, not iteratively.
        let content = concat!(
            "//host-a/:_authToken=${MISSING_A}\n",
            "//host-b/:_authToken=${MISSING_B}\n",
        );
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let err = RouteTable::new(RouteMode::Direct, npmrc).expect_err("must Err");
        assert_eq!(err.errors.len(), 2);
        let rendered = format!("{err}");
        assert!(rendered.contains("MISSING_A"));
        assert!(rendered.contains("MISSING_B"));
        // Multi-error Display puts each on its own line.
        assert!(rendered.contains('\n'));
    }

    #[test]
    fn route_table_new_succeeds_with_only_warnings() {
        // Warnings (per-origin TLS / path-prefix tokens) are advisory —
        // they do NOT block construction. Only fatal errors do.
        // Per-origin cafile is still parse-warned in Phase 58.1 (deferred
        // to 58.3 mTLS); use that as a deterministic warning trigger.
        let content = "//npm.internal/:cafile=/etc/ssl/cert.pem\n";
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("warnings don't block");
        assert_eq!(table.npmrc_warnings().len(), 1);
        assert!(table.npmrc_warnings()[0].contains("Phase 58.3"));
    }
}
