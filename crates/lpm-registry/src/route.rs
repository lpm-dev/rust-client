//! Upstream routing policy for package metadata fetches.
//!
//! `@lpm.dev/*` packages always route via the LPM Worker (auth + batch
//! endpoint). Everything else fetches direct from `registry.npmjs.org`
//! by default — same shape as `npm`, `yarn`, `pnpm`, and `bun`. The
//! `LPM_NPM_ROUTE` env var stays as an internal debug knob; it is not
//! a user-facing setting.
//!
//! ## Custom registries via `.npmrc`
//!
//! [`RouteTable`] wraps `RouteMode` plus a parsed [`crate::NpmrcConfig`]
//! so `.npmrc`-declared private/internal registries become first-class
//! routing destinations. When a package matches an npmrc-declared
//! `@scope:registry=...` or the default `registry=...` overrides
//! npmjs.org, [`RouteTable::route_for_package`] emits
//! [`UpstreamRoute::Custom`] carrying the destination URL plus any
//! origin-scoped auth.

use std::path::Path;
use std::sync::{Arc, LazyLock};

use crate::npmrc::{AuthScope, NpmrcConfig, OriginKey, RegistryAuth, RegistryKind, RegistryTarget};

const JSR_NPM_REGISTRY_URL: &str = "https://npm.jsr.io";
const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

static JSR_TARGET: LazyLock<RegistryTarget> = LazyLock::new(|| RegistryTarget {
    base_url: Arc::from(JSR_NPM_REGISTRY_URL),
    kind: RegistryKind::NpmCompatible,
});
static NPM_TARGET: LazyLock<RegistryTarget> = LazyLock::new(|| RegistryTarget {
    base_url: Arc::from(NPM_REGISTRY_URL),
    kind: RegistryKind::NpmCompatible,
});
static JSR_URL: LazyLock<reqwest::Url> = LazyLock::new(|| {
    reqwest::Url::parse(JSR_NPM_REGISTRY_URL).expect("built-in JSR registry URL must be valid")
});
static JSR_ORIGIN: LazyLock<OriginKey> = LazyLock::new(|| {
    OriginKey::from_parsed_url(&JSR_URL).expect("built-in JSR registry origin must be valid")
});
static NPM_ORIGIN: LazyLock<OriginKey> = LazyLock::new(|| {
    OriginKey::from_request_url(NPM_REGISTRY_URL)
        .expect("built-in npm registry origin must be valid")
});

/// How the rust-client routes npm-scoped package fetches.
///
/// `@lpm.dev/*` packages are unaffected by this setting — they always
/// route through the LPM Worker for auth + batched cost attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RouteMode {
    /// Fetch non-`@lpm.dev/*` packages via the LPM Worker. Internal
    /// debug knob only.
    Proxy,

    /// Fetch non-`@lpm.dev/*` packages direct from
    /// `registry.npmjs.org`. Default — matches `npm`/`yarn`/`pnpm`/`bun`.
    #[default]
    Direct,
}

/// Route and credential identity used to decide whether workspace importer
/// requests may share one resolver traversal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceResolutionKey {
    mode: RouteMode,
    default_registry: Option<String>,
    scope_registries: Vec<(String, String)>,
    credentialed_origins: Vec<(AuthScope, [u8; 32])>,
    package_route_overrides: Vec<(String, RouteMode)>,
}

/// The concrete upstream selected for a single package.
///
/// Produced by [`RouteMode::route_for_package`] (2-arm) or
/// [`RouteTable::route_for_package`] (3-arm). Walker dispatch + the
/// provider's escape-hatch fetch both branch on this.
///
/// **Drop of `Copy`**: the `Custom` variant carries `RegistryTarget`
/// (`Arc<str>` base URL) and a shared optional credential. Cloning a
/// custom route only bumps reference counts; it never copies secret bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamRoute {
    /// Fetch via the LPM Worker (auth + `batch-metadata-deep` endpoint).
    LpmWorker,

    /// Fetch direct from `registry.npmjs.org` (no Worker hop).
    NpmDirect,

    /// Fetch from a custom npm-compatible registry declared in `.npmrc`.
    /// `target.base_url` is the canonicalized
    /// registry root; `auth` is the origin-scoped credential to attach,
    /// if any. The dispatcher MUST verify auth's origin matches the
    /// destination URL's host before sending — defense-in-depth against
    /// cross-origin token leaks.
    Custom {
        target: RegistryTarget,
        auth: Option<Arc<RegistryAuth>>,
    },
}

#[derive(Clone, Copy)]
enum SelectedRoute<'a> {
    Mode(RouteMode),
    Custom(&'a RegistryTarget),
    Jsr,
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
/// `npmrc` is `Arc`-shared so cloning a `RouteTable` (e.g., one per
/// dispatcher task) is one ref-bump, not a HashMap clone.
#[derive(Debug, Clone)]
pub struct RouteTable {
    mode: RouteMode,
    npmrc: Arc<NpmrcConfig>,
    package_route_overrides: Arc<std::collections::HashMap<String, RouteMode>>,
}

impl RouteTable {
    /// Build a `RouteTable` from explicit components.
    ///
    /// Returns `Err(NpmrcLoadErrors)` if `npmrc` has any **fatal**
    /// errors (currently: missing env vars referenced via `${VAR}`).
    /// This is the type-system enforcement of the "no install proceeds
    /// with broken `.npmrc`" contract. A side-channel `npmrc_errors()`
    /// accessor on a constructed
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
                errors: npmrc.errors,
            });
        }
        Ok(Self {
            mode,
            npmrc: Arc::new(npmrc),
            package_route_overrides: Arc::new(std::collections::HashMap::new()),
        })
    }

    /// Build a `RouteTable` with no `.npmrc` configuration — equivalent
    /// to today's `RouteMode`-only routing. Infallible (empty npmrc has
    /// no errors). Convenience for callers that don't need `.npmrc`
    /// support, and for tests.
    pub fn from_mode_only(mode: RouteMode) -> Self {
        let mut npmrc = NpmrcConfig::default();
        npmrc.finalize();
        Self {
            mode,
            npmrc: Arc::new(npmrc),
            package_route_overrides: Arc::new(std::collections::HashMap::new()),
        }
    }

    /// Pin package routes that were already validated earlier in one command.
    pub fn with_package_route_overrides(
        mut self,
        overrides: std::collections::HashMap<String, RouteMode>,
    ) -> Self {
        self.package_route_overrides = Arc::new(overrides);
        self
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
    /// Resolution order:
    /// 1. `@lpm.dev/*` → `LpmWorker` (unchanged invariant; LPM packages
    ///    always go through the Worker for auth + batch + attribution).
    /// 2. `@scope/foo` and `npmrc.scope_registries[@scope]` exists →
    ///    `Custom { target, auth }`.
    /// 3. `@jsr/*` → `Custom { target: https://npm.jsr.io, auth }`.
    /// 4. `npmrc.default_registry` is `Some(target)` → `Custom { … }`.
    /// 5. Else → fall back to `mode.route_for_package(name)` (existing
    ///    2-arm `LpmWorker`/`NpmDirect` behavior).
    ///
    /// Auth lookup uses the **destination URL's origin**, not the
    /// package's scope. If the user has `@mycompany:registry=https://X/`
    /// AND `//X/:_authToken=...`, the token is attached to fetches
    /// of `@mycompany/foo`. If they have a scope mapping with no auth,
    /// the request goes anonymous — npm parity.
    pub fn route_for_package(&self, name: &str) -> UpstreamRoute {
        match self.selected_route_for_package(name) {
            SelectedRoute::Mode(mode) => self.route_for_mode(name, mode),
            SelectedRoute::Custom(target) => UpstreamRoute::Custom {
                target: target.clone(),
                auth: self.npmrc.shared_auth_for_url(&target.base_url).cloned(),
            },
            SelectedRoute::Jsr => UpstreamRoute::Custom {
                target: JSR_TARGET.clone(),
                auth: self
                    .npmrc
                    .shared_auth_for_origin_path(&JSR_ORIGIN, "/")
                    .cloned(),
            },
        }
    }

    fn route_for_mode(&self, name: &str, mode: RouteMode) -> UpstreamRoute {
        match mode.route_for_package(name) {
            UpstreamRoute::NpmDirect => {
                let Some(auth) = self
                    .npmrc
                    .shared_auth_for_origin_path(&NPM_ORIGIN, "/")
                    .cloned()
                else {
                    return UpstreamRoute::NpmDirect;
                };
                UpstreamRoute::Custom {
                    target: NPM_TARGET.clone(),
                    auth: Some(auth),
                }
            }
            route => route,
        }
    }

    /// Return the configured npm-compatible route only when `candidate`
    /// is within the registry path authorized for `name`.
    pub fn custom_route_for_package_url(
        &self,
        name: &str,
        candidate: &str,
    ) -> Option<UpstreamRoute> {
        if let Some(target) = self.npmrc_scope_target_for_package(name) {
            return registry_url_contains(candidate, &target.base_url).then(|| {
                UpstreamRoute::Custom {
                    target: target.clone(),
                    auth: self.npmrc.shared_auth_for_url(&target.base_url).cloned(),
                }
            });
        }
        if name.starts_with("@jsr/") {
            return registry_url_contains_parsed(candidate, &JSR_URL).then(|| {
                UpstreamRoute::Custom {
                    target: JSR_TARGET.clone(),
                    auth: self
                        .npmrc
                        .shared_auth_for_origin_path(&JSR_ORIGIN, "/")
                        .cloned(),
                }
            });
        }
        let target = self.npmrc.default_registry.as_ref()?;
        registry_url_contains(candidate, &target.base_url).then(|| UpstreamRoute::Custom {
            target: target.clone(),
            auth: self.npmrc.shared_auth_for_url(&target.base_url).cloned(),
        })
    }

    fn selected_route_for_package<'a>(&'a self, name: &str) -> SelectedRoute<'a> {
        if name.starts_with("@lpm.dev/") {
            return SelectedRoute::Mode(RouteMode::Proxy);
        }
        if let Some(mode) = self.package_route_overrides.get(name) {
            return SelectedRoute::Mode(*mode);
        }
        if let Some(target) = self.npmrc_scope_target_for_package(name) {
            return SelectedRoute::Custom(target);
        }
        if name.starts_with("@jsr/") {
            return SelectedRoute::Jsr;
        }
        self.npmrc
            .default_registry
            .as_ref()
            .map_or(SelectedRoute::Mode(self.mode), SelectedRoute::Custom)
    }

    fn npmrc_scope_target_for_package(&self, name: &str) -> Option<&RegistryTarget> {
        let scope_end = name.find('/')?;
        let scope = name.get(..scope_end)?;
        if !scope.starts_with('@') {
            return None;
        }
        if let Some(target) = self.npmrc.scope_registries.get(scope) {
            return Some(target);
        }
        scope
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
            .then(|| scope.to_ascii_lowercase())
            .and_then(|scope| self.npmrc.scope_registries.get(&scope))
    }

    /// Non-fatal warnings raised during npmrc parse + walker discovery.
    /// Callers (e.g., `lpm install`) dump these via `output::warn`
    /// before resolution starts.
    pub fn npmrc_warnings(&self) -> &[String] {
        &self.npmrc.warnings
    }

    /// Security-grade `.npmrc` warnings that MUST be surfaced even in
    /// `--json` mode. Today carries M7's refusal of project-local
    /// `strict-ssl=false`. Callers emit these unconditionally so a
    /// hostile config doesn't slip past CI / agent runs.
    pub fn npmrc_security_warnings(&self) -> &[String] {
        &self.npmrc.security_warnings
    }

    /// TLS overrides parsed from `.npmrc` (`cafile=` / `ca=` extra roots
    /// and `strict-ssl=false`). Callers thread this into
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
    /// `RegistryClient::download_tarball_to_file_with_auth`. The metadata
    /// path goes through
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

    /// Whether immutable registry artifacts may be shared with another
    /// importer using the same command-scoped client.
    ///
    /// This deliberately accepts only the default routing universe. Auth
    /// entries do not affect its anonymous metadata routes, while any custom
    /// registry or TLS override keeps that importer on its own dispatcher.
    pub fn supports_workspace_fetch_sharing(&self) -> bool {
        self.npmrc.default_registry.is_none()
            && self.npmrc.scope_registries.is_empty()
            && self.npmrc.tls.is_empty()
    }

    /// Return an equivalence key for resolver inputs that may safely share a
    /// workspace union. Registry mappings and opaque credential fingerprints
    /// participate in the key; TLS-customized routes stay isolated.
    pub fn workspace_resolution_key(&self) -> Option<WorkspaceResolutionKey> {
        if !self.npmrc.tls.is_empty() {
            return None;
        }

        let mut scope_registries = self
            .npmrc
            .scope_registries
            .iter()
            .map(|(scope, target)| (scope.clone(), target.base_url.to_string()))
            .collect::<Vec<_>>();
        scope_registries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut credentialed_origins = self
            .npmrc
            .origin_auth
            .iter()
            .map(|(origin, auth)| (origin.clone(), auth.credential_fingerprint()))
            .collect::<Vec<_>>();
        credentialed_origins.sort_unstable_by(|left, right| {
            left.0
                .origin
                .host_lower
                .cmp(&right.0.origin.host_lower)
                .then_with(|| left.0.origin.port.cmp(&right.0.origin.port))
                .then_with(|| left.0.path_prefix.cmp(&right.0.path_prefix))
        });
        let mut package_route_overrides = self
            .package_route_overrides
            .iter()
            .map(|(name, mode)| (name.clone(), *mode))
            .collect::<Vec<_>>();
        package_route_overrides.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Some(WorkspaceResolutionKey {
            mode: self.mode,
            default_registry: self
                .npmrc
                .default_registry
                .as_ref()
                .map(|target| target.base_url.to_string()),
            scope_registries,
            credentialed_origins,
            package_route_overrides,
        })
    }

    /// The **request-aware effective-origin set** for
    /// `with_tls_overrides_for`'s eager-build pass.
    ///
    /// Walks `top_level_specs` and emits the origin each spec would
    /// route to per the current [`RouteMode`] + npmrc table. Returns
    /// a deduplicated `Vec` (insertion order preserved). Caller passes
    /// this to [`crate::client::RegistryClient::with_tls_overrides_for`],
    /// which intersects it with the per-origin TLS map and eager-builds
    /// only for the intersection.
    ///
    /// **Why request-aware (not config-union):** if `~/.npmrc` declares
    /// per-origin TLS for `//legacy.artifactory/` and the current
    /// invocation never touches that origin, we MUST NOT eager-build
    /// for it. A bad `certfile=` / missing passphrase / wrong passphrase
    /// for a configured-but-unreached origin would otherwise abort an
    /// unrelated install. Transitive scopes / tarball CDNs surfacing
    /// later go through the lazy path.
    ///
    /// **Sources of origins:**
    /// 1. [`UpstreamRoute::LpmWorker`] specs → `lpm_worker_url`'s origin.
    /// 2. [`UpstreamRoute::NpmDirect`] specs → `npm_direct_url`'s origin.
    /// 3. [`UpstreamRoute::Custom`] specs (scope or default registry hits)
    ///    → the target's origin.
    ///
    /// Origins parsed from URLs that aren't valid http/https are
    /// silently skipped — they couldn't dispatch anyway.
    pub fn effective_registry_origins(
        &self,
        top_level_specs: &[String],
        lpm_worker_url: &str,
        npm_direct_url: &str,
    ) -> Vec<crate::npmrc::OriginKey> {
        use std::collections::HashSet;

        let worker_origin = OriginKey::from_request_url(lpm_worker_url);
        let npm_origin = OriginKey::from_request_url(npm_direct_url);
        let mut origins = Vec::with_capacity(top_level_specs.len().min(8));
        let mut seen = HashSet::with_capacity(top_level_specs.len().min(8));
        let mut push_if_new = |o: OriginKey| {
            if seen.insert(o.clone()) {
                origins.push(o);
            }
        };
        for spec in top_level_specs {
            match self.selected_route_for_package(spec) {
                SelectedRoute::Mode(RouteMode::Proxy) => {
                    if let Some(origin) = worker_origin.as_ref() {
                        push_if_new(origin.clone());
                    }
                }
                SelectedRoute::Mode(RouteMode::Direct) => {
                    if let Some(origin) = npm_origin.as_ref() {
                        push_if_new(origin.clone());
                    }
                }
                SelectedRoute::Custom(target) => {
                    if let Some(o) = OriginKey::from_request_url(&target.base_url) {
                        push_if_new(o);
                    }
                }
                SelectedRoute::Jsr => {
                    push_if_new(JSR_ORIGIN.clone());
                }
            }
        }
        origins
    }
}

fn registry_url_contains(candidate: &str, registry: &str) -> bool {
    let Ok(registry) = reqwest::Url::parse(registry) else {
        return false;
    };
    registry_url_contains_parsed(candidate, &registry)
}

fn registry_url_contains_parsed(candidate: &str, registry: &reqwest::Url) -> bool {
    let Ok(candidate) = reqwest::Url::parse(candidate) else {
        return false;
    };
    if candidate.scheme() != registry.scheme()
        || candidate.host_str().map(str::to_ascii_lowercase)
            != registry.host_str().map(str::to_ascii_lowercase)
        || candidate.port_or_known_default() != registry.port_or_known_default()
    {
        return false;
    }
    let base = registry.path().trim_end_matches('/');
    base.is_empty()
        || candidate.path() == base
        || candidate
            .path()
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with('/'))
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
    fn package_route_override_preserves_planning_source() {
        let table = RouteTable::from_mode_only(RouteMode::Proxy).with_package_route_overrides(
            std::collections::HashMap::from([("planned-public".to_string(), RouteMode::Direct)]),
        );

        assert_eq!(
            table.route_for_package("planned-public"),
            UpstreamRoute::NpmDirect
        );
        assert_eq!(
            table.route_for_package("unplanned-proxy"),
            UpstreamRoute::LpmWorker
        );
        assert_eq!(
            table.route_for_package("@lpm.dev/owner.package"),
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

    // ---- RouteTable tests ----

    fn no_env(_name: &str) -> Option<String> {
        None
    }

    #[test]
    fn route_table_lpm_packages_always_route_to_worker() {
        // Even with a default-registry override in npmrc, @lpm.dev/*
        // bypasses everything and goes straight to the Worker — LPM
        // packages require auth + batched attribution that npm-compatible
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
    fn default_route_table_supports_workspace_fetch_sharing() {
        let table = RouteTable::from_mode_only(RouteMode::Direct);

        assert!(table.supports_workspace_fetch_sharing());
    }

    #[test]
    fn custom_registry_route_table_does_not_support_workspace_fetch_sharing() {
        let npmrc = NpmrcConfig::parse("registry=https://registry.example.test", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("valid npmrc");

        assert!(!table.supports_workspace_fetch_sharing());
    }

    #[test]
    fn npm_auth_token_does_not_disable_default_workspace_fetch_sharing() {
        let npmrc = NpmrcConfig::parse("//registry.npmjs.org/:_authToken=secret", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("valid npmrc");

        assert!(table.supports_workspace_fetch_sharing());
    }

    #[test]
    fn explicit_strict_ssl_true_preserves_workspace_fetch_sharing() {
        let npmrc = NpmrcConfig::parse("strict-ssl=true", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("valid npmrc");

        assert!(table.supports_workspace_fetch_sharing());
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
    fn route_table_routes_jsr_scope_to_jsr_registry_by_default() {
        let table = RouteTable::from_mode_only(RouteMode::Direct);
        match table.route_for_package("@jsr/std__path") {
            UpstreamRoute::Custom { target, auth } => {
                assert_eq!(target.base_url.as_ref(), "https://npm.jsr.io");
                assert_eq!(target.kind, RegistryKind::NpmCompatible);
                assert!(auth.is_none());
            }
            other => panic!("expected Custom JSR route, got {other:?}"),
        }
    }

    #[test]
    fn route_table_jsr_scope_registry_from_npmrc_overrides_builtin_jsr_registry() {
        let npmrc = NpmrcConfig::parse("@jsr:registry=https://mirror.internal/\n", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
        match table.route_for_package("@jsr/std__path") {
            UpstreamRoute::Custom { target, .. } => {
                assert_eq!(target.base_url.as_ref(), "https://mirror.internal");
            }
            other => panic!("expected Custom for @jsr scope override, got {other:?}"),
        }
    }

    #[test]
    fn route_table_jsr_builtin_precedes_default_registry_from_npmrc() {
        let npmrc = NpmrcConfig::parse("registry=https://npm.internal/\n", "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("npmrc has no errors");
        match table.route_for_package("@jsr/std__path") {
            UpstreamRoute::Custom { target, .. } => {
                assert_eq!(target.base_url.as_ref(), "https://npm.jsr.io");
            }
            other => panic!("expected built-in JSR route, got {other:?}"),
        }
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
                match auth.as_ref() {
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
    fn repeated_route_decisions_share_the_same_credential_allocation() {
        let table = make_table(
            "registry=https://npm.internal/\n//npm.internal/:_authToken=ABC123\n",
            RouteMode::Direct,
        );
        let first = match table.route_for_package("react") {
            UpstreamRoute::Custom {
                auth: Some(auth), ..
            } => auth,
            route => panic!("expected authenticated custom route, got {route:?}"),
        };
        let second = match table.route_for_package("lodash") {
            UpstreamRoute::Custom {
                auth: Some(auth), ..
            } => auth,
            route => panic!("expected authenticated custom route, got {route:?}"),
        };

        assert!(Arc::ptr_eq(&first, &second));
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
    fn route_table_accepts_literal_missing_env_references() {
        let content = "//host/:_authToken=${MISSING}\n";
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        RouteTable::new(RouteMode::Direct, npmrc)
            .expect("npm keeps a missing non-optional environment reference literal");
    }

    #[test]
    fn route_table_new_collects_multiple_fatal_errors() {
        let mut npmrc = NpmrcConfig::default();
        npmrc.errors = vec!["first failure".to_string(), "second failure".to_string()];
        let err = RouteTable::new(RouteMode::Direct, npmrc).expect_err("must Err");
        assert_eq!(err.errors.len(), 2);
        let rendered = format!("{err}");
        assert!(rendered.contains("first failure"));
        assert!(rendered.contains("second failure"));
        // Multi-error Display puts each on its own line.
        assert!(rendered.contains('\n'));
    }

    #[test]
    fn route_table_new_succeeds_with_only_warnings() {
        let content = "strict-ssl=invalid\n";
        let npmrc = NpmrcConfig::parse(content, "test", &no_env);
        let table = RouteTable::new(RouteMode::Direct, npmrc).expect("warnings don't block");
        assert_eq!(table.npmrc_warnings().len(), 1);
        assert!(table.npmrc_warnings()[0].contains("strict-ssl"));
    }

    // ---- effective_registry_origins (request-aware) ----

    fn make_table(npmrc_content: &str, mode: RouteMode) -> RouteTable {
        let npmrc = NpmrcConfig::parse(npmrc_content, "test", &no_env);
        RouteTable::new(mode, npmrc).expect("npmrc clean")
    }

    #[test]
    fn workspace_resolution_key_is_independent_of_scope_declaration_order() {
        let first = make_table(
            "@one:registry=https://one.internal/\n@two:registry=https://two.internal/\n",
            RouteMode::Direct,
        );
        let second = make_table(
            "@two:registry=https://two.internal/\n@one:registry=https://one.internal/\n",
            RouteMode::Direct,
        );

        assert_eq!(
            first.workspace_resolution_key(),
            second.workspace_resolution_key(),
        );
    }

    #[test]
    fn workspace_resolution_key_groups_matching_credential_postures() {
        let first = make_table(
            "registry=https://registry.internal/\n\
             //registry.internal/:_authToken=secret\n\
             //uploads.internal/:_authToken=uploads-secret\n",
            RouteMode::Direct,
        );
        let second = make_table(
            "//uploads.internal/:_authToken=uploads-secret\n\
             //registry.internal/:_authToken=secret\n\
             registry=https://registry.internal/\n",
            RouteMode::Direct,
        );

        assert_eq!(
            first.workspace_resolution_key(),
            second.workspace_resolution_key()
        );
        assert!(first.workspace_resolution_key().is_some());
    }

    #[test]
    fn workspace_resolution_key_separates_different_credentials_for_the_same_origin() {
        let first = make_table(
            "registry=https://registry.internal/\n//registry.internal/:_authToken=first\n",
            RouteMode::Direct,
        );
        let second = make_table(
            "registry=https://registry.internal/\n//registry.internal/:_authToken=second\n",
            RouteMode::Direct,
        );

        assert_ne!(
            first.workspace_resolution_key(),
            second.workspace_resolution_key()
        );
    }

    #[test]
    fn workspace_resolution_key_accepts_explicit_strict_ssl_true() {
        let table = make_table("strict-ssl=true\n", RouteMode::Direct);

        assert!(table.workspace_resolution_key().is_some());
    }

    /// Empty top-level → empty effective set, no matter what's in
    /// `.npmrc`. The whole point of request-aware Δ1: nothing is
    /// "implied" by config alone.
    #[test]
    fn effective_origins_empty_top_level_returns_empty() {
        let table = make_table(
            "registry=https://default.internal/\n\
             @scope:registry=https://scope.internal/\n",
            RouteMode::Direct,
        );
        let got =
            table.effective_registry_origins(&[], "https://lpm.dev", "https://registry.npmjs.org");
        assert!(got.is_empty());
    }

    /// Only `@lpm.dev/*` in top-level → only the LPM Worker origin
    /// is effective. npmjs.org is NOT included even though
    /// `RouteMode::Direct` would route non-LPM specs there.
    #[test]
    fn effective_origins_only_lpm_dev_scopes_to_worker() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["@lpm.dev/owner.pkg".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "lpm.dev");
    }

    /// Only non-`@lpm.dev/*` in top-level under `Direct` mode →
    /// only npmjs.org's origin. LPM Worker is NOT included.
    #[test]
    fn effective_origins_npm_direct_scopes_to_npmjs() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["react".to_string(), "lodash".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "registry.npmjs.org");
    }

    #[test]
    fn effective_origins_jsr_specs_scope_to_jsr_registry() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["@jsr/std__path".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "npm.jsr.io");
    }

    /// Mixed top-level: one `@lpm.dev/*` + one bare → BOTH origins.
    /// Order is insertion order (lpm spec first → lpm.dev first).
    #[test]
    fn effective_origins_mixed_lpm_and_npm_emits_both() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["@lpm.dev/owner.pkg".to_string(), "react".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].host_lower, "lpm.dev");
        assert_eq!(got[1].host_lower, "registry.npmjs.org");
    }

    /// Scope mapping in `.npmrc` → that origin is effective ONLY
    /// when the scope appears in top-level. Other configured scopes
    /// stay LAZY (Δ1 contract: unrelated config doesn't pollute
    /// the eager set).
    #[test]
    fn effective_origins_scope_registry_only_when_scope_in_top_level() {
        let table = make_table(
            "@wanted:registry=https://wanted.internal/\n\
             @ignored:registry=https://ignored.internal/\n",
            RouteMode::Direct,
        );
        // Top-level uses @wanted but NOT @ignored.
        let specs = vec!["@wanted/foo".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        // Only the wanted scope's origin appears.
        let hosts: Vec<&str> = got.iter().map(|o| o.host_lower.as_str()).collect();
        assert!(hosts.contains(&"wanted.internal"));
        assert!(
            !hosts.contains(&"ignored.internal"),
            "ignored scope must not pollute the eager set"
        );
    }

    /// `npmrc.default_registry` → that origin is effective ONLY when
    /// a non-LPM, non-scope-mapped spec falls through to it.
    #[test]
    fn effective_origins_default_registry_only_when_a_spec_falls_through() {
        let table = make_table("registry=https://default.internal/\n", RouteMode::Direct);
        let specs = vec!["lodash".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        // default_registry override means non-LPM specs route to
        // `Custom`, NOT `NpmDirect`. So registry.npmjs.org should
        // NOT appear.
        assert_eq!(got[0].host_lower, "default.internal");
        assert!(got.iter().all(|o| o.host_lower != "registry.npmjs.org"));
    }

    /// Default registry + only `@lpm.dev/*` specs in top-level →
    /// default registry is NOT effective (no spec falls through).
    #[test]
    fn effective_origins_default_registry_not_emitted_when_no_fallthrough_spec() {
        let table = make_table("registry=https://default.internal/\n", RouteMode::Direct);
        let specs = vec!["@lpm.dev/owner.pkg".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "lpm.dev");
        assert!(got.iter().all(|o| o.host_lower != "default.internal"));
    }

    /// `RouteMode::Proxy` → non-LPM specs route to Worker, NOT to
    /// npmjs.org. The effective set reflects that.
    #[test]
    fn effective_origins_proxy_mode_routes_npm_specs_to_worker() {
        let table = make_table("", RouteMode::Proxy);
        let specs = vec!["react".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "lpm.dev");
        // npmjs.org must NOT be included (proxy mode skips it).
        assert!(got.iter().all(|o| o.host_lower != "registry.npmjs.org"));
    }

    /// De-dup contract: same scope twice in top-level → one origin.
    #[test]
    fn effective_origins_dedupes_duplicate_routes() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["react".to_string(), "lodash".to_string(), "vue".to_string()];
        let got = table.effective_registry_origins(
            &specs,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        // All three route to npmjs.org → one entry.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host_lower, "registry.npmjs.org");
    }

    /// The eager set must reflect the actual top-level network request
    /// surface, not just the dep map keys. The CLI is responsible for
    /// filtering
    /// `deps` to network-routing entries (skipping `file:`, `link:`,
    /// `tarball:` URL, `git:`, `workspace:` specs) and for unwrapping
    /// `npm:<target>` aliases to their underlying target name BEFORE
    /// passing to `effective_registry_origins`. This route-side test
    /// pins the end-to-end shape: given the filtered + unwrapped
    /// list, the right origins emerge.
    #[test]
    fn effective_origins_consume_filtered_unwrapped_top_level_set() {
        // Synthesize what a CLI caller would have computed AFTER
        // filtering for network-routing entries and unwrapping npm
        // aliases. Inputs:
        //   - "react"            (SemverRange, npmjs.org route)
        //   - "@wanted/foo"      (SemverRange, custom @wanted scope)
        //   - "react"            (alias unwrap target — same as above; dedupe)
        //   - "vue"              (alias unwrap target — different; same default)
        // Inputs that the CLI WOULD have skipped (and therefore
        // don't appear in the slice we pass): `file:./local`,
        // `link:../sibling`, `https://cdn/foo.tgz`, `workspace:*`.
        let table = make_table(
            "@wanted:registry=https://wanted.internal/\n",
            RouteMode::Direct,
        );
        let filtered: Vec<String> = vec![
            "react".to_string(),
            "@wanted/foo".to_string(),
            "react".to_string(),
            "vue".to_string(),
        ];
        let got = table.effective_registry_origins(
            &filtered,
            "https://lpm.dev",
            "https://registry.npmjs.org",
        );
        // Expected: npmjs.org (react + vue) + wanted.internal.
        // De-duped to 2 distinct origins.
        let hosts: Vec<&str> = got.iter().map(|o| o.host_lower.as_str()).collect();
        assert_eq!(got.len(), 2, "got: {hosts:?}");
        assert!(hosts.contains(&"registry.npmjs.org"));
        assert!(hosts.contains(&"wanted.internal"));
    }

    /// Malformed worker / direct URLs → silently skipped (no
    /// crash, no spurious entry). Real callers always pass valid
    /// http(s) URLs; this is defense in depth.
    #[test]
    fn effective_origins_silently_skips_invalid_urls() {
        let table = make_table("", RouteMode::Direct);
        let specs = vec!["react".to_string()];
        let got = table.effective_registry_origins(&specs, "not a url", "also not a url");
        assert!(got.is_empty());
    }

    #[test]
    fn npmjs_token_without_redundant_registry_line_routes_with_auth() {
        let table = make_table(
            "//registry.npmjs.org/:_authToken=private-token\n",
            RouteMode::Direct,
        );
        match table.route_for_package("private-package") {
            UpstreamRoute::Custom { target, auth } => {
                assert_eq!(target.base_url.as_ref(), "https://registry.npmjs.org");
                assert!(
                    auth.is_some(),
                    "npmjs credential must reach direct metadata"
                );
            }
            other => panic!("expected authenticated npm-compatible route, got {other:?}"),
        }
    }
}
