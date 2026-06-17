use super::types::{
    AuthBuffer, OriginKey, OriginTlsOverrides, RegistryAuth, RegistryTarget, TlsOverrides,
};
use std::collections::HashMap;

/// Parsed `.npmrc` config, mergeable across precedence layers.
///
/// Two-phase lifecycle:
///
/// 1. **Build**: call `parse_layer` on each of the four `.npmrc` files
///    (system → user → project order, lowest precedence first), or use
///    `parse` for single-file convenience. `merge_over` composes the
///    layers — including raw auth subkeys, so `_username` from one file
///    and `_password` from another will combine.
/// 2. **Finalize**: call `finalize` once after all layers are merged.
///    This resolves the per-origin auth buffers into concrete
///    `RegistryAuth` entries and emits warnings for any partial /
///    malformed credentials.
///
/// `parse` does both for the common single-file case so most call sites
/// don't have to think about it. The filesystem walker uses the layered
/// API explicitly.
#[derive(Default, Debug)]
pub struct NpmrcConfig {
    /// Default registry, if any layer set `registry=<url>`.
    pub default_registry: Option<RegistryTarget>,
    /// Scope → registry. Keys include the leading `@` and are
    /// ASCII-lowercased.
    pub scope_registries: HashMap<String, RegistryTarget>,
    /// Origin → auth. Empty until `finalize()` is called. Populated from
    /// `auth_buffers` at finalize time so cross-layer credential merging
    /// works.
    pub origin_auth: HashMap<OriginKey, RegistryAuth>,
    /// Non-fatal parse messages: malformed lines, deferred-feature
    /// (mTLS / per-origin TLS) notices. Caller dumps via `output::warn`.
    pub warnings: Vec<String>,
    /// Security-grade warnings: facts the caller MUST surface even
    /// under `--json` output (where regular warnings are silenced to
    /// keep stdout structured). Carries refusal details for project-local
    /// `.npmrc` TLS downgrades and env-backed auth/routing.
    pub security_warnings: Vec<String>,
    /// Fatal parse errors: missing env-var interpolation, unreadable
    /// `cafile=` paths. Caller surfaces and exits non-zero before any
    /// network. npm errors here too, so we match.
    pub errors: Vec<String>,
    /// TLS overrides — `cafile=` / `ca=` extra roots and `strict-ssl=false`.
    /// Wired by `RegistryClient::with_tls_overrides` at install start.
    pub tls: TlsOverrides,

    /// Raw auth state across all merged layers, indexed by origin. Each
    /// `AuthBuffer` holds tagged subkeys (value + source label + line)
    /// that survive `merge_over`. Consumed and cleared by `finalize`.
    /// Private — callers should reach for `origin_auth` after finalize,
    /// or `auth_for_url` for lookup.
    pub(super) auth_buffers: HashMap<OriginKey, AuthBuffer>,

    /// Whether `finalize()` has been called. Used as a debug-assert
    /// guard in `auth_for_url`; production code that forgets to
    /// finalize will get an empty `origin_auth` map and miss every
    /// lookup, which is a loud-but-correct failure mode (no auth gets
    /// silently sent without explicit finalize).
    pub(super) finalized: bool,
}

impl NpmrcConfig {
    /// Resolve all per-origin auth buffers into concrete `RegistryAuth`
    /// entries. Idempotent — calling twice is a no-op (the buffers are
    /// drained on first call). Emits warnings for any partial / malformed
    /// credentials, citing the source label of whichever subkey contributed
    /// the partial state.
    ///
    /// Also enforces the GLOBAL mTLS identity XOR contract: `certfile=` and
    /// `keyfile=` at the top level must both be set or both absent. A
    /// half-configured global identity gets a fatal `cfg.errors` entry
    /// citing the present line and naming the missing key. The same contract
    /// for per-origin identities is enforced at client-build time, so a
    /// half-config for an unreached origin never aborts the install.
    pub fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        let buffers = std::mem::take(&mut self.auth_buffers);
        for (origin, buf) in buffers {
            if let Some(auth) = buf.resolve(&origin, &mut self.warnings) {
                self.origin_auth.insert(origin, auth);
            }
        }
        // GLOBAL mTLS identity XOR check. Per-origin identities are validated
        // at client-build time, not here — unreached half-configs must not
        // abort unrelated installs.
        match (
            self.tls.identity_certfile.as_ref(),
            self.tls.identity_keyfile.as_ref(),
        ) {
            (Some(cert), None) => {
                self.errors.push(format!(
                    "{}:{}: 'certfile' (mTLS client cert) is set but 'keyfile' is missing across all merged layers; both must be set or both absent",
                    cert.source, cert.line
                ));
            }
            (None, Some(key)) => {
                self.errors.push(format!(
                    "{}:{}: 'keyfile' (mTLS private key) is set but 'certfile' is missing across all merged layers; both must be set or both absent",
                    key.source, key.line
                ));
            }
            // (Some, Some) → complete pair, validated further at
            // identity-load time (concat + Identity::from_pem).
            // (None, None) → no global mTLS, nothing to check.
            _ => {}
        }
        self.finalized = true;
    }

    /// Merge `other` ON TOP OF `self` — `other` wins on every key.
    /// Used by the walker to compose lower-precedence layers (system,
    /// user) under higher-precedence ones (project).
    ///
    /// Auth subkeys merge per-subkey: if `self` has `_username` for an
    /// origin and `other` has `_password` for the same origin, the
    /// finalized result is a Basic credential composed from both.
    ///
    /// `merge_over` panics if either side has been finalized — finalize
    /// is the irreversible last step. Tests assert this contract.
    pub fn merge_over(&mut self, other: NpmrcConfig) {
        assert!(
            !self.finalized && !other.finalized,
            "merge_over called after finalize; auth buffers have already been drained"
        );
        if other.default_registry.is_some() {
            self.default_registry = other.default_registry;
        }
        self.scope_registries.extend(other.scope_registries);
        for (origin, other_buf) in other.auth_buffers {
            self.auth_buffers
                .entry(origin)
                .or_default()
                .merge_over(other_buf);
        }
        // TLS overrides merge:
        // - `extra_roots`: concatenate, then deduplicate by `pem_bytes`
        //   keeping the FIRST source seen. Lower-precedence roots
        //   stay first in trust-chain order (reqwest treats all roots
        //   equivalently, but the chronological attribution helps
        //   error-citation stay stable across runs). Dedup matters
        //   for the common shop pattern where both `~/.npmrc` and a
        //   project `.npmrc` set `cafile=/etc/ssl/corp-ca.pem` — without
        //   it, validate_pem_root + from_pem run twice on identical bytes.
        // - `strict_ssl`: higher-explicit wins; higher-silent doesn't
        //   clear lower. Same shape as `default_registry` above. A user's
        //   `~/.npmrc strict-ssl=false` persists across projects unless a
        //   project explicitly says `=true`.
        self.tls.extra_roots.extend(other.tls.extra_roots);
        // Linear-scan dedup. The trust-store size is small (1-3 entries
        // in practice; spec allows arbitrary bundles but real-world
        // configs concentrate on one corporate root). O(n²) is fine.
        let mut seen: Vec<Vec<u8>> = Vec::with_capacity(self.tls.extra_roots.len());
        self.tls.extra_roots.retain(|r| {
            if seen.iter().any(|prev| prev == &r.pem_bytes) {
                false
            } else {
                seen.push(r.pem_bytes.clone());
                true
            }
        });
        if other.tls.strict_ssl.is_some() {
            self.tls.strict_ssl = other.tls.strict_ssl;
        }
        // Global mTLS identity: higher-explicit wins. The XOR-validation
        // contract (both certfile + keyfile, or neither) is enforced at
        // finalize time across all merged layers, so a user can legitimately
        // set `certfile=` in `~/.npmrc` and `keyfile=` in a project `.npmrc`
        // and have them compose.
        if other.tls.identity_certfile.is_some() {
            self.tls.identity_certfile = other.tls.identity_certfile;
        }
        if other.tls.identity_keyfile.is_some() {
            self.tls.identity_keyfile = other.tls.identity_keyfile;
        }
        // Per-origin TLS: each origin's settings merge independently via
        // `OriginTlsOverrides::merge_over`:
        // - `cafiles` accumulate (multiple roots stack);
        // - `certfile` / `keyfile` higher-explicit wins.
        // The per-origin XOR-validation contract is NOT enforced here —
        // it's deferred to client-build time so a half-config for an origin
        // this invocation never reaches doesn't abort unrelated installs.
        for (origin, other_per_origin) in other.tls.per_origin {
            self.tls
                .per_origin
                .entry(origin)
                .or_default()
                .merge_over(other_per_origin);
        }
        self.warnings.extend(other.warnings);
        self.security_warnings.extend(other.security_warnings);
        self.errors.extend(other.errors);
    }

    /// Look up the registry target for a package, scope-aware.
    ///
    /// Resolution order:
    /// 1. `@scope/foo` and `scope_registries[@scope]` exists → that target.
    /// 2. `default_registry` is `Some` → that target.
    /// 3. `None` — caller falls back to `RouteMode` defaults.
    ///
    /// Both the stored scope keys (set in `classify_and_apply`) and the
    /// query scope are lowercased before comparison. Real-world npmrc
    /// files in the wild sometimes have `@MyCompany:registry=...`, and
    /// real install commands use `lpm install @MyCompany/foo` — both
    /// should resolve. npm-the-CLI normalizes the same way.
    pub fn target_for_package(&self, package_name: &str) -> Option<&RegistryTarget> {
        if let Some(scope_end) = package_name.find('/')
            && let Some(scope) = package_name.get(..scope_end)
            && scope.starts_with('@')
            && let Some(t) = self.scope_registries.get(&scope.to_ascii_lowercase())
        {
            return Some(t);
        }
        self.default_registry.as_ref()
    }

    /// Look up auth for a request URL we're about to send. Origin-matched
    /// per npm semantics: try the exact `(host, Some(port))` first; on
    /// miss, fall back to `(host, None)` so an npmrc entry without an
    /// explicit port covers any port for that host (scheme-agnostic for
    /// http vs https).
    ///
    /// Returns `None` if `finalize()` hasn't been called — auth_for_url
    /// reads from `origin_auth`, which is empty pre-finalize. The
    /// `debug_assert!` is a development-time signal; release builds
    /// silently miss the lookup, which is the safer failure mode (no
    /// credential leak, just a 401 that the user can debug).
    pub fn auth_for_url(&self, url: &str) -> Option<&RegistryAuth> {
        debug_assert!(
            self.finalized,
            "auth_for_url called before finalize() — credentials will silently miss"
        );
        let exact = OriginKey::from_request_url(url)?;
        if let Some(auth) = self.origin_auth.get(&exact) {
            return Some(auth);
        }
        let any_port = OriginKey {
            host_lower: exact.host_lower,
            port: None,
        };
        self.origin_auth.get(&any_port)
    }

    /// Look up per-origin TLS settings for a request URL. Mirrors
    /// [`Self::auth_for_url`]'s match rule: try `(host, Some(port))`
    /// first, fall back to `(host, None)` so an `.npmrc` entry
    /// without an explicit port covers any port for that host.
    pub fn tls_for_url(&self, url: &str) -> Option<&OriginTlsOverrides> {
        let exact = OriginKey::from_request_url(url)?;
        self.tls_for_origin(&exact)
    }

    /// Look up per-origin TLS settings by `OriginKey`. Used by the
    /// per-origin client builder which already has the resolved origin
    /// and doesn't need a URL parse round-trip.
    pub fn tls_for_origin(&self, origin: &OriginKey) -> Option<&OriginTlsOverrides> {
        if let Some(t) = self.tls.per_origin.get(origin) {
            return Some(t);
        }
        let any_port = OriginKey {
            host_lower: origin.host_lower.clone(),
            port: None,
        };
        self.tls.per_origin.get(&any_port)
    }
}
