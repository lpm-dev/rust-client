//! Parse and route via `.npmrc`-style configuration files.
//!
//! Phase 58 — see
//! `DOCS/new-features/37-rust-client-RUNNER-VISION-phase58-npmrc-walker-preplan.md`
//! in the a-package-manager repo for the full design.
//!
//! This module is **parser-only** in day-1. The filesystem walker (day-2),
//! `RouteTable` integration (day-3), and `RegistryClient::get_npm_metadata_from`
//! (day-4) land in subsequent commits on this branch.
//!
//! ## What we parse
//!
//! - `registry=<url>` — default registry override.
//! - `@scope:registry=<url>` — per-scope registry. Scope is normalized to
//!   ASCII lowercase (npm publish names are lowercase, but real-world
//!   `.npmrc` files in the wild sometimes have mixed case).
//! - `//host[:port]/:_authToken=<token>` — bearer auth, origin-scoped.
//! - `//host[:port]/:_auth=<base64>` — basic auth (already-encoded).
//! - `//host[:port]/:_username=<user>` + `:_password=<base64>` — basic auth
//!   that we join + re-encode at materialization time.
//! - `${VAR}` env-var interpolation. Missing var → fatal (`errors` field
//!   populated; caller surfaces and exits before any network).
//! - Comments (`;` and `#`), blank lines, CRLF, BOM, trailing whitespace.
//!
//! ## What we deliberately don't parse (v1)
//!
//! - `cafile=<path>` / `ca=<pem>` / `strict-ssl=false` — recorded as
//!   deferred-feature warnings. v1.1 wires through `reqwest::ClientBuilder`.
//! - Path-prefix-scoped auth (`//host/some/path/:_authToken=...`). v1 matches
//!   by origin (host + port) only, which covers ~99% of `.npmrc` files seen
//!   in the wild. v1.1 adds prefix matching.
//! - Yarn / pnpm extensions.
//!
//! ## Origin matching nuance
//!
//! npm's "nerf-dart" auth keys are scheme-agnostic — `//host/:_authToken=X`
//! applies to both `http://host/` and `https://host/`. We follow that.
//! `OriginKey` stores `(host_lower, port)` where `port` is `Option<u16>`:
//!
//! - `None` — npmrc key omitted the port (`//host/`). Matches a request
//!   to that host on **any** port. This is what 99% of real-world `.npmrc`
//!   files write, and is required for the http/https equivalence above.
//! - `Some(p)` — npmrc key wrote an explicit port (`//host:8443/`).
//!   Matches a request only on that exact port. Lets users be specific
//!   when they have multiple registries on the same host.
//!
//! Lookup tries `(host, Some(req_port))` first; on miss, falls back to
//! `(host, None)`. So an explicit-port entry never leaks to a different
//! port, but an unspecified-port entry covers both http and https.
//! `--insecure` governs the http-to-non-localhost decision separately
//! at request-build time.

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Arc;

/// What kind of registry a target represents. Drives dispatch — the LPM
/// Worker has a batch endpoint that npm-compatible registries don't.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryKind {
    /// Plain npm-compatible registry (custom from `.npmrc`, or
    /// `registry.npmjs.org` itself).
    NpmCompatible,
    /// The LPM Worker — supports `batch-metadata-deep`. Used only when
    /// `RouteMode::Proxy` is in effect for non-`@lpm.dev/*` packages.
    LpmWorker,
}

/// A registry target — base URL plus dispatch-kind marker.
///
/// The `base_url` is canonicalized (no trailing slash) so URL composition
/// is just `format!("{base}/{name}")` everywhere. `Arc<str>` so cloning a
/// `RegistryTarget` into per-request dispatch is cheap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryTarget {
    pub base_url: Arc<str>,
    pub kind: RegistryKind,
}

impl RegistryTarget {
    /// Build a target from a raw `.npmrc` URL value. Strips one trailing
    /// slash if present so downstream `format!("{base}/{name}")` produces
    /// `https://npm.example.com/react`, not `…//react`.
    fn from_npmrc_url(raw: &str) -> Self {
        let trimmed = raw.trim_end_matches('/');
        Self {
            base_url: Arc::from(trimmed),
            kind: RegistryKind::NpmCompatible,
        }
    }
}

/// Origin key for auth lookup: case-insensitive host + optional port.
///
/// `port` is `Option<u16>`:
/// - `None` — port was unspecified in the npmrc key (`//host/`). The
///   stored entry matches a request to this host on **any** port,
///   making auth scheme-agnostic for http vs https.
/// - `Some(p)` — port was explicit (`//host:p/`). The stored entry
///   matches only that exact port.
///
/// `OriginKey::from_request_url` always returns `Some(port)` (concrete),
/// so the lookup falls back to `(host, None)` when an exact-port match
/// misses. See `NpmrcConfig::auth_for_url`.
///
/// Scheme is intentionally absent — npm's nerf-dart auth keys
/// (`//host[:port]/`) are scheme-agnostic. The `--insecure` flag
/// governs the http/https decision separately at request-build time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginKey {
    pub host_lower: String,
    pub port: Option<u16>,
}

impl std::fmt::Display for OriginKey {
    /// Renders for use in user-facing warnings. Mirrors the npmrc
    /// nerf-dart format the user wrote: `//host/` if port is None,
    /// `//host:p/` if explicit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(p) => write!(f, "//{}:{}/", self.host_lower, p),
            None => write!(f, "//{}/", self.host_lower),
        }
    }
}

impl OriginKey {
    /// Parse from a `//host[:port]/...` `.npmrc` auth-key fragment.
    ///
    /// Caller has already verified the leading `//`. We strip it,
    /// lop everything from the first `/` onward (path is ignored in
    /// v1 per pre-plan §2), then split host:port. An omitted port
    /// yields `port: None` (matches any port for that host).
    fn from_npmrc_origin(after_double_slash: &str) -> Option<Self> {
        // Drop the path component, if any.
        let host_port = match after_double_slash.find('/') {
            Some(idx) => &after_double_slash[..idx],
            None => after_double_slash,
        };
        if host_port.is_empty() {
            return None;
        }
        Self::from_host_port_str(host_port, None)
    }

    /// Parse a `host` or `host:port` literal. `default_port` is used iff
    /// the literal omits a port AND the caller has a concrete fallback
    /// in mind (request URL parsing). For npmrc parsing the caller
    /// passes `None` so omitted port stays `None`.
    fn from_host_port_str(host_port: &str, default_port: Option<u16>) -> Option<Self> {
        // IPv6 literals: `[::1]:8080` or `[::1]`. We see them in real
        // testing fixtures occasionally; handle gracefully.
        if let Some(rest) = host_port.strip_prefix('[') {
            let close = rest.find(']')?;
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let port = if let Some(p) = after.strip_prefix(':') {
                Some(p.parse::<u16>().ok()?)
            } else if after.is_empty() {
                default_port
            } else {
                return None;
            };
            return Some(Self {
                host_lower: host.to_ascii_lowercase(),
                port,
            });
        }
        match host_port.rsplit_once(':') {
            Some((host, port_str)) if !host.is_empty() => Some(Self {
                host_lower: host.to_ascii_lowercase(),
                port: Some(port_str.parse().ok()?),
            }),
            _ => Some(Self {
                host_lower: host_port.to_ascii_lowercase(),
                port: default_port,
            }),
        }
    }

    /// Build from a fully-formed request URL the way the dispatcher will
    /// see it. Always returns `port: Some(_)` — the scheme implies a
    /// concrete default (80 for http, 443 for https) when no port is in
    /// the URL itself. Lookup callers fall back to `(host, None)` when
    /// the exact-port match misses; see `NpmrcConfig::auth_for_url`.
    pub fn from_request_url(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme_lower = scheme.to_ascii_lowercase();
        let default_port = match scheme_lower.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        // Cut path/query/fragment.
        let host_port = rest
            .split(['/', '?', '#'])
            .next()
            .filter(|s| !s.is_empty())?;
        let parsed = Self::from_host_port_str(host_port, Some(default_port))?;
        // Request URLs always resolve to a concrete port — even if the
        // URL omits one, the scheme supplies the default. Belt-and-braces
        // assertion that the helper kept that invariant.
        parsed.port?;
        Some(parsed)
    }
}

/// Auth credential to attach to a request.
///
/// Wrapped in `SecretString` so accidental `Debug`/`Display` prints
/// `[REDACTED]` instead of the raw token. Hand-written `Debug` below
/// reinforces this — never rely on derive for secret-bearing types.
#[derive(Clone)]
pub enum RegistryAuth {
    /// Sent as `Authorization: Bearer <token>`. From `_authToken=...`.
    Bearer(SecretString),
    /// Sent as `Authorization: Basic <b64>`. The inner string is the
    /// already-base64-encoded `user:pass`. From `_auth=...` directly,
    /// or computed by joining `_username` + base64-decoded `_password`.
    Basic(SecretString),
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => write!(f, "RegistryAuth::Bearer([REDACTED])"),
            Self::Basic(_) => write!(f, "RegistryAuth::Basic([REDACTED])"),
        }
    }
}

impl PartialEq for RegistryAuth {
    /// Equality by variant + secret material. Used by tests; production
    /// code should never compare auth credentials. Constant-time-ish
    /// because both sides go through identical exposure paths, but we
    /// don't promise constant-time and the `secrecy` crate doesn't
    /// either — this is for test ergonomics, not security.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bearer(a), Self::Bearer(b)) => a.expose_secret() == b.expose_secret(),
            (Self::Basic(a), Self::Basic(b)) => a.expose_secret() == b.expose_secret(),
            _ => false,
        }
    }
}

impl Eq for RegistryAuth {}

/// A value that remembers where it came from. Threaded through layered
/// merges so finalize warnings can cite the contributing source file
/// (and line, when relevant) — not just the host/port the credential
/// was for.
#[derive(Clone, Debug)]
struct TaggedValue {
    value: String,
    source: String,
    line: usize,
}

impl TaggedValue {
    fn new(value: String, source: &str, line: usize) -> Self {
        Self {
            value,
            source: source.to_string(),
            line,
        }
    }
}

/// Per-origin auth buffer. Holds raw tagged subkeys until
/// `NpmrcConfig::finalize` resolves them into a concrete
/// `RegistryAuth`. Buffers persist across `merge_over` so subkeys set
/// by different layers (e.g., system-wide `_username` + per-user
/// `_password`) compose correctly — Gemini's Finding 1.
#[derive(Default, Clone, Debug)]
struct AuthBuffer {
    auth_token: Option<TaggedValue>,
    auth_b64: Option<TaggedValue>,
    username: Option<TaggedValue>,
    password_b64: Option<TaggedValue>,
}

impl AuthBuffer {
    /// Resolve to a final `RegistryAuth`, or `None` if nothing usable.
    /// Precedence matches npm: `_authToken` > `_auth` > `_username`+`_password`.
    /// Warnings about partial/malformed credentials cite the source
    /// label of whichever subkey contributed the partial state.
    fn resolve(self, origin: &OriginKey, warnings: &mut Vec<String>) -> Option<RegistryAuth> {
        if let Some(t) = self.auth_token {
            return Some(RegistryAuth::Bearer(SecretString::from(t.value)));
        }
        if let Some(b) = self.auth_b64 {
            return Some(RegistryAuth::Basic(SecretString::from(b.value)));
        }
        match (self.username, self.password_b64) {
            (Some(user), Some(pw_tagged)) => {
                let pw = match base64::engine::general_purpose::STANDARD.decode(&pw_tagged.value) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            warnings.push(format!(
                                "{}:{}: {} _password is not valid UTF-8 after base64 decode; ignoring credential",
                                pw_tagged.source, pw_tagged.line, origin
                            ));
                            return None;
                        }
                    },
                    Err(_) => {
                        warnings.push(format!(
                            "{}:{}: {} _password is not valid base64; ignoring credential",
                            pw_tagged.source, pw_tagged.line, origin
                        ));
                        return None;
                    }
                };
                let combined = format!("{}:{}", user.value, pw);
                let encoded = base64::engine::general_purpose::STANDARD.encode(combined.as_bytes());
                Some(RegistryAuth::Basic(SecretString::from(encoded)))
            }
            (Some(user), None) => {
                warnings.push(format!(
                    "{}:{}: {} has _username but no _password (across all merged layers); ignoring partial credential",
                    user.source, user.line, origin
                ));
                None
            }
            (None, Some(pw_tagged)) => {
                warnings.push(format!(
                    "{}:{}: {} has _password but no _username (across all merged layers); ignoring partial credential",
                    pw_tagged.source, pw_tagged.line, origin
                ));
                None
            }
            (None, None) => None,
        }
    }

    /// Merge `other` ON TOP OF `self` per subkey. `other`'s `Some` slots
    /// overwrite `self`'s; `other`'s `None` slots leave `self` unchanged.
    /// This is what makes cross-layer credential composition work
    /// (e.g., `_username` from system-wide, `_password` from project).
    fn merge_over(&mut self, other: AuthBuffer) {
        if other.auth_token.is_some() {
            self.auth_token = other.auth_token;
        }
        if other.auth_b64.is_some() {
            self.auth_b64 = other.auth_b64;
        }
        if other.username.is_some() {
            self.username = other.username;
        }
        if other.password_b64.is_some() {
            self.password_b64 = other.password_b64;
        }
    }
}

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
/// don't have to think about it. The walker (Phase 58 day 2) uses the
/// layered API explicitly.
#[derive(Default, Debug)]
pub struct NpmrcConfig {
    /// Default registry, if any layer set `registry=<url>`.
    pub default_registry: Option<RegistryTarget>,
    /// Scope → registry. Keys include the leading `@` and are
    /// ASCII-lowercased.
    pub scope_registries: HashMap<String, RegistryTarget>,
    /// Origin → auth. Empty until `finalize()` is called. Populated from
    /// `auth_buffers` at finalize time so cross-layer credential merging
    /// works (Gemini Finding 1).
    pub origin_auth: HashMap<OriginKey, RegistryAuth>,
    /// Non-fatal parse messages: malformed lines, deferred-feature
    /// (cafile/strict-ssl) notices. Caller dumps via `output::warn`.
    pub warnings: Vec<String>,
    /// Fatal parse errors: missing env-var interpolation. Caller
    /// surfaces and exits non-zero before any network. npm errors here
    /// too, so we match.
    pub errors: Vec<String>,

    /// Raw auth state across all merged layers, indexed by origin. Each
    /// `AuthBuffer` holds tagged subkeys (value + source label + line)
    /// that survive `merge_over`. Consumed and cleared by `finalize`.
    /// Private — callers should reach for `origin_auth` after finalize,
    /// or `auth_for_url` for lookup.
    auth_buffers: HashMap<OriginKey, AuthBuffer>,

    /// Whether `finalize()` has been called. Used as a debug-assert
    /// guard in `auth_for_url`; production code that forgets to
    /// finalize will get an empty `origin_auth` map and miss every
    /// lookup, which is a loud-but-correct failure mode (no auth gets
    /// silently sent without explicit finalize).
    finalized: bool,
}

impl NpmrcConfig {
    /// Parse a single `.npmrc` file's textual content as one layer.
    /// Auth buffers are populated but **not** resolved — call
    /// `finalize()` after merging all layers, or use `parse()` for the
    /// single-file convenience that does both.
    ///
    /// `source_label` is folded into warning/error messages so the user
    /// can tell which file (project / user / system) caused a complaint.
    /// `env_lookup` is injected so tests can pass a fake env without
    /// mutating process state.
    pub fn parse_layer(
        content: &str,
        source_label: &str,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut cfg = NpmrcConfig::default();

        // Strip leading UTF-8 BOM if present. Some Windows editors save
        // .npmrc with one and npm tolerates it.
        let content = content.strip_prefix('\u{feff}').unwrap_or(content);

        for (lineno, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let Some(eq_idx) = line.find('=') else {
                cfg.warnings.push(format!(
                    "{}:{}: line has no '=' separator; skipped",
                    source_label,
                    lineno + 1
                ));
                continue;
            };
            let key = line[..eq_idx].trim();
            let raw_value = line[eq_idx + 1..].trim();
            let value = strip_surrounding_quotes(raw_value);

            // Env-var interpolation. Missing var is fatal per npm.
            let interpolated = match interpolate_env(value, env_lookup) {
                Ok(s) => s,
                Err(missing) => {
                    cfg.errors.push(format!(
                        "{}:{}: environment variable '${{{}}}' is not set; refusing to use this config",
                        source_label,
                        lineno + 1,
                        missing
                    ));
                    continue;
                }
            };

            classify_and_apply(key, &interpolated, source_label, lineno + 1, &mut cfg);
        }

        cfg
    }

    /// Single-file convenience: `parse_layer` then `finalize`. Used by
    /// tests and by callers (like the existing `lpm npmrc` helper) that
    /// don't need to compose layers.
    pub fn parse(
        content: &str,
        source_label: &str,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut cfg = Self::parse_layer(content, source_label, env_lookup);
        cfg.finalize();
        cfg
    }

    /// Resolve all per-origin auth buffers into concrete `RegistryAuth`
    /// entries. Idempotent — calling twice is a no-op (the buffers are
    /// drained on first call). Emits warnings for any partial /
    /// malformed credentials, citing the source label of whichever
    /// subkey contributed the partial state (Gemini Finding 3).
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
        self.finalized = true;
    }

    /// Merge `other` ON TOP OF `self` — `other` wins on every key.
    /// Used by the walker to compose lower-precedence layers (system,
    /// user) under higher-precedence ones (project).
    ///
    /// Auth subkeys merge per-subkey: if `self` has `_username` for an
    /// origin and `other` has `_password` for the same origin, the
    /// finalized result is a Basic credential composed from both.
    /// (Gemini Finding 1.)
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
        self.warnings.extend(other.warnings);
        self.errors.extend(other.errors);
    }

    /// Look up the registry target for a package, scope-aware.
    ///
    /// Resolution order:
    /// 1. `@scope/foo` and `scope_registries[@scope]` exists → that target.
    /// 2. `default_registry` is `Some` → that target.
    /// 3. `None` — caller falls back to `RouteMode` defaults (Phase 49 behavior).
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
    /// http vs https — Gemini Finding 2).
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
}

/// Strip surrounding single or double quotes from a value, if any.
/// `"foo"` → `foo`, `'foo'` → `foo`. Mismatched quotes left alone.
fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        let last = bytes[s.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Expand `${VAR}` references in `value`. On the first missing var, return
/// `Err(var_name)` so the caller can surface a fatal parse error matching
/// npm's behavior.
///
/// We only expand `${NAME}` — bare `$NAME` is left as-is, matching npm.
fn interpolate_env(
    value: &str,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    if !value.contains("${") {
        return Ok(value.to_string());
    }
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'{'
            && let Some(rel) = value[i + 2..].find('}')
        {
            let var_name = &value[i + 2..i + 2 + rel];
            match env_lookup(var_name) {
                Some(v) => out.push_str(&v),
                None => return Err(var_name.to_string()),
            }
            i += 2 + rel + 1;
            continue;
        }
        // Advance one Unicode scalar — `value` is &str so `i` is on a
        // valid char boundary on entry to each iteration.
        let ch = value[i..].chars().next().expect("non-empty by loop guard");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Classify a key/value pair and apply it to the config-being-built.
/// All control flow lives here so the parser loop stays readable. Auth
/// subkeys are written into `cfg.auth_buffers` as `TaggedValue`s; they
/// don't get resolved into `RegistryAuth` until `NpmrcConfig::finalize`.
fn classify_and_apply(
    key: &str,
    value: &str,
    source_label: &str,
    lineno: usize,
    cfg: &mut NpmrcConfig,
) {
    // Scope registry: `@foo:registry`.
    if key.starts_with('@')
        && let Some(scope) = key.strip_suffix(":registry")
    {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty registry URL for scope '{scope}'; skipped"
            ));
            return;
        }
        cfg.scope_registries.insert(
            scope.to_ascii_lowercase(),
            RegistryTarget::from_npmrc_url(value),
        );
        return;
    }

    // Default registry.
    if key == "registry" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty registry URL; skipped"
            ));
            return;
        }
        cfg.default_registry = Some(RegistryTarget::from_npmrc_url(value));
        return;
    }

    // Origin-scoped auth: `//host[:port][/path]/:_<attr>`.
    if let Some(rest) = key.strip_prefix("//") {
        // The auth attribute is the substring after the LAST occurrence
        // of `/:` in the key. Everything before that slash is the
        // (path-aware) URL prefix; we use its origin only in v1.
        if let Some(split_idx) = rest.rfind("/:") {
            let origin_part = &rest[..split_idx]; // host[:port][/path] without trailing slash
            let attr = &rest[split_idx + 2..]; // attribute name after `:`
            let Some(origin) = OriginKey::from_npmrc_origin(origin_part) else {
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: cannot parse origin from auth key '{key}'; skipped"
                ));
                return;
            };
            // V1 limitation: warn if the user wrote a path-prefixed key.
            // We're matching by origin only — which means the token
            // applies to ALL paths on that origin, which is more
            // permissive than what the user wrote. Loud warning so this
            // can't surprise anyone.
            if origin_part.contains('/') {
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: path-scoped auth ('{key}') is parsed as origin-only in v1; \
                     token will apply to ALL paths on {origin} — see Phase 58 docs"
                ));
            }
            let tagged = TaggedValue::new(value.to_string(), source_label, lineno);
            let buf = cfg.auth_buffers.entry(origin).or_default();
            match attr {
                "_authToken" => buf.auth_token = Some(tagged),
                "_auth" => buf.auth_b64 = Some(tagged),
                "_username" => buf.username = Some(tagged),
                "_password" => buf.password_b64 = Some(tagged),
                "always-auth" | "email" | "certfile" | "keyfile" => {
                    // Recognized but not v1.
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: '{attr}' on origin keys is not yet wired up in lpm (parse-only)"
                    ));
                }
                "cafile" => {
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: per-origin 'cafile' is not yet supported in lpm; \
                         see Phase 58.1 — request will use system CA bundle"
                    ));
                }
                _ => {
                    // Unknown attribute on a `//host` key. Silent ignore
                    // matches npm: unknown keys aren't an error.
                }
            }
            return;
        }
        // Malformed: starts with `//` but no `/:` separator.
        cfg.warnings.push(format!(
            "{source_label}:{lineno}: auth key '{key}' has no '/:<attr>' suffix; skipped"
        ));
        return;
    }

    // Globally-scoped TLS settings — recognized, deferred to v1.1.
    if key == "cafile" || key == "ca" {
        cfg.warnings.push(format!(
            "{source_label}:{lineno}: '{key}' is not yet supported in lpm; \
             see Phase 58.1 — system CA bundle will be used"
        ));
        return;
    }
    if key == "strict-ssl" && value.eq_ignore_ascii_case("false") {
        cfg.warnings.push(format!(
            "{source_label}:{lineno}: 'strict-ssl=false' is not yet honored in lpm; \
             TLS verification stays on — see Phase 58.1"
        ));
    }

    // Anything else — silent ignore. Matches npm: unknown keys aren't
    // an error. Things like `engine-strict`, `save-prefix`, `lockfile`
    // are lpm's own concerns and the npmrc value (if any) is just
    // noise from this module's perspective.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_name: &str) -> Option<String> {
        None
    }

    fn fixed_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn empty_file_yields_default_config() {
        let cfg = NpmrcConfig::parse("", "test", &no_env);
        assert!(cfg.default_registry.is_none());
        assert!(cfg.scope_registries.is_empty());
        assert!(cfg.origin_auth.is_empty());
        assert!(cfg.warnings.is_empty());
        assert!(cfg.errors.is_empty());
    }

    #[test]
    fn comments_only_yields_default_config() {
        let content = "; comment one\n# comment two\n\n   ; indented comment\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_none());
        assert!(cfg.warnings.is_empty());
        assert!(cfg.errors.is_empty());
    }

    #[test]
    fn default_registry_is_captured_and_trimmed() {
        let cfg = NpmrcConfig::parse("registry=https://npm.example.com/", "test", &no_env);
        let target = cfg.default_registry.expect("registry should be set");
        assert_eq!(target.base_url.as_ref(), "https://npm.example.com");
        assert_eq!(target.kind, RegistryKind::NpmCompatible);
    }

    #[test]
    fn scope_registry_lowercases_and_routes() {
        // User contract: an `.npmrc` with `@MyCompany:registry=...` and
        // an install of either `@mycompany/foo` or `@MyCompany/foo` must
        // both resolve to that registry. Storage and lookup both
        // lowercase, mirroring npm-the-CLI.
        let content = "@MyCompany:registry=https://npm.internal/\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.scope_registries.len(), 1);
        // Lowercase package name resolves.
        let lower = cfg
            .target_for_package("@mycompany/foo")
            .expect("lowercase scope target should resolve");
        assert_eq!(lower.base_url.as_ref(), "https://npm.internal");
        // Mixed-case package name resolves to the SAME target.
        let mixed = cfg
            .target_for_package("@MyCompany/foo")
            .expect("mixed-case scope target should resolve");
        assert_eq!(mixed.base_url.as_ref(), "https://npm.internal");
        // Unrelated scope falls through to `default_registry` (None here).
        assert!(cfg.target_for_package("@other/foo").is_none());
    }

    #[test]
    fn bearer_token_parses_for_origin() {
        let content = "//npm.internal/:_authToken=ABC123\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://npm.internal/some/pkg")
            .expect("auth should match");
        match auth {
            RegistryAuth::Bearer(s) => assert_eq!(s.expose_secret(), "ABC123"),
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn env_var_interpolation_present() {
        let content = "//npm.internal/:_authToken=${NPM_TOKEN}\n";
        let env = fixed_env(&[("NPM_TOKEN", "secret-value")]);
        let cfg = NpmrcConfig::parse(content, "test", &env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        let auth = cfg
            .auth_for_url("https://npm.internal/")
            .expect("auth should match");
        match auth {
            RegistryAuth::Bearer(s) => assert_eq!(s.expose_secret(), "secret-value"),
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn env_var_interpolation_missing_is_fatal() {
        let content = "//npm.internal/:_authToken=${NPM_TOKEN}\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.errors.len(), 1);
        assert!(
            cfg.errors[0].contains("NPM_TOKEN"),
            "error mentions var name: {:?}",
            cfg.errors[0]
        );
        // No partial credential should be stored.
        assert!(cfg.origin_auth.is_empty());
    }

    #[test]
    fn basic_auth_via_combined_field() {
        // base64("user:pass") = "dXNlcjpwYXNz"
        let content = "//npm.internal/:_auth=dXNlcjpwYXNz\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Basic(s) => assert_eq!(s.expose_secret(), "dXNlcjpwYXNz"),
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn basic_auth_via_split_username_password() {
        // username=user, password is base64("pass")="cGFzcw=="
        // Joined+re-encoded: base64("user:pass")="dXNlcjpwYXNz"
        let content = concat!(
            "//npm.internal/:_username=user\n",
            "//npm.internal/:_password=cGFzcw==\n"
        );
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Basic(s) => assert_eq!(s.expose_secret(), "dXNlcjpwYXNz"),
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn token_with_special_chars() {
        // Ensure we don't choke on `:`, `/`, `=` inside the token value.
        // The split is on the FIRST `=`; everything after is the value.
        let content = "//npm.internal/:_authToken=ab:cd/ef=gh+ij\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Bearer(s) => assert_eq!(s.expose_secret(), "ab:cd/ef=gh+ij"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let content = "registry=https://npm.example.com/\r\n@s:registry=https://b/\r\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.scope_registries.len(), 1);
    }

    #[test]
    fn utf8_bom_is_stripped() {
        let content = "\u{feff}registry=https://npm.example.com/\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    #[test]
    fn malformed_line_warns_and_continues() {
        // No `=` separator: should warn, not abort.
        let content = "registry=https://good.example.com/\nthis-line-is-bad\nstill-parsing=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("test:2"));
    }

    #[test]
    fn unknown_keys_are_silently_ignored() {
        // `engine-strict`, `save-prefix` etc. are lpm's own concerns.
        let content = concat!(
            "engine-strict=true\n",
            "save-prefix=^\n",
            "lockfile=true\n",
            "registry=https://good.example.com/\n",
        );
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
    }

    #[test]
    fn cafile_records_deferred_warning() {
        let content = "cafile=/etc/ssl/cert.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("Phase 58.1"));
    }

    // ---- Beyond the 15 contract tests: defense-in-depth checks ----

    #[test]
    fn merge_over_lets_higher_layer_win() {
        // Layered API: parse_layer per file, merge, then finalize.
        let lower = NpmrcConfig::parse_layer("registry=https://lower/\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("registry=https://higher/\n", "higher", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://higher"
        );
    }

    #[test]
    fn merge_preserves_non_overlapping_keys() {
        let lower = NpmrcConfig::parse_layer(
            "registry=https://lower/\n@a:registry=https://a/\n",
            "lower",
            &no_env,
        );
        let higher = NpmrcConfig::parse_layer("@b:registry=https://b/\n", "higher", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://lower"
        );
        assert_eq!(acc.scope_registries.len(), 2);
    }

    // ---- Gemini Finding 1: cross-layer credential merge ----

    #[test]
    fn cross_layer_username_password_merge() {
        // System-level file declares the username; user-level adds the
        // password. Finalize must combine them into Basic auth, not
        // emit two partial-credential warnings. Pre-fix this test
        // failed both ways: zero auth entries + two "partial" warnings.
        let system =
            NpmrcConfig::parse_layer("//npm.internal/:_username=alice\n", "/etc/npmrc", &no_env);
        let user = NpmrcConfig::parse_layer(
            "//npm.internal/:_password=cGFzcw==\n", // base64("pass")
            "~/.npmrc",
            &no_env,
        );
        let mut acc = system;
        acc.merge_over(user);
        acc.finalize();
        assert!(
            acc.warnings.is_empty(),
            "no partial-credential warnings expected: {:?}",
            acc.warnings
        );
        let auth = acc
            .auth_for_url("https://npm.internal/foo")
            .expect("composed Basic credential should resolve");
        // base64("alice:pass") == "YWxpY2U6cGFzcw=="
        match auth {
            RegistryAuth::Basic(s) => assert_eq!(s.expose_secret(), "YWxpY2U6cGFzcw=="),
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn higher_layer_password_overrides_lower_layer_password() {
        // Per-subkey last-wins: lower layer's _password is replaced by
        // higher layer's, but lower layer's _username survives because
        // higher doesn't set one.
        let lower = NpmrcConfig::parse_layer(
            "//npm.internal/:_username=alice\n//npm.internal/:_password=b2xkLXB3\n", // "old-pw"
            "/etc/npmrc",
            &no_env,
        );
        let higher = NpmrcConfig::parse_layer(
            "//npm.internal/:_password=bmV3LXB3\n", // "new-pw"
            "~/.npmrc",
            &no_env,
        );
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        let auth = acc.auth_for_url("https://npm.internal/").unwrap();
        // base64("alice:new-pw") == "YWxpY2U6bmV3LXB3"
        match auth {
            RegistryAuth::Basic(s) => assert_eq!(s.expose_secret(), "YWxpY2U6bmV3LXB3"),
            _ => panic!("expected Basic"),
        }
    }

    // ---- Gemini Finding 2: scheme-agnostic implicit-port match ----

    #[test]
    fn implicit_port_npmrc_matches_both_http_and_https() {
        // The user wrote `//host/:_authToken=X` with no explicit port.
        // Stored as port=None — matches a request on either http or
        // https (any port for that host). Pre-fix, this stored 443 and
        // missed http requests.
        let content = "//npm.internal/:_authToken=AGNOSTIC\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let https_auth = cfg
            .auth_for_url("https://npm.internal/foo")
            .expect("https should match");
        let http_auth = cfg
            .auth_for_url("http://npm.internal/foo")
            .expect("http should match (Gemini Finding 2)");
        match (https_auth, http_auth) {
            (RegistryAuth::Bearer(a), RegistryAuth::Bearer(b)) => {
                assert_eq!(a.expose_secret(), "AGNOSTIC");
                assert_eq!(b.expose_secret(), "AGNOSTIC");
            }
            _ => panic!("expected Bearer on both"),
        }
    }

    #[test]
    fn explicit_port_443_does_not_leak_to_http() {
        // Defense for the Finding 2 fix: an explicit `:443` in the
        // npmrc key means "this auth is for port 443 specifically",
        // so an http request (default port 80) must NOT pick it up.
        // This test exists to catch regressions where someone "fixes"
        // the implicit-port case by widening matching too aggressively.
        let content = "//npm.internal:443/:_authToken=HTTPS_ONLY\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.auth_for_url("https://npm.internal/").is_some());
        assert!(
            cfg.auth_for_url("http://npm.internal/").is_none(),
            "explicit :443 must not leak to http (port 80)"
        );
    }

    // ---- Gemini Finding 3: source-label in finalize warnings ----

    #[test]
    fn partial_credential_warning_cites_source() {
        // Single-file partial: only _username, no _password.
        // Warning must mention `~/.npmrc:7` (the source + line) and
        // the origin, so a user with multiple .npmrc files can find
        // and fix the offender.
        let content = "\n\n\n\n\n\n//npm.internal/:_username=alice\n";
        let cfg = NpmrcConfig::parse(content, "~/.npmrc", &no_env);
        assert!(cfg.origin_auth.is_empty());
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        let w = &cfg.warnings[0];
        assert!(
            w.contains("~/.npmrc:7"),
            "warning must cite source:line, got {w:?}"
        );
        assert!(
            w.contains("//npm.internal/"),
            "warning must cite the origin via Display impl, got {w:?}"
        );
    }

    #[test]
    fn cross_layer_partial_warning_cites_contributing_layer() {
        // After cross-layer merge: only one half ever set, so the
        // tagged source identifies which layer contributed the
        // half-credential. The other layer didn't write anything for
        // that origin, so there's nothing else to cite.
        let lower =
            NpmrcConfig::parse_layer("//npm.internal/:_username=alice\n", "/etc/npmrc", &no_env);
        // Higher layer adds nothing to this origin — different host.
        let higher = NpmrcConfig::parse_layer("//other.host/:_authToken=X\n", "~/.npmrc", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        let warning = acc
            .warnings
            .iter()
            .find(|w| w.contains("npm.internal"))
            .expect("partial-credential warning expected");
        assert!(
            warning.contains("/etc/npmrc:1"),
            "warning must cite the layer that set the partial subkey, got {warning:?}"
        );
    }

    // ---- contract guards ----

    #[test]
    #[should_panic(expected = "merge_over called after finalize")]
    fn merge_after_finalize_panics() {
        let mut a = NpmrcConfig::parse("registry=https://a/\n", "a", &no_env);
        let b = NpmrcConfig::parse_layer("registry=https://b/\n", "b", &no_env);
        // a is finalized (parse() does it), b is not.
        a.merge_over(b);
    }

    #[test]
    fn debug_impl_redacts_secret() {
        let auth = RegistryAuth::Bearer(SecretString::from("very-secret"));
        let formatted = format!("{auth:?}");
        assert!(!formatted.contains("very-secret"));
        assert!(formatted.contains("REDACTED"));
    }

    #[test]
    fn origin_with_explicit_port_matches_request_url_with_same_port() {
        let content = "//npm.internal:8443/:_authToken=PORTED\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        // With matching port — hit.
        assert!(
            cfg.auth_for_url("https://npm.internal:8443/foo").is_some(),
            "explicit port should match"
        );
        // Without matching port — miss. (Documented gotcha.)
        assert!(
            cfg.auth_for_url("https://npm.internal/foo").is_none(),
            "default 443 should NOT match explicit 8443"
        );
    }

    #[test]
    fn token_does_not_leak_to_unrelated_origin() {
        // SECURITY: the whole point of this module. A token for host A
        // must NOT match a request to host B.
        let content = "//npm.internal/:_authToken=A_TOKEN\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.auth_for_url("https://npm.internal/x").is_some());
        assert!(cfg.auth_for_url("https://registry.npmjs.org/x").is_none());
        assert!(cfg.auth_for_url("https://attacker.example/x").is_none());
    }

    #[test]
    fn quoted_values_are_unwrapped() {
        let content = "registry=\"https://quoted.example.com/\"\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(
            cfg.default_registry.unwrap().base_url.as_ref(),
            "https://quoted.example.com"
        );
    }

    #[test]
    fn path_prefixed_auth_key_warns_loudly() {
        // V1 limitation: we match by origin only. Path-prefix keys are
        // accepted but produce a warning so the user knows the scope is
        // wider than what they wrote.
        let content = "//gitlab.com/api/v4/projects/123/packages/npm/:_authToken=glpat-x\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
            .expect("origin-only match should hit");
        match auth {
            RegistryAuth::Bearer(s) => assert_eq!(s.expose_secret(), "glpat-x"),
            _ => panic!("expected Bearer"),
        }
        assert!(
            cfg.warnings.iter().any(|w| w.contains("path-scoped auth")),
            "path-prefix warning required; got {:?}",
            cfg.warnings
        );
    }

    #[test]
    fn _authtoken_beats_auth_within_same_origin() {
        // Precedence: _authToken > _auth > _username/_password.
        let content = concat!(
            "//npm.internal/:_authToken=BEARER\n",
            "//npm.internal/:_auth=dXNlcjpwYXNz\n",
        );
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Bearer(s) => assert_eq!(s.expose_secret(), "BEARER"),
            other => panic!("expected Bearer (precedence rule), got {other:?}"),
        }
    }
}
