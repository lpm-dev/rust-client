//! Parse and route via `.npmrc`-style configuration files.
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
//! ## TLS settings
//!
//! Global keys:
//! - `cafile=<path>` — PEM is read from disk at parse time
//!   (fail-fast: typos surface as `cfg.errors` before any network).
//!   Bytes are stored on `NpmrcConfig::tls` for
//!   `RegistryClient::with_tls_overrides_for` to attach via
//!   `ClientBuilder::add_root_certificate`.
//! - `ca=<pem>` — inline PEM. Multiple lines accumulate.
//! - `strict-ssl=false` — maps to
//!   `ClientBuilder::danger_accept_invalid_certs(true)` and a loud
//!   install-start warning (cites contributing source/line). Default
//!   and explicit `=true` are no-ops.
//! - `certfile=<path>` + `keyfile=<path>` — global mTLS identity.
//!   Path-only at parse time; the actual cert/key file is read at
//!   client-build time. XOR contract (both set or both absent) is
//!   enforced at `finalize()` across all merged layers.
//! - `always-auth=<bool>` — silently accepted at any scope. lpm always
//!   sends a matching-origin token regardless; the per-registry
//!   `always-auth` distinction was deprecated in npm 7+ and is vestigial.
//!
//! Per-origin keys (`//host[:port]/:<key>=...`):
//! - `:cafile=<path>` — additive trust root for that origin only.
//!   Deferred-read: file IO happens at client-build time for the
//!   matching origin, NOT at parse time.
//! - `:certfile=<path>` + `:keyfile=<path>` — per-origin mTLS
//!   identity. Replaces the global identity for that origin. XOR
//!   validation is build-time per origin — half-config for an unreached
//!   origin doesn't abort unrelated installs.
//!
//! ## What we don't parse (v1)
//!
//! - Path-prefix-scoped auth (`//host/some/path/:_authToken=...`). v1 matches
//!   by origin (host + port) only, which covers ~99% of `.npmrc` files seen
//!   in the wild. v1.1 adds prefix matching.
//! - Per-origin `strict-ssl=false`. Global only — the parser warns on
//!   per-origin use. Disabling cert verification per host is a
//!   security footgun once shipped; v1 keeps it global with the
//!   loud install-start warning.
//! - PKCS#12 (`.p12`/`.pfx`) cert/key archives. rustls (the TLS
//!   backend) doesn't ingest them; the loader emits a cited error
//!   pointing the user at the openssl conversion recipe.
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
use std::path::{Path, PathBuf};
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

/// PEM-decoded root certificate bytes plus where they came from. The
/// `source` / `line` plumb through `TlsOverrides::extra_roots` so when
/// `reqwest::Certificate::from_pem` rejects bytes at builder time the
/// error message can cite which `.npmrc` layer/line contributed them.
#[derive(Clone, Debug)]
pub struct TaggedRoot {
    /// Raw PEM bytes — one or more `-----BEGIN CERTIFICATE-----` blocks.
    /// Cryptographic validation deferred to `reqwest::Certificate::from_pem`
    /// at builder time; parse time only verifies the marker is present.
    pub pem_bytes: Vec<u8>,
    /// Source label (file path or test stub).
    pub source: String,
    /// 1-indexed line number of the contributing `cafile=` / `ca=` line.
    pub line: usize,
}

/// Bool-valued setting tagged with its contributing source. Used for
/// `strict_ssl` so the install-start warning can cite where the setting
/// came from (`"strict-ssl=false in /Users/me/.npmrc:3 — TLS verification
/// disabled for this install"`).
#[derive(Clone, Debug)]
pub struct TaggedBool {
    pub value: bool,
    pub source: String,
    pub line: usize,
}

/// Filesystem path tagged with its contributing source — used for
/// `certfile=` / `keyfile=` (global and per-origin). Path is stored
/// verbatim from `.npmrc`; the loader resolves and reads at client-
/// build time so per-origin entries the install never reaches don't
/// turn into ambient-config preconditions.
///
/// **Relative-path resolution.** When the user writes
/// `certfile=corp-ca.pem` in `~/.npmrc`, they expect the file to be
/// found next to `~/.npmrc`, not next to `${PWD}`. `source_dir`
/// carries the directory of the contributing `.npmrc` file so
/// [`Self::resolve`] can compose `<source_dir>/<path>` for relative
/// `path` values. `None` means the source is a non-file label (test
/// stub) or the loader should resolve against `${PWD}`.
#[derive(Clone, Debug)]
pub struct TaggedPath {
    pub path: PathBuf,
    pub source: String,
    pub line: usize,
    /// Directory of the `.npmrc` file that contained this entry, when
    /// known. Used by [`Self::resolve`] for relative paths.
    pub source_dir: Option<PathBuf>,
}

impl TaggedPath {
    /// Resolve to an absolute path the loader can stat/read.
    ///
    /// - If `path` is already absolute, return it verbatim.
    /// - Else if `source_dir` is `Some`, return `source_dir.join(path)`.
    /// - Else return `path` (loader will resolve against `${PWD}`,
    ///   matching npm's behavior for paths whose source is unknown).
    ///
    /// Resolves relative to the source file's directory so `certfile=corp.pem`
    /// in `~/.npmrc` finds the cert next to `~/.npmrc`, not `${PWD}`.
    pub fn resolve(&self) -> PathBuf {
        if self.path.is_absolute() {
            return self.path.clone();
        }
        if let Some(dir) = self.source_dir.as_ref() {
            return dir.join(&self.path);
        }
        self.path.clone()
    }
}

/// Per-origin TLS settings parsed from `//host[:port]/:cafile=` /
/// `:certfile=` / `:keyfile=`. Empty by default; only origins with at
/// least one TLS key set get an entry in [`TlsOverrides::per_origin`].
///
/// **Deferred-read contract.** Unlike global `cafile=`, per-origin
/// `cafile=` stores only the path here — the loader reads the PEM at
/// client-build time for the matching origin. This keeps unrelated
/// `.npmrc` entries (e.g., a stale corporate registry path on a
/// shared `~/.npmrc`) from breaking installs that never touch the
/// configured origin. Same scoping rule applies to `certfile` /
/// `keyfile`.
///
/// **Identity atomicity.** `certfile` and `keyfile` must both be set
/// or both absent. If only one is set, the loader emits a fatal
/// error citing the present line — but only when this origin is
/// actually built into a client (eager or lazy). Configured-but-
/// unreached half-configs do not abort the install.
#[derive(Default, Clone, Debug)]
pub struct OriginTlsOverrides {
    /// Extra root certificates from `//host/:cafile=<path>`. Stored
    /// as path-only (deferred-read) — the loader stat+reads at
    /// build time and surfaces IO errors cited at this line.
    pub cafiles: Vec<TaggedPath>,
    /// Per-origin mTLS client certificate file. Pairs with `keyfile`
    /// — see struct doc for the atomicity contract.
    pub certfile: Option<TaggedPath>,
    /// Per-origin mTLS private key file. Pairs with `certfile`.
    pub keyfile: Option<TaggedPath>,
}

impl OriginTlsOverrides {
    /// Whether this origin has any TLS settings configured. Used by
    /// the per-origin client builder to skip building a separate client
    /// for an origin whose entry exists only because `merge_over` created
    /// it empty.
    pub fn is_empty(&self) -> bool {
        self.cafiles.is_empty() && self.certfile.is_none() && self.keyfile.is_none()
    }

    /// Merge `other` ON TOP OF `self` per field. Used when a higher-
    /// precedence `.npmrc` layer adds keys for the same origin a
    /// lower-precedence layer already covered.
    fn merge_over(&mut self, other: OriginTlsOverrides) {
        // cafiles concatenate (multiple roots may stack).
        self.cafiles.extend(other.cafiles);
        if other.certfile.is_some() {
            self.certfile = other.certfile;
        }
        if other.keyfile.is_some() {
            self.keyfile = other.keyfile;
        }
    }
}

/// TLS overrides parsed from `.npmrc`. The split between global and
/// per-origin is intentional:
///
/// - **Global** (`extra_roots`, `strict_ssl`, `identity_certfile`,
///   `identity_keyfile`) applies to every request from the default
///   client. Wrong here breaks every fetch, so wrong values are
///   surfaced at parse/finalize time and abort the install.
///
/// - **Per-origin** (`per_origin`) applies only to clients built for
///   matching origins. Wrong here is surfaced at client-build time
///   for that specific origin, not globally — so an unrelated bad
///   entry in a shared `~/.npmrc` never breaks an unrelated install.
///
/// The consumer is `RegistryClient::with_tls_overrides_for`, which builds
/// the default client from the global surface and per-origin clients eagerly
/// for the request set's reached origins (lazy for the rest).
#[derive(Default, Debug, Clone)]
pub struct TlsOverrides {
    /// Extra root certificates from `cafile=<path>` and `ca=<pem>`.
    /// Accumulates across layers; lower-precedence layers come first
    /// (insertion order). Stored as raw PEM bytes so this module stays
    /// decoupled from the TLS stack.
    pub extra_roots: Vec<TaggedRoot>,

    /// `strict-ssl=false` → `Some(TaggedBool { value: false, .. })`.
    /// Explicit `strict-ssl=true` → `Some(TaggedBool { value: true, .. })`.
    /// Default (line not present anywhere) → `None`.
    ///
    /// Recording explicit `=true` as `Some(true)` rather than collapsing
    /// to `None` is intentional: it lets a higher-precedence layer flip
    /// an earlier `=false` cleanly under the `merge_over` rule below.
    /// The install-start security warning fires only on the explicit
    /// `Some(false)` case; the `None` and `Some(true)` cases are silent.
    ///
    /// Merge shape (matches `default_registry`): higher-explicit wins;
    /// higher-silent doesn't clear lower. A user's `~/.npmrc strict-ssl=false`
    /// persists across projects unless a project explicitly says `=true`.
    pub strict_ssl: Option<TaggedBool>,

    /// Global mTLS client certificate file (`certfile=<path>`). Pairs
    /// with [`Self::identity_keyfile`]. Atomicity: both must be set
    /// or both absent — `finalize()` enforces this with a fatal
    /// `cfg.errors` entry citing the present line.
    pub identity_certfile: Option<TaggedPath>,

    /// Global mTLS private key file (`keyfile=<path>`). Pairs with
    /// [`Self::identity_certfile`].
    pub identity_keyfile: Option<TaggedPath>,

    /// Per-origin TLS settings, keyed by `//host[:port]/`. Looked up
    /// via [`NpmrcConfig::tls_for_origin`] with the same `(host,
    /// Some(port))` → `(host, None)` fallback rule the auth path uses.
    pub per_origin: HashMap<OriginKey, OriginTlsOverrides>,
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
    /// lop everything from the first `/` onward (path is ignored in v1),
    /// then split host:port. An omitted port
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
    ///
    /// Delegates to `reqwest::Url::parse` (the RFC 3986 parser reqwest
    /// itself uses to dispatch) so the host extracted here matches the
    /// host reqwest will connect to. The previous implementation
    /// hand-rolled `split_once("://")` + `split(['/','?','#'])`, which
    /// never stripped `userinfo`: a URL like
    /// `https://attacker.com@registry.npmjs.org/foo` produced host
    /// `attacker.com@registry.npmjs.org` for auth matching while
    /// reqwest connected to `registry.npmjs.org` — a cross-origin
    /// auth-leak window for any URL flowing through a lockfile or
    /// registry-metadata field.
    pub fn from_request_url(url: &str) -> Option<Self> {
        let parsed = reqwest::Url::parse(url).ok()?;
        let default_port = match parsed.scheme() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        let host = parsed.host_str()?;
        // `Url::port_or_known_default` returns the scheme's default
        // when the URL omits an explicit port. For http/https this is
        // 80/443; we keep the explicit fallback so non-default schemes
        // (rejected above) never sneak through with an unexpected port.
        let port = parsed.port().unwrap_or(default_port);
        Some(Self {
            host_lower: host.to_ascii_lowercase(),
            port: Some(port),
        })
    }
}

/// Auth credential to attach to a request.
///
/// Each variant carries the [`OriginKey`] the credential is scoped to.
/// `RegistryClient::get_npm_metadata_from` re-verifies that this origin
/// is compatible with the destination URL via [`Self::matches_destination`]
/// before sending the `Authorization` header, so a routing bug elsewhere
/// can't leak a token cross-origin.
///
/// Secret material is wrapped in [`SecretString`]; hand-written `Debug`
/// below prints `[REDACTED]` and never the raw token.
#[derive(Clone)]
pub enum RegistryAuth {
    /// Sent as `Authorization: Bearer <token>`. From `_authToken=...`.
    Bearer {
        origin: OriginKey,
        token: SecretString,
    },
    /// Sent as `Authorization: Basic <b64>`. From `_auth=...` directly,
    /// or computed by joining `_username` + base64-decoded `_password`.
    Basic {
        origin: OriginKey,
        credential: SecretString,
    },
}

impl RegistryAuth {
    /// The origin this credential is scoped to. The fetch site uses
    /// this to verify the destination URL before attaching auth —
    /// never trust a separately-supplied auth/URL pair.
    pub fn origin(&self) -> &OriginKey {
        match self {
            Self::Bearer { origin, .. } | Self::Basic { origin, .. } => origin,
        }
    }

    /// Whether this credential is acceptable to attach to a request to
    /// `dest`. Mirrors the [`NpmrcConfig::auth_for_url`] match rule:
    /// same host, AND (auth port is `None` OR equal to dest port).
    /// Asymmetric on purpose — an auth registered without a port covers
    /// any port for that host, but an explicit-port auth never leaks
    /// to a different port.
    pub fn matches_destination(&self, dest: &OriginKey) -> bool {
        let auth_origin = self.origin();
        if auth_origin.host_lower != dest.host_lower {
            return false;
        }
        match auth_origin.port {
            Some(p) => Some(p) == dest.port,
            None => true,
        }
    }
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { origin, .. } => write!(
                f,
                "RegistryAuth::Bearer {{ origin: {origin}, token: [REDACTED] }}"
            ),
            Self::Basic { origin, .. } => write!(
                f,
                "RegistryAuth::Basic {{ origin: {origin}, credential: [REDACTED] }}"
            ),
        }
    }
}

impl PartialEq for RegistryAuth {
    /// Equality by variant + origin + secret material. For test
    /// ergonomics; production code should never compare auth
    /// credentials directly.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Bearer {
                    origin: a_o,
                    token: a_t,
                },
                Self::Bearer {
                    origin: b_o,
                    token: b_t,
                },
            ) => a_o == b_o && a_t.expose_secret() == b_t.expose_secret(),
            (
                Self::Basic {
                    origin: a_o,
                    credential: a_c,
                },
                Self::Basic {
                    origin: b_o,
                    credential: b_c,
                },
            ) => a_o == b_o && a_c.expose_secret() == b_c.expose_secret(),
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
/// `_password`) compose correctly.
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
            return Some(RegistryAuth::Bearer {
                origin: origin.clone(),
                token: SecretString::from(t.value),
            });
        }
        if let Some(b) = self.auth_b64 {
            return Some(RegistryAuth::Basic {
                origin: origin.clone(),
                credential: SecretString::from(b.value),
            });
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
                Some(RegistryAuth::Basic {
                    origin: origin.clone(),
                    credential: SecretString::from(encoded),
                })
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
        Self::parse_layer_with_source_dir(content, source_label, None, env_lookup)
    }

    /// Parse a single `.npmrc` layer and tag every TLS path entry with the
    /// source directory.
    ///
    /// `source_dir` is the parent directory of the `.npmrc` file
    /// being parsed. Used by [`TaggedPath::resolve`] to compose
    /// absolute paths from relative `certfile=` / `keyfile=` /
    /// per-origin `cafile=` values. Pass `None` for in-memory tests
    /// or any caller whose source isn't a file on disk.
    ///
    /// Production: [`Self::load_from_paths`] passes
    /// `Some(file_path.parent())` for each layer.
    pub fn parse_layer_with_source_dir(
        content: &str,
        source_label: &str,
        source_dir: Option<&Path>,
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

            classify_and_apply(
                key,
                &interpolated,
                source_label,
                source_dir,
                lineno + 1,
                &mut cfg,
            );
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

    // ---- Filesystem walker ----

    /// Compute the four `.npmrc` paths in **lowest-to-highest precedence
    /// order**, ready to feed `load_from_paths`, plus any warnings raised
    /// during discovery (e.g., a project `.npmrc` that turned out to be a
    /// directory). Pure / no IO beyond `stat`-style probing.
    ///
    /// Layers:
    /// 1. `/usr/etc/npmrc` — npm builtin, rarely present.
    /// 2. `/etc/npmrc` — system-wide, also rare.
    /// 3. `<home>/.npmrc` — user-level, included only if `home` is `Some`.
    ///    Most teams put their auth tokens here.
    /// 4. `<some-ancestor>/.npmrc` — found by `walk_for_project_npmrc`.
    ///    The walker returns the nearest `.npmrc` on the walk-up path
    ///    such that a project marker (regular-file `package.json`) has
    ///    been seen at-or-below that level. This restores the
    ///    monorepo-inheritance pattern (a workspace member without
    ///    its own `.npmrc` inherits the workspace root's one) while
    ///    keeping the security boundary against shared-ancestor
    ///    injection — a `.npmrc` with no marker anywhere on the path
    ///    is never trusted.
    ///
    /// Layers 1–3 are returned even if their files don't exist; the
    /// loader silently skips missing files. Layer 4 is **bounded** to
    /// the project — without a regular-file project marker on the path,
    /// no project layer is included (a planted non-regular marker would
    /// otherwise qualify any directory as a project root).
    pub fn discover_layer_paths(cwd: &Path, home: Option<&Path>) -> LayerDiscovery {
        let mut paths = Vec::with_capacity(4);
        let mut warnings = Vec::new();
        paths.push(PathBuf::from("/usr/etc/npmrc"));
        paths.push(PathBuf::from("/etc/npmrc"));
        if let Some(h) = home {
            paths.push(h.join(".npmrc"));
        }
        match walk_for_project_npmrc(cwd, home) {
            ProjectNpmrcOutcome::File(p) => paths.push(p),
            ProjectNpmrcOutcome::NotRegular { path, kind } => {
                warnings.push(format!(
                    "{}: project .npmrc {}; project layer skipped",
                    path.display(),
                    kind
                ));
            }
            ProjectNpmrcOutcome::None => {
                // No marker on path → no project layer. Silent — most
                // installs don't have a project layer.
            }
        }
        LayerDiscovery { paths, warnings }
    }

    /// Read and merge a list of `.npmrc` files in
    /// **lowest-to-highest precedence order**, then `finalize()`.
    ///
    /// File outcomes:
    /// - **Reads OK** — `parse_layer` then `merge_over`.
    /// - **NotFound** — silently skipped. Most users don't have
    ///   `/etc/npmrc` or `/usr/etc/npmrc`; warning every time would be
    ///   pure noise.
    /// - **Any other IO error** (PermissionDenied, EISDIR, etc.) —
    ///   warned and skipped. Never aborts the install.
    ///
    /// The `env_lookup` is threaded through to each file's parse so
    /// `${VAR}` interpolation works the same way the single-file API
    /// does. `load_from_filesystem` wires this to the real process env.
    pub fn load_from_paths(paths: &[PathBuf], env_lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let mut acc = NpmrcConfig::default();
        for path in paths {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let label = path.display().to_string();
                    // Pass the file's parent dir so `certfile=` / `keyfile=`
                    // / per-origin `cafile=` tagged paths resolve relative
                    // to *this* `.npmrc` (not `${PWD}`).
                    let source_dir = path.parent();
                    let layer = NpmrcConfig::parse_layer_with_source_dir(
                        &content, &label, source_dir, env_lookup,
                    );
                    acc.merge_over(layer);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Silent — see method-level comment.
                }
                Err(e) => {
                    acc.warnings.push(format!(
                        "{}: failed to read .npmrc ({}); skipped this layer",
                        path.display(),
                        e
                    ));
                }
            }
        }
        acc.finalize();
        acc
    }

    /// Production wrapper — discover the standard four layers from
    /// disk and load them, with `${VAR}` resolved against the real
    /// process env.
    ///
    /// `cwd` should be the project root (for `lpm install`) or the
    /// home dir (for `lpm install -g`). The walker handles both shapes
    /// via `find_project_root`.
    pub fn load_from_filesystem(cwd: &Path) -> Self {
        let home = dirs::home_dir();
        let discovery = Self::discover_layer_paths(cwd, home.as_deref());
        let mut cfg = Self::load_from_paths(&discovery.paths, &|name| std::env::var(name).ok());
        // Discovery warnings happened first chronologically; prepend so
        // they read in the order the user would expect.
        let mut all = discovery.warnings;
        all.append(&mut cfg.warnings);
        cfg.warnings = all;
        cfg
    }
}

/// Result of [`NpmrcConfig::discover_layer_paths`] — the file paths to
/// load and any non-fatal warnings raised during discovery itself
/// (e.g., a project `.npmrc` that's a directory).
#[derive(Debug, Default)]
pub struct LayerDiscovery {
    pub paths: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

/// Markers that identify a directory as a project root for the
/// purposes of `.npmrc` discovery. Deliberately narrow — `package.json`
/// is the universal npm-style answer. Adding broader markers like
/// `.git` would re-open the shared-ancestor injection class for any
/// directory inside a git repo.
const PROJECT_MARKERS: &[&str] = &["package.json"];

/// Whether `dir` contains at least one **regular-file** project marker.
/// `metadata().is_file()` follows symlinks (so a symlink to a real
/// `package.json` still counts) but rejects directories and broken
/// symlinks — `mkdir /tmp/package.json` must not qualify `/tmp` as a
/// project root.
fn dir_has_regular_marker(dir: &Path) -> bool {
    PROJECT_MARKERS.iter().any(|m| {
        std::fs::metadata(dir.join(m))
            .map(|meta| meta.is_file())
            .unwrap_or(false)
    })
}

/// Disposition of an `.npmrc` candidate path.
#[derive(Debug)]
enum NpmrcEntry {
    /// Regular file (or symlink resolving to a regular file) — feed
    /// to the loader.
    File(PathBuf),
    /// Entry exists but isn't usable as an `.npmrc` source. Surfaced
    /// as a warning; walker stops here and does NOT fall through to
    /// higher ancestors.
    NotRegular { path: PathBuf, kind: &'static str },
    /// No `.npmrc` entry of any kind at this path.
    Missing,
}

/// Classify a single `.npmrc` candidate path. `symlink_metadata` first
/// so broken symlinks register as entries (`metadata` alone would
/// follow and return `NotFound`, which the caller would silently treat
/// as Missing — that's a silent privilege escalation if left unguarded).
fn inspect_npmrc_at(candidate: &Path) -> NpmrcEntry {
    let lstat = match std::fs::symlink_metadata(candidate) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return NpmrcEntry::Missing,
        Err(_) => {
            return NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "cannot stat",
            };
        }
    };
    let ft = lstat.file_type();
    if ft.is_file() {
        return NpmrcEntry::File(candidate.to_path_buf());
    }
    if ft.is_symlink() {
        return match std::fs::metadata(candidate) {
            Ok(target_meta) if target_meta.is_file() => NpmrcEntry::File(candidate.to_path_buf()),
            Ok(_) => NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "is a symlink whose target is not a regular file",
            },
            Err(_) => NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "is a broken symlink (target unreachable)",
            },
        };
    }
    if ft.is_dir() {
        return NpmrcEntry::NotRegular {
            path: candidate.to_path_buf(),
            kind: "is a directory",
        };
    }
    NpmrcEntry::NotRegular {
        path: candidate.to_path_buf(),
        kind: "is not a regular file",
    }
}

/// Outcome of walking up from `cwd` looking for a project-layer
/// `.npmrc`.
#[derive(Debug)]
enum ProjectNpmrcOutcome {
    /// A regular `.npmrc` was found at an ancestor (including cwd) AND
    /// at least one regular-file project marker was seen at-or-below
    /// that ancestor on the walk path.
    File(PathBuf),
    /// The walker found an `.npmrc` candidate at a level where the
    /// marker requirement was satisfied, but the entry isn't loadable.
    /// Surfaced as a warning by the caller; walker does NOT fall
    /// through to higher ancestors.
    NotRegular { path: PathBuf, kind: &'static str },
    /// No project layer applies. Either no marker was seen on the
    /// walk-up, or the walker exhausted the path without finding a
    /// usable `.npmrc` past a marker.
    None,
}

/// Walk up from `cwd` looking for the project-layer `.npmrc`.
///
/// Algorithm: track `seen_marker` as we walk up. At each level:
/// 1. If `dir == home`: stop.
/// 2. If `dir_has_regular_marker(dir)`: set `seen_marker = true`.
/// 3. If `seen_marker`: classify `dir/.npmrc`.
///    - `File` → return it. Closest-wins: the deepest ancestor whose
///      `.npmrc` we trust is the answer.
///    - `NotRegular` → return it as a warning; do NOT fall through.
///    - `Missing` → continue up. A higher ancestor might still have
///      the workspace-root `.npmrc` (nested member's `package.json`
///      flips the flag, then we walk up to the repo root's `.npmrc`).
/// 4. If not `seen_marker`: do not even look at `dir/.npmrc`. Without
///    a marker on the path, we can't tell a legitimate `.npmrc` from
///    a planted one.
///
/// Why "marker at-or-below" rather than "marker exact-here": npm-style
/// monorepos put `package.json` in each member but `.npmrc` only at
/// the workspace root. A walker that required `.npmrc` and `package.json`
/// in the same directory would miss that pattern entirely.
fn walk_for_project_npmrc(cwd: &Path, home: Option<&Path>) -> ProjectNpmrcOutcome {
    let mut current = Some(cwd);
    let mut seen_marker = false;
    while let Some(dir) = current {
        if Some(dir) == home {
            break;
        }
        if dir_has_regular_marker(dir) {
            seen_marker = true;
        }
        if seen_marker {
            match inspect_npmrc_at(&dir.join(".npmrc")) {
                NpmrcEntry::File(p) => return ProjectNpmrcOutcome::File(p),
                NpmrcEntry::NotRegular { path, kind } => {
                    return ProjectNpmrcOutcome::NotRegular { path, kind };
                }
                NpmrcEntry::Missing => {
                    // Keep walking — repo root might have the workspace .npmrc.
                }
            }
        }
        current = dir.parent();
    }
    ProjectNpmrcOutcome::None
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
///
/// `source_dir` is the directory of the `.npmrc` file being parsed;
/// when populated, every emitted [`TaggedPath`] carries it so
/// [`TaggedPath::resolve`] can turn relative paths into absolute ones
/// at load time. Test stubs pass `None`.
fn classify_and_apply(
    key: &str,
    value: &str,
    source_label: &str,
    source_dir: Option<&Path>,
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
            // M40: pre-fix we WARN and then materialize the credential
            // anyway, broadening a narrow path-scoped token to the
            // entire origin. For shared-host registries (GitLab,
            // Artifactory) this is a real over-disclosure: a token
            // scoped to `/api/v4/projects/123/packages/npm/` shouldn't
            // get sent to `/api/v4/projects/999/packages/npm/`.
            // Refuse-with-warning for credential attrs specifically;
            // TLS attrs (certfile/keyfile/cafile) are still
            // materialized because they're not credentials per se and
            // legitimate per-path TLS overrides are uncommon enough
            // that the override-with-warning path is the right UX.
            let is_credential_attr =
                matches!(attr, "_authToken" | "_auth" | "_password" | "_username");
            if origin_part.contains('/') {
                if is_credential_attr {
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: path-scoped npmrc credential key ('{key}') would \
                         be widened to ALL paths on {origin} (v1 matches by origin only); \
                         refusing to materialize — narrow the host config OR rewrite the key as \
                         `//{origin}/:{attr}` to opt into origin-wide reach."
                    ));
                    return;
                }
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: path-scoped npmrc key ('{key}') is parsed as origin-only in v1; \
                     setting will apply to ALL paths on {origin}"
                ));
            }
            let tagged = TaggedValue::new(value.to_string(), source_label, lineno);
            // Auth subkeys go into the per-origin auth buffer; TLS subkeys
            // go into the per-origin TLS buffer. Two distinct entry maps share
            // the same `OriginKey` so a matching-origin lookup fetches both.
            match attr {
                "_authToken" => {
                    cfg.auth_buffers.entry(origin).or_default().auth_token = Some(tagged);
                }
                "_auth" => {
                    cfg.auth_buffers.entry(origin).or_default().auth_b64 = Some(tagged);
                }
                "_username" => {
                    cfg.auth_buffers.entry(origin).or_default().username = Some(tagged);
                }
                "_password" => {
                    cfg.auth_buffers.entry(origin).or_default().password_b64 = Some(tagged);
                }
                "always-auth" | "email" => {
                    // Silently accepted at origin scope. `always-auth` is
                    // vestigial — modern npm 7+ removed
                    // the per-registry distinction; lpm always sends
                    // matching-origin tokens. `email` is publish-flow
                    // metadata, irrelevant to install routing.
                }
                "cafile" => {
                    // Per-origin extra root. DEFERRED-READ by design: the PEM
                    // is read at client-build time for the matching origin,
                    // NOT at parse time. Unrelated `.npmrc` entries (e.g., a
                    // stale path on a shared `~/.npmrc`) cannot break installs
                    // that never reach the configured origin.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin cafile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls
                        .per_origin
                        .entry(origin)
                        .or_default()
                        .cafiles
                        .push(TaggedPath {
                            path: PathBuf::from(value),
                            source: source_label.to_string(),
                            line: lineno,
                            source_dir: source_dir.map(|p| p.to_path_buf()),
                        });
                }
                "certfile" => {
                    // Per-origin mTLS client cert path. Path-only at parse
                    // time; XOR-pair validation + file read deferred to
                    // client-build time. Configured-but-unreached half-configs
                    // do not abort the install.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin certfile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls.per_origin.entry(origin).or_default().certfile = Some(TaggedPath {
                        path: PathBuf::from(value),
                        source: source_label.to_string(),
                        line: lineno,
                        source_dir: source_dir.map(|p| p.to_path_buf()),
                    });
                }
                "keyfile" => {
                    // Per-origin mTLS private key path.
                    // Same deferred-read contract as `certfile`.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin keyfile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls.per_origin.entry(origin).or_default().keyfile = Some(TaggedPath {
                        path: PathBuf::from(value),
                        source: source_label.to_string(),
                        line: lineno,
                        source_dir: source_dir.map(|p| p.to_path_buf()),
                    });
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

    // Globally-scoped TLS settings.
    if key == "cafile" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty cafile path; skipped"
            ));
            return;
        }
        match std::fs::read(value) {
            Ok(bytes) => {
                // No `decode_npmrc_pem_escapes` here — `cafile=<path>` reads
                // the PEM from disk where newlines are real (`\n` bytes),
                // not the escape-encoded `\\n` sequences npm uses for
                // inline `ca=` values on a single `.npmrc` line. The
                // asymmetry is intentional and matches npm.
                if !contains_pem_certificate_block(&bytes) {
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: cafile='{value}' contains no \
                         '-----BEGIN CERTIFICATE-----' block; skipped"
                    ));
                    return;
                }
                cfg.tls.extra_roots.push(TaggedRoot {
                    pem_bytes: bytes,
                    source: source_label.to_string(),
                    line: lineno,
                });
            }
            Err(e) => {
                // Fail-fast: a typo'd cafile path silently falls back to
                // system roots, which means the user hits a confusing
                // handshake error mid-install. Surface it at config-load
                // instead so the install aborts before any network.
                cfg.errors.push(format!(
                    "{source_label}:{lineno}: cafile='{value}': failed to read: {e}"
                ));
            }
        }
        return;
    }
    if key == "ca" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty ca PEM value; skipped"
            ));
            return;
        }
        // `.npmrc` is line-based; npm encodes multi-line PEMs as a single
        // line using literal `\n` escapes:
        //   ca = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
        // Decode those to real newlines so the marker check and downstream
        // `reqwest::Certificate::from_pem` see structurally-valid PEM.
        let decoded = decode_npmrc_pem_escapes(value);
        let bytes = decoded.as_bytes();
        if !contains_pem_certificate_block(bytes) {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: ca PEM contains no \
                 '-----BEGIN CERTIFICATE-----' block; skipped"
            ));
            return;
        }
        cfg.tls.extra_roots.push(TaggedRoot {
            pem_bytes: bytes.to_vec(),
            source: source_label.to_string(),
            line: lineno,
        });
        return;
    }
    if key == "strict-ssl" {
        match value.to_ascii_lowercase().as_str() {
            "false" => {
                cfg.tls.strict_ssl = Some(TaggedBool {
                    value: false,
                    source: source_label.to_string(),
                    line: lineno,
                });
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: strict-ssl=false — TLS certificate \
                     verification will be DISABLED for this install"
                ));
            }
            "true" => {
                // Explicit =true: silent no-op (the default). Still
                // recorded so a higher-precedence layer can flip an
                // earlier `=false` back on.
                cfg.tls.strict_ssl = Some(TaggedBool {
                    value: true,
                    source: source_label.to_string(),
                    line: lineno,
                });
            }
            _ => {
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: strict-ssl='{value}' is not a \
                     boolean; ignored"
                ));
            }
        }
        return;
    }
    if key == "certfile" || key == "keyfile" {
        // Global mTLS identity (cert chain + private key). Path-only at parse
        // time; the actual cert/key file is read at client-build time. The
        // XOR-pair contract (both set or both absent) is enforced at
        // finalize() across all merged layers, so `certfile=` in `~/.npmrc`
        // plus `keyfile=` in a project `.npmrc` legitimately compose.
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty {key} path; skipped"
            ));
            return;
        }
        let tagged_path = TaggedPath {
            path: PathBuf::from(value),
            source: source_label.to_string(),
            line: lineno,
            source_dir: source_dir.map(|p| p.to_path_buf()),
        };
        if key == "certfile" {
            cfg.tls.identity_certfile = Some(tagged_path);
        } else {
            cfg.tls.identity_keyfile = Some(tagged_path);
        }
        return;
    }
    if key == "always-auth" {
        // Silently accepted. lpm always sends a matching-origin token, which
        // is what `always-auth=true` users want; `=false` is a no-op.
        // Modern npm 7+ removed the per-registry distinction.
    }

    // Anything else — silent ignore. Matches npm: unknown keys aren't
    // an error. Things like `engine-strict`, `save-prefix`, `lockfile`
    // are lpm's own concerns and the npmrc value (if any) is just
    // noise from this module's perspective.
}

/// Cheap parse-time validation: does this byte slice contain at least one
/// PEM certificate block? We don't decode the body here — that's
/// [`crate::client::validate_pem_root`]'s job at install start, which
/// runs the full base64 + per-block walk and cites the offending block
/// in `LpmError::Cert(..)`.
///
/// **Two-layer defense, by design.** This parse-time check exists so a
/// user who points `cafile=` at `/etc/passwd` learns at config-load
/// (with `cfg.errors` populated) before any other parsing decisions are
/// made. The builder-time check exists so `_strictly_ valid PEM_ at
/// parse time but with malformed base64 inside one of the blocks` (rare
/// but real) gets cited cleanly with source/line + block number rather
/// than as a generic "HTTP client build failed" — see
/// [`crate::client::validate_pem_root`] for the full rationale on why
/// reqwest's permissive `from_pem` makes the second layer necessary.
fn contains_pem_certificate_block(bytes: &[u8]) -> bool {
    // PEM marker is ASCII-only; byte-search is correct.
    const MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}

/// Decode npm's PEM-escape form: `\n` → real newline, `\r` → carriage return.
/// `.npmrc` is line-based, so npm encodes multi-line PEMs as a single
/// line with literal backslash-n / backslash-r sequences. We decode those
/// before storing so downstream consumers (`reqwest::Certificate::from_pem`)
/// see structurally-valid PEM.
///
/// **Scope limitation (intentional):** only `\n` and `\r` are decoded.
/// We do NOT process backslash-escaping (`\\` → `\`), so a hypothetical
/// input containing `\\n` (escaped backslash followed by `n`) would be
/// transformed into `\` + literal newline rather than the literal
/// 2-char string `\n`. This is unreachable in practice — PEM bodies are
/// pure ASCII (base64 + 5-dash headers) and contain no backslash
/// characters in the unencoded form. Documenting the limitation here
/// so a future "let's also support `\\` escaping" change is a deliberate
/// decision, not an accidental rewrite of the contract.
fn decode_npmrc_pem_escapes(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\r", "\r")
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
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "ABC123"),
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
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "secret-value"),
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
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), "dXNlcjpwYXNz")
            }
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
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), "dXNlcjpwYXNz")
            }
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
            RegistryAuth::Bearer { token: s, .. } => {
                assert_eq!(s.expose_secret(), "ab:cd/ef=gh+ij")
            }
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

    // ---- TLS overrides: cafile / ca / strict-ssl / always-auth ----

    /// Generate a self-signed test PEM (cert + key); only the cert PEM
    /// is used by these parser tests. Key is dropped. Used in lieu of a
    /// committed binary fixture so future test-cert rotations are free.
    fn generate_test_cert_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
        cert.cert.pem()
    }

    #[test]
    fn cafile_path_loads_pem_into_extra_roots() {
        let pem = generate_test_cert_pem();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, &pem).unwrap();
        let content = format!("cafile={}\n", path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let root = &cfg.tls.extra_roots[0];
        assert_eq!(root.pem_bytes, pem.as_bytes());
        assert_eq!(root.source, "test");
        assert_eq!(root.line, 1);
    }

    #[test]
    fn cafile_path_with_io_error_pushes_to_errors_not_warnings() {
        // Non-existent path. Fail-fast contract: this is fatal, not a
        // silent system-root fallback.
        let content = "cafile=/this/path/should/never/exist/ca.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(
            cfg.errors[0].contains("cafile=") && cfg.errors[0].contains("failed to read"),
            "error message: {}",
            cfg.errors[0]
        );
    }

    #[test]
    fn cafile_path_with_garbage_content_pushes_warning_and_skips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-cert.pem");
        std::fs::write(&path, b"this is not a PEM file at all\n").unwrap();
        let content = format!("cafile={}\n", path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("contains no")
                && cfg.warnings[0].contains("BEGIN CERTIFICATE")
        );
    }

    #[test]
    fn ca_inline_pem_appends_to_extra_roots() {
        let pem = generate_test_cert_pem();
        // npm convention: multi-line PEM on a single ca= line, real
        // newlines encoded as literal `\n`. Round-trip through escape →
        // decode and assert the stored bytes match the original PEM.
        let escaped = pem.replace('\n', "\\n");
        let content = format!("ca={escaped}\n");
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let root = &cfg.tls.extra_roots[0];
        assert_eq!(root.source, "test");
        assert_eq!(
            root.pem_bytes,
            pem.as_bytes(),
            "decoded PEM bytes should match the original"
        );
    }

    #[test]
    fn ca_inline_pem_with_literal_escapes_decodes_correctly() {
        // Synthetic minimal PEM-shaped value (validation only checks for
        // the BEGIN marker, not the body) — this test specifically pins
        // the `\n` / `\r` decoding.
        let content = "ca=-----BEGIN CERTIFICATE-----\\nABCDEF\\n-----END CERTIFICATE-----\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let stored = &cfg.tls.extra_roots[0].pem_bytes;
        assert_eq!(
            stored,
            b"-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn ca_inline_empty_value_warns_and_skips() {
        let cfg = NpmrcConfig::parse("ca=\n", "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("empty ca PEM"));
    }

    #[test]
    fn ca_inline_garbage_warns_and_skips() {
        let cfg = NpmrcConfig::parse("ca=hunter2\n", "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("contains no")
                && cfg.warnings[0].contains("BEGIN CERTIFICATE")
        );
    }

    #[test]
    fn multiple_cafile_and_ca_mixed_all_present_in_extra_roots() {
        let pem_a = generate_test_cert_pem();
        let pem_b = generate_test_cert_pem();
        let dir = tempfile::tempdir().unwrap();
        let cafile_path = dir.path().join("a.pem");
        std::fs::write(&cafile_path, &pem_a).unwrap();
        let escaped_b = pem_b.replace('\n', "\\n");
        let content = format!("cafile={}\nca={escaped_b}\n", cafile_path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.tls.extra_roots.len(), 2);
        // Order is insertion order (cafile= line 1, ca= line 2).
        assert_eq!(cfg.tls.extra_roots[0].line, 1);
        assert_eq!(cfg.tls.extra_roots[1].line, 2);
    }

    #[test]
    fn merge_over_concatenates_extra_roots_lower_first() {
        let pem_lower = generate_test_cert_pem().replace('\n', "\\n");
        let pem_higher = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem_lower}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem_higher}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(acc.tls.extra_roots.len(), 2);
        assert_eq!(acc.tls.extra_roots[0].source, "lower");
        assert_eq!(acc.tls.extra_roots[1].source, "higher");
    }

    #[test]
    fn merge_over_dedupes_identical_extra_roots_preserving_first_source() {
        // Regression — if two layers contribute the same PEM bytes
        // (common in shops where `~/.npmrc` and a project `.npmrc`
        // both set `cafile=/etc/ssl/corp-ca.pem`), the merged
        // `extra_roots` should NOT duplicate the cert. Rustls handles
        // duplicate roots without erroring, but we'd still pay an
        // extra `validate_pem_root` + `Certificate::from_pem` round
        // for nothing, AND the source attribution would silently
        // shift from "the file you set first" to "the file you set
        // later" depending on which one wins downstream.
        //
        // Dedup by `pem_bytes`, keeping the FIRST source seen (the
        // lower-precedence / earliest layer). That preserves
        // chronological attribution and matches the lower-first
        // ordering used everywhere else in this merge.
        let pem = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.tls.extra_roots.len(),
            1,
            "duplicate PEM bytes across layers must be deduplicated"
        );
        assert_eq!(
            acc.tls.extra_roots[0].source, "lower",
            "first source must persist on dedup so attribution doesn't shift"
        );
    }

    #[test]
    fn strict_ssl_false_sets_some_false_with_loud_warning() {
        let cfg = NpmrcConfig::parse("strict-ssl=false\n", "test", &no_env);
        let tagged = cfg.tls.strict_ssl.expect("strict_ssl should be Some");
        assert!(!tagged.value);
        assert_eq!(tagged.source, "test");
        assert_eq!(tagged.line, 1);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("DISABLED"),
            "warning: {}",
            cfg.warnings[0]
        );
    }

    #[test]
    fn strict_ssl_true_sets_some_true_silently() {
        let cfg = NpmrcConfig::parse("strict-ssl=true\n", "test", &no_env);
        let tagged = cfg.tls.strict_ssl.expect("strict_ssl should be Some(true)");
        assert!(tagged.value);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    #[test]
    fn strict_ssl_missing_remains_none() {
        let cfg = NpmrcConfig::parse("registry=https://example.com/\n", "test", &no_env);
        assert!(cfg.tls.strict_ssl.is_none());
    }

    #[test]
    fn strict_ssl_other_values_warn_and_remain_none() {
        let cfg = NpmrcConfig::parse("strict-ssl=maybe\n", "test", &no_env);
        assert!(cfg.tls.strict_ssl.is_none());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("not a"));
    }

    #[test]
    fn merge_over_strict_ssl_higher_silent_does_not_clear_lower() {
        // (a) precedence: lower-explicit persists when higher is silent.
        // Same shape as `default_registry`. A user's `~/.npmrc` strict-ssl=false
        // applies to projects that don't say anything.
        let mut lower = NpmrcConfig::parse_layer("strict-ssl=false\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("registry=https://x/\n", "higher", &no_env);
        lower.merge_over(higher);
        let tagged = lower.tls.strict_ssl.expect("lower setting should persist");
        assert!(!tagged.value);
        assert_eq!(tagged.source, "lower");
    }

    #[test]
    fn merge_over_strict_ssl_higher_explicit_overrides_lower() {
        // Higher-explicit wins (any value, even back-to-true).
        let mut lower = NpmrcConfig::parse_layer("strict-ssl=false\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("strict-ssl=true\n", "higher", &no_env);
        lower.merge_over(higher);
        let tagged = lower.tls.strict_ssl.expect("higher should override");
        assert!(tagged.value);
        assert_eq!(tagged.source, "higher");
    }

    #[test]
    fn always_auth_global_silently_accepted_no_warning() {
        for v in ["true", "false", "always"] {
            let content = format!("always-auth={v}\n");
            let cfg = NpmrcConfig::parse(&content, "test", &no_env);
            assert!(
                cfg.warnings.is_empty(),
                "warnings for value {v}: {:?}",
                cfg.warnings
            );
            assert!(
                cfg.errors.is_empty(),
                "errors for value {v}: {:?}",
                cfg.errors
            );
        }
    }

    #[test]
    fn always_auth_per_origin_silently_accepted_no_warning() {
        let content = "//npm.internal/:always-auth=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    // ---- per-origin TLS / mTLS parsing ----

    #[test]
    fn global_certfile_xor_keyfile_is_fatal_with_cited_line() {
        // Half-configured global identity at finalize time → fatal, citing
        // the line of the present key and naming the missing one. This is
        // GLOBAL state — wrong here breaks every fetch, so install must
        // abort before any network.
        let cfg = NpmrcConfig::parse("certfile=/path/cert.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("certfile"));
        assert!(cfg.errors[0].contains("keyfile"));

        let cfg = NpmrcConfig::parse("keyfile=/path/key.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("keyfile"));
        assert!(cfg.errors[0].contains("certfile"));
    }

    #[test]
    fn global_certfile_and_keyfile_complete_pair_is_clean() {
        let content = "certfile=/path/cert.pem\nkeyfile=/path/key.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(
            cfg.tls.identity_certfile.as_ref().unwrap().path,
            PathBuf::from("/path/cert.pem")
        );
        assert_eq!(
            cfg.tls.identity_keyfile.as_ref().unwrap().path,
            PathBuf::from("/path/key.pem")
        );
    }

    #[test]
    fn global_certfile_keyfile_compose_across_layers() {
        // certfile in lower-precedence + keyfile in higher-precedence
        // should compose into a complete pair, NOT trigger the XOR
        // fatal — the contract is across all merged layers.
        let mut acc = NpmrcConfig::parse_layer("certfile=/etc/cert.pem\n", "system", &no_env);
        let higher = NpmrcConfig::parse_layer("keyfile=/home/u/key.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert!(acc.errors.is_empty(), "errors: {:?}", acc.errors);
        assert_eq!(acc.tls.identity_certfile.as_ref().unwrap().source, "system");
        assert_eq!(acc.tls.identity_keyfile.as_ref().unwrap().source, "user");
    }

    #[test]
    fn global_certfile_empty_value_warns_skipped() {
        let cfg = NpmrcConfig::parse("certfile=\n", "test", &no_env);
        // Empty value warned + skipped means no certfile is set,
        // which means no XOR fatal either.
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("empty certfile"));
        assert!(cfg.tls.identity_certfile.is_none());
    }

    #[test]
    fn per_origin_cafile_populates_per_origin_not_global_roots() {
        let cfg = NpmrcConfig::parse("//npm.internal/:cafile=/path/ca.pem\n", "test", &no_env);
        // Per-origin cafile is path-only at parse time (deferred-read), so a
        // non-existent path here is NOT a parse-time error. Only loaded at
        // client-build time for the matching origin.
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(
            cfg.tls.extra_roots.is_empty(),
            "per-origin cafile must not feed global extra_roots"
        );
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(per_origin.cafiles.len(), 1);
        assert_eq!(per_origin.cafiles[0].path, PathBuf::from("/path/ca.pem"));
        assert_eq!(per_origin.cafiles[0].source, "test");
        assert_eq!(per_origin.cafiles[0].line, 1);
    }

    #[test]
    fn per_origin_certfile_keyfile_populate_per_origin_not_global() {
        let content = "//npm.internal/:certfile=/path/cert.pem\n\
                       //npm.internal/:keyfile=/path/key.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(cfg.tls.identity_certfile.is_none());
        assert!(cfg.tls.identity_keyfile.is_none());
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().path,
            PathBuf::from("/path/cert.pem")
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().path,
            PathBuf::from("/path/key.pem")
        );
    }

    #[test]
    fn per_origin_half_configured_identity_does_not_abort_at_finalize() {
        // Per-origin half-configs are NOT fatal at finalize. They become fatal
        // only when that origin is actually built into a client (eager or
        // lazy). Configured-but-unreached half-configs do not break unrelated
        // installs.
        let cfg = NpmrcConfig::parse(
            "//unused.internal/:certfile=/path/cert.pem\n",
            "test",
            &no_env,
        );
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
    }

    #[test]
    fn tls_for_origin_falls_back_to_any_port() {
        let cfg = NpmrcConfig::parse("//npm.internal/:cafile=/path/ca.pem\n", "test", &no_env);
        // Lookup with a concrete port should fall back to the
        // port-less entry, mirroring auth_for_url's semantics.
        let with_port = OriginKey {
            host_lower: "npm.internal".into(),
            port: Some(443),
        };
        assert!(cfg.tls_for_origin(&with_port).is_some());
        let other_host = OriginKey {
            host_lower: "other.internal".into(),
            port: Some(443),
        };
        assert!(cfg.tls_for_origin(&other_host).is_none());
    }

    #[test]
    fn merge_over_per_origin_cafiles_concatenate() {
        let mut acc =
            NpmrcConfig::parse_layer("//npm.internal/:cafile=/system/ca.pem\n", "system", &no_env);
        let higher =
            NpmrcConfig::parse_layer("//npm.internal/:cafile=/user/ca.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = acc.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(per_origin.cafiles.len(), 2);
        assert_eq!(per_origin.cafiles[0].source, "system");
        assert_eq!(per_origin.cafiles[1].source, "user");
    }

    #[test]
    fn parse_layer_with_source_dir_tags_certfile_for_resolve() {
        // When parse_layer_with_source_dir is given a directory, every
        // TaggedPath in this layer (global + per-origin) must carry it so
        // `TaggedPath::resolve()` can compose absolute paths from relative
        // `.npmrc` values.
        let dir = std::path::Path::new("/etc/npm");
        let content = "certfile=corp-cert.pem\n\
                       keyfile=corp-key.pem\n\
                       //npm.internal/:cafile=ca.pem\n\
                       //npm.internal/:certfile=client.pem\n\
                       //npm.internal/:keyfile=client.key\n";
        let cfg =
            NpmrcConfig::parse_layer_with_source_dir(content, "/etc/npmrc", Some(dir), &no_env);

        // Global identity tags both paths with source_dir.
        let global_cert = cfg.tls.identity_certfile.as_ref().unwrap();
        assert_eq!(global_cert.path, PathBuf::from("corp-cert.pem"));
        assert_eq!(global_cert.source_dir.as_deref(), Some(dir));
        assert_eq!(
            global_cert.resolve(),
            PathBuf::from("/etc/npm/corp-cert.pem")
        );

        let global_key = cfg.tls.identity_keyfile.as_ref().unwrap();
        assert_eq!(global_key.resolve(), PathBuf::from("/etc/npm/corp-key.pem"));

        // Per-origin entries: same scoping.
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("per_origin entry");
        assert_eq!(per_origin.cafiles.len(), 1);
        assert_eq!(
            per_origin.cafiles[0].resolve(),
            PathBuf::from("/etc/npm/ca.pem")
        );
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().resolve(),
            PathBuf::from("/etc/npm/client.pem")
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().resolve(),
            PathBuf::from("/etc/npm/client.key")
        );
    }

    #[test]
    fn parse_layer_without_source_dir_leaves_path_unchanged_on_resolve() {
        // Tests / single-file convenience callers pass None — the
        // resolve() helper returns the verbatim path so loaders
        // fall back to ${PWD}-relative resolution (matching the
        // pre-58.3 behavior).
        let cfg = NpmrcConfig::parse(
            "certfile=/abs/cert.pem\nkeyfile=relative.pem\n",
            "test",
            &no_env,
        );
        let cert = cfg.tls.identity_certfile.as_ref().unwrap();
        assert!(cert.source_dir.is_none());
        // Absolute path: unchanged regardless.
        assert_eq!(cert.resolve(), PathBuf::from("/abs/cert.pem"));

        let key = cfg.tls.identity_keyfile.as_ref().unwrap();
        assert!(key.source_dir.is_none());
        // Relative + no source_dir → returned as-is (loader resolves vs cwd).
        assert_eq!(key.resolve(), PathBuf::from("relative.pem"));
    }

    #[test]
    fn merge_over_per_origin_certfile_higher_wins() {
        let mut acc = NpmrcConfig::parse_layer(
            "//npm.internal/:certfile=/system/cert.pem\n\
             //npm.internal/:keyfile=/system/key.pem\n",
            "system",
            &no_env,
        );
        let higher =
            NpmrcConfig::parse_layer("//npm.internal/:certfile=/user/cert.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = acc.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().source,
            "user",
            "higher layer's certfile must win"
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().source,
            "system",
            "lower layer's keyfile is preserved when higher doesn't set it"
        );
    }

    #[test]
    fn password_containing_colon_round_trips() {
        // Defensive regression test against a hypothetical future "split on
        // every `:`" refactor of the _username/_password join.
        //
        // Per RFC 7617, the userid:password wire format reserves only
        // the FIRST `:` as the separator; the password may contain
        // any number of additional `:` characters. The current
        // [`AuthBuffer::resolve`] does `format!("{user}:{pw}")` which
        // is correct (the encoded blob places the user-pass split at
        // the first `:` in the decoded form). A future change that
        // base64-decoded `_password`, joined, and then re-split on
        // every `:` would break passwords like `p@ss:word`.
        //
        // npm itself preserves the colons via the same path; this
        // test pins parity. The cost is ~10 LOC and it shields the
        // contract.
        use base64::Engine as _;
        let raw_pw = "p@ss:word";
        let encoded_pw = base64::engine::general_purpose::STANDARD.encode(raw_pw.as_bytes());
        let content = format!(
            "//npm.internal/:_username=user\n\
             //npm.internal/:_password={encoded_pw}\n"
        );
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.origin_auth.len(), 1);
        let auth = cfg.origin_auth.values().next().unwrap();
        match auth {
            RegistryAuth::Basic { credential, .. } => {
                let combined = base64::engine::general_purpose::STANDARD
                    .decode(credential.expose_secret())
                    .expect("credential is valid base64");
                let combined_str = std::str::from_utf8(&combined).unwrap();
                // The wire form must be `user:p@ss:word` (FIRST `:` is
                // the separator, all subsequent `:` are part of the
                // password). A buggy "split-on-every-:" round-trip
                // would either drop bytes or rejoin them in the wrong
                // place — pin the exact expected wire form.
                assert_eq!(combined_str, "user:p@ss:word");
            }
            other => panic!("expected Basic auth, got {other:?}"),
        }
    }

    // ---- Beyond the contract tests: defense-in-depth checks ----

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

    // ---- cross-layer credential merge ----

    #[test]
    fn cross_layer_username_password_merge() {
        // System-level file declares the username; user-level adds the
        // password. Finalize must combine them into Basic auth, not emit two
        // partial-credential warnings.
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
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), "YWxpY2U6cGFzcw==")
            }
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
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), "YWxpY2U6bmV3LXB3")
            }
            _ => panic!("expected Basic"),
        }
    }

    // ---- scheme-agnostic implicit-port match ----

    #[test]
    fn implicit_port_npmrc_matches_both_http_and_https() {
        // The user wrote `//host/:_authToken=X` with no explicit port.
        // Stored as port=None — matches a request on either http or https
        // (any port for that host).
        let content = "//npm.internal/:_authToken=AGNOSTIC\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let https_auth = cfg
            .auth_for_url("https://npm.internal/foo")
            .expect("https should match");
        let http_auth = cfg
            .auth_for_url("http://npm.internal/foo")
            .expect("http should match");
        match (https_auth, http_auth) {
            (RegistryAuth::Bearer { token: a, .. }, RegistryAuth::Bearer { token: b, .. }) => {
                assert_eq!(a.expose_secret(), "AGNOSTIC");
                assert_eq!(b.expose_secret(), "AGNOSTIC");
            }
            _ => panic!("expected Bearer on both"),
        }
    }

    #[test]
    fn explicit_port_443_does_not_leak_to_http() {
        // An explicit `:443` in the npmrc key means "this auth is for port 443 specifically",
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

    // ---- source-label in finalize warnings ----

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
        let auth = RegistryAuth::Bearer {
            origin: OriginKey {
                host_lower: "example.com".to_string(),
                port: None,
            },
            token: SecretString::from("very-secret"),
        };
        let formatted = format!("{auth:?}");
        assert!(!formatted.contains("very-secret"));
        assert!(formatted.contains("REDACTED"));
        // Origin must still be visible — it's not a secret.
        assert!(formatted.contains("example.com"));
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

    /// A URL of the shape `https://<userinfo>@<host>/...` resolves to
    /// `<host>` per RFC 3986; the pre-fix hand-rolled parser kept the
    /// `<userinfo>@<host>` blob as the "host" for auth matching while
    /// reqwest connected to `<host>`. That mismatch could quietly
    /// route the bearer for one origin to a different host. Pinning
    /// the parse here so a future refactor that drops `reqwest::Url`
    /// can't reintroduce the gap.
    #[test]
    fn from_request_url_strips_userinfo_before_host_match() {
        let key =
            OriginKey::from_request_url("https://attacker.com@registry.npmjs.org/foo").unwrap();
        assert_eq!(key.host_lower, "registry.npmjs.org");
        assert_eq!(key.port, Some(443));
    }

    #[test]
    fn from_request_url_strips_user_and_password_userinfo() {
        let key = OriginKey::from_request_url("https://user:pass@registry.npmjs.org/foo").unwrap();
        assert_eq!(key.host_lower, "registry.npmjs.org");
        assert_eq!(key.port, Some(443));
    }

    #[test]
    fn from_request_url_with_userinfo_does_not_match_attacker_origin() {
        // End-to-end of the H2 finding: an attacker who can inject
        // `https://attacker.com@npm.internal/...` into a lockfile or
        // metadata response must NOT cause the npm.internal bearer to
        // be sent. Pre-fix the OriginKey's host was the literal blob
        // including `attacker.com@`, so a lookup by that key returned
        // None — but lookup by the connect-host (npm.internal) was
        // unchanged. The hazard was that any future code path that
        // built the OriginKey via from_request_url and then trusted
        // it as "the connect origin" was wrong by construction.
        let content = "//npm.internal/:_authToken=INT_TOKEN\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        // Post-fix: the userinfo URL resolves to host npm.internal
        // and DOES match the configured auth — same behaviour reqwest
        // exhibits when it dispatches the request.
        assert!(
            cfg.auth_for_url("https://attacker.com@npm.internal/x")
                .is_some(),
            "userinfo URL must resolve to npm.internal and match the configured auth — \
             this proves the parser is not misled by the userinfo blob",
        );
        // A URL whose actual host is attacker.example must NOT match.
        assert!(
            cfg.auth_for_url("https://npm.internal@attacker.example/x")
                .is_none(),
            "userinfo `npm.internal` must NOT confuse the parser into matching \
             the configured `npm.internal` auth — the real host is attacker.example",
        );
    }

    #[test]
    fn from_request_url_handles_ipv6_host_without_brackets() {
        // Sanity that the reqwest::Url-based parser produces the
        // bracket-stripped form, matching what the previous parser
        // emitted via [`from_host_port_str`].
        let key = OriginKey::from_request_url("https://[::1]:8443/foo").unwrap();
        assert_eq!(key.host_lower, "[::1]");
        assert_eq!(key.port, Some(8443));
    }

    #[test]
    fn from_request_url_rejects_unsupported_scheme() {
        assert!(OriginKey::from_request_url("ftp://npm.internal/x").is_none());
        assert!(OriginKey::from_request_url("file:///tmp/foo").is_none());
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

    /// M40: pre-fix, a path-scoped `_authToken` key was widened to
    /// the entire origin (with a warning). Post-fix the credential
    /// is REFUSED and the warning explains how to opt in. Closes the
    /// shared-host over-disclosure window where a narrow GitLab
    /// project-scoped token was sent to unrelated projects on the
    /// same host.
    #[test]
    fn path_prefixed_auth_key_is_refused_with_explanatory_warning() {
        let content = "//gitlab.com/api/v4/projects/123/packages/npm/:_authToken=glpat-x\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(
            cfg.auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
                .is_none(),
            "path-scoped credential must NOT be materialized after the fix",
        );
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("refusing to materialize")
                    && w.contains("path-scoped npmrc credential")),
            "explanatory warning required; got {:?}",
            cfg.warnings
        );
    }

    /// Origin-scoped (no path) credentials still work — the M40 fix
    /// only refuses path-scoped credential keys.
    #[test]
    fn origin_scoped_auth_key_still_materialized_after_m40() {
        let content = "//gitlab.com/:_authToken=glpat-y\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
            .expect("origin-only key should hit");
        match auth {
            RegistryAuth::Bearer { token, .. } => assert_eq!(token.expose_secret(), "glpat-y"),
            _ => panic!("expected Bearer"),
        }
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
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "BEARER"),
            other => panic!("expected Bearer (precedence rule), got {other:?}"),
        }
    }

    // ---- Walker tests ----

    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Write a `.npmrc` containing `content` at `dir/.npmrc` and return
    /// the file path. Test ergonomics — the panics here are fine because
    /// a test that can't write to its own tempdir is a real failure.
    fn write_npmrc(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join(".npmrc");
        fs::write(&path, content).expect("write npmrc");
        path
    }

    #[test]
    fn walker_finds_project_only() {
        let proj = TempDir::new().unwrap();
        write_npmrc(proj.path(), "registry=https://project.example/\n");
        let cfg = NpmrcConfig::load_from_paths(&[proj.path().join(".npmrc")], &no_env);
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://project.example"
        );
        assert!(cfg.errors.is_empty());
        assert!(cfg.warnings.is_empty());
    }

    #[test]
    fn walker_user_only() {
        let home = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://user.example/\n");
        let cfg = NpmrcConfig::load_from_paths(&[home.path().join(".npmrc")], &no_env);
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://user.example"
        );
    }

    #[test]
    fn walker_project_overrides_user_per_key() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://user.example/\n");
        write_npmrc(proj.path(), "registry=https://project.example/\n");
        // Lowest first, highest last.
        let cfg = NpmrcConfig::load_from_paths(
            &[home.path().join(".npmrc"), proj.path().join(".npmrc")],
            &no_env,
        );
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://project.example",
            "project layer must win per-key"
        );
    }

    #[test]
    fn walker_merges_non_overlapping_keys_across_layers() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(home.path(), "@a:registry=https://a.example/\n");
        write_npmrc(proj.path(), "@b:registry=https://b.example/\n");
        let cfg = NpmrcConfig::load_from_paths(
            &[home.path().join(".npmrc"), proj.path().join(".npmrc")],
            &no_env,
        );
        assert_eq!(cfg.scope_registries.len(), 2);
        assert!(cfg.scope_registries.contains_key("@a"));
        assert!(cfg.scope_registries.contains_key("@b"));
    }

    #[test]
    fn walker_skips_missing_files_silently() {
        let nonexistent = PathBuf::from("/definitely/does/not/exist/.npmrc");
        let other = PathBuf::from("/also/missing/.npmrc");
        let cfg = NpmrcConfig::load_from_paths(&[nonexistent, other], &no_env);
        assert!(
            cfg.warnings.is_empty(),
            "NotFound must be silent: {:?}",
            cfg.warnings
        );
        assert!(cfg.errors.is_empty());
        assert!(cfg.default_registry.is_none());
    }

    #[test]
    fn walker_warns_on_other_io_errors() {
        // Pass a directory path. `read_to_string` on a directory errors
        // with EISDIR-ish kind; not NotFound, so we warn (not silent).
        // Cross-platform — directories aren't readable as strings on
        // Unix or Windows.
        let dir = TempDir::new().unwrap();
        let cfg = NpmrcConfig::load_from_paths(&[dir.path().to_path_buf()], &no_env);
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("failed to read"));
        assert!(cfg.errors.is_empty(), "non-fatal — install must continue");
    }

    #[test]
    fn walker_cross_layer_credential_merge_end_to_end() {
        // System layer sets _username, project layer sets _password; walker
        // composes them via merge_over before finalize — must produce one
        // Basic credential with no partial-credential warnings.
        let system_dir = TempDir::new().unwrap();
        let proj_dir = TempDir::new().unwrap();
        write_npmrc(system_dir.path(), "//npm.internal/:_username=alice\n");
        write_npmrc(proj_dir.path(), "//npm.internal/:_password=cGFzcw==\n");
        let cfg = NpmrcConfig::load_from_paths(
            &[
                system_dir.path().join(".npmrc"),
                proj_dir.path().join(".npmrc"),
            ],
            &no_env,
        );
        assert!(
            cfg.warnings.is_empty(),
            "no partial-credential warnings: {:?}",
            cfg.warnings
        );
        let auth = cfg
            .auth_for_url("https://npm.internal/foo")
            .expect("composed Basic credential should resolve");
        match auth {
            // base64("alice:pass") == "YWxpY2U6cGFzcw=="
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), "YWxpY2U6cGFzcw==")
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    /// Test helper — write a regular-file `package.json` so the dir
    /// counts as a project marker for `walk_for_project_npmrc`. `{}` is
    /// enough; we never parse it.
    fn mark_as_project_root(dir: &Path) {
        fs::write(dir.join("package.json"), "{}").expect("write package.json");
    }

    /// Match a `ProjectNpmrcOutcome::File(_)` and return the path.
    fn expect_outcome_file(outcome: ProjectNpmrcOutcome) -> PathBuf {
        match outcome {
            ProjectNpmrcOutcome::File(p) => p,
            other => panic!("expected ProjectNpmrcOutcome::File, got {other:?}"),
        }
    }

    fn assert_outcome_none(outcome: ProjectNpmrcOutcome) {
        match outcome {
            ProjectNpmrcOutcome::None => {}
            other => panic!("expected ProjectNpmrcOutcome::None, got {other:?}"),
        }
    }

    #[test]
    fn walker_returns_npmrc_when_marker_present_at_same_level() {
        let home = TempDir::new().unwrap();
        let proj = home.path().join("proj");
        fs::create_dir_all(&proj).unwrap();
        mark_as_project_root(&proj);
        let expected = write_npmrc(&proj, "registry=https://here/\n");
        let outcome = walk_for_project_npmrc(&proj, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&expected).unwrap()
        );
    }

    #[test]
    fn walker_finds_npmrc_at_higher_marker_when_cwd_lacks_one() {
        // cwd is a leaf inside a marked project; the .npmrc lives at
        // the same marker level. Walker walks up: leaf → parent → marker
        // dir, finds .npmrc there.
        let home = TempDir::new().unwrap();
        let project_root = home.path().join("project");
        let leaf = project_root.join("src/utils");
        fs::create_dir_all(&leaf).unwrap();
        mark_as_project_root(&project_root);
        let expected = write_npmrc(&project_root, "registry=https://higher/\n");
        let outcome = walk_for_project_npmrc(&leaf, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&expected).unwrap()
        );
    }

    #[test]
    fn walker_inherits_repo_root_npmrc_through_workspace_member() {
        // Monorepo layout: workspace member `packages/app` has its own package.json
        // but no .npmrc; workspace root has both. Running from `packages/app` must
        // inherit the workspace-root .npmrc — walker must not stop at the first marker.
        let home = TempDir::new().unwrap();
        let repo = home.path().join("repo");
        let app = repo.join("packages").join("app");
        fs::create_dir_all(&app).unwrap();
        mark_as_project_root(&repo);
        mark_as_project_root(&app);
        let expected = write_npmrc(&repo, "registry=https://workspace-root/\n");
        let outcome = walk_for_project_npmrc(&app, Some(home.path()));
        let found = expect_outcome_file(outcome);
        assert_eq!(
            fs::canonicalize(&found).unwrap(),
            fs::canonicalize(&expected).unwrap(),
            "workspace member must inherit repo-root .npmrc"
        );
    }

    #[test]
    fn walker_app_npmrc_wins_over_repo_npmrc_when_both_present() {
        // Defense for the inheritance fix: when BOTH the member and the
        // workspace root have an .npmrc, the closer one (member) wins.
        // Walker is bottom-up; first match returned.
        let home = TempDir::new().unwrap();
        let repo = home.path().join("repo");
        let app = repo.join("packages").join("app");
        fs::create_dir_all(&app).unwrap();
        mark_as_project_root(&repo);
        mark_as_project_root(&app);
        write_npmrc(&repo, "registry=https://workspace-root/\n");
        let app_npmrc = write_npmrc(&app, "registry=https://app-local/\n");
        let outcome = walk_for_project_npmrc(&app, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&app_npmrc).unwrap()
        );
    }

    #[test]
    fn walker_stops_at_home() {
        // No marker between cwd and home → None. A marker exactly AT
        // home is ignored (we stop AT home, not past it) so the user-
        // level layer is never double-counted as project.
        let home = TempDir::new().unwrap();
        mark_as_project_root(home.path());
        let child = home.path().join("project");
        fs::create_dir_all(&child).unwrap();
        let outcome = walk_for_project_npmrc(&child, Some(home.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn walker_returns_none_when_no_marker_anywhere() {
        // Bounded by tempdir as fake home. No marker anywhere reachable
        // from nested cwd → None even if a planted .npmrc exists below.
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        // Plant an .npmrc at the deeply-nested cwd. Without a marker,
        // the walker must NOT pick it up.
        write_npmrc(&nested, "registry=https://orphan/\n");
        let outcome = walk_for_project_npmrc(&nested, Some(dir.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn walker_rejects_directory_named_package_json_marker() {
        // A directory named `package.json` must NOT qualify as a project-root
        // marker — an attacker could `mkdir /tmp/package.json && touch /tmp/.npmrc`
        // to inject auth into any install run from /tmp/build/.
        let outer = TempDir::new().unwrap();
        let attacker_dir = outer.path().join("planted");
        let cwd = attacker_dir.join("build");
        fs::create_dir_all(&cwd).unwrap();
        // Directory (not a regular file) — must NOT count as a marker.
        fs::create_dir(attacker_dir.join("package.json")).unwrap();
        write_npmrc(&attacker_dir, "registry=https://attacker/\n");
        let outcome = walk_for_project_npmrc(&cwd, Some(outer.path()));
        assert_outcome_none(outcome);
    }

    #[cfg(unix)]
    #[test]
    fn walker_rejects_broken_symlink_named_package_json_marker() {
        // A broken-symlink package.json must not qualify the dir as a project root
        // for the same reason as a directory marker: it's not a regular file.
        use std::os::unix::fs::symlink;
        let outer = TempDir::new().unwrap();
        let attacker_dir = outer.path().join("planted");
        let cwd = attacker_dir.join("build");
        fs::create_dir_all(&cwd).unwrap();
        symlink("/does/not/exist/path", attacker_dir.join("package.json")).unwrap();
        write_npmrc(&attacker_dir, "registry=https://attacker/\n");
        let outcome = walk_for_project_npmrc(&cwd, Some(outer.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn discover_layer_paths_omits_project_when_no_marker() {
        // Same security contract at the public-API level: discovery
        // must NOT include a project layer if no marker was found,
        // even if `<cwd>/.npmrc` exists. This is the load-bearing
        // anti-injection guarantee for cwd-outside-home cases.
        let outer = TempDir::new().unwrap();
        let dir = outer.path().join("project-without-marker");
        fs::create_dir_all(&dir).unwrap();
        // Plant a .npmrc but no package.json — must be ignored.
        write_npmrc(&dir, "registry=https://injected/\n");
        let result = NpmrcConfig::discover_layer_paths(&dir, Some(outer.path()));
        // home boundary is the outer tempdir; dir itself has no marker.
        // Expect only builtin + system + user (3 paths) — NO project layer.
        assert_eq!(result.paths.len(), 3, "paths: {:?}", result.paths);
        assert!(
            !result.paths.iter().any(|p| p == &dir.join(".npmrc")),
            "planted .npmrc must NOT be in paths: {:?}",
            result.paths
        );
    }

    #[test]
    fn discover_layer_paths_warns_on_directory_dot_npmrc() {
        // When the project's .npmrc is a directory, surface a warning;
        // do NOT silently fall through to an ancestor.
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        fs::create_dir(proj.path().join(".npmrc")).unwrap();
        // home boundary: the parent of our tempdir, so the walk
        // doesn't hit anything outside our control.
        let home = proj.path().parent().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home));
        assert!(
            !result
                .paths
                .iter()
                .any(|p| p.ends_with(".npmrc") && p.starts_with(proj.path())),
            "directory .npmrc must NOT be in paths: {:?}",
            result.paths
        );
        assert_eq!(result.warnings.len(), 1, "warnings: {:?}", result.warnings);
        assert!(result.warnings[0].contains("is a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn discover_layer_paths_warns_on_broken_symlink() {
        // A broken symlink must surface a warning, not silently fall through.
        // Unix-only — Windows symlink semantics differ enough that a parallel
        // codepath in this test isn't worth maintaining.
        use std::os::unix::fs::symlink;
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        symlink("/nonexistent/target/path", proj.path().join(".npmrc"))
            .expect("create broken symlink");
        let home = proj.path().parent().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home));
        assert!(
            !result.paths.iter().any(|p| p.starts_with(proj.path())),
            "broken-symlink .npmrc must NOT be loaded: {:?}",
            result.paths
        );
        assert_eq!(result.warnings.len(), 1, "warnings: {:?}", result.warnings);
        assert!(
            result.warnings[0].contains("broken symlink"),
            "expected broken-symlink warning, got: {:?}",
            result.warnings[0]
        );
    }

    #[test]
    fn discover_layer_paths_includes_user_when_home_set() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        write_npmrc(proj.path(), "registry=https://p/\n");
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home.path()));
        assert_eq!(result.paths.len(), 4);
        assert_eq!(result.paths[0], PathBuf::from("/usr/etc/npmrc"));
        assert_eq!(result.paths[1], PathBuf::from("/etc/npmrc"));
        assert_eq!(result.paths[2], home.path().join(".npmrc"));
        assert_eq!(result.paths[3], proj.path().join(".npmrc"));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn discover_layer_paths_omits_user_when_home_none() {
        // Bound the search by giving discover a home-equivalent (the
        // tempdir's own parent) so we don't traverse the dev machine's
        // entire FS looking for an ancestor package.json. The
        // `home: None` argument means no user-level layer is included,
        // not "no home boundary at all".
        //
        // We can't easily test the home=None path in isolation without
        // potentially picking up the real `~/.npmrc` of whoever runs
        // the test. The contract under test here is just "no user layer
        // when home arg is None".
        let proj = TempDir::new().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), None);
        // First two are always builtin and system.
        assert!(result.paths.len() >= 2);
        assert_eq!(result.paths[0], PathBuf::from("/usr/etc/npmrc"));
        assert_eq!(result.paths[1], PathBuf::from("/etc/npmrc"));
        // Anything beyond paths[1] would be a project layer that
        // `find_project_root` discovered above our tempdir on the
        // dev machine. None of it should reference our own tempdir
        // (we never wrote a marker there).
        for p in &result.paths[2..] {
            assert!(
                !p.starts_with(proj.path()),
                "no project layer should reference our tempdir: {p:?}"
            );
        }
    }

    #[test]
    fn walker_propagates_env_lookup_per_layer() {
        // Each parsed layer goes through env interpolation independently.
        // System layer references $TOK_A, project references $TOK_B —
        // both must resolve via the same env_lookup we pass in.
        let system = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(system.path(), "//host-a/:_authToken=${TOK_A}\n");
        write_npmrc(proj.path(), "//host-b/:_authToken=${TOK_B}\n");
        let env = fixed_env(&[("TOK_A", "alpha"), ("TOK_B", "beta")]);
        let cfg = NpmrcConfig::load_from_paths(
            &[system.path().join(".npmrc"), proj.path().join(".npmrc")],
            &env,
        );
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        match cfg.auth_for_url("https://host-a/x").unwrap() {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "alpha"),
            _ => panic!("expected Bearer A"),
        }
        match cfg.auth_for_url("https://host-b/x").unwrap() {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "beta"),
            _ => panic!("expected Bearer B"),
        }
    }
}
