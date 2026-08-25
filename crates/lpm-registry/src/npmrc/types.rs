use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

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
    pub(super) fn from_npmrc_url(raw: &str) -> Self {
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
    pub pem_bytes: Arc<Vec<u8>>,
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
    pub(super) fn merge_over(&mut self, other: OriginTlsOverrides) {
        if !other.cafiles.is_empty() {
            self.cafiles = other.cafiles;
        }
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

impl TlsOverrides {
    pub(crate) fn is_empty(&self) -> bool {
        self.extra_roots.is_empty()
            && !matches!(self.strict_ssl.as_ref(), Some(setting) if !setting.value)
            && self.identity_certfile.is_none()
            && self.identity_keyfile.is_none()
            && self.per_origin.is_empty()
    }
}

/// Origin key for auth lookup: case-insensitive host + optional port.
///
/// `port` is `Option<u16>`:
/// - `None` — port was unspecified in the npmrc key (`//host/`). The
///   stored entry matches request URLs without an explicit non-default port.
/// - `Some(p)` — port was explicit (`//host:p/`). The stored entry
///   matches only that exact port.
///
/// Scheme is intentionally absent — npm's nerf-dart auth keys
/// (`//host[:port]/`) are scheme-agnostic. The `--insecure` flag
/// governs the http/https decision separately at request-build time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginKey {
    pub host_lower: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthScope {
    pub origin: OriginKey,
    pub path_prefix: Arc<str>,
}

impl AuthScope {
    pub fn from_origin(origin: OriginKey) -> Self {
        Self {
            origin,
            path_prefix: Arc::from("/"),
        }
    }

    pub(super) fn from_npmrc_scope(scope: &str) -> Option<Self> {
        let (host_port, path) = scope.split_once('/').unwrap_or((scope, ""));
        let origin = OriginKey::from_host_port_str(host_port, None)?;
        let path_prefix = if path.is_empty() {
            Arc::from("/")
        } else {
            let mut normalized = String::with_capacity(path.len() + 2);
            normalized.push('/');
            normalized.push_str(path.trim_matches('/'));
            normalized.push('/');
            Arc::from(normalized)
        };
        Some(Self {
            origin,
            path_prefix,
        })
    }

    pub(super) fn matches(&self, origin: &OriginKey, path: &str) -> bool {
        if self.origin != *origin {
            return false;
        }
        if self.path_prefix.as_ref() == "/" {
            return true;
        }
        let without_trailing_slash = self.path_prefix.trim_end_matches('/');
        path == without_trailing_slash || path.starts_with(self.path_prefix.as_ref())
    }
}

impl std::fmt::Display for AuthScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.origin,
            self.path_prefix.trim_start_matches('/')
        )
    }
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
    /// see it. A missing/default port remains `None`; a non-default explicit
    /// port remains `Some(port)`, matching WHATWG `URL.host` and npm 12's
    /// registry-auth scoping.
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
        Self::from_parsed_url(&parsed)
    }

    pub(crate) fn from_parsed_url(parsed: &reqwest::Url) -> Option<Self> {
        if !matches!(parsed.scheme(), "https" | "http") {
            return None;
        }
        let host = parsed.host_str()?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        Some(Self {
            host_lower: host.to_ascii_lowercase(),
            port: parsed.port(),
        })
    }
}

/// Auth credential to attach to a request.
///
/// Each variant carries the [`AuthScope`] the credential is scoped to.
/// `RegistryClient::get_npm_metadata_from` re-verifies that this scope
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
        scope: AuthScope,
        token: SecretString,
    },
    /// Sent as `Authorization: Basic <b64>`. From `_auth=...` directly,
    /// or computed by joining `username` + base64-decoded `_password`.
    Basic {
        scope: AuthScope,
        credential: SecretString,
    },
}

impl RegistryAuth {
    /// The origin this credential is scoped to. The fetch site uses
    /// this to verify the destination URL before attaching auth —
    /// never trust a separately-supplied auth/URL pair.
    pub fn origin(&self) -> &OriginKey {
        match self {
            Self::Bearer { scope, .. } | Self::Basic { scope, .. } => &scope.origin,
        }
    }

    pub fn scope(&self) -> &AuthScope {
        match self {
            Self::Bearer { scope, .. } | Self::Basic { scope, .. } => scope,
        }
    }

    /// Whether this credential is acceptable to attach to a request to
    /// `dest`. Mirrors the [`NpmrcConfig::auth_for_url`] match rule:
    /// same canonical host and the same explicit-port posture.
    pub fn matches_destination(&self, dest: &reqwest::Url) -> bool {
        let Some(origin) = OriginKey::from_parsed_url(dest) else {
            return false;
        };
        self.matches_origin_path(&origin, dest.path())
    }

    pub(crate) fn matches_origin_path(&self, origin: &OriginKey, path: &str) -> bool {
        self.scope().matches(origin, path)
    }

    /// Stable auth identity for security-preserving workspace grouping.
    /// The digest keeps raw credential material out of grouping keys and logs.
    pub(crate) fn credential_fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        match self {
            Self::Bearer { token, .. } => {
                hasher.update(b"bearer:");
                hasher.update(token.expose_secret().as_bytes());
            }
            Self::Basic { credential, .. } => {
                hasher.update(b"basic:");
                hasher.update(credential.expose_secret().as_bytes());
            }
        }
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { .. } => {
                f.write_str("RegistryAuth::Bearer { scope: [REDACTED], token: [REDACTED] }")
            }
            Self::Basic { .. } => {
                f.write_str("RegistryAuth::Basic { scope: [REDACTED], credential: [REDACTED] }")
            }
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
                    scope: a_s,
                    token: a_t,
                },
                Self::Bearer {
                    scope: b_s,
                    token: b_t,
                },
            ) => a_s == b_s && a_t.expose_secret() == b_t.expose_secret(),
            (
                Self::Basic {
                    scope: a_s,
                    credential: a_c,
                },
                Self::Basic {
                    scope: b_s,
                    credential: b_c,
                },
            ) => a_s == b_s && a_c.expose_secret() == b_c.expose_secret(),
            _ => false,
        }
    }
}

impl Eq for RegistryAuth {}

/// A value that remembers where it came from. Threaded through layered
/// merges so finalize warnings can cite the contributing source file
/// (and line, when relevant) — not just the host/port the credential
/// was for.
#[derive(Clone)]
pub(super) struct TaggedValue {
    value: String,
    source: String,
    line: usize,
}

impl std::fmt::Debug for TaggedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaggedValue")
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .field("line", &self.line)
            .finish()
    }
}

impl TaggedValue {
    pub(super) fn new(value: String, source: &str, line: usize) -> Self {
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
/// by different layers (e.g., system-wide `username` + per-user
/// `_password`) compose correctly.
#[derive(Default, Clone, Debug)]
pub(super) struct AuthBuffer {
    pub(super) auth_token: Option<TaggedValue>,
    pub(super) auth_b64: Option<TaggedValue>,
    pub(super) username: Option<TaggedValue>,
    pub(super) password_b64: Option<TaggedValue>,
}

impl AuthBuffer {
    /// Resolve to a final `RegistryAuth`, or `None` if nothing usable.
    /// Precedence matches npm: `_authToken` > `_auth` > `username`+`_password`.
    /// Warnings about partial/malformed credentials cite the source
    /// label of whichever subkey contributed the partial state.
    pub(super) fn resolve(
        self,
        scope: &AuthScope,
        warnings: &mut Vec<String>,
    ) -> Option<RegistryAuth> {
        if let Some(t) = self.auth_token
            && !t.value.is_empty()
        {
            return Some(RegistryAuth::Bearer {
                scope: scope.clone(),
                token: SecretString::from(t.value),
            });
        }
        if let Some(b) = self.auth_b64
            && !b.value.is_empty()
        {
            return Some(RegistryAuth::Basic {
                scope: scope.clone(),
                credential: SecretString::from(b.value),
            });
        }
        match (self.username, self.password_b64) {
            (Some(user), Some(pw_tagged)) => {
                if user.value.is_empty() || pw_tagged.value.is_empty() {
                    return None;
                }
                let pw = match base64::engine::general_purpose::STANDARD.decode(&pw_tagged.value) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            lpm_common::push_npmrc_diagnostic(warnings, &pw_tagged.source, || {
                                format!(
                                    "{}:{}: {} _password is not valid UTF-8 after base64 decode; ignoring credential",
                                    pw_tagged.source, pw_tagged.line, scope
                                )
                            });
                            return None;
                        }
                    },
                    Err(_) => {
                        lpm_common::push_npmrc_diagnostic(warnings, &pw_tagged.source, || {
                            format!(
                                "{}:{}: {} _password is not valid base64; ignoring credential",
                                pw_tagged.source, pw_tagged.line, scope
                            )
                        });
                        return None;
                    }
                };
                let combined = format!("{}:{}", user.value, pw);
                let encoded = base64::engine::general_purpose::STANDARD.encode(combined.as_bytes());
                Some(RegistryAuth::Basic {
                    scope: scope.clone(),
                    credential: SecretString::from(encoded),
                })
            }
            (Some(user), None) => {
                lpm_common::push_npmrc_diagnostic(warnings, &user.source, || {
                    format!(
                        "{}:{}: {} has username but no _password (across all merged layers); ignoring partial credential",
                        user.source, user.line, scope
                    )
                });
                None
            }
            (None, Some(pw_tagged)) => {
                lpm_common::push_npmrc_diagnostic(warnings, &pw_tagged.source, || {
                    format!(
                        "{}:{}: {} has _password but no username (across all merged layers); ignoring partial credential",
                        pw_tagged.source, pw_tagged.line, scope
                    )
                });
                None
            }
            (None, None) => None,
        }
    }

    /// Merge `other` ON TOP OF `self` per subkey. `other`'s `Some` slots
    /// overwrite `self`'s; `other`'s `None` slots leave `self` unchanged.
    /// This is what makes cross-layer credential composition work
    /// (e.g., `username` from system-wide, `_password` from project).
    pub(super) fn merge_over(&mut self, other: AuthBuffer) {
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
