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

mod config;
mod discovery;
mod parse;
mod types;

pub use config::NpmrcConfig;
pub use discovery::LayerDiscovery;
pub use types::{
    OriginKey, OriginTlsOverrides, RegistryAuth, RegistryKind, RegistryTarget, TaggedBool,
    TaggedPath, TaggedRoot, TlsOverrides,
};
