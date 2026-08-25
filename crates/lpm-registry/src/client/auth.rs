use super::*;

pub(super) struct RequestDestination {
    url: reqwest::Url,
    origin: crate::npmrc::OriginKey,
}

impl RequestDestination {
    pub(super) fn parse(url: &str) -> Result<Self, LpmError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| {
            LpmError::Registry(format!(
                "invalid registry URL '{}'",
                lpm_common::safe_url_origin(url)
            ))
        })?;
        let origin = crate::npmrc::OriginKey::from_parsed_url(&parsed).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid URL '{}' — must be http(s) with a host",
                lpm_common::safe_url_origin(url)
            ))
        })?;
        Ok(Self {
            url: parsed,
            origin,
        })
    }

    pub(super) fn as_url(&self) -> &reqwest::Url {
        &self.url
    }

    pub(super) fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub(super) fn origin(&self) -> &crate::npmrc::OriginKey {
        &self.origin
    }

    fn is_cleartext_non_loopback(&self) -> bool {
        if self.url.scheme() != "http" {
            return false;
        }
        let Some(host) = self.url.host_str() else {
            return true;
        };
        if host.eq_ignore_ascii_case("localhost") {
            return false;
        }
        let normalized_host = host.trim_start_matches('[').trim_end_matches(']');
        !normalized_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(super::url_gate::is_loopback_ip)
    }
}

/// Per-request auth posture.
///
/// Every public request method on `RegistryClient` is annotated with
/// one of these so the recovery layer (`execute_with_recovery`) can
/// decide whether to attach a bearer at all and whether to attempt a
/// silent refresh on 401.
///
/// - **AnonymousOnly**: never attach a bearer. Used for endpoints that
///   are universally public (npm fallback, health checks).
/// - **AnonymousPreferred**: never attach a bearer even when stored.
///   Used for endpoints that *may* accept auth but the fast path is
///   anonymous (search, public info reads). Avoids needless refresh
///   storms when an old token sits on disk.
/// - **AuthRequired**: attach the bearer if present; on 401, perform
///   a single silent refresh + retry for refresh-backed sessions.
///   Used for install / download / metadata for `@lpm.dev` packages,
///   publish, token management, account-scoped reads.
/// - **SessionRequired**: same as `AuthRequired` for transport, but
///   the **calling command** must additionally check that the
///   `SessionManager` source is `StoredSession`. Used for tunnel,
///   env pairing, and other features that require a real interactive
///   login (not `LPM_TOKEN`/`--token`/CI tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPosture {
    AnonymousOnly,
    AnonymousPreferred,
    AuthRequired,
    SessionRequired,
}

impl AuthPosture {
    /// Whether this posture attaches a bearer when one is available.
    pub fn attaches_bearer(self) -> bool {
        matches!(
            self,
            AuthPosture::AuthRequired | AuthPosture::SessionRequired
        )
    }

    /// Whether this posture allows a silent refresh + retry on 401.
    pub fn allows_recovery(self) -> bool {
        matches!(
            self,
            AuthPosture::AuthRequired | AuthPosture::SessionRequired
        )
    }
}

/// Apply an `.npmrc`-derived credential to a request builder.
///
/// Re-verifies that the auth's origin is compatible with the destination
/// URL before attaching the `Authorization` header. A mismatch hard-fails
/// with `LpmError::Registry` rather than silently dropping the auth or
/// leaking the token cross-origin. Anonymous (`auth = None`) is a no-op.
///
/// Used by both metadata fetches (`get_npm_metadata_from`) and tarball
/// downloads (`download_tarball_*_with_auth`) so the auth-scope
/// invariant is enforced uniformly across every request that carries
/// an npmrc credential.
pub(super) fn apply_npmrc_auth(
    req: reqwest::RequestBuilder,
    url: &str,
    auth: Option<&crate::npmrc::RegistryAuth>,
) -> Result<reqwest::RequestBuilder, LpmError> {
    let destination = RequestDestination::parse(url)?;
    apply_npmrc_auth_to_destination(req, &destination, auth)
}

pub(super) fn apply_npmrc_auth_to_destination(
    req: reqwest::RequestBuilder,
    destination: &RequestDestination,
    auth: Option<&crate::npmrc::RegistryAuth>,
) -> Result<reqwest::RequestBuilder, LpmError> {
    use secrecy::ExposeSecret;
    let Some(a) = auth else {
        return Ok(req);
    };
    if destination.is_cleartext_non_loopback() {
        return Err(LpmError::Registry(format!(
            "refusing to send registry credentials over cleartext HTTP to {}",
            lpm_common::safe_url_origin(destination.as_str())
        )));
    }
    if !a.matches_origin_path(destination.origin(), destination.as_url().path()) {
        return Err(LpmError::Registry(format!(
            "auth/destination scope mismatch: credential scoped to {} but request targets {} (this is an lpm bug — please report)",
            a.scope(),
            lpm_common::safe_url_origin(destination.as_str())
        )));
    }
    let req = match a {
        crate::npmrc::RegistryAuth::Bearer { token, .. } => {
            req.header("Authorization", format!("Bearer {}", token.expose_secret()))
        }
        crate::npmrc::RegistryAuth::Basic { credential, .. } => req.header(
            "Authorization",
            format!("Basic {}", credential.expose_secret()),
        ),
    };
    Ok(req)
}

/// Compute a stable opaque fingerprint for a `RegistryAuth` credential
/// PLUS the TLS client identity's cert PEM.
///
/// **Combinatorics:** the cache namespace is `(auth, identity)`-pair
/// scoped, not auth-only. Same URL + same auth + DIFFERENT identity
/// (e.g., user re-issued their client cert) → different cache
/// namespace. Without this, a private registry that varies content
/// per client identity could leak data across principals on the same
/// machine.
///
/// **Output shape:**
/// - Auth `None` + identity `None` → `"anon"` (canonical empty).
/// - Anything else → `"principal-<16hex>"`, where `<16hex>` is the
///   first 16 hex chars of `SHA-256(tagged_inputs)`. Variant tags
///   (`b:` Bearer, `a:` Basic, `i:` Identity) prevent shape
///   collisions across input kinds.
///
/// **Why hashes, not raw secrets:** the cache key flows through
/// `tracing::debug!` calls and may surface in stack traces / panic
/// messages. SHA-256 truncation reveals nothing about the credential
/// or cert while staying deterministic enough for warm-hit reuse
/// across calls with the same principal.
pub(super) fn principal_fingerprint(
    auth: Option<&crate::npmrc::RegistryAuth>,
    identity_fp: Option<&str>,
) -> String {
    use secrecy::ExposeSecret;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut tagged = false;
    match auth {
        None => {}
        Some(crate::npmrc::RegistryAuth::Bearer { token, .. }) => {
            hasher.update(b"b:");
            hasher.update(token.expose_secret().as_bytes());
            tagged = true;
        }
        Some(crate::npmrc::RegistryAuth::Basic { credential, .. }) => {
            hasher.update(b"a:");
            hasher.update(credential.expose_secret().as_bytes());
            tagged = true;
        }
    }
    if let Some(fp) = identity_fp {
        hasher.update(b"i:");
        hasher.update(fp.as_bytes());
        tagged = true;
    }
    if !tagged {
        return "anon".to_string();
    }
    let hash = format!("{:x}", hasher.finalize());
    format!("principal-{}", &hash[..16])
}

pub(super) fn bearer_principal_fingerprint(
    bearer: Option<&str>,
    identity_fp: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut tagged = false;
    if let Some(bearer) = bearer.filter(|value| !value.is_empty()) {
        hasher.update(b"b:");
        hasher.update(bearer.as_bytes());
        tagged = true;
    }
    if let Some(identity_fp) = identity_fp {
        hasher.update(b"i:");
        hasher.update(identity_fp.as_bytes());
        tagged = true;
    }
    if !tagged {
        return "anon".to_string();
    }
    let hash = format!("{:x}", hasher.finalize());
    format!("principal-{}", &hash[..16])
}

/// SHA-256 truncated fingerprint of a cert PEM blob — used as the
/// `identity_fp` input to [`principal_fingerprint`]. Hashing happens
/// once at client-build time; the resulting `Arc<str>` rides along
/// the cached client and feeds every cache-key composition for
/// requests that route to it.
pub(super) fn cert_pem_fingerprint(pem: &[u8]) -> Arc<str> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pem);
    let hash = format!("{:x}", hasher.finalize());
    Arc::from(&hash[..16])
}
