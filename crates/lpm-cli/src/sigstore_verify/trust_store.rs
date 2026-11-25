//! Which Sigstore trust root verification uses, and how it stays current.
//!
//! Verification uses the newest trust root this machine holds: one that
//! Sigstore's TUF repository delivered on an earlier run and that still
//! verifies, or the one built into the binary when that is newer or nothing
//! usable is cached. When a bundle needs a key or certificate authority that
//! trust root lacks, the store fetches Sigstore's current trust root, at most
//! once an hour, and verifies again. Self-update fetches it before
//! verifying a release, so keys Sigstore has retired stop counting there.
//!
//! A failed fetch never weakens verification: the store keeps the trust root
//! it had, which is never older than the one built into the binary.

use super::bundle::verify_sigstore_bundle_with;
use super::trust_root::EMBEDDED_TRUST_ROOT_JSON;
use super::tuf::{self, Fetcher, Freshness, TrustedMetadata, VerifiedTrustedRoot};
use super::{IdentityExpectations, TrustRoot, VerifiedProvenance, VerifyError, VerifyOptions};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// Version of Sigstore's targets metadata that signed the trust root built
/// into the binary. A cached trust root from older targets metadata is
/// ignored.
pub(crate) const EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION: u64 = 14;

const EMBEDDED_TUF_ROOT: &[u8] = include_bytes!("../../assets/sigstore_tuf_root.json");

const DEFAULT_REPOSITORY_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Points refreshes at a mirror of Sigstore's TUF repository, or turns them
/// off with `off`. Everything fetched is verified against the TUF root built
/// into the binary, so a mirror can withhold updates but can't forge them.
pub(crate) const REPOSITORY_URL_OVERRIDE_ENV: &str = "LPM_SIGSTORE_TUF_URL_OVERRIDE";

const CACHE_FILE_NAME: &str = "sigstore-trust.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const CACHE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// How long one fetch's outcome stands before a signature that needs newer
/// keys may fetch again. Most commands finish well within it; it bounds what
/// a long-running process, such as an MCP server, misses.
const REFETCH_AFTER: Duration = Duration::from_secs(60 * 60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// When a verification fetches Sigstore's current trust root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustRefresh {
    /// Fetch it before verifying, so keys Sigstore has retired since the
    /// trust root this machine holds stop counting. A failed fetch falls
    /// back to the trust root already held.
    BeforeVerifying,
    /// Fetch it only when the trust root held lacks a key or certificate
    /// authority the bundle needs.
    WhenMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Repository {
    Url(String),
    Disabled,
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    schema_version: u32,
    metadata: TrustedMetadata,
}

pub(crate) struct TrustStore {
    embedded_tuf_root: Cow<'static, [u8]>,
    embedded_trusted_root: Cow<'static, [u8]>,
    embedded_targets_version: u64,
    cache_file: Option<PathBuf>,
    repository: Repository,
    current: RwLock<Option<Arc<TrustRoot>>>,
    last_fetch: tokio::sync::Mutex<Option<(Instant, Result<(), String>)>>,
    /// The last metadata this process verified, the rollback baseline when
    /// the cache can't be written or another process wrote an older one.
    last_metadata: Mutex<Option<TrustedMetadata>>,
}

/// The store every verification in this process shares.
pub(crate) fn global() -> &'static TrustStore {
    static STORE: OnceLock<TrustStore> = OnceLock::new();
    STORE.get_or_init(TrustStore::from_environment)
}

/// Verify `body` like [`super::verify_sigstore_bundle`], fetching
/// Sigstore's current trust root as `refresh` says.
pub async fn verify_sigstore_bundle_refreshing(
    body: &[u8],
    expectations: &IdentityExpectations,
    options: VerifyOptions,
    refresh: TrustRefresh,
) -> Result<VerifiedProvenance, VerifyError> {
    global().verify(body, expectations, options, refresh).await
}

impl TrustStore {
    fn from_environment() -> Self {
        let cache_file = lpm_common::LpmRoot::from_env()
            .ok()
            .map(|root| root.cache_metadata().join(CACHE_FILE_NAME));
        Self {
            embedded_tuf_root: Cow::Borrowed(EMBEDDED_TUF_ROOT),
            embedded_trusted_root: Cow::Borrowed(EMBEDDED_TRUST_ROOT_JSON),
            embedded_targets_version: EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION,
            cache_file,
            repository: repository_from_environment(),
            current: RwLock::new(None),
            last_fetch: tokio::sync::Mutex::new(None),
            last_metadata: Mutex::new(None),
        }
    }

    /// The trust root verification uses now.
    pub(crate) fn current(&self) -> Result<Arc<TrustRoot>, VerifyError> {
        if let Some(root) = self
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            return Ok(Arc::clone(root));
        }
        let loaded = Arc::new(self.load()?);
        let mut slot = self.current.write().unwrap_or_else(PoisonError::into_inner);
        Ok(Arc::clone(slot.get_or_insert(loaded)))
    }

    pub(crate) async fn verify(
        &self,
        body: &[u8],
        expectations: &IdentityExpectations,
        options: VerifyOptions,
        refresh: TrustRefresh,
    ) -> Result<VerifiedProvenance, VerifyError> {
        if refresh == TrustRefresh::BeforeVerifying
            && let Err(error) = self.refresh().await
        {
            tracing::debug!(
                target: "lpm_cli::sigstore_verify",
                %error,
                "verifying with the Sigstore trust root this machine holds",
            );
        }
        let used = self.current()?;
        let missing = match verify_sigstore_bundle_with(body, expectations, options, &used) {
            Err(error) if error.is_missing_trust_material() => error,
            outcome => return outcome,
        };
        let refreshed = self.refresh().await;
        let latest = self.current()?;
        if !Arc::ptr_eq(&used, &latest) {
            return verify_sigstore_bundle_with(body, expectations, options, &latest);
        }
        match refreshed {
            Ok(()) => Err(missing),
            Err(refresh) => Err(VerifyError::TrustRootNotRefreshed {
                error: Box::new(missing),
                refresh,
            }),
        }
    }

    /// Fetch Sigstore's current trust root and use it from now on. Calls
    /// within [`REFETCH_AFTER`] of a fetch return its outcome instead, and
    /// concurrent calls share one fetch.
    async fn refresh(&self) -> Result<(), String> {
        let mut last_fetch = self.last_fetch.lock().await;
        if let Some((at, outcome)) = last_fetch.as_ref()
            && at.elapsed() < REFETCH_AFTER
        {
            return outcome.clone();
        }
        let outcome = self.fetch_current().await;
        *last_fetch = Some((Instant::now(), outcome.clone()));
        outcome
    }

    async fn fetch_current(&self) -> Result<(), String> {
        let Repository::Url(url) = &self.repository else {
            return Err(format!(
                "fetching it is turned off by {REPOSITORY_URL_OVERRIDE_ENV}=off"
            ));
        };
        let fetcher = HttpFetcher::new(url)?;
        let stored = self.newest_stored_metadata();
        let metadata = tokio::time::timeout(
            REFRESH_TIMEOUT,
            tuf::refresh(
                &self.embedded_tuf_root,
                stored.as_ref(),
                &fetcher,
                SystemTime::now(),
            ),
        )
        .await
        .map_err(|_| {
            format!(
                "{url} didn't finish answering within {} seconds",
                REFRESH_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| error.to_string())?;
        let verified = metadata
            .verified_trusted_root(&self.embedded_tuf_root)
            .map_err(|error| error.to_string())?;
        if verified.targets_version < self.embedded_targets_version {
            return Err(format!(
                "{url} serves targets metadata version {}, older than the version {} \
                 that signed the trust root built into LPM",
                verified.targets_version, self.embedded_targets_version
            ));
        }
        let root = usable_trust_root(&verified.bytes, SystemTime::now())?;
        *self
            .last_metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(metadata.clone());
        self.write_cache(metadata).await;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(root));
        tracing::debug!(
            target: "lpm_cli::sigstore_verify",
            targets_version = verified.targets_version,
            "using Sigstore's current trust root",
        );
        Ok(())
    }

    fn load(&self) -> Result<TrustRoot, VerifyError> {
        let cached = self
            .read_cached_trusted_root()
            .filter(|cached| cached.targets_version >= self.embedded_targets_version)
            .and_then(|cached| {
                usable_trust_root(&cached.bytes, SystemTime::now())
                    .inspect_err(|error| {
                        tracing::debug!(
                            target: "lpm_cli::sigstore_verify",
                            %error,
                            "ignoring the cached Sigstore trust root",
                        );
                    })
                    .ok()
            });
        let root = match cached {
            Some(root) => root,
            None => TrustRoot::parse(&self.embedded_trusted_root)?,
        };
        if let Some(retires) = root.within_warn_window(SystemTime::now()) {
            tracing::debug!(
                target: "lpm_cli::sigstore_verify",
                retires_at = %retires.to_plain_utc(),
                "a role in the Sigstore trust root in use retires soon; \
                 a signature that needs a newer key fetches Sigstore's current trust root",
            );
        }
        Ok(root)
    }

    fn read_cached_metadata(&self) -> Option<TrustedMetadata> {
        let path = self.cache_file.as_ref()?;
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(
                        target: "lpm_cli::sigstore_verify",
                        path = %path.display(),
                        %error,
                        "can't read the cached Sigstore trust root",
                    );
                }
                return None;
            }
        };
        let mut bytes = Vec::new();
        file.take(CACHE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > CACHE_MAX_BYTES {
            return None;
        }
        let cache: CacheFile = serde_json::from_slice(&bytes).ok()?;
        (cache.schema_version == CACHE_SCHEMA_VERSION).then_some(cache.metadata)
    }

    fn read_cached_trusted_root(&self) -> Option<VerifiedTrustedRoot> {
        let metadata = self.read_cached_metadata()?;
        metadata
            .verified_trusted_root(&self.embedded_tuf_root)
            .inspect_err(|error| {
                tracing::debug!(
                    target: "lpm_cli::sigstore_verify",
                    %error,
                    "ignoring the cached Sigstore trust root",
                );
            })
            .ok()
    }

    /// The newer of the cached metadata and what this process last verified,
    /// whichever still verifies.
    fn newest_stored_metadata(&self) -> Option<TrustedMetadata> {
        let in_memory = self
            .last_metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        [self.read_cached_metadata(), in_memory]
            .into_iter()
            .flatten()
            .filter_map(|metadata| Some((self.freshness(&metadata)?, metadata)))
            .max_by_key(|(freshness, _)| *freshness)
            .map(|(_, metadata)| metadata)
    }

    fn freshness(&self, metadata: &TrustedMetadata) -> Option<Freshness> {
        metadata.freshness(&self.embedded_tuf_root).ok()
    }

    /// Cache `metadata` unless another process already cached newer
    /// metadata, so concurrent fetches that finish out of order never roll
    /// the cache back.
    async fn write_cache(&self, metadata: TrustedMetadata) {
        let Some(path) = &self.cache_file else {
            return;
        };
        let Some(ours) = self.freshness(&metadata) else {
            return;
        };
        let written = async {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(lpm_common::LpmError::Io)?;
            }
            lpm_common::with_exclusive_lock_async(path.with_extension("lock"), async {
                let cached = self
                    .read_cached_metadata()
                    .and_then(|cached| self.freshness(&cached));
                if cached.is_some_and(|cached| cached > ours) {
                    return Ok(());
                }
                let cache = CacheFile {
                    schema_version: CACHE_SCHEMA_VERSION,
                    metadata,
                };
                let bytes = serde_json::to_vec(&cache)
                    .map_err(|error| lpm_common::LpmError::Io(std::io::Error::other(error)))?;
                lpm_common::write_file_atomic_with_options(
                    path,
                    bytes,
                    lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
                )
                .map_err(lpm_common::LpmError::Io)
            })
            .await
        }
        .await;
        if let Err(error) = written {
            tracing::debug!(
                target: "lpm_cli::sigstore_verify",
                path = %path.display(),
                %error,
                "can't cache Sigstore's current trust root; the next run fetches it again",
            );
        }
    }
}

/// Parse a trust root Sigstore's repository delivered, refusing one in which
/// a role has no usable key because of entries this version can't read.
/// Using it would fail every verification the held trust root still passes.
/// A role whose readable keys Sigstore retired is a decision, and stands.
fn usable_trust_root(bytes: &[u8], now: SystemTime) -> Result<TrustRoot, String> {
    let (root, skipped) =
        TrustRoot::parse_skipping_unreadable(bytes).map_err(|error| error.to_string())?;
    let unusable: Vec<&str> = root
        .roles_without_active_key(now)
        .into_iter()
        .filter(|role| skipped.contains(role))
        .collect();
    if unusable.is_empty() {
        Ok(root)
    } else {
        Err(format!(
            "its {} entries are in a form this version of LPM can't read",
            unusable.join(", ")
        ))
    }
}

fn repository_from_environment() -> Repository {
    // Unit tests build their own stores, so the shared one never reaches
    // the network.
    if cfg!(test) {
        return Repository::Disabled;
    }
    repository_from_override(std::env::var(REPOSITORY_URL_OVERRIDE_ENV).ok())
}

fn repository_from_override(value: Option<String>) -> Repository {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Repository::Url(DEFAULT_REPOSITORY_URL.to_string());
    };
    if value.eq_ignore_ascii_case("off") {
        return Repository::Disabled;
    }
    let shown = crate::install_ui::safe_url_origin(&value);
    if crate::release_lookup::accept_override(&value) {
        tracing::warn!(
            env_var = REPOSITORY_URL_OVERRIDE_ENV,
            override_url = %shown,
            "fetching Sigstore's trust root from an overridden repository",
        );
        Repository::Url(value)
    } else {
        tracing::warn!(
            env_var = REPOSITORY_URL_OVERRIDE_ENV,
            override_url = %shown,
            "ignoring a Sigstore repository override that is neither https:// nor loopback",
        );
        Repository::Url(DEFAULT_REPOSITORY_URL.to_string())
    }
}

struct HttpFetcher {
    client: reqwest::Client,
    base: String,
}

impl HttpFetcher {
    fn new(base: &str) -> Result<Self, String> {
        let client = lpm_http::client_builder()
            .https_only(base.starts_with("https://"))
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
        })
    }
}

impl Fetcher for HttpFetcher {
    async fn fetch(&self, path: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
        let response = self
            .client
            .get(format!("{}/{path}", self.base))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        // TUF clients read both as "no such file": some static hosts answer
        // 403 for a missing object.
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        lpm_http::read_body_capped(response, cap)
            .await
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests;
