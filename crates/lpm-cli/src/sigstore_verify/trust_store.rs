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
use super::tuf::{self, Fetcher, Freshness, TrustedMetadata};
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
const CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// How long one fetch's outcome stands before a signature that needs newer
/// keys may fetch again. Most commands finish well within it; it bounds what
/// a long-running process, such as an MCP server, misses.
const REFETCH_AFTER: Duration = Duration::from_secs(60 * 60);

/// How long a failed fetch's outcome stands, so a long-running process
/// recovers soon after the network does.
const RETRY_FAILED_FETCH_AFTER: Duration = Duration::from_secs(60);

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
    /// When a process fetched this metadata, in seconds since the Unix
    /// epoch. Other processes skip their own fetch within
    /// [`REFETCH_AFTER`] of it.
    fetched_at: u64,
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

/// Verify `body` against the trust root built into this binary, ignoring
/// any fetched one. The release gate uses it, so a release it accepts
/// verifies even on a machine that has never reached Sigstore's repository.
pub fn verify_sigstore_bundle_with_built_in_trust_root(
    body: &[u8],
    expectations: &IdentityExpectations,
    options: VerifyOptions,
) -> Result<VerifiedProvenance, VerifyError> {
    let built_in = TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON)?;
    verify_sigstore_bundle_with(body, expectations, options, &built_in)
}

impl TrustStore {
    fn from_environment() -> Self {
        // Unit tests build their own stores; the shared one must not read
        // the developer's cache, so it verifies with the built-in root.
        let cache_file = (!cfg!(test))
            .then(|| lpm_common::LpmRoot::from_env().ok())
            .flatten()
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

    /// Fetch Sigstore's current trust root and use it from now on.
    ///
    /// Concurrent calls share one fetch. A call within [`REFETCH_AFTER`] of
    /// a fetch in this process, or within [`RETRY_FAILED_FETCH_AFTER`] of a
    /// failed one, returns that outcome. When another process cached a fetch
    /// within [`REFETCH_AFTER`], its trust root is used without fetching.
    async fn refresh(&self) -> Result<(), String> {
        let mut last_fetch = self.last_fetch.lock().await;
        if let Some((at, outcome)) = last_fetch.as_ref() {
            let stands_for = if outcome.is_ok() {
                REFETCH_AFTER
            } else {
                RETRY_FAILED_FETCH_AFTER
            };
            if at.elapsed() < stands_for {
                return outcome.clone();
            }
        }
        let outcome = match self.recently_fetched_root() {
            Some(root) => {
                *self.current.write().unwrap_or_else(PoisonError::into_inner) =
                    Some(Arc::new(root));
                Ok(())
            }
            None => self.fetch_current().await,
        };
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
        let root = match self
            .read_cache_file()
            .and_then(|cache| self.usable_cached_root(cache))
        {
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

    /// The cached trust root, if a process cached it within
    /// [`REFETCH_AFTER`] and it is one this store would use.
    fn recently_fetched_root(&self) -> Option<TrustRoot> {
        let cache = self.read_cache_file()?;
        let now = lpm_common::Timestamp::now().unix_seconds();
        let age = u64::try_from(now).ok()?.checked_sub(cache.fetched_at)?;
        if age >= REFETCH_AFTER.as_secs() {
            return None;
        }
        self.usable_cached_root(cache)
    }

    /// The trust root a cache file holds, when it verifies against the
    /// built-in TUF root, is no older than the built-in trust root, and has a
    /// usable key for every role.
    fn usable_cached_root(&self, cache: CacheFile) -> Option<TrustRoot> {
        let ignore = |error: String| {
            tracing::debug!(
                target: "lpm_cli::sigstore_verify",
                %error,
                "ignoring the cached Sigstore trust root",
            );
        };
        let cached = cache
            .metadata
            .verified_trusted_root(&self.embedded_tuf_root)
            .map_err(|error| ignore(error.to_string()))
            .ok()?;
        if cached.targets_version < self.embedded_targets_version {
            return None;
        }
        usable_trust_root(&cached.bytes, SystemTime::now())
            .map_err(ignore)
            .ok()
    }

    fn read_cached_metadata(&self) -> Option<TrustedMetadata> {
        self.read_cache_file().map(|cache| cache.metadata)
    }

    fn read_cache_file(&self) -> Option<CacheFile> {
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
        (cache.schema_version == CACHE_SCHEMA_VERSION).then_some(cache)
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
                    fetched_at: u64::try_from(lpm_common::Timestamp::now().unix_seconds())
                        .unwrap_or_default(),
                    metadata,
                };
                let bytes = serde_json::to_vec(&cache)
                    .map_err(|error| lpm_common::LpmError::Io(std::io::Error::other(error)))?;
                if bytes.len() as u64 > CACHE_MAX_BYTES {
                    return Ok(());
                }
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
/// a role has no usable key because its entries are missing or in a form
/// this version can't read, as after a schema change. Using it would fail
/// every verification the held trust root still passes. A role whose
/// readable keys Sigstore retired is a decision, and stands.
fn usable_trust_root(bytes: &[u8], now: SystemTime) -> Result<TrustRoot, String> {
    let (root, skipped) =
        TrustRoot::parse_skipping_unreadable(bytes).map_err(|error| error.to_string())?;
    let empty = root.roles_without_entries();
    let unusable: Vec<&str> = root
        .roles_without_active_key(now)
        .into_iter()
        .filter(|role| skipped.contains(role) || empty.contains(role))
        .collect();
    if unusable.is_empty() {
        Ok(root)
    } else {
        Err(format!(
            "it has no {} entry this version of LPM can read",
            unusable.join(", ")
        ))
    }
}

fn repository_from_environment() -> Repository {
    // Unit tests build their own stores; the shared one never reaches the
    // network.
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
            .https_only(
                reqwest::Url::parse(base)
                    .map_err(|error| error.to_string())?
                    .scheme()
                    == "https",
            )
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
