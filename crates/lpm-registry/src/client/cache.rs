use super::*;

mod write_buffer;

use write_buffer::{BufferLimit, MetadataCacheBuffer};

pub(super) const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Max bytes accepted from a single on-disk metadata cache entry.
///
/// The cache lives under `~/.lpm/cache/metadata/` (the trust boundary
/// documented above the magic constant); but a same-user process that
/// can plant a multi-GB file there would force every fresh-path read
/// to allocate it before serde even noticed the bytes were nonsense.
/// This ceiling remains wider than the on-the-wire metadata cap so existing
/// cache entries continue to decode after a transport-limit reduction, while
/// pathological files collapse to a cache miss before any decode work happens.
pub(super) const METADATA_CACHE_FILE_CAP: u64 = 100 * 1024 * 1024;
pub(super) const METADATA_CACHE_ETAG_LINE_CAP: u64 = 8 * 1024;
const METADATA_CACHE_FRESHNESS_LINE_CAP: u64 = 20;
pub(super) const MAX_PENDING_METADATA_CACHE_BYTES: usize = 128 * 1024 * 1024;
// MessagePack reserves 0xc1, so older readers treat JSON fallback entries as misses.
pub(super) const METADATA_CACHE_JSON_MARKER: u8 = 0xc1;

/// Magic header for the manifest cache file format. Replaces the
/// per-payload HMAC-SHA256 that used to run on every write. The cache
/// lives at `~/.lpm/cache/metadata/` inside the user's home; if an
/// attacker can write there they own the install anyway, so signing
/// the bytes adds no real security boundary.
///
/// On format change, bump the trailing version number — old cache
/// entries fail the magic match and are silently treated as misses.
///
/// V6 adds per-manifest Swift metadata to the persisted
/// metadata schema and stores each response's bounded local freshness.
/// The magic also salts cache filenames, so schema-old entries cannot make
/// the resolver's stat-only batch probe disagree with the typed reader.
pub(super) const METADATA_CACHE_MAGIC: &[u8] = b"LPM-MD-V6\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MetadataCacheDirective {
    Unspecified,
    Store { fresh_for: std::time::Duration },
    NoStore,
}

impl MetadataCacheDirective {
    pub(super) fn local_freshness(self) -> Option<std::time::Duration> {
        match self {
            Self::Unspecified => Some(METADATA_CACHE_TTL),
            Self::Store { fresh_for } => Some(fresh_for.min(METADATA_CACHE_TTL)),
            Self::NoStore => None,
        }
    }
}

pub(super) fn ensure_private_metadata_cache_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_metadata_cache_file(
    path: &std::path::Path,
    content: &MetadataCacheBuffer,
    fresh_for: std::time::Duration,
) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache path has no parent")
    })?;
    ensure_private_metadata_cache_dir(parent)?;

    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            content.write_to(&mut file)?;
            set_metadata_cache_file_expiry(&file, fresh_for)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    content.write_to(&mut file)?;
    set_metadata_cache_file_expiry(file.as_file(), fresh_for)?;
    file.persist(path).map(|_| ()).map_err(|error| error.error)
}

fn set_metadata_cache_file_expiry(
    file: &std::fs::File,
    fresh_for: std::time::Duration,
) -> std::io::Result<()> {
    let now = std::time::SystemTime::now();
    let expires_at = now.checked_add(fresh_for).unwrap_or(now);
    filetime::set_file_handle_times(
        file,
        None,
        Some(filetime::FileTime::from_system_time(expires_at)),
    )
}

fn reserve_pending_metadata_cache_bytes(
    budget: &Arc<tokio::sync::Semaphore>,
    bytes: usize,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permits = u32::try_from(bytes).ok()?;
    Arc::clone(budget).try_acquire_many_owned(permits).ok()
}

fn remaining_cache_freshness(modified: std::time::SystemTime) -> Option<std::time::Duration> {
    let remaining = modified.duration_since(std::time::SystemTime::now()).ok()?;
    (!remaining.is_zero()).then_some(remaining)
}

fn read_bounded_cache_line<R: std::io::BufRead>(reader: &mut R, cap: u64) -> Option<Vec<u8>> {
    use std::io::{BufRead as _, Read as _};

    let mut line = Vec::with_capacity(64);
    let bytes_read = reader
        .by_ref()
        .take(cap + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if bytes_read == 0 || line.last().copied() != Some(b'\n') {
        return None;
    }
    line.pop();
    if line.len() as u64 > cap {
        return None;
    }
    Some(line)
}

fn read_metadata_cache_header<R: std::io::BufRead>(
    reader: &mut R,
) -> Option<(std::time::Duration, Option<String>)> {
    let freshness_line = read_bounded_cache_line(reader, METADATA_CACHE_FRESHNESS_LINE_CAP)?;
    let fresh_for_secs = std::str::from_utf8(&freshness_line)
        .ok()?
        .parse::<u64>()
        .ok()?;
    if fresh_for_secs > METADATA_CACHE_TTL.as_secs() {
        return None;
    }
    let etag_line = read_bounded_cache_line(reader, METADATA_CACHE_ETAG_LINE_CAP)?;
    let etag = std::str::from_utf8(&etag_line)
        .ok()
        .filter(|value| !value.is_empty())
        .and_then(|value| reqwest::header::HeaderValue::from_str(value).ok())
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    if !etag_line.is_empty() && etag.is_none() {
        return None;
    }
    Some((std::time::Duration::from_secs(fresh_for_secs), etag))
}

impl RegistryClient {
    // ─── Metadata Cache ──────────────────────────────────────────────

    pub(super) fn direct_metadata_memory_cache_key(&self, cache_key: &str) -> String {
        use std::fmt::Write as _;

        let registry = &self.npm_registry_url;
        let mut key = String::with_capacity(registry.len() + cache_key.len() + 32);
        write!(key, "direct:{}:", registry.len())
            .expect("writing registry length to a String cannot fail");
        key.push_str(registry);
        key.push(':');
        key.push_str(cache_key);
        key
    }

    fn routed_metadata_memory_cache_key(&self, name: &str, route: &crate::UpstreamRoute) -> String {
        use std::fmt::Write as _;

        match route {
            crate::UpstreamRoute::NpmDirect => {
                let cache_key = self.npm_direct_metadata_cache_key(name);
                self.direct_metadata_memory_cache_key(&cache_key)
            }
            crate::UpstreamRoute::LpmWorker => {
                let mut key = String::with_capacity(self.base_url.len() + name.len() + 24);
                write!(key, "worker:{}:", self.base_url.len())
                    .expect("writing registry length to a String cannot fail");
                key.push_str(&self.base_url);
                key.push(':');
                key.push_str(name);
                key
            }
            crate::UpstreamRoute::Custom { target, .. } => {
                let mut key = String::with_capacity(target.base_url.len() + name.len() + 24);
                write!(key, "custom:{}:", target.base_url.len())
                    .expect("writing registry length to a String cannot fail");
                key.push_str(&target.base_url);
                key.push(':');
                key.push_str(name);
                key
            }
        }
    }

    pub(super) fn read_metadata_memory_cache(&self, key: &str) -> Option<PackageMetadata> {
        self.read_metadata_memory_cache_arc(key)
            .map(|metadata| metadata.as_ref().clone())
    }

    fn read_metadata_memory_cache_arc(&self, key: &str) -> Option<Arc<PackageMetadata>> {
        let mut cache = self
            .metadata_memory_cache
            .as_ref()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .get(key)
            .is_some_and(|entry| entry.expires_at <= std::time::Instant::now())
        {
            cache.remove(key);
            return None;
        }
        cache.get(key).map(|entry| Arc::clone(&entry.value))
    }

    /// Returns immutable command-scoped direct-registry metadata without
    /// cloning the packument.
    pub fn npm_metadata_direct_memory_cache(&self, name: &str) -> Option<Arc<PackageMetadata>> {
        self.npm_metadata_memory_cache(name, &crate::UpstreamRoute::NpmDirect)
    }

    /// Return immutable metadata seeded for one route during the current command.
    pub fn npm_metadata_memory_cache(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<Arc<PackageMetadata>> {
        let memory_cache_key = self.routed_metadata_memory_cache_key(name, route);
        let cached = self.read_metadata_memory_cache_arc(&memory_cache_key);
        if cached.is_some() {
            crate::timing::record_metadata_request(name);
            crate::timing::record_metadata_cache_hit();
        }
        cached
    }

    /// Read fresh routed metadata without issuing a network request.
    /// Exact-version documents are excluded because they do not establish tag state.
    pub async fn cached_package_metadata(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<Arc<PackageMetadata>> {
        if let Some(metadata) = self.npm_metadata_memory_cache(name, route) {
            return Some(metadata);
        }
        let key = self.routed_metadata_storage_cache_key(name, route)?;
        let (metadata, _) = self.read_metadata_cache_async(&key).await?;
        if metadata.name != name
            || metadata
                .versions
                .values()
                .any(|version| version.name != name)
        {
            return None;
        }
        Some(Arc::new(metadata))
    }

    /// Seed one immutable, already-validated packument for later resolver use.
    pub fn seed_metadata_for_command(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
        metadata: Arc<PackageMetadata>,
    ) -> bool {
        let Some(cache) = &self.metadata_memory_cache else {
            return false;
        };
        if name.starts_with("@lpm.dev/") && !matches!(route, crate::UpstreamRoute::LpmWorker) {
            return false;
        }
        if metadata.name != name
            || metadata
                .versions
                .values()
                .any(|version| version.name != name)
        {
            return false;
        }

        let route_mode = match route {
            crate::UpstreamRoute::LpmWorker => Some(crate::RouteMode::Proxy),
            crate::UpstreamRoute::NpmDirect => Some(crate::RouteMode::Direct),
            crate::UpstreamRoute::Custom { .. } => None,
        };
        if let Some(route_mode) = route_mode {
            let Some(overrides) = &self.metadata_route_overrides else {
                return false;
            };
            let mut overrides = overrides
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match overrides.entry(name.to_string()) {
                std::collections::hash_map::Entry::Occupied(entry)
                    if *entry.get() != route_mode =>
                {
                    return false;
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(route_mode);
                }
            }
        }

        let key = self.routed_metadata_memory_cache_key(name, route);
        let expires_at = self.command_cache_expiry_for_seed(name, route);
        let Some(expires_at) = expires_at else {
            self.forget_metadata_for_command(&key);
            return true;
        };
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key,
                MetadataMemoryEntry {
                    value: metadata,
                    expires_at,
                },
            );
        true
    }

    fn command_cache_expiry_for_seed(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<std::time::Instant> {
        let now = std::time::Instant::now();
        let Some(cache_key) = self.routed_metadata_storage_cache_key(name, route) else {
            return Some(now + METADATA_CACHE_TTL);
        };
        let policy = self
            .metadata_command_cache_policies
            .as_ref()
            .and_then(|policies| {
                policies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&cache_key)
                    .copied()
            });
        match policy {
            Some(MetadataCommandCachePolicy::NoStore) => None,
            Some(MetadataCommandCachePolicy::StoreUntil(expires_at)) if expires_at <= now => None,
            Some(MetadataCommandCachePolicy::StoreUntil(expires_at)) => Some(expires_at),
            None => Some(now + METADATA_CACHE_TTL),
        }
    }

    /// Opaque identity of the registry and credential principal used for a package.
    /// A missing identity prevents reuse across invocations.
    pub fn routed_cache_identity(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<String> {
        use sha2::{Digest, Sha256};
        self.routed_metadata_storage_cache_key(name, route)
            .map(|key| hex::encode(Sha256::digest(key.as_bytes())))
    }

    fn routed_metadata_storage_cache_key(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<String> {
        match route {
            crate::UpstreamRoute::NpmDirect => Some(self.npm_direct_metadata_cache_key(name)),
            crate::UpstreamRoute::LpmWorker if name.starts_with("@lpm.dev/") => {
                self.lpm_metadata_cache_key(name).ok()
            }
            crate::UpstreamRoute::LpmWorker => self.npm_worker_metadata_cache_key(name).ok(),
            crate::UpstreamRoute::Custom { target, auth } => {
                let destination =
                    RequestDestination::parse(&format!("{}/{name}", target.base_url)).ok()?;
                let url = destination.as_str();
                Some(format!(
                    "npm:{}:{url}",
                    principal_fingerprint(
                        auth.as_deref(),
                        self.http.identity_fp_for_destination(&destination)
                    )
                ))
            }
        }
    }

    /// Return the package routes pinned by validated command-scoped metadata.
    pub fn metadata_route_overrides(&self) -> Option<HashMap<String, crate::RouteMode>> {
        self.metadata_route_overrides.as_ref().map(|overrides| {
            overrides
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }

    pub(super) fn remember_metadata_for_command(
        &self,
        key: &str,
        metadata: &PackageMetadata,
        fresh_for: std::time::Duration,
    ) {
        if fresh_for.is_zero() {
            self.forget_metadata_for_command(key);
            return;
        }
        let Some(cache) = &self.metadata_memory_cache else {
            return;
        };
        let metadata = Arc::new(metadata.clone());
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key.to_owned(),
                MetadataMemoryEntry {
                    value: metadata,
                    expires_at: std::time::Instant::now() + fresh_for,
                },
            );
    }

    pub(super) fn forget_metadata_for_command(&self, key: &str) {
        if let Some(cache) = &self.metadata_memory_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
    }

    pub(super) fn read_release_time_memory_cache(&self, key: &str) -> Option<ReleaseTimeMetadata> {
        let mut cache = self
            .release_time_memory_cache
            .as_ref()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .get(key)
            .is_some_and(|entry| entry.expires_at <= std::time::Instant::now())
        {
            cache.remove(key);
            return None;
        }
        cache.get(key).map(|entry| entry.value.as_ref().clone())
    }

    pub(super) fn remember_release_times_for_command(
        &self,
        key: &str,
        metadata: &ReleaseTimeMetadata,
        fresh_for: std::time::Duration,
    ) {
        if fresh_for.is_zero() {
            if let Some(cache) = &self.release_time_memory_cache {
                cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(key);
            }
            return;
        }
        let Some(cache) = &self.release_time_memory_cache else {
            return;
        };
        let metadata = Arc::new(metadata.clone());
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key.to_owned(),
                MetadataMemoryEntry {
                    value: metadata,
                    expires_at: std::time::Instant::now() + fresh_for,
                },
            );
    }

    fn invalidate_metadata_memory_cache(&self, key: &str) {
        if let Some(cache) = &self.metadata_memory_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
    }

    fn metadata_cache_mutation(&self, path: &std::path::Path) -> Arc<MetadataCacheMutation> {
        let mut mutations = self
            .metadata_cache_mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(mutations.entry(path.to_path_buf()).or_insert_with(|| {
            Arc::new(MetadataCacheMutation {
                revision: std::sync::atomic::AtomicU64::new(0),
                operation: std::sync::Mutex::new(()),
            })
        }))
    }

    fn invalidate_metadata_cache_path(&self, path: &std::path::Path) {
        use std::sync::atomic::Ordering;

        let mutation = self.metadata_cache_mutation(path);
        mutation.revision.fetch_add(1, Ordering::AcqRel);
        let _operation = mutation
            .operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::debug!(%error, "failed to invalidate metadata cache entry"),
        }
    }

    pub(super) fn invalidate_metadata_cache_key(&self, key: &str) {
        if let Some(policies) = &self.metadata_command_cache_policies {
            policies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
        self.invalidate_metadata_memory_cache(key);
        let direct_memory_key = self.direct_metadata_memory_cache_key(key);
        self.invalidate_metadata_memory_cache(&direct_memory_key);
        self.invalidate_metadata_memory_cache(&format!("custom:{key}"));
        if let Some(path) = self.cache_path(key) {
            self.invalidate_metadata_cache_path(&path);
        }
    }

    pub(super) fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(METADATA_CACHE_MAGIC);
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Some(dir.join(&hash[..16]))
    }

    /// Invalidate cached packuments for the current Worker principal and the
    /// configured direct npm origin.
    ///
    /// Used when a tarball download returns 404 — the cached metadata
    /// likely references an unpublished version. Deleting the cache
    /// forces a fresh fetch on the next request.
    ///
    /// Custom-registry metadata (served by
    /// `get_npm_metadata_from`) is keyed by
    /// `npm:<auth_fingerprint>:<full_url>` — neither the URL nor the
    /// auth is recoverable from `package_name` alone, so this method
    /// cannot invalidate those entries. Callers on the custom-registry
    /// path MUST use [`Self::invalidate_custom_metadata_cache`] instead.
    pub fn invalidate_metadata_cache(&self, package_name: &str) {
        self.history_cache.invalidate();
        if package_name.starts_with("@lpm.dev/") {
            if let Ok(key) = self.lpm_metadata_cache_key(package_name) {
                self.invalidate_metadata_cache_key(&key);
            }
        } else {
            let direct_key = self.npm_direct_metadata_cache_key(package_name);
            self.invalidate_metadata_cache_key(&direct_key);
            self.invalidate_metadata_cache_key(
                &self.npm_preferred_metadata_cache_key(package_name),
            );
            if let Ok(worker_key) = self.npm_worker_metadata_cache_key(package_name) {
                self.invalidate_metadata_cache_key(&worker_key);
            }
        }
        tracing::debug!("invalidated metadata cache for {package_name}");
    }

    /// Invalidate a direct-npm exact-version metadata document.
    ///
    /// Exact version documents are cached separately from packuments so they
    /// cannot satisfy broad ranges. Stale tarball recovery knows the concrete
    /// version that failed and clears this cache alongside the package-level
    /// metadata cache.
    pub fn invalidate_npm_version_metadata_cache(&self, package_name: &str, version: &str) {
        self.history_cache.invalidate();
        let cache_key = self.npm_direct_version_metadata_cache_key(package_name, version);
        self.invalidate_metadata_cache_key(&cache_key);
        let selected_key = self.npm_selected_history_cache_key(package_name, version);
        self.invalidate_metadata_cache_key(&selected_key);
        tracing::debug!("invalidated npm version metadata cache for {package_name}@{version}");
    }

    /// Invalidate a cached custom-registry metadata entry.
    ///
    /// `base_url` and `auth` MUST match exactly the values that were
    /// passed to [`Self::get_npm_metadata_from`] when the entry was
    /// written; the cache key is host- and path- and auth-fingerprint-
    /// derived, so a name-only call (like
    /// [`Self::invalidate_metadata_cache`]) cannot reach these entries.
    pub fn invalidate_custom_metadata_cache(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) {
        let Ok(destination) = RequestDestination::parse(&format!("{base_url}/{name}")) else {
            return;
        };
        let url = destination.as_str();
        let cache_key = format!(
            "npm:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_destination(&destination))
        );
        self.invalidate_metadata_memory_cache(&cache_key);
        self.invalidate_metadata_memory_cache(&format!("custom:{cache_key}"));
        if let Some(path) = self.cache_path(&cache_key) {
            self.invalidate_metadata_cache_path(&path);
            tracing::debug!("invalidated custom metadata cache for {name} at {base_url}");
        }
    }

    /// Lightweight check: is there a fresh metadata cache entry for this package?
    ///
    /// Only does a `stat()` syscall — no file read, no HMAC verification,
    /// no deserialization. Used by the resolver's batch-prefetch logic to
    /// skip HTTP requests for packages already on disk from a prior batch.
    pub fn is_metadata_fresh(&self, package_name: &str) -> bool {
        let cache_key = match self.batch_metadata_cache_key(package_name) {
            Some(key) => key,
            None => return false,
        };
        let Some(path) = self.cache_path(&cache_key) else {
            return false;
        };
        let Ok(meta) = path.metadata() else {
            return false;
        };
        meta.modified()
            .ok()
            .and_then(remaining_cache_freshness)
            .is_some()
    }

    /// Read cached metadata if it exists, is within TTL, and starts with
    /// the expected magic header.
    ///
    /// Returns `(PackageMetadata, Option<etag>)`. The ETag (if present) can be
    /// sent as `If-None-Match` on the next request to enable 304 responses.
    ///
    /// Cache format (v6): `LPM-MD-V6\n{freshness_seconds}\n{ETag}\n{payload}`
    /// - Bytes 0..MAGIC.len(): magic header (ends in `\n`)
    /// - After magic, up to next `\n`: local freshness in seconds
    /// - Next line: ETag string (empty if absent)
    /// - Remainder: named MessagePack, or `0xc1` followed by JSON after an encoding failure
    ///
    /// Old cache files written in the `HMAC\nETag\ndata` format fail the
    /// magic check and are silently treated as misses — the next fetch
    /// rewrites the entry in the new format.
    #[cfg(test)]
    pub(super) fn read_metadata_cache(
        &self,
        key: &str,
    ) -> Option<(PackageMetadata, Option<String>)> {
        self.read_metadata_cache_as(key)
    }

    pub(super) async fn read_metadata_cache_async(
        &self,
        key: &str,
    ) -> Option<(PackageMetadata, Option<String>)> {
        self.read_metadata_cache_as_async(key).await
    }

    pub(super) async fn read_metadata_cache_as_async<
        T: serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        key: &str,
    ) -> Option<(T, Option<String>)> {
        let entry = self.read_metadata_cache_entry_as_async(key).await?;
        Some((entry.value, entry.etag))
    }

    pub(super) async fn read_metadata_cache_entry_as_async<
        T: serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        key: &str,
    ) -> Option<MetadataCacheEntry<T>> {
        let path = self.cache_path(key)?;
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_read");
        tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
        let worker_span = span.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _entered = worker_span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let result = Self::read_metadata_cache_path_entry_as::<T>(&path);
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, cached = result.is_some());
            result
        }).await;
        tracing::event!(name: "await_resume", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, success = result.is_ok());
        result.ok().flatten()
    }

    /// Generic variant of [`Self::read_metadata_cache`]: deserializes the cached
    /// metadata bytes into any `T: DeserializeOwned` instead of always
    /// allocating a full [`PackageMetadata`].
    ///
    /// Callers that need only a subset of fields (e.g., the blocked-set capture
    /// path) can pass a minimal struct so serde skips allocating unneeded fields.
    ///
    /// **Streaming deserialization**: uses `BufReader<File>` + `rmp_serde::decode::from_read`
    /// instead of `fs::read` to avoid allocating a `Vec<u8>` for the full file
    /// content (~68 KB × N packages on every blocked-set capture call). Old caches
    /// in JSON or positional-array msgpack format trigger a cache miss here (returns
    /// `None`) and are rewritten in named-format msgpack on the next fetch.
    #[cfg(test)]
    pub(super) fn read_metadata_cache_as<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Option<(T, Option<String>)> {
        let path = self.cache_path(key)?;
        Self::read_metadata_cache_path_as(&path)
    }

    #[cfg(test)]
    pub(super) fn read_metadata_cache_path_as<T: serde::de::DeserializeOwned>(
        path: &std::path::Path,
    ) -> Option<(T, Option<String>)> {
        let entry = Self::read_metadata_cache_path_entry_as(path)?;
        Some((entry.value, entry.etag))
    }

    fn read_metadata_cache_path_entry_as<T: serde::de::DeserializeOwned>(
        path: &std::path::Path,
    ) -> Option<MetadataCacheEntry<T>> {
        let file = std::fs::File::open(path).ok()?;
        let file_metadata = file.metadata().ok()?;
        let remaining_freshness = remaining_cache_freshness(file_metadata.modified().ok()?)?;
        let (value, etag, fresh_for) =
            Self::decode_metadata_cache_file_as(path, file, &file_metadata)?;
        if remaining_freshness > fresh_for {
            return None;
        }

        Some(MetadataCacheEntry {
            value,
            etag,
            remaining_freshness,
        })
    }

    pub(super) fn read_stale_metadata_cache_path_as<T: serde::de::DeserializeOwned>(
        path: &std::path::Path,
    ) -> Option<(T, Option<String>, std::time::Duration)> {
        let file = std::fs::File::open(path).ok()?;
        let file_metadata = file.metadata().ok()?;
        Self::decode_metadata_cache_file_as(path, file, &file_metadata)
    }

    fn decode_metadata_cache_file_as<T: serde::de::DeserializeOwned>(
        path: &std::path::Path,
        file: std::fs::File,
        file_metadata: &std::fs::Metadata,
    ) -> Option<(T, Option<String>, std::time::Duration)> {
        use std::io::{BufRead as _, Read as _};

        if file_metadata.len() > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = file_metadata.len(),
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        let mut reader =
            std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));

        let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
        reader.read_exact(&mut magic).ok()?;
        if magic != *METADATA_CACHE_MAGIC {
            return None;
        }
        let (fresh_for, etag) = read_metadata_cache_header(&mut reader)?;

        let value: T = if reader.fill_buf().ok()?.first() == Some(&METADATA_CACHE_JSON_MARKER) {
            reader.consume(1);
            serde_json::from_reader(&mut reader).ok()?
        } else {
            rmp_serde::decode::from_read(&mut reader).ok()?
        };
        Some((value, etag, fresh_for))
    }

    /// Read the ETag and raw data bytes from a cached entry without
    /// deserializing.
    ///
    /// Returns `(Option<etag>, raw_data_bytes)`. The data bytes can be
    /// deserialized by the caller on a 304 response, avoiding a second file
    /// read. Does NOT check TTL — used for conditional requests where the
    /// cache may be stale.
    #[cfg(test)]
    pub(super) fn read_cache_content(&self, key: &str) -> Option<CacheContent> {
        let path = self.cache_path(key)?;
        Self::read_cache_content_path(&path)
    }

    #[cfg(test)]
    pub(super) fn read_cache_content_path(path: &std::path::Path) -> Option<CacheContent> {
        let content = match lpm_common::read_file_capped(path, METADATA_CACHE_FILE_CAP) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::TooLarge { .. }) => {
                tracing::warn!(
                    path = %path.display(),
                    cap = METADATA_CACHE_FILE_CAP,
                    "metadata cache entry exceeds size cap — treating as miss"
                );
                return None;
            }
            Err(_) => return None,
        };
        let (fresh_for, etag, data) = parse_cached_metadata_blob(&content)?;

        Some(CacheContent {
            etag,
            fresh_for,
            data: data.to_vec(),
        })
    }

    /// Read only the ETag from a cached entry for a conditional request.
    ///
    /// Unlike [`Self::read_cache_content`], this avoids reading the cached
    /// packument payload before the HTTP response is known. If the server
    /// returns 304, the caller can hydrate the cached body then.
    pub(super) fn read_cache_validator(&self, key: &str) -> Option<CacheValidator> {
        let path = self.cache_path(key)?;
        Self::read_cache_validator_path(&path)
    }

    pub(super) fn read_cache_validator_path(path: &std::path::Path) -> Option<CacheValidator> {
        use std::io::Read as _;

        let file = std::fs::File::open(path).ok()?;
        let file_metadata = file.metadata().ok()?;
        let file_size = file_metadata.len();
        if file_size > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = file_size,
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        let mut reader =
            std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));

        let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
        reader.read_exact(&mut magic).ok()?;
        if magic != *METADATA_CACHE_MAGIC {
            return None;
        }

        let (fresh_for, etag) = read_metadata_cache_header(&mut reader)?;
        let validated_at = file_metadata.modified().ok()?.checked_sub(fresh_for)?;
        let age_seconds = std::time::SystemTime::now()
            .duration_since(validated_at)
            .ok()
            .map(|age| age.as_secs());

        Some(CacheValidator { etag, age_seconds })
    }

    /// Write metadata to cache with a magic-header marker and optional ETag.
    ///
    /// Serializes to MessagePack (binary, ~40-60% smaller than JSON).
    /// Falls back to JSON if MessagePack serialization fails.
    ///
    /// Serialization runs on the calling thread (CPU-fast), but the
    /// blocking `std::fs::write` is dispatched onto tokio's
    /// `spawn_blocking` pool so it never stalls a runtime worker. Falls
    /// back to in-place sync write when no tokio runtime is available
    /// (unit tests).
    #[cfg(test)]
    pub(super) fn write_metadata_cache<T: serde::Serialize + ?Sized>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
    ) {
        let _ = self.write_metadata_cache_with_directive(
            key,
            metadata,
            etag,
            MetadataCacheDirective::Unspecified,
        );
    }

    pub(super) fn metadata_cache_directive(
        headers: &reqwest::header::HeaderMap,
    ) -> MetadataCacheDirective {
        let mut no_store = false;
        let mut no_cache = false;
        let mut max_age: Option<u64> = None;

        for value in headers.get_all(reqwest::header::CACHE_CONTROL) {
            let Ok(value) = value.to_str() else {
                return MetadataCacheDirective::Store {
                    fresh_for: std::time::Duration::ZERO,
                };
            };
            for directive in value.split(',') {
                let directive = directive.trim();
                let (name, argument) = directive
                    .split_once('=')
                    .map_or((directive, None), |(name, value)| {
                        (name.trim(), Some(value.trim()))
                    });
                if name.eq_ignore_ascii_case("no-store") {
                    no_store = true;
                } else if name.eq_ignore_ascii_case("no-cache") {
                    no_cache = true;
                } else if name.eq_ignore_ascii_case("max-age") {
                    let parsed = argument
                        .and_then(|argument| {
                            if argument.starts_with('"') && argument.ends_with('"') {
                                argument.get(1..argument.len().saturating_sub(1))
                            } else if argument.contains('"') {
                                None
                            } else {
                                Some(argument)
                            }
                        })
                        .and_then(|argument| argument.parse::<u64>().ok())
                        .unwrap_or(0)
                        .min(METADATA_CACHE_TTL.as_secs());
                    max_age = Some(max_age.map_or(parsed, |current| current.min(parsed)));
                }
            }
        }

        if no_store {
            MetadataCacheDirective::NoStore
        } else if no_cache {
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO,
            }
        } else if let Some(max_age) = max_age {
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::from_secs(max_age),
            }
        } else {
            MetadataCacheDirective::Unspecified
        }
    }

    pub(super) fn write_metadata_cache_with_directive<T: serde::Serialize + ?Sized>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
    ) -> Option<std::time::Duration> {
        use std::io::Write as _;
        use std::sync::atomic::Ordering;

        let fresh_for = match directive.local_freshness() {
            Some(fresh_for) => {
                self.remember_command_cache_policy(
                    key,
                    MetadataCommandCachePolicy::StoreUntil(std::time::Instant::now() + fresh_for),
                );
                fresh_for
            }
            None => {
                self.invalidate_metadata_cache_key(key);
                self.remember_command_cache_policy(key, MetadataCommandCachePolicy::NoStore);
                return None;
            }
        };
        let path = self.cache_path(key)?;
        let mutation = self.metadata_cache_mutation(&path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;

        let etag_str = etag
            .filter(|etag| etag.len() as u64 <= METADATA_CACHE_ETAG_LINE_CAP)
            .and_then(|etag| {
                reqwest::header::HeaderValue::from_str(etag)
                    .ok()
                    .map(|_| etag)
            })
            .unwrap_or("");
        let freshness = fresh_for.as_secs().to_string();
        let prefix_len = METADATA_CACHE_MAGIC.len() + freshness.len() + 1 + etag_str.len() + 1;
        let new_buffer = || {
            MetadataCacheBuffer::new(
                &self.pending_cache_write_bytes,
                &[
                    METADATA_CACHE_MAGIC,
                    freshness.as_bytes(),
                    b"\n",
                    etag_str.as_bytes(),
                    b"\n",
                ],
            )
        };
        let skip_exhausted = |limit| match limit {
            BufferLimit::Budget => {
                tracing::debug!(
                    "skipping best-effort metadata cache write because the allocation budget is full"
                );
                Some(fresh_for)
            }
            BufferLimit::FileSize => None,
        };
        let mut content = match new_buffer() {
            Ok(content) => content,
            Err(limit) => return skip_exhausted(limit),
        };
        let serialization =
            tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_serialization")
                .entered();
        if let Err(messagepack_error) = rmp_serde::encode::write_named(&mut content, metadata) {
            if let Some(limit) = content.exhausted() {
                return skip_exhausted(limit);
            }
            drop(content);
            content = match new_buffer() {
                Ok(content) => content,
                Err(limit) => return skip_exhausted(limit),
            };
            content.write_all(&[METADATA_CACHE_JSON_MARKER]).ok()?;
            if let Err(json_error) = serde_json::to_writer(&mut content, metadata) {
                if let Some(limit) = content.exhausted() {
                    return skip_exhausted(limit);
                }
                tracing::warn!(
                    "metadata cache serialization failed for {key}: MessagePack: {messagepack_error}; JSON: {json_error}"
                );
                return None;
            }
        }
        if content.len() == prefix_len {
            return None;
        }

        tracing::event!(name: "serialized", target: "lpm_install_timeline", tracing::Level::TRACE, bytes = content.len() as u64);
        drop(serialization);
        let key_owned = key.to_string();
        let runtime_handle = tokio::runtime::Handle::try_current();
        if self.synchronous_cache_writes || runtime_handle.is_err() {
            let _operation = mutation
                .operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mutation.revision.load(Ordering::Acquire) == revision
                && let Err(e) = write_metadata_cache_file(&path, &content, fresh_for)
            {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
            return Some(fresh_for);
        }

        let handle = runtime_handle.unwrap();
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_write");
        tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
        let join = handle.spawn_blocking(move || {
            let _entered = span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let _operation = mutation
                .operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mutation.revision.load(Ordering::Acquire) == revision
                && let Err(e) = write_metadata_cache_file(&path, &content, fresh_for)
            {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, {});
        });
        if let Ok(mut pending) = self.pending_cache_writes.lock() {
            pending.push(join);
        }
        Some(fresh_for)
    }

    pub(super) fn refresh_metadata_cache_freshness(
        &self,
        key: &str,
        fresh_for: std::time::Duration,
    ) -> Option<std::time::Duration> {
        use std::sync::atomic::Ordering;

        let fresh_for = fresh_for.min(METADATA_CACHE_TTL);
        self.remember_command_cache_policy(
            key,
            MetadataCommandCachePolicy::StoreUntil(std::time::Instant::now() + fresh_for),
        );
        let path = self.cache_path(key)?;
        let mutation = self.metadata_cache_mutation(&path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;
        let _operation = mutation
            .operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if mutation.revision.load(Ordering::Acquire) != revision {
            return Some(fresh_for);
        }

        let now = std::time::SystemTime::now();
        let expires_at = now.checked_add(fresh_for).unwrap_or(now);
        if let Err(error) =
            filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(expires_at))
        {
            tracing::warn!(%error, "failed to refresh metadata cache freshness");
        }
        Some(fresh_for)
    }

    fn remember_command_cache_policy(&self, key: &str, policy: MetadataCommandCachePolicy) {
        if let Some(policies) = &self.metadata_command_cache_policies {
            policies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.to_owned(), policy);
        }
    }

    /// Drain and await every pending fire-and-forget metadata cache
    /// write spawned by this client (or any clone sharing its
    /// `pending_cache_writes` tracker).
    ///
    /// Production callers don't need this — the writes are best-effort
    /// and the handles drop with the client. Tests call this between
    /// "fetch metadata" and "expect cache hit" so they observe the
    /// post-write state deterministically. The Mutex is poisoned-tolerant
    /// (we treat poison as "no work to flush") because losing track of a
    /// pending write is strictly less bad than panicking the test runner.
    pub async fn flush_pending_cache_writes(&self) {
        let drained: Vec<_> = match self.pending_cache_writes.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return,
        };
        for h in drained {
            // Ignore JoinError — the inner closure already logs failures
            // via `tracing::warn!`; nothing actionable on this side.
            let _ = h.await;
        }
    }
}

#[cfg(test)]
mod pending_write_budget_tests {
    use super::*;

    struct PausedSerialization {
        started: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        value: serde_json::Value,
    }

    impl serde::Serialize for PausedSerialization {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.started.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
            self.value.serialize(serializer)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn newer_cache_mutations_win_over_an_older_paused_serializer() {
        for action in ["invalidate", "no-store", "replace"] {
            let cache_dir = tempfile::tempdir().unwrap();
            let client =
                Arc::new(RegistryClient::new().with_cache_dir(Some(cache_dir.path().into())));
            let (started, observed) = std::sync::mpsc::sync_channel(1);
            let (resume, resumed) = std::sync::mpsc::sync_channel(1);
            let old_client = client.clone();
            let older = tokio::task::spawn_blocking(move || {
                old_client.write_metadata_cache(
                    "ordered",
                    &PausedSerialization {
                        started,
                        resume: std::sync::Mutex::new(resumed),
                        value: serde_json::json!({"name":"older"}),
                    },
                    None,
                );
            });
            observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            match action {
                "invalidate" => client.invalidate_metadata_cache_key("ordered"),
                "no-store" => {
                    client.write_metadata_cache_with_directive(
                        "ordered",
                        &serde_json::json!({"name":"newer"}),
                        None,
                        MetadataCacheDirective::NoStore,
                    );
                }
                _ => client.write_metadata_cache(
                    "ordered",
                    &serde_json::json!({"name":"newer"}),
                    None,
                ),
            }
            resume.send(()).unwrap();
            older.await.unwrap();
            client.flush_pending_cache_writes().await;
            if action == "replace" {
                let (value, _) = client
                    .read_metadata_cache_as::<serde_json::Value>("ordered")
                    .unwrap();
                assert_eq!(value["name"], "newer");
            } else {
                assert!(
                    !client.cache_path("ordered").unwrap().exists(),
                    "{action} was overwritten by older serialization"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn older_serialization_budget_failure_cannot_cancel_a_newer_queued_write() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(12_000));
        let client = Arc::new(client);
        let (started, observed) = std::sync::mpsc::sync_channel(1);
        let (resume, resumed) = std::sync::mpsc::sync_channel(1);
        let (finished, completed) = std::sync::mpsc::sync_channel(1);
        let old_client = client.clone();
        let older = tokio::task::spawn_blocking(move || {
            old_client.write_metadata_cache(
                "ordered",
                &PausedSerialization {
                    started,
                    resume: std::sync::Mutex::new(resumed),
                    value: serde_json::json!({"name":"older", "payload":"x".repeat(8192)}),
                },
                None,
            );
            finished.send(()).unwrap();
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mutation = client.metadata_cache_mutation(&client.cache_path("ordered").unwrap());
        {
            let _operation = mutation.operation.lock().unwrap();
            client.write_metadata_cache("ordered", &serde_json::json!({"name":"newer"}), None);
            resume.send(()).unwrap();
            completed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        older.await.unwrap();
        client.flush_pending_cache_writes().await;
        let (value, _) = client
            .read_metadata_cache_as::<serde_json::Value>("ordered")
            .unwrap();
        assert_eq!(value["name"], "newer");
        assert_eq!(client.pending_cache_write_bytes.available_permits(), 12_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn newer_admission_failure_supersedes_an_older_queued_write() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(5000));
        let path = client.cache_path("ordered").unwrap();
        let mutation = client.metadata_cache_mutation(&path);
        {
            let _operation = mutation.operation.lock().unwrap();
            client.write_metadata_cache("ordered", &serde_json::json!({"name":"older"}), None);
            client.write_metadata_cache("ordered", &serde_json::json!({"name":"newer"}), None);
        }
        client.flush_pending_cache_writes().await;
        assert!(!path.exists());
        assert_eq!(client.pending_cache_write_bytes.available_permits(), 5000);
    }

    #[tokio::test]
    async fn exhausted_cache_budget_skips_serialization_before_allocating_a_buffer() {
        struct CountSerialization(std::sync::atomic::AtomicUsize);
        impl serde::Serialize for CountSerialization {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                serializer.serialize_str("metadata")
            }
        }
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(1024));
        let metadata = CountSerialization(std::sync::atomic::AtomicUsize::new(0));

        client.write_metadata_cache("no-admission", &metadata, None);
        client.flush_pending_cache_writes().await;

        assert_eq!(metadata.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!client.cache_path("no-admission").unwrap().exists());
        assert_eq!(client.pending_cache_write_bytes.available_permits(), 1024);
    }

    #[tokio::test]
    async fn cache_buffer_growth_exhaustion_does_not_retry_json_serialization() {
        struct LargeSerialization(std::sync::atomic::AtomicUsize);
        impl serde::Serialize for LargeSerialization {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                serializer.serialize_bytes(&[0x5a; 8192])
            }
        }
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(8192));
        let metadata = LargeSerialization(std::sync::atomic::AtomicUsize::new(0));

        client.write_metadata_cache("growth-denied", &metadata, None);
        client.flush_pending_cache_writes().await;

        assert_eq!(metadata.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(!client.cache_path("growth-denied").unwrap().exists());
        assert_eq!(client.pending_cache_write_bytes.available_permits(), 8192);
    }

    #[tokio::test]
    async fn genuine_messagepack_failure_preserves_json_cache_fallback() {
        struct JsonOnly;
        impl serde::Serialize for JsonOnly {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if !serializer.is_human_readable() {
                    return Err(serde::ser::Error::custom(
                        "requires a human-readable format",
                    ));
                }
                serializer.serialize_str("json fallback")
            }
        }
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));

        client.write_metadata_cache("json-fallback", &JsonOnly, Some("\"v1\""));
        client.flush_pending_cache_writes().await;

        let (value, etag) = client
            .read_metadata_cache_as::<String>("json-fallback")
            .unwrap();
        assert_eq!(value, "json fallback");
        let raw = client.read_cache_content("json-fallback").unwrap().data;
        assert_eq!(raw.first(), Some(&METADATA_CACHE_JSON_MARKER));
        assert_eq!(
            RegistryClient::deserialize_cached_metadata_as::<String>(&raw),
            Some(value.clone())
        );
        let (stale, _, _) = RegistryClient::read_stale_metadata_cache_path_as::<String>(
            &client.cache_path("json-fallback").unwrap(),
        )
        .unwrap();
        assert_eq!(stale, value);
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            client.pending_cache_write_bytes.available_permits(),
            MAX_PENDING_METADATA_CACHE_BYTES
        );
    }

    #[test]
    fn malformed_tagged_json_cache_payloads_are_misses() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().into()));
        let path = client.cache_path("malformed").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for payload in [b"".as_slice(), b"{", b"null trailing"] {
            let mut contents = METADATA_CACHE_MAGIC.to_vec();
            contents.extend_from_slice(b"300\n\n");
            contents.push(METADATA_CACHE_JSON_MARKER);
            contents.extend_from_slice(payload);
            std::fs::write(&path, contents).unwrap();
            filetime::set_file_mtime(
                &path,
                filetime::FileTime::from_system_time(
                    std::time::SystemTime::now() + METADATA_CACHE_TTL,
                ),
            )
            .unwrap();
            assert!(
                client
                    .read_metadata_cache_as::<serde_json::Value>("malformed")
                    .is_none()
            );
            assert!(
                RegistryClient::read_stale_metadata_cache_path_as::<serde_json::Value>(&path)
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn queued_metadata_cache_write_budget_covers_spare_buffer_capacity() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(1024));
        let key = "small-metadata-large-allocation";

        client.write_metadata_cache(key, &serde_json::json!({ "name": "small" }), None);
        client.flush_pending_cache_writes().await;

        assert!(
            !client.cache_path(key).unwrap().exists(),
            "the 4 KiB serialization buffer must not fit a 1 KiB pending allocation budget"
        );
        assert_eq!(client.pending_cache_write_bytes.available_permits(), 1024);
    }

    #[test]
    fn queued_metadata_cache_writes_cannot_exceed_the_byte_budget() {
        let budget = Arc::new(tokio::sync::Semaphore::new(
            MAX_PENDING_METADATA_CACHE_BYTES,
        ));
        let retained = reserve_pending_metadata_cache_bytes(&budget, 96 * 1024 * 1024)
            .expect("the first write must fit in the byte budget");

        assert!(
            reserve_pending_metadata_cache_bytes(&budget, 33 * 1024 * 1024).is_none(),
            "a queued write must not exceed the remaining byte budget"
        );
        assert_eq!(budget.available_permits(), 32 * 1024 * 1024);

        drop(retained);
        assert_eq!(budget.available_permits(), MAX_PENDING_METADATA_CACHE_BYTES);
    }
}

#[cfg(test)]
mod cache_control_tests {
    use super::*;

    fn directive(cache_control: &str, age: Option<&str>) -> MetadataCacheDirective {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            reqwest::header::HeaderValue::from_str(cache_control).unwrap(),
        );
        if let Some(age) = age {
            headers.insert(
                reqwest::header::AGE,
                reqwest::header::HeaderValue::from_str(age).unwrap(),
            );
        }
        RegistryClient::metadata_cache_directive(&headers)
    }

    #[test]
    fn cache_control_no_store_takes_precedence_over_other_directives() {
        assert_eq!(
            directive("max-age=120, no-cache, no-store", None),
            MetadataCacheDirective::NoStore
        );
    }

    #[test]
    fn cache_control_no_cache_requires_immediate_revalidation() {
        assert_eq!(
            directive("max-age=120, no-cache", None),
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO
            }
        );
    }

    #[test]
    fn cache_control_max_age_is_capped_at_five_minutes_without_subtracting_age() {
        assert_eq!(
            directive("max-age=3600", Some("3599")),
            MetadataCacheDirective::Store {
                fresh_for: METADATA_CACHE_TTL
            }
        );
    }

    #[test]
    fn cache_control_must_revalidate_keeps_the_declared_freshness_window() {
        assert_eq!(
            directive("max-age=60, must-revalidate", None),
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::from_secs(60)
            }
        );
    }

    #[test]
    fn malformed_cache_control_max_age_requires_immediate_revalidation() {
        assert_eq!(
            directive("max-age=not-a-number", None),
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO
            }
        );
    }

    #[test]
    fn missing_cache_control_uses_the_five_minute_local_default() {
        assert_eq!(
            RegistryClient::metadata_cache_directive(&reqwest::header::HeaderMap::new()),
            MetadataCacheDirective::Unspecified
        );
    }

    #[test]
    fn repeated_cache_control_headers_use_the_shortest_quoted_max_age() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::CACHE_CONTROL,
            reqwest::header::HeaderValue::from_static("public, MAX-AGE=\"120\""),
        );
        headers.append(
            reqwest::header::CACHE_CONTROL,
            reqwest::header::HeaderValue::from_static("max-age=30, must-revalidate"),
        );

        assert_eq!(
            RegistryClient::metadata_cache_directive(&headers),
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::from_secs(30)
            }
        );
    }

    #[test]
    fn overflowing_cache_control_max_age_requires_immediate_revalidation() {
        assert_eq!(
            directive("max-age=18446744073709551616", None),
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO
            }
        );
    }

    #[test]
    fn oversized_cache_etag_line_is_rejected_without_reading_the_payload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized-etag");
        let mut content = Vec::with_capacity(METADATA_CACHE_ETAG_LINE_CAP as usize + 32);
        content.extend_from_slice(METADATA_CACHE_MAGIC);
        content.extend_from_slice(b"300\n");
        content.resize(
            content.len() + METADATA_CACHE_ETAG_LINE_CAP as usize + 1,
            b'x',
        );
        content.extend_from_slice(b"\npayload");
        std::fs::write(&path, content).unwrap();

        assert!(RegistryClient::read_cache_validator_path(&path).is_none());
    }

    #[test]
    fn oversized_cache_freshness_line_is_rejected_without_reading_the_payload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized-freshness");
        let mut content = METADATA_CACHE_MAGIC.to_vec();
        content.resize(
            content.len() + METADATA_CACHE_FRESHNESS_LINE_CAP as usize + 1,
            b'1',
        );
        content.extend_from_slice(b"\n\npayload");
        std::fs::write(&path, content).unwrap();

        assert!(RegistryClient::read_cache_validator_path(&path).is_none());
    }
}

#[cfg(test)]
mod metadata_cache_schema_tests {
    use super::*;

    fn package_metadata_v6_fields(metadata: PackageMetadata) {
        let PackageMetadata {
            name: _,
            description: _,
            modified: _,
            dist_tags: _,
            versions: _,
            time: _,
            downloads: _,
            distribution_mode: _,
            package_type: _,
            latest_version: _,
            latest_hint: _,
            ecosystem: _,
        } = metadata;
    }

    fn version_metadata_v6_fields(metadata: VersionMetadata) {
        let VersionMetadata {
            name: _,
            version: _,
            description: _,
            deprecated: _,
            dependencies: _,
            dev_dependencies: _,
            peer_dependencies: _,
            peer_dependencies_meta: _,
            bundle_dependencies: _,
            optional_dependencies: _,
            engines: _,
            os: _,
            cpu: _,
            libc: _,
            dist: _,
            readme: _,
            lpm_config: _,
            ecosystem: _,
            swift_meta: _,
            npm_user: _,
            behavioral_tags: _,
            lifecycle_scripts: _,
            scripts: _,
            has_install_script: _,
            security_findings: _,
            quality_score: _,
            vulnerabilities: _,
            publication_status: _,
        } = metadata;
    }

    fn peer_dependency_meta_v6_fields(metadata: PeerDependencyMeta) {
        let PeerDependencyMeta { optional: _ } = metadata;
    }

    fn vulnerability_v6_fields(vulnerability: Vulnerability) {
        let Vulnerability {
            id: _,
            summary: _,
            severity: _,
            aliases: _,
        } = vulnerability;
    }

    fn behavioral_tags_v6_fields(tags: BehavioralTags) {
        let BehavioralTags {
            eval: _,
            child_process: _,
            shell: _,
            network: _,
            filesystem: _,
            crypto: _,
            dynamic_require: _,
            native_bindings: _,
            environment_vars: _,
            web_socket: _,
            obfuscated: _,
            high_entropy_strings: _,
            minified: _,
            telemetry: _,
            url_strings: _,
            trivial: _,
            protestware: _,
            git_dependency: _,
            http_dependency: _,
            wildcard_dependency: _,
            copyleft_license: _,
            no_license: _,
        } = tags;
    }

    fn security_finding_v6_fields(finding: SecurityFinding) {
        let SecurityFinding {
            severity: _,
            description: _,
            file: _,
        } = finding;
    }

    fn swift_meta_v6_fields(metadata: SwiftMeta) {
        let SwiftMeta {
            products: _,
            platforms: _,
            required_capabilities: _,
            manifest_set: _,
        } = metadata;
    }

    fn swift_manifest_set_v6_fields(set: crate::SwiftManifestSet) {
        let crate::SwiftManifestSet {
            schema_version: _,
            manifests: _,
        } = set;
    }
    fn swift_manifest_v6_fields(manifest: crate::SwiftManifest) {
        let crate::SwiftManifest {
            filename: _,
            tools_version: _,
            products: _,
            platforms: _,
        } = manifest;
    }
    fn swift_product_v6_fields(product: SwiftProduct) {
        let SwiftProduct {
            name: _,
            product_type: _,
            targets: _,
        } = product;
    }

    fn swift_platform_v6_fields(platform: SwiftPlatform) {
        let SwiftPlatform {
            platform_name: _,
            version: _,
        } = platform;
    }

    fn dist_info_v6_fields(dist: DistInfo) {
        let DistInfo {
            tarball: _,
            integrity: _,
            shasum: _,
            unpacked_size: _,
            signatures: _,
            attestations: _,
        } = dist;
    }

    fn npm_user_metadata_v6_fields(metadata: NpmUserMetadata) {
        let NpmUserMetadata {
            trusted_publisher: _,
            approver: _,
        } = metadata;
    }

    fn registry_signature_v6_fields(signature: RegistrySignature) {
        let RegistrySignature { keyid: _, sig: _ } = signature;
    }

    fn attestation_ref_v6_fields(attestation: AttestationRef) {
        let AttestationRef {
            url: _,
            provenance: _,
        } = attestation;
    }

    fn release_time_metadata_v6_fields(metadata: ReleaseTimeMetadata) {
        let ReleaseTimeMetadata {
            name: _,
            time: _,
            versions: _,
        } = metadata;
    }

    fn release_time_version_metadata_v6_fields(metadata: ReleaseTimeVersionMetadata) {
        let ReleaseTimeVersionMetadata {
            os: _,
            cpu: _,
            libc: _,
        } = metadata;
    }

    #[test]
    fn persisted_metadata_schema_v6_fields_are_exhaustive() {
        assert_eq!(METADATA_CACHE_MAGIC, b"LPM-MD-V6\n");
        let _: fn(PackageMetadata) = package_metadata_v6_fields;
        let _: fn(VersionMetadata) = version_metadata_v6_fields;
        let _: fn(PeerDependencyMeta) = peer_dependency_meta_v6_fields;
        let _: fn(Vulnerability) = vulnerability_v6_fields;
        let _: fn(BehavioralTags) = behavioral_tags_v6_fields;
        let _: fn(SecurityFinding) = security_finding_v6_fields;
        let _: fn(SwiftMeta) = swift_meta_v6_fields;
        let _: fn(crate::SwiftManifestSet) = swift_manifest_set_v6_fields;
        let _: fn(crate::SwiftManifest) = swift_manifest_v6_fields;
        let _: fn(SwiftProduct) = swift_product_v6_fields;
        let _: fn(SwiftPlatform) = swift_platform_v6_fields;
        let _: fn(DistInfo) = dist_info_v6_fields;
        let _: fn(NpmUserMetadata) = npm_user_metadata_v6_fields;
        let _: fn(RegistrySignature) = registry_signature_v6_fields;
        let _: fn(AttestationRef) = attestation_ref_v6_fields;
        let _: fn(ReleaseTimeMetadata) = release_time_metadata_v6_fields;
        let _: fn(ReleaseTimeVersionMetadata) = release_time_version_metadata_v6_fields;
    }
}

#[cfg(test)]
mod command_metadata_seed_tests {
    use super::*;

    fn package_metadata(name: &str) -> Arc<PackageMetadata> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" }
                }
            }))
            .expect("valid package metadata"),
        )
    }

    #[tokio::test]
    async fn cached_metadata_is_fresh_route_scoped_and_identity_checked() {
        let directory = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(directory.path().into()));
        let route = crate::UpstreamRoute::NpmDirect;
        let name = "cached-peer-provider";
        let key = client
            .routed_metadata_storage_cache_key(name, &route)
            .unwrap();
        client.write_metadata_cache(&key, package_metadata(name).as_ref(), None);
        client.flush_pending_cache_writes().await;
        assert_eq!(
            client
                .cached_package_metadata(name, &route)
                .await
                .unwrap()
                .latest_version_tag(),
            Some("1.0.0")
        );
        assert!(
            client
                .cached_package_metadata(name, &crate::UpstreamRoute::LpmWorker)
                .await
                .is_none()
        );

        client.write_metadata_cache(&key, package_metadata("different-package").as_ref(), None);
        client.flush_pending_cache_writes().await;
        assert!(client.cached_package_metadata(name, &route).await.is_none());

        client.write_metadata_cache_with_directive(
            &key,
            package_metadata(name).as_ref(),
            None,
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO,
            },
        );
        client.flush_pending_cache_writes().await;
        assert!(client.cached_package_metadata(name, &route).await.is_none());
    }

    #[test]
    fn command_metadata_seed_rejects_conflicting_routes_for_one_package() {
        let client = RegistryClient::new().clone_with_metadata_memory_cache();
        let package = "shared-canonical-package";

        assert!(client.seed_metadata_for_command(
            package,
            &crate::UpstreamRoute::NpmDirect,
            package_metadata(package),
        ));
        assert!(!client.seed_metadata_for_command(
            package,
            &crate::UpstreamRoute::LpmWorker,
            package_metadata(package),
        ));
        assert_eq!(
            client
                .metadata_route_overrides()
                .expect("command cache has route overrides")
                .get(package),
            Some(&crate::RouteMode::Direct)
        );
        assert!(
            client
                .npm_metadata_memory_cache(package, &crate::UpstreamRoute::LpmWorker)
                .is_none(),
            "rejected metadata must not remain reachable under the conflicting route"
        );
    }

    #[test]
    fn command_metadata_seed_does_not_retain_no_store_response() {
        let client = RegistryClient::new()
            .with_cache_dir(None)
            .clone_with_metadata_memory_cache();
        let package = "no-store-command-seed";
        let metadata = package_metadata(package);
        let cache_key = client.npm_direct_metadata_cache_key(package);

        client.write_metadata_cache_with_directive(
            &cache_key,
            metadata.as_ref(),
            None,
            MetadataCacheDirective::NoStore,
        );
        assert!(client.seed_metadata_for_command(
            package,
            &crate::UpstreamRoute::NpmDirect,
            metadata,
        ));

        assert!(
            client.npm_metadata_direct_memory_cache(package).is_none(),
            "no-store metadata must not enter the command-scoped cache"
        );
    }

    #[test]
    fn command_metadata_seed_does_not_retain_revalidation_required_response() {
        let client = RegistryClient::new()
            .with_cache_dir(None)
            .clone_with_metadata_memory_cache();
        let package = "no-cache-command-seed";
        let metadata = package_metadata(package);
        let cache_key = client.npm_direct_metadata_cache_key(package);

        client.write_metadata_cache_with_directive(
            &cache_key,
            metadata.as_ref(),
            None,
            MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO,
            },
        );
        assert!(client.seed_metadata_for_command(
            package,
            &crate::UpstreamRoute::NpmDirect,
            metadata,
        ));

        assert!(
            client.npm_metadata_direct_memory_cache(package).is_none(),
            "metadata requiring revalidation must not enter the command-scoped cache"
        );
    }
}

/// Parse a cached metadata blob.
///
/// Validates the magic header, freshness, and ETag lines, then returns the
/// freshness duration, parsed ETag, and payload bytes. Returns `None` on any
/// shape mismatch. Old-format cache entries fail the magic check here and are
/// silently re-fetched.
#[cfg(test)]
pub(super) fn parse_cached_metadata_blob(
    content: &[u8],
) -> Option<(std::time::Duration, Option<String>, &[u8])> {
    if content.len() < METADATA_CACHE_MAGIC.len() {
        return None;
    }
    if !content.starts_with(METADATA_CACHE_MAGIC) {
        return None;
    }
    let after_magic = &content[METADATA_CACHE_MAGIC.len()..];
    let freshness_end = after_magic.iter().position(|&b| b == b'\n')?;
    if freshness_end as u64 > METADATA_CACHE_FRESHNESS_LINE_CAP {
        return None;
    }
    let fresh_for_secs = std::str::from_utf8(&after_magic[..freshness_end])
        .ok()?
        .parse::<u64>()
        .ok()?;
    if fresh_for_secs > METADATA_CACHE_TTL.as_secs() {
        return None;
    }
    let after_freshness = &after_magic[freshness_end + 1..];
    let etag_end = after_freshness.iter().position(|&b| b == b'\n')?;
    if etag_end as u64 > METADATA_CACHE_ETAG_LINE_CAP {
        return None;
    }
    let etag = std::str::from_utf8(&after_freshness[..etag_end])
        .ok()
        .filter(|value| !value.is_empty())
        .and_then(|value| reqwest::header::HeaderValue::from_str(value).ok())
        .and_then(|value| value.to_str().ok().map(str::to_owned));
    if etag_end != 0 && etag.is_none() {
        return None;
    }
    Some((
        std::time::Duration::from_secs(fresh_for_secs),
        etag,
        &after_freshness[etag_end + 1..],
    ))
}

#[cfg(test)]
mod timeline_tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt as _;

    struct TraceRecords(Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>);

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for TraceRecords
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == "lpm_install_timeline" {
                self.0
                    .lock()
                    .unwrap()
                    .push(("event", event.metadata().name()));
            }
        }
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::Id,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().target() == "lpm_install_timeline" {
                self.0
                    .lock()
                    .unwrap()
                    .push(("open", attrs.metadata().name()));
            }
        }
        fn on_close(&self, id: tracing::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            if let Some(span) = ctx.span(&id)
                && span.metadata().target() == "lpm_install_timeline"
            {
                self.0
                    .lock()
                    .unwrap()
                    .push(("close", span.metadata().name()));
            }
        }
    }

    #[test]
    fn cache_serialization_budget_skip_finishes_its_trace_operation() {
        let dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(dir.path().to_owned()));
        client.pending_cache_write_bytes = Arc::new(tokio::sync::Semaphore::new(8192));
        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(TraceRecords(Arc::clone(&records)));
        tracing::subscriber::with_default(subscriber, || {
            client.write_metadata_cache(
                "skip",
                &serde_json::json!({"payload": "x".repeat(8192)}),
                None,
            );
        });
        assert!(!client.cache_path("skip").unwrap().exists());
        let records = records.lock().unwrap();
        if records.contains(&("event", "cache_serialize_start")) {
            assert!(
                records.contains(&("event", "cache_serialize_end")),
                "{records:?}"
            );
        }
        assert!(
            records.contains(&("open", "metadata_cache_serialization")),
            "{records:?}"
        );
        assert!(
            records.contains(&("close", "metadata_cache_serialization")),
            "{records:?}"
        );
    }
}
