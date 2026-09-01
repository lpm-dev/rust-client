use super::*;

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
const METADATA_CACHE_ETAG_LINE_CAP: u64 = 8 * 1024;
const METADATA_CACHE_FRESHNESS_LINE_CAP: u64 = 20;
pub(super) const MAX_PENDING_METADATA_CACHE_BYTES: usize = 128 * 1024 * 1024;

/// Magic header for the manifest cache file format. Replaces the
/// per-payload HMAC-SHA256 that used to run on every write. The cache
/// lives at `~/.lpm/cache/metadata/` inside the user's home; if an
/// attacker can write there they own the install anyway, so signing
/// the bytes adds no real security boundary.
///
/// On format change, bump the trailing version number — old cache
/// entries fail the magic match and are silently treated as misses.
///
/// V4 invalidates typed payloads written before the current persisted
/// metadata schema and stores each response's bounded local freshness.
/// The magic also salts cache filenames, so schema-old entries cannot make
/// the resolver's stat-only batch probe disagree with the typed reader.
pub(super) const METADATA_CACHE_MAGIC: &[u8] = b"LPM-MD-V4\n";

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
    content: &[u8],
    fresh_for: std::time::Duration,
) -> std::io::Result<()> {
    use std::io::Write as _;

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
            file.write_all(content)?;
            set_metadata_cache_file_expiry(&file, fresh_for)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(content)?;
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
        if package_name.starts_with("@lpm.dev/") {
            if let Ok(key) = self.lpm_metadata_cache_key(package_name) {
                self.invalidate_metadata_cache_key(&key);
            }
        } else {
            let direct_key = self.npm_direct_metadata_cache_key(package_name);
            self.invalidate_metadata_cache_key(&direct_key);
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
        let cache_key = self.npm_direct_version_metadata_cache_key(package_name, version);
        self.invalidate_metadata_cache_key(&cache_key);
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
    /// Cache format (v4): `LPM-MD-V4\n{freshness_seconds}\n{ETag}\n{binary_data}`
    /// - Bytes 0..MAGIC.len(): magic header (ends in `\n`)
    /// - After magic, up to next `\n`: local freshness in seconds
    /// - Next line: ETag string (empty if absent)
    /// - Remainder: named MessagePack-serialized PackageMetadata
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
        tokio::task::spawn_blocking(move || Self::read_metadata_cache_path_entry_as::<T>(&path))
            .await
            .ok()
            .flatten()
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
    pub(super) fn read_metadata_cache_as<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Option<(T, Option<String>)> {
        let path = self.cache_path(key)?;
        Self::read_metadata_cache_path_as(&path)
    }

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
        use std::io::Read as _;

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

        let value: T = rmp_serde::decode::from_read(&mut reader).ok()?;
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
        let mut content = Vec::with_capacity(prefix_len + 4096);
        content.extend_from_slice(METADATA_CACHE_MAGIC);
        content.extend_from_slice(freshness.as_bytes());
        content.push(b'\n');
        content.extend_from_slice(etag_str.as_bytes());
        content.push(b'\n');

        if let Err(messagepack_error) = rmp_serde::encode::write_named(&mut content, metadata) {
            content.truncate(prefix_len);
            if let Err(json_error) = serde_json::to_writer(&mut content, metadata) {
                tracing::warn!(
                    "metadata cache serialization failed for {key}: MessagePack: {messagepack_error}; JSON: {json_error}"
                );
                return None;
            }
        }
        if content.len() == prefix_len || content.len() as u64 > METADATA_CACHE_FILE_CAP {
            return None;
        }

        let key_owned = key.to_string();
        let mutation = self.metadata_cache_mutation(&path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;
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

        let Some(reservation) =
            reserve_pending_metadata_cache_bytes(&self.pending_cache_write_bytes, content.len())
        else {
            tracing::debug!(
                bytes = content.len(),
                "skipping best-effort metadata cache write because the queued-byte budget is full"
            );
            return Some(fresh_for);
        };
        let handle = runtime_handle.unwrap();
        let join = handle.spawn_blocking(move || {
            let _reservation = reservation;
            let _operation = mutation
                .operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mutation.revision.load(Ordering::Acquire) == revision
                && let Err(e) = write_metadata_cache_file(&path, &content, fresh_for)
            {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
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

    fn package_metadata_v4_fields(metadata: PackageMetadata) {
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
            ecosystem: _,
        } = metadata;
    }

    fn version_metadata_v4_fields(metadata: VersionMetadata) {
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
            security_findings: _,
            quality_score: _,
            vulnerabilities: _,
        } = metadata;
    }

    fn peer_dependency_meta_v4_fields(metadata: PeerDependencyMeta) {
        let PeerDependencyMeta { optional: _ } = metadata;
    }

    fn vulnerability_v4_fields(vulnerability: Vulnerability) {
        let Vulnerability {
            id: _,
            summary: _,
            severity: _,
            aliases: _,
        } = vulnerability;
    }

    fn behavioral_tags_v4_fields(tags: BehavioralTags) {
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

    fn security_finding_v4_fields(finding: SecurityFinding) {
        let SecurityFinding {
            severity: _,
            description: _,
            file: _,
        } = finding;
    }

    fn swift_meta_v4_fields(metadata: SwiftMeta) {
        let SwiftMeta {
            products: _,
            platforms: _,
        } = metadata;
    }

    fn swift_product_v4_fields(product: SwiftProduct) {
        let SwiftProduct {
            name: _,
            product_type: _,
            targets: _,
        } = product;
    }

    fn swift_platform_v4_fields(platform: SwiftPlatform) {
        let SwiftPlatform {
            platform_name: _,
            version: _,
        } = platform;
    }

    fn dist_info_v4_fields(dist: DistInfo) {
        let DistInfo {
            tarball: _,
            integrity: _,
            shasum: _,
            unpacked_size: _,
            signatures: _,
            attestations: _,
        } = dist;
    }

    fn npm_user_metadata_v4_fields(metadata: NpmUserMetadata) {
        let NpmUserMetadata {
            trusted_publisher: _,
            approver: _,
        } = metadata;
    }

    fn registry_signature_v4_fields(signature: RegistrySignature) {
        let RegistrySignature { keyid: _, sig: _ } = signature;
    }

    fn attestation_ref_v4_fields(attestation: AttestationRef) {
        let AttestationRef {
            url: _,
            provenance: _,
        } = attestation;
    }

    fn release_time_metadata_v4_fields(metadata: ReleaseTimeMetadata) {
        let ReleaseTimeMetadata {
            name: _,
            time: _,
            versions: _,
        } = metadata;
    }

    fn release_time_version_metadata_v4_fields(metadata: ReleaseTimeVersionMetadata) {
        let ReleaseTimeVersionMetadata {
            os: _,
            cpu: _,
            libc: _,
        } = metadata;
    }

    #[test]
    fn persisted_metadata_schema_v4_fields_are_exhaustive() {
        assert_eq!(METADATA_CACHE_MAGIC, b"LPM-MD-V4\n");
        let _: fn(PackageMetadata) = package_metadata_v4_fields;
        let _: fn(VersionMetadata) = version_metadata_v4_fields;
        let _: fn(PeerDependencyMeta) = peer_dependency_meta_v4_fields;
        let _: fn(Vulnerability) = vulnerability_v4_fields;
        let _: fn(BehavioralTags) = behavioral_tags_v4_fields;
        let _: fn(SecurityFinding) = security_finding_v4_fields;
        let _: fn(SwiftMeta) = swift_meta_v4_fields;
        let _: fn(SwiftProduct) = swift_product_v4_fields;
        let _: fn(SwiftPlatform) = swift_platform_v4_fields;
        let _: fn(DistInfo) = dist_info_v4_fields;
        let _: fn(NpmUserMetadata) = npm_user_metadata_v4_fields;
        let _: fn(RegistrySignature) = registry_signature_v4_fields;
        let _: fn(AttestationRef) = attestation_ref_v4_fields;
        let _: fn(ReleaseTimeMetadata) = release_time_metadata_v4_fields;
        let _: fn(ReleaseTimeVersionMetadata) = release_time_version_metadata_v4_fields;
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
