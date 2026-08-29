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
/// V3 bump: custom-registry support means a single package name can
/// be served by multiple distinct registries (e.g., `react` from
/// `registry.npmjs.org` vs an internal mirror). `get_npm_metadata_from`
/// keys per-host (`npm:<host>:<name>`); the magic bump invalidates
/// pre-V3 caches in one shot rather than letting two key formats
/// co-exist with the same magic.
pub(super) const METADATA_CACHE_MAGIC: &[u8] = b"LPM-MD-V3\n";

pub(super) fn ensure_private_metadata_cache_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_metadata_cache_file(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        ensure_private_metadata_cache_dir(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(content)
}

fn reserve_pending_metadata_cache_bytes(
    budget: &Arc<tokio::sync::Semaphore>,
    bytes: usize,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permits = u32::try_from(bytes).ok()?;
    Arc::clone(budget).try_acquire_many_owned(permits).ok()
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
        self.metadata_memory_cache
            .as_ref()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
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
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, metadata);
        true
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

    pub(super) fn remember_metadata_for_command(&self, key: &str, metadata: &PackageMetadata) {
        let Some(cache) = &self.metadata_memory_cache else {
            return;
        };
        let metadata = Arc::new(metadata.clone());
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key.to_owned())
            .or_insert(metadata);
    }

    pub(super) fn read_release_time_memory_cache(&self, key: &str) -> Option<ReleaseTimeMetadata> {
        let cached = self
            .release_time_memory_cache
            .as_ref()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned();
        cached.map(|metadata| metadata.as_ref().clone())
    }

    pub(super) fn remember_release_times_for_command(
        &self,
        key: &str,
        metadata: &ReleaseTimeMetadata,
    ) {
        let Some(cache) = &self.release_time_memory_cache else {
            return;
        };
        let metadata = Arc::new(metadata.clone());
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key.to_owned())
            .or_insert(metadata);
    }

    fn invalidate_metadata_memory_cache(&self, key: &str) {
        if let Some(cache) = &self.metadata_memory_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
    }

    fn invalidate_metadata_cache_key(&self, key: &str) {
        self.invalidate_metadata_memory_cache(key);
        let direct_memory_key = self.direct_metadata_memory_cache_key(key);
        self.invalidate_metadata_memory_cache(&direct_memory_key);
        if let Some(path) = self.cache_path(key) {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => tracing::debug!(%error, "failed to invalidate metadata cache entry"),
            }
        }
    }

    pub(super) fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
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
        if let Some(path) = self.cache_path(&cache_key)
            && path.exists()
        {
            let _ = std::fs::remove_file(&path);
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
        let Ok(modified) = meta.modified() else {
            return false;
        };
        let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
            return false;
        };
        age < METADATA_CACHE_TTL
    }

    /// Read cached metadata if it exists, is within TTL, and starts with
    /// the expected magic header.
    ///
    /// Returns `(PackageMetadata, Option<etag>)`. The ETag (if present) can be
    /// sent as `If-None-Match` on the next request to enable 304 responses.
    ///
    /// Cache format (v3): `LPM-MD-V3\n{ETag}\n{binary_data}`
    /// - Bytes 0..MAGIC.len(): magic header (ends in `\n`)
    /// - After magic, up to next `\n`: ETag string (empty if absent)
    /// - Remainder: MessagePack-serialized PackageMetadata (with JSON fallback for migration)
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
        let path = self.cache_path(key)?;
        tokio::task::spawn_blocking(move || Self::read_metadata_cache_path_as::<T>(&path))
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
        use std::io::{BufRead as _, Read as _};

        if !path.exists() {
            return None;
        }

        // Check TTL based on file modification time AND enforce a
        // hard size cap before any bytes are buffered. Same-user
        // attacker who plants a multi-GB cache file no longer gets
        // a free `Vec<u8>` allocation on every install start.
        let meta = path.metadata().ok()?;
        let modified = meta.modified().ok()?;
        let age = std::time::SystemTime::now().duration_since(modified).ok()?;
        if age > METADATA_CACHE_TTL {
            return None;
        }
        if meta.len() > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = meta.len(),
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        // Open with a buffered reader — avoids allocating the full file into
        // a Vec<u8> before deserialization.
        let file = std::fs::File::open(path).ok()?;
        // Bound the decoder's read window so a cache file that grows
        // between the metadata check and the open() (race with another
        // writer) still can't exceed the cap.
        let mut reader =
            std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));

        // Validate magic prefix (METADATA_CACHE_MAGIC includes a trailing \n)
        let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
        reader.read_exact(&mut magic).ok()?;
        if magic != *METADATA_CACHE_MAGIC {
            return None;
        }

        // Read ETag line (terminated by \n; empty string means no ETag)
        let mut etag_line = String::with_capacity(64);
        reader.read_line(&mut etag_line).ok()?;
        let etag_str = etag_line.trim_end_matches('\n');
        let etag = if etag_str.is_empty() {
            None
        } else {
            Some(etag_str.to_string())
        };

        // Stream-deserialize the named-format msgpack data.
        // For old (positional-array or JSON) caches this returns Err → None,
        // triggering a cache miss and a re-fetch that rewrites in named format.
        let metadata: T = rmp_serde::decode::from_read(&mut reader).ok()?;

        Some((metadata, etag))
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
        let (etag_bytes, data) = parse_cached_metadata_blob(&content)?;

        #[cfg(test)]
        let etag = std::str::from_utf8(etag_bytes)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        #[cfg(not(test))]
        let _ = etag_bytes;

        Some(CacheContent {
            #[cfg(test)]
            etag,
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
        use std::io::{BufRead as _, Read as _};

        if !path.exists() {
            return None;
        }

        let file_metadata = path.metadata().ok()?;
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

        let file = std::fs::File::open(path).ok()?;
        let mut reader =
            std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));

        let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
        reader.read_exact(&mut magic).ok()?;
        if magic != *METADATA_CACHE_MAGIC {
            return None;
        }

        let mut etag_line = Vec::with_capacity(64);
        let bytes_read = reader
            .by_ref()
            .take(METADATA_CACHE_ETAG_LINE_CAP + 1)
            .read_until(b'\n', &mut etag_line)
            .ok()?;
        if bytes_read == 0
            || etag_line.last().copied() != Some(b'\n')
            || etag_line.len() as u64 > METADATA_CACHE_ETAG_LINE_CAP
        {
            return None;
        }
        etag_line.pop();

        let etag = std::str::from_utf8(&etag_line)
            .ok()
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let age_seconds = file_metadata
            .modified()
            .ok()
            .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
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
    pub(super) fn write_metadata_cache<T: serde::Serialize + ?Sized>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
    ) {
        let Some(path) = self.cache_path(key) else {
            return;
        };

        // Serialize: prefer MessagePack (map/named format so partial-struct
        // deserialization works — e.g., `BlockedSetPackageMeta` reads only
        // `time` + `versions._behavioralTags`), fall back to JSON.
        // Named format adds ~10% size vs. array format but the cache files
        // are small (≤30 KB) so the delta is negligible.
        let etag_str = etag.unwrap_or("");
        let prefix_len = METADATA_CACHE_MAGIC.len() + etag_str.len() + 1;
        let mut content = Vec::with_capacity(prefix_len + 4096);
        content.extend_from_slice(METADATA_CACHE_MAGIC);
        content.extend_from_slice(etag_str.as_bytes());
        content.push(b'\n');

        if let Err(messagepack_error) = rmp_serde::encode::write_named(&mut content, metadata) {
            content.truncate(prefix_len);
            if let Err(json_error) = serde_json::to_writer(&mut content, metadata) {
                tracing::warn!(
                    "metadata cache serialization failed for {key}: MessagePack: {messagepack_error}; JSON: {json_error}"
                );
                return;
            }
        }
        if content.len() == prefix_len || content.len() as u64 > METADATA_CACHE_FILE_CAP {
            return;
        }

        let key_owned = key.to_string();
        let runtime_handle = tokio::runtime::Handle::try_current();
        if self.synchronous_cache_writes || runtime_handle.is_err() {
            if let Err(e) = write_metadata_cache_file(&path, &content) {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
            return;
        }

        let Some(reservation) =
            reserve_pending_metadata_cache_bytes(&self.pending_cache_write_bytes, content.len())
        else {
            tracing::debug!(
                bytes = content.len(),
                "skipping best-effort metadata cache write because the queued-byte budget is full"
            );
            return;
        };
        let handle = runtime_handle.unwrap();
        let join = handle.spawn_blocking(move || {
            let _reservation = reservation;
            if let Err(e) = write_metadata_cache_file(&path, &content) {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
        });
        if let Ok(mut pending) = self.pending_cache_writes.lock() {
            pending.push(join);
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
}

/// Parse a cached metadata blob.
///
/// Validates the magic header, then locates the ETag line terminator and
/// returns `(etag_bytes, payload_bytes)` borrowed from the input. Returns
/// `None` on any shape mismatch (wrong magic, missing ETag terminator,
/// truncated payload). Old-format cache entries fail the magic check here
/// and are silently re-fetched.
pub(super) fn parse_cached_metadata_blob(content: &[u8]) -> Option<(&[u8], &[u8])> {
    if content.len() < METADATA_CACHE_MAGIC.len() {
        return None;
    }
    if !content.starts_with(METADATA_CACHE_MAGIC) {
        return None;
    }
    let after_magic = &content[METADATA_CACHE_MAGIC.len()..];
    let nl_offset = after_magic.iter().position(|&b| b == b'\n')?;
    Some((&after_magic[..nl_offset], &after_magic[nl_offset + 1..]))
}
