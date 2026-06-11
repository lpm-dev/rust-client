use super::*;

pub(super) const METADATA_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Max bytes accepted from a single on-disk metadata cache entry.
///
/// The cache lives under `~/.lpm/cache/metadata/` (the trust boundary
/// documented above the magic constant); but a same-user process that
/// can plant a multi-GB file there would force every fresh-path read
/// to allocate it before serde even noticed the bytes were nonsense.
/// 100 MB matches the on-the-wire `MAX_METADATA_BYTES` cap so a
/// legitimate worst-case packument always round-trips through the
/// cache, while pathological files collapse to a cache miss before
/// any decode work happens.
pub(super) const METADATA_CACHE_FILE_CAP: u64 = 100 * 1024 * 1024;

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

impl RegistryClient {
    // ─── Metadata Cache ──────────────────────────────────────────────

    pub(super) fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Some(dir.join(&hash[..16]))
    }

    /// Invalidate a cached metadata entry served by the LPM Worker
    /// (`@lpm.dev/*`) or by direct npm.org (built-in `npm:{name}`).
    ///
    /// Used when a tarball download returns 404 — the cached metadata
    /// likely references an unpublished version. Deleting the cache
    /// forces a fresh fetch on the next request.
    ///
    /// **Limitation:** custom-registry metadata (served by
    /// `get_npm_metadata_from`) is keyed by
    /// `npm:<auth_fingerprint>:<full_url>` — neither the URL nor the
    /// auth is recoverable from `package_name` alone, so this method
    /// cannot invalidate those entries. Callers on the custom-registry
    /// path MUST use [`Self::invalidate_custom_metadata_cache`] instead.
    pub fn invalidate_metadata_cache(&self, package_name: &str) {
        let cache_key = if package_name.starts_with("@lpm.dev/") {
            format!("lpm:{package_name}")
        } else {
            format!("npm:{package_name}")
        };
        if let Some(path) = self.cache_path(&cache_key)
            && path.exists()
        {
            let _ = std::fs::remove_file(&path);
            tracing::debug!("invalidated metadata cache for {package_name}");
        }
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
        let url = format!("{base_url}/{name}");
        let cache_key = format!(
            "npm:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );
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
        let cache_key = if package_name.starts_with("@lpm.dev/") {
            format!("lpm:{package_name}")
        } else {
            format!("npm:{package_name}")
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
    pub(super) fn read_cache_content(&self, key: &str) -> Option<CacheContent> {
        let path = self.cache_path(key)?;
        if !path.exists() {
            return None;
        }

        // Reject oversized cache files before any bytes hit memory.
        // Same boundary as `read_metadata_cache_as`; complements its
        // TTL-only check on the stale-conditional-request path.
        let file_size = path.metadata().ok()?.len();
        if file_size > METADATA_CACHE_FILE_CAP {
            tracing::warn!(
                path = %path.display(),
                size = file_size,
                cap = METADATA_CACHE_FILE_CAP,
                "metadata cache entry exceeds size cap — treating as miss"
            );
            return None;
        }

        let content = std::fs::read(&path).ok()?;
        let (etag_bytes, data) = parse_cached_metadata_blob(&content)?;

        let etag = std::str::from_utf8(etag_bytes)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        Some(CacheContent {
            etag,
            data: data.to_vec(),
        })
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
    pub(super) fn write_metadata_cache(
        &self,
        key: &str,
        metadata: &PackageMetadata,
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
        let data = match rmp_serde::to_vec_named(metadata) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "MessagePack serialization failed for {key}, falling back to JSON: {e}"
                );
                serde_json::to_vec(metadata).unwrap_or_default()
            }
        };
        if data.is_empty() {
            return;
        }

        let etag_str = etag.unwrap_or("");

        // Build: MAGIC ETag\ndata. The magic constant ends with `\n` so the
        // ETag line begins immediately after it.
        let mut content =
            Vec::with_capacity(METADATA_CACHE_MAGIC.len() + etag_str.len() + 1 + data.len());
        content.extend_from_slice(METADATA_CACHE_MAGIC);
        content.extend_from_slice(etag_str.as_bytes());
        content.push(b'\n');
        content.extend_from_slice(&data);

        let key_owned = key.to_string();
        // Sync path: no runtime available, OR caller explicitly opted
        // into synchronous writes (test helpers verifying cache-hit
        // behavior — see `with_synchronous_cache_writes` docs).
        let runtime_handle = tokio::runtime::Handle::try_current();
        if self.synchronous_cache_writes || runtime_handle.is_err() {
            if let Err(e) = std::fs::write(&path, &content) {
                tracing::warn!("failed to write metadata cache for {key_owned}: {e}");
            }
            return;
        }
        // Async context: dispatch the blocking write to spawn_blocking.
        // The handle is recorded on `pending_cache_writes` so tests can
        // deterministically await completion via
        // `flush_pending_cache_writes()`. Production callers ignore it.
        let handle = runtime_handle.unwrap();
        let join = handle.spawn_blocking(move || {
            if let Err(e) = std::fs::write(&path, &content) {
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
