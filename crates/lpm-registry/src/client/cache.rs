use super::projection::{
    MetadataProjection, ProjectionFacts, ProjectionSource, projection_path, read_projection,
};
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
// MessagePack reserves 0xc1, so older readers treat tagged fallback entries as misses.
// Payloads starting with `[0xc1, ZSTD_FRAME_MAGIC...]` are zstd-compressed named MessagePack;
// other `0xc1`-prefixed payloads are JSON fallback entries (valid JSON never starts with 0x28).
pub(super) const METADATA_CACHE_JSON_MARKER: u8 = 0xc1;
pub(super) const ZSTD_FRAME_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
const ZSTD_COMPRESS_THRESHOLD: usize = 4096;
const ZSTD_COMPRESS_LEVEL: i32 = 1;
pub(super) const ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// Magic header for the manifest cache file format. Replaces the
/// per-payload HMAC-SHA256 that used to run on every write. The cache
/// lives at `~/.lpm/cache/metadata/` inside the user's home; if an
/// attacker can write there they own the install anyway, so signing
/// the bytes adds no real security boundary.
///
/// On format change, bump the trailing version number — old cache
/// entries fail the magic match and are silently treated as misses.
///
/// V9 adds zstd-framed named MessagePack compression for larger payloads and
/// omits empty optional fields on serialization.
/// The magic also salts cache filenames, so schema-old entries cannot make
/// the resolver's stat-only batch probe disagree with the typed reader.
pub(super) const METADATA_CACHE_MAGIC: &[u8] = b"LPM-MD-V9\n";
const METADATA_CACHE_CONTENT_ID_LEN: u64 = 32;

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
    expires_at: std::time::SystemTime,
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
            set_metadata_cache_file_expiry(&file, expires_at)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    content.write_to(&mut file)?;
    set_metadata_cache_file_expiry(file.as_file(), expires_at)?;
    file.persist(path).map(|_| ()).map_err(|error| error.error)
}

fn set_metadata_cache_file_expiry(
    file: &std::fs::File,
    expires_at: std::time::SystemTime,
) -> std::io::Result<()> {
    file.set_times(std::fs::FileTimes::new().set_modified(expires_at))
}

pub(super) fn reserve_pending_metadata_cache_bytes(
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

#[derive(Clone)]
pub(super) struct MetadataCacheHeader {
    pub(super) fresh_for: std::time::Duration,
    pub(super) etag: Option<String>,
    pub(super) content_id: u128,
}

fn read_metadata_cache_header<R: std::io::BufRead>(reader: &mut R) -> Option<MetadataCacheHeader> {
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
    let content_id = parse_content_id(&read_bounded_cache_line(
        reader,
        METADATA_CACHE_CONTENT_ID_LEN,
    )?)?;
    Some(MetadataCacheHeader {
        fresh_for: std::time::Duration::from_secs(fresh_for_secs),
        etag,
        content_id,
    })
}

fn parse_content_id(line: &[u8]) -> Option<u128> {
    if line.len() as u64 != METADATA_CACHE_CONTENT_ID_LEN || !line.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    u128::from_str_radix(std::str::from_utf8(line).ok()?, 16).ok()
}

pub(super) type MetadataCacheReader = std::io::BufReader<std::io::Take<std::fs::File>>;

pub(super) struct OpenedMetadataCacheEntry {
    pub(super) reader: MetadataCacheReader,
    pub(super) header: MetadataCacheHeader,
    pub(super) modified: std::time::SystemTime,
}

/// Open a cache entry and read its header, leaving the reader at the payload.
pub(super) fn open_metadata_cache_entry(
    path: &std::path::Path,
) -> Option<OpenedMetadataCacheEntry> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).ok()?;
    let file_metadata = file.metadata().ok()?;
    if file_metadata.len() > METADATA_CACHE_FILE_CAP {
        tracing::warn!(
            path = %path.display(),
            size = file_metadata.len(),
            cap = METADATA_CACHE_FILE_CAP,
            "metadata cache entry exceeds size cap — treating as miss"
        );
        return None;
    }
    let mut reader = std::io::BufReader::new(std::io::Read::take(file, METADATA_CACHE_FILE_CAP));
    let mut magic = [0u8; METADATA_CACHE_MAGIC.len()];
    reader.read_exact(&mut magic).ok()?;
    if magic != *METADATA_CACHE_MAGIC {
        return None;
    }
    let header = read_metadata_cache_header(&mut reader)?;
    Some(OpenedMetadataCacheEntry {
        reader,
        header,
        modified: file_metadata.modified().ok()?,
    })
}

pub(super) fn decode_zstd_msgpack_with_seed<R, T, S>(reader: R, seed: S) -> Option<T>
where
    R: std::io::Read,
    S: for<'de> serde::de::DeserializeSeed<'de, Value = T>,
{
    use std::io::Read as _;

    let mut decoder = zstd::stream::read::Decoder::new(reader).ok()?;
    decoder.window_log_max(ZSTD_WINDOW_LOG_MAX).ok()?;
    let mut limited = std::io::Read::take(decoder, METADATA_CACHE_FILE_CAP + 1);
    let mut deserializer = rmp_serde::Deserializer::new(&mut limited);
    let value = seed.deserialize(&mut deserializer).ok()?;
    let mut trailing = [0u8; 1];
    if limited.read(&mut trailing).ok()? != 0 || limited.limit() == 0 {
        return None;
    }
    Some(value)
}

#[cfg(test)]
pub(super) fn decode_zstd_msgpack_payload<T: serde::de::DeserializeOwned>(
    data: &[u8],
) -> Option<T> {
    decode_zstd_msgpack_with_seed(data, std::marker::PhantomData::<T>)
}

pub(super) fn decode_metadata_cache_payload_with_seed<T, S>(
    reader: &mut MetadataCacheReader,
    seed: S,
) -> Option<T>
where
    S: for<'de> serde::de::DeserializeSeed<'de, Value = T>,
{
    use std::io::{BufRead as _, Read as _};

    if reader.fill_buf().ok()?.first() == Some(&METADATA_CACHE_JSON_MARKER) {
        reader.consume(1);
        let mut head = [0u8; ZSTD_FRAME_MAGIC.len()];
        let mut read_len = 0usize;
        while read_len < head.len() {
            match reader.read(&mut head[read_len..]) {
                Ok(0) => break,
                Ok(n) => read_len += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
        let chained = std::io::Read::chain(&head[..read_len], reader);
        if read_len == ZSTD_FRAME_MAGIC.len() && head == *ZSTD_FRAME_MAGIC {
            decode_zstd_msgpack_with_seed(chained, seed)
        } else {
            let mut deserializer = serde_json::Deserializer::from_reader(chained);
            let value = seed.deserialize(&mut deserializer).ok()?;
            deserializer.end().ok()?;
            Some(value)
        }
    } else {
        let mut deserializer = rmp_serde::Deserializer::new(&mut *reader);
        let value = seed.deserialize(&mut deserializer).ok()?;
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing).ok()? != 0 {
            return None;
        }
        Some(value)
    }
}

pub(super) fn decode_metadata_cache_payload<T: serde::de::DeserializeOwned>(
    reader: &mut MetadataCacheReader,
) -> Option<T> {
    decode_metadata_cache_payload_with_seed(reader, std::marker::PhantomData::<T>)
}

impl OpenedMetadataCacheEntry {
    /// Remaining freshness, when the entry is fresh and its expiry is within
    /// the freshness it was written with.
    pub(super) fn remaining_freshness(&self) -> Option<std::time::Duration> {
        remaining_cache_freshness(self.modified)
            .filter(|remaining| *remaining <= self.header.fresh_for)
    }

    /// The stored projection of this document, or else the decoded document.
    pub(super) fn resolve<T: serde::de::DeserializeOwned, P: MetadataProjection>(
        mut self,
        path: &std::path::Path,
    ) -> Option<CachedResolution<T, P>> {
        let source = ProjectionSource {
            entry: path.to_path_buf(),
            content_id: self.header.content_id,
        };
        if let Some((value, facts)) = read_projection::<P>(path, self.header.content_id) {
            return Some(CachedResolution::Projected {
                value,
                facts,
                source,
            });
        }
        let value = decode_metadata_cache_payload(&mut self.reader)?;
        Some(CachedResolution::Document {
            value,
            source: Some(source),
        })
    }
}

/// A cached document, or the stored projection bound to it.
pub(super) enum CachedResolution<T, P> {
    Document {
        value: T,
        /// The entry holding the document, absent when it was not persisted.
        source: Option<ProjectionSource>,
    },
    Projected {
        value: P,
        facts: ProjectionFacts,
        source: ProjectionSource,
    },
}

/// The outcome of a dispatched metadata cache write.
pub(super) struct MetadataCacheWrite {
    pub(super) fresh_for: std::time::Duration,
    /// The entry being written, absent when the write was skipped.
    pub(super) source: Option<ProjectionSource>,
}

fn sanitize_url_without_secrets(raw: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(raw) else {
        return lpm_common::safe_url_origin(raw);
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return lpm_common::safe_url_origin(raw);
    }
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    let rendered = parsed.to_string();
    if !raw.ends_with('/') && parsed.path() == "/" {
        rendered.trim_end_matches('/').to_string()
    } else {
        rendered
    }
}

fn sanitize_cache_key_for_log(key: &str) -> String {
    // Handle length-prefixed routed memory keys:
    //   direct:<len>:<url>:<pkg>
    //   worker:<principal>:<len>:<url>:<pkg>
    //   custom:<principal>:<len>:<url>:<pkg>
    for prefix in ["direct:", "worker:", "custom:"] {
        if let Some(after_prefix) = key.strip_prefix(prefix) {
            let (lead, len_and_rest) = if prefix == "direct:" {
                ("", after_prefix)
            } else if let Some((principal, rest)) = after_prefix.split_once(':') {
                (principal, rest)
            } else {
                break;
            };
            if let Some((len_str, rest)) = len_and_rest.split_once(':')
                && let Ok(url_len) = len_str.parse::<usize>()
                && url_len <= rest.len()
                && rest.is_char_boundary(url_len)
            {
                let (raw_url, tail) = rest.split_at(url_len);
                let safe_url = sanitize_url_without_secrets(raw_url);
                let safe_tail = tail.split(['?', '#']).next().unwrap_or(tail);
                return if lead.is_empty() {
                    format!("{prefix}{safe_url}{safe_tail}")
                } else {
                    format!("{prefix}{lead}:{safe_url}{safe_tail}")
                };
            }
        }
    }
    // Handle storage keys like `npm:<principal>:<url>` or raw URLs.
    if let Some(scheme_pos) = key.find("://") {
        let prefix = &key[..scheme_pos];
        let scheme = prefix
            .rsplit(':')
            .next()
            .filter(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
            .unwrap_or("https");
        let url_start = scheme_pos.saturating_sub(scheme.len());
        let before_url = &key[..url_start];
        let raw_url = &key[url_start..];
        let safe_url = sanitize_url_without_secrets(raw_url);
        return format!("{before_url}{safe_url}");
    }
    key.split(['?', '#']).next().unwrap_or(key).to_string()
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

    fn worker_principal_fingerprint(&self) -> Option<String> {
        use sha2::{Digest as _, Sha256};

        let identity_fp = self.http.identity_fp_for_url(&self.base_url);
        let bearer = self
            .current_bearer(super::auth::AuthPosture::PackageRead)
            .ok()?;
        if bearer.is_none() && identity_fp.is_none() {
            return Some("anon".to_string());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"lpm-worker:");
        if let Some(bearer) = bearer.as_deref() {
            hasher.update(bearer.as_bytes());
        }
        hasher.update(b"\0id:");
        if let Some(id) = identity_fp {
            hasher.update(id.as_bytes());
        }
        Some(hex::encode(&hasher.finalize()[..16]))
    }

    /// Capture the current command-cache principal fingerprint for `route`
    /// prior to issuing a metadata fetch so seeding can bind to the exact
    /// principal that authorized the response.
    pub fn capture_command_cache_principal(&self, route: &crate::UpstreamRoute) -> Option<String> {
        match route {
            crate::UpstreamRoute::NpmDirect => Some("anon".to_string()),
            crate::UpstreamRoute::LpmWorker => self.worker_principal_fingerprint(),
            crate::UpstreamRoute::Custom { target, auth } => {
                Some(super::auth::principal_fingerprint(
                    auth.as_deref(),
                    self.http.identity_fp_for_url(&target.base_url),
                ))
            }
        }
    }

    fn routed_metadata_memory_cache_key(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
    ) -> Option<String> {
        use std::fmt::Write as _;

        match route {
            crate::UpstreamRoute::NpmDirect => {
                let cache_key =
                    self.npm_direct_metadata_cache_key(name, PublicNpmAccess::ANONYMOUS);
                Some(self.direct_metadata_memory_cache_key(&cache_key))
            }
            crate::UpstreamRoute::LpmWorker => {
                let principal = self.worker_principal_fingerprint()?;
                let mut key =
                    String::with_capacity(self.base_url.len() + name.len() + principal.len() + 28);
                write!(key, "worker:{principal}:{}:", self.base_url.len())
                    .expect("writing registry length to a String cannot fail");
                key.push_str(&self.base_url);
                key.push(':');
                key.push_str(name);
                Some(key)
            }
            crate::UpstreamRoute::Custom { target, auth } => {
                if let Some(access) = self.public_npm_access(route) {
                    let cache_key = self.npm_direct_metadata_cache_key(name, access);
                    return Some(self.direct_metadata_memory_cache_key(&cache_key));
                }
                let package_url = format!("{}/{name}", target.base_url.trim_end_matches('/'));
                let principal = super::auth::principal_fingerprint(
                    auth.as_deref(),
                    self.http.identity_fp_for_url(&package_url),
                );
                let mut key = String::with_capacity(
                    target.base_url.len() + name.len() + principal.len() + 28,
                );
                write!(key, "custom:{principal}:{}:", target.base_url.len())
                    .expect("writing registry length to a String cannot fail");
                key.push_str(&target.base_url);
                key.push(':');
                key.push_str(name);
                Some(key)
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
        self.metadata_memory_cache.as_ref()?;
        let memory_cache_key = self.routed_metadata_memory_cache_key(name, route)?;
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

        let Some(key) = self.routed_metadata_memory_cache_key(name, route) else {
            return false;
        };
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

    /// Seed command metadata only when the current principal still matches the
    /// principal captured before fetching the response.
    pub fn seed_metadata_for_command_for_principal(
        &self,
        name: &str,
        route: &crate::UpstreamRoute,
        expected_principal: Option<&str>,
        metadata: Arc<PackageMetadata>,
    ) -> bool {
        let Some(expected) = expected_principal else {
            return false;
        };
        if self.capture_command_cache_principal(route).as_deref() != Some(expected) {
            return false;
        }
        self.seed_metadata_for_command(name, route, metadata)
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
            crate::UpstreamRoute::NpmDirect => {
                Some(self.npm_direct_metadata_cache_key(name, PublicNpmAccess::ANONYMOUS))
            }
            crate::UpstreamRoute::LpmWorker if name.starts_with("@lpm.dev/") => {
                self.lpm_metadata_cache_key(name).ok()
            }
            crate::UpstreamRoute::LpmWorker => self.npm_worker_metadata_cache_key(name).ok(),
            crate::UpstreamRoute::Custom { target, auth } => {
                if let Some(access) = self.public_npm_access(route) {
                    return Some(self.npm_direct_metadata_cache_key(name, access));
                }
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

    pub fn clear_metadata_memory_cache(&self) {
        if let Some(cache) = &self.metadata_memory_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    pub(super) fn read_release_time_memory_cache(
        &self,
        key: &str,
    ) -> Option<Arc<ReleaseTimeMetadata>> {
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
        cache.get(key).map(|entry| Arc::clone(&entry.value))
    }

    pub(super) fn remember_release_times_for_command(
        &self,
        key: &str,
        metadata: Arc<ReleaseTimeMetadata>,
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
        if let Some(cache) = &self.release_time_memory_cache {
            cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
    }

    pub(super) fn metadata_cache_mutation(
        &self,
        path: &std::path::Path,
    ) -> Arc<MetadataCacheMutation> {
        let mut mutations = self
            .metadata_cache_mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mutations.get_or_insert(path, || {
            Arc::new(MetadataCacheMutation {
                revision: std::sync::atomic::AtomicU64::new(0),
                operation: std::sync::Mutex::new(()),
            })
        })
    }

    fn invalidate_metadata_cache_path(&self, path: &std::path::Path) {
        use std::sync::atomic::Ordering;

        let mutation = self.metadata_cache_mutation(path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;
        remove_metadata_cache_files_locked(path, &mutation, revision);
    }

    fn invalidate_metadata_cache_key_in_memory(&self, key: &str) {
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
    }

    pub(super) fn invalidate_metadata_cache_key(&self, key: &str) {
        self.invalidate_metadata_cache_key_in_memory(key);
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
        let hash = hex::encode(hasher.finalize());
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
            self.invalidate_public_npm_metadata(package_name, PublicNpmAccess::ANONYMOUS);
            if let Ok(worker_key) = self.npm_worker_metadata_cache_key(package_name) {
                self.invalidate_metadata_cache_key(&worker_key);
            }
        }
        tracing::debug!("invalidated metadata cache for {package_name}");
    }

    fn invalidate_public_npm_metadata(&self, package_name: &str, access: PublicNpmAccess<'_>) {
        for key in [
            self.npm_direct_metadata_cache_key(package_name, access),
            self.npm_preferred_metadata_cache_key(package_name, access),
            self.npm_latest_metadata_cache_key(package_name, access),
            self.npm_direct_release_times_cache_key(package_name),
            self.npm_direct_full_metadata_cache_key(package_name),
        ] {
            self.invalidate_metadata_cache_key(&key);
        }
    }

    fn invalidate_public_npm_version_metadata(
        &self,
        package_name: &str,
        version: &str,
        access: PublicNpmAccess<'_>,
    ) {
        for key in [
            self.npm_direct_version_metadata_cache_key(package_name, version, access),
            self.npm_selected_history_cache_key(package_name, version, access),
            self.npm_latest_metadata_cache_key(package_name, access),
        ] {
            self.invalidate_metadata_cache_key(&key);
        }
    }

    /// Invalidate what `route` cached for `package_name`, including the
    /// exact-version documents for `version` when one is given.
    pub fn invalidate_routed_metadata_cache(
        &self,
        route: &crate::UpstreamRoute,
        package_name: &str,
        version: Option<&str>,
    ) {
        if self.metadata_memory_cache.is_some()
            && let Some(memory_key) = self.routed_metadata_memory_cache_key(package_name, route)
        {
            self.invalidate_metadata_memory_cache(&memory_key);
        }
        match route {
            crate::UpstreamRoute::Custom { target, auth } => {
                self.invalidate_custom_metadata_cache(
                    &target.base_url,
                    package_name,
                    auth.as_deref(),
                );
                if let (Some(version), Some(access)) = (version, self.public_npm_access(route)) {
                    self.invalidate_public_npm_version_metadata(package_name, version, access);
                }
            }
            crate::UpstreamRoute::NpmDirect | crate::UpstreamRoute::LpmWorker => {
                self.invalidate_metadata_cache(package_name);
                if let Some(version) = version {
                    self.invalidate_npm_version_metadata_cache(package_name, version);
                }
            }
        }
    }

    /// Invalidate a direct-npm exact-version metadata document.
    ///
    /// Exact version documents are cached separately from packuments so they
    /// cannot satisfy broad ranges. Stale tarball recovery knows the concrete
    /// version that failed and clears this cache alongside the package-level
    /// metadata cache.
    pub fn invalidate_npm_version_metadata_cache(&self, package_name: &str, version: &str) {
        self.history_cache.invalidate();
        self.invalidate_public_npm_version_metadata(
            package_name,
            version,
            PublicNpmAccess::ANONYMOUS,
        );
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
        if self.is_npm_registry(base_url) {
            self.history_cache.invalidate();
            self.invalidate_public_npm_metadata(name, PublicNpmAccess::with_auth(auth));
            return;
        }
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
            let safe_base = sanitize_url_without_secrets(base_url);
            tracing::debug!("invalidated custom metadata cache for {name} at {safe_base}");
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
    /// Cache format (v9): `LPM-MD-V9\n{freshness_seconds}\n{ETag}\n{content_id}\n{payload}`
    /// - Bytes 0..MAGIC.len(): magic header (ends in `\n`)
    /// - After magic, up to next `\n`: local freshness in seconds
    /// - Next line: ETag string (empty if absent)
    /// - Next line: 32 hex digits naming this write, which projections bind to
    /// - Remainder: named MessagePack, `0xc1` + zstd-framed named MessagePack,
    ///   or `0xc1` followed by JSON after an encoding failure
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
        let mut entry = open_metadata_cache_entry(path)?;
        let remaining_freshness = entry.remaining_freshness()?;
        let value = decode_metadata_cache_payload(&mut entry.reader)?;
        Some(MetadataCacheEntry {
            value,
            etag: entry.header.etag,
            remaining_freshness,
        })
    }

    pub(super) async fn read_stale_metadata_cache_entry_as_async<
        T: serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        key: &str,
    ) -> Option<MetadataCacheEntry<T>> {
        let path = self.cache_path(key)?;
        tokio::task::spawn_blocking(move || {
            let (value, etag, fresh_for) = Self::read_stale_metadata_cache_path_as::<T>(&path)?;
            Some(MetadataCacheEntry {
                value,
                etag,
                remaining_freshness: fresh_for,
            })
        })
        .await
        .ok()
        .flatten()
    }

    pub(super) fn read_stale_metadata_cache_path_as<T: serde::de::DeserializeOwned>(
        path: &std::path::Path,
    ) -> Option<(T, Option<String>, std::time::Duration)> {
        let mut entry = open_metadata_cache_entry(path)?;
        let value = decode_metadata_cache_payload(&mut entry.reader)?;
        Some((value, entry.header.etag, entry.header.fresh_for))
    }

    /// Read a fresh entry as the stored projection `P` bound to it, or else
    /// as the document `T`.
    pub(super) async fn read_metadata_cache_resolution_async<
        T: serde::de::DeserializeOwned + Send + 'static,
        P: MetadataProjection,
    >(
        &self,
        key: &str,
    ) -> Option<MetadataCacheEntry<CachedResolution<T, P>>> {
        let path = self.cache_path(key)?;
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_read");
        tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
        let worker_span = span.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _entered = worker_span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let result = open_metadata_cache_entry(&path).and_then(|entry| {
                let remaining_freshness = entry.remaining_freshness()?;
                let etag = entry.header.etag.clone();
                Some(MetadataCacheEntry {
                    value: entry.resolve(&path)?,
                    etag,
                    remaining_freshness,
                })
            });
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, cached = result.is_some());
            result
        })
        .await;
        tracing::event!(name: "await_resume", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, success = result.is_ok());
        result.ok().flatten()
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
    #[cfg(test)]
    pub(super) fn read_cache_validator(&self, key: &str) -> Option<CacheValidator> {
        let path = self.cache_path(key)?;
        Self::read_cache_validator_path(&path)
    }

    pub(super) async fn read_cache_validator_async(&self, key: &str) -> Option<CacheValidator> {
        let path = self.cache_path(key)?;
        tokio::task::spawn_blocking(move || Self::read_cache_validator_path(&path))
            .await
            .ok()
            .flatten()
    }

    pub(super) fn read_cache_validator_path(path: &std::path::Path) -> Option<CacheValidator> {
        let entry = open_metadata_cache_entry(path)?;
        let validated_at = entry.modified.checked_sub(entry.header.fresh_for)?;
        let age_seconds = std::time::SystemTime::now()
            .duration_since(validated_at)
            .ok()
            .map(|age| age.as_secs());

        Some(CacheValidator {
            etag: entry.header.etag,
            age_seconds,
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
    #[cfg(test)]
    pub(super) fn write_metadata_cache<T: serde::Serialize + 'static>(
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

    pub(super) fn write_metadata_cache_with_directive<T: serde::Serialize + 'static>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
    ) -> Option<std::time::Duration> {
        self.write_metadata_cache_entry(key, metadata, etag, directive)
            .map(|write| write.fresh_for)
    }

    /// Write one entry and report its content ID, so the caller can bind a
    /// projection of `metadata` to it.
    pub(super) fn write_metadata_cache_entry<T: serde::Serialize + 'static>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
    ) -> Option<MetadataCacheWrite> {
        self.write_metadata_cache_entry_at_generation(key, metadata, etag, directive, None)
    }

    fn prepare_metadata_cache_write(
        &self,
        key: &str,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
        history_generation: Option<u64>,
    ) -> PreparedMetadataCacheAction {
        use std::sync::atomic::Ordering;

        if history_generation
            .is_some_and(|generation| !self.history_cache.is_generation(generation))
        {
            return PreparedMetadataCacheAction::Skip;
        }
        let fresh_for = match directive.local_freshness() {
            Some(fresh_for) => {
                let record = || {
                    self.remember_command_cache_policy(
                        key,
                        MetadataCommandCachePolicy::StoreUntil(
                            std::time::Instant::now() + fresh_for,
                        ),
                    );
                };
                if let Some(generation) = history_generation {
                    self.history_cache.with_generation(generation, record);
                    if !self.history_cache.is_generation(generation) {
                        return PreparedMetadataCacheAction::Skip;
                    }
                } else {
                    record();
                }
                fresh_for
            }
            None => {
                let mut disk_invalidation = None;
                let mut record_no_store = || {
                    self.invalidate_metadata_cache_key_in_memory(key);
                    self.remember_command_cache_policy(key, MetadataCommandCachePolicy::NoStore);
                    if let Some(path) = self.cache_path(key) {
                        let mutation = self.metadata_cache_mutation(&path);
                        // Advance revision before releasing the generation lock so any
                        // in-flight write for this key observes the invalidation, and a
                        // subsequent newer write is never clobbered by a queued removal.
                        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;
                        disk_invalidation = Some((path, mutation, revision));
                    }
                };
                if let Some(generation) = history_generation {
                    self.history_cache
                        .with_generation(generation, record_no_store);
                } else {
                    record_no_store();
                }
                return match disk_invalidation {
                    Some((path, mutation, revision)) => PreparedMetadataCacheAction::NoStore {
                        path,
                        mutation,
                        revision,
                    },
                    None => PreparedMetadataCacheAction::Skip,
                };
            }
        };
        // Freshness counts from the response, however long the write waits.
        let now = std::time::SystemTime::now();
        let expires_at = now.checked_add(fresh_for).unwrap_or(now);
        let Some(path) = self.cache_path(key) else {
            return PreparedMetadataCacheAction::Skip;
        };
        let mutation = self.metadata_cache_mutation(&path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;

        let etag_str = sanitize_cache_etag(etag).to_owned();
        let freshness = fresh_for.as_secs().to_string();
        let content_id = rand::random::<u128>();
        let content_id_line = format!("{content_id:032x}\n");
        let written = MetadataCacheWrite {
            fresh_for,
            source: Some(ProjectionSource {
                entry: path.clone(),
                content_id,
            }),
        };
        let history_guard =
            history_generation.map(|generation| (Arc::clone(&self.history_cache), generation));

        PreparedMetadataCacheAction::Write {
            prepared: PreparedMetadataCacheWrite {
                fresh_for,
                expires_at,
                path,
                mutation,
                revision,
                etag_str,
                freshness,
                content_id_line,
                history_guard,
            },
            written,
        }
    }

    pub(super) fn write_metadata_cache_entry_at_generation<T: serde::Serialize + 'static>(
        &self,
        key: &str,
        metadata: &T,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
        history_generation: Option<u64>,
    ) -> Option<MetadataCacheWrite> {
        let (prepared, written) = match self.prepare_metadata_cache_write(
            key,
            etag,
            directive,
            history_generation,
        ) {
            PreparedMetadataCacheAction::Skip => return None,
            PreparedMetadataCacheAction::NoStore {
                path,
                mutation,
                revision,
            } => {
                remove_metadata_cache_files_locked(&path, &mutation, revision);
                return None;
            }
            PreparedMetadataCacheAction::Write { prepared, written } => (prepared, written),
        };
        let (content, prefix_len, used_json_fallback) = match encode_metadata_cache_buffer(
            &self.pending_cache_write_bytes,
            key,
            &prepared.freshness,
            &prepared.etag_str,
            &prepared.content_id_line,
            metadata,
        ) {
            Ok(encoded) => encoded,
            Err(Some(BufferLimit::Budget)) => {
                tracing::debug!(
                    "skipping best-effort metadata cache write because the allocation budget is full"
                );
                return Some(MetadataCacheWrite {
                    fresh_for: prepared.fresh_for,
                    source: None,
                });
            }
            Err(Some(BufferLimit::FileSize) | None) => return None,
        };

        let runtime_handle = tokio::runtime::Handle::try_current();
        if self.synchronous_cache_writes || runtime_handle.is_err() {
            finish_metadata_cache_write(
                key,
                content,
                prefix_len,
                used_json_fallback,
                &self.pending_cache_write_bytes,
                &prepared,
            );
            return Some(written);
        }

        let handle = runtime_handle.unwrap();
        let key_owned = key.to_owned();
        let budget = Arc::clone(&self.pending_cache_write_bytes);
        let pending_guard = self.pending_cache_writes.enter();
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_write");
        tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
        handle.spawn_blocking(move || {
            let _pending_guard = pending_guard;
            let _entered = span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            finish_metadata_cache_write(
                &key_owned,
                content,
                prefix_len,
                used_json_fallback,
                &budget,
                &prepared,
            );
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, {});
        });
        Some(written)
    }

    /// Encode and persist a best-effort metadata cache entry without failing
    /// the fetch, offloading serialization, zstd compression, and disk I/O to
    /// the blocking pool so sibling async futures on the caller's task are
    /// never stalled.
    pub(super) async fn write_metadata_cache_entry_async<T: serde::Serialize + Send + 'static>(
        &self,
        key: &str,
        metadata: T,
        etag: Option<&str>,
        directive: MetadataCacheDirective,
        history_generation: Option<u64>,
    ) -> Result<(T, Option<MetadataCacheWrite>), LpmError> {
        let runtime_handle = tokio::runtime::Handle::try_current();
        let (prepared, written) = match self.prepare_metadata_cache_write(
            key,
            etag,
            directive,
            history_generation,
        ) {
            PreparedMetadataCacheAction::Skip => return Ok((metadata, None)),
            PreparedMetadataCacheAction::NoStore {
                path,
                mutation,
                revision,
            } => {
                if !self.synchronous_cache_writes
                    && let Ok(handle) = runtime_handle
                {
                    let pending_guard = self.pending_cache_writes.enter();
                    handle.spawn_blocking(move || {
                        let _pending_guard = pending_guard;
                        remove_metadata_cache_files_locked(&path, &mutation, revision);
                    });
                } else {
                    remove_metadata_cache_files_locked(&path, &mutation, revision);
                }
                return Ok((metadata, None));
            }
            PreparedMetadataCacheAction::Write { prepared, written } => (prepared, written),
        };

        if self.synchronous_cache_writes || runtime_handle.is_err() {
            let encoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                encode_metadata_cache_buffer(
                    &self.pending_cache_write_bytes,
                    key,
                    &prepared.freshness,
                    &prepared.etag_str,
                    &prepared.content_id_line,
                    &metadata,
                )
            }));
            let written = match encoded {
                Ok(Ok((content, prefix_len, used_json_fallback))) => {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        finish_metadata_cache_write(
                            key,
                            content,
                            prefix_len,
                            used_json_fallback,
                            &self.pending_cache_write_bytes,
                            &prepared,
                        );
                    }))
                    .is_err()
                    {
                        let key_for_log = sanitize_cache_key_for_log(key);
                        tracing::warn!("metadata cache write panicked for {key_for_log}");
                        None
                    } else {
                        Some(written)
                    }
                }
                Ok(Err(Some(BufferLimit::Budget))) => {
                    tracing::debug!(
                        "skipping best-effort metadata cache write because the allocation budget is full"
                    );
                    Some(MetadataCacheWrite {
                        fresh_for: prepared.fresh_for,
                        source: None,
                    })
                }
                Ok(Err(Some(BufferLimit::FileSize) | None)) => None,
                Err(_) => {
                    let key_for_log = sanitize_cache_key_for_log(key);
                    tracing::warn!("metadata cache serialization panicked for {key_for_log}");
                    None
                }
            };
            return Ok((metadata, written));
        }

        let handle = runtime_handle.unwrap();
        let key_owned = key.to_owned();
        let budget = Arc::clone(&self.pending_cache_write_bytes);
        let pending_guard = self.pending_cache_writes.enter();
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_write");
        tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle.spawn_blocking(move || {
            let _pending_guard = pending_guard;
            let _entered = span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let encoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                encode_metadata_cache_buffer(
                    &budget,
                    &key_owned,
                    &prepared.freshness,
                    &prepared.etag_str,
                    &prepared.content_id_line,
                    &metadata,
                )
            }));
            match encoded {
                Ok(Ok((content, prefix_len, used_json_fallback))) => {
                    let _ = tx.send((metadata, Some(written)));
                    finish_metadata_cache_write(
                        &key_owned,
                        content,
                        prefix_len,
                        used_json_fallback,
                        &budget,
                        &prepared,
                    );
                }
                Ok(Err(Some(BufferLimit::Budget))) => {
                    tracing::debug!(
                        "skipping best-effort metadata cache write because the allocation budget is full"
                    );
                    let _ = tx.send((
                        metadata,
                        Some(MetadataCacheWrite {
                            fresh_for: prepared.fresh_for,
                            source: None,
                        }),
                    ));
                }
                Ok(Err(Some(BufferLimit::FileSize) | None)) => {
                    let _ = tx.send((metadata, None));
                }
                Err(_) => {
                    let key_for_log = sanitize_cache_key_for_log(&key_owned);
                    tracing::warn!("metadata cache serialization panicked for {key_for_log}");
                    let _ = tx.send((metadata, None));
                }
            }
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, {});
        });
        rx.await.map_err(|error| {
            LpmError::Registry(format!(
                "metadata cache worker failed unexpectedly: {error}"
            ))
        })
    }

    #[cfg(test)]
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
            std::fs::set_times(&path, std::fs::FileTimes::new().set_modified(expires_at))
        {
            tracing::warn!(%error, "failed to refresh metadata cache freshness");
        }
        Some(fresh_for)
    }

    pub(super) fn refresh_metadata_cache_freshness_async(
        &self,
        key: &str,
        fresh_for: std::time::Duration,
    ) -> std::time::Duration {
        self.refresh_metadata_cache_freshness_at_generation_async(key, fresh_for, None)
            .unwrap_or(std::time::Duration::ZERO)
    }

    pub(super) fn refresh_metadata_cache_freshness_at_generation_async(
        &self,
        key: &str,
        fresh_for: std::time::Duration,
        history_generation: Option<u64>,
    ) -> Option<std::time::Duration> {
        use std::sync::atomic::Ordering;

        if history_generation
            .is_some_and(|generation| !self.history_cache.is_generation(generation))
        {
            return None;
        }
        let fresh_for = fresh_for.min(METADATA_CACHE_TTL);
        if fresh_for.is_zero() {
            return Some(fresh_for);
        }
        let record_policy = || {
            self.remember_command_cache_policy(
                key,
                MetadataCommandCachePolicy::StoreUntil(std::time::Instant::now() + fresh_for),
            );
        };
        if let Some(generation) = history_generation {
            self.history_cache
                .with_generation(generation, record_policy);
            if !self.history_cache.is_generation(generation) {
                return None;
            }
        } else {
            record_policy();
        }
        let path = self.cache_path(key)?;
        let mutation = self.metadata_cache_mutation(&path);
        let revision = mutation.revision.fetch_add(1, Ordering::AcqRel) + 1;
        let history_guard =
            history_generation.map(|generation| (Arc::clone(&self.history_cache), generation));
        let refresh = move || {
            let _operation = mutation
                .operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mutation.revision.load(Ordering::Acquire) != revision
                || history_guard
                    .as_ref()
                    .is_some_and(|(hc, generation)| !hc.is_generation(*generation))
            {
                return;
            }
            let now = std::time::SystemTime::now();
            let expires_at = now.checked_add(fresh_for).unwrap_or(now);
            if let Err(error) =
                std::fs::set_times(&path, std::fs::FileTimes::new().set_modified(expires_at))
            {
                tracing::warn!(%error, "failed to refresh metadata cache freshness");
            }
        };
        if self.synchronous_cache_writes {
            refresh();
            return Some(fresh_for);
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let pending_guard = self.pending_cache_writes.enter();
                runtime.spawn_blocking(move || {
                    let _pending_guard = pending_guard;
                    refresh();
                });
            }
            Err(_) => refresh(),
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
    pub async fn flush_pending_cache_writes(&self) {
        self.pending_cache_writes.flush().await;
    }
}

fn sanitize_cache_etag(etag: Option<&str>) -> &str {
    etag.filter(|etag| etag.len() as u64 <= METADATA_CACHE_ETAG_LINE_CAP)
        .and_then(|etag| {
            reqwest::header::HeaderValue::from_str(etag)
                .ok()
                .map(|_| etag)
        })
        .unwrap_or("")
}

#[derive(serde::Serialize)]
struct SparseDistInfo<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    tarball: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shasum: &'a Option<String>,
    #[serde(rename = "unpackedSize", skip_serializing_if = "Option::is_none")]
    unpacked_size: &'a Option<std::num::NonZeroU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signatures: &'a Option<Vec<crate::types::RegistrySignature>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestations: &'a Option<crate::types::AttestationRef>,
}

impl<'a> From<&'a crate::types::DistInfo> for SparseDistInfo<'a> {
    fn from(dist: &'a crate::types::DistInfo) -> Self {
        let crate::types::DistInfo {
            tarball,
            integrity,
            shasum,
            unpacked_size,
            signatures,
            attestations,
        } = dist;
        Self {
            tarball,
            integrity,
            shasum,
            unpacked_size,
            signatures,
            attestations,
        }
    }
}

#[derive(serde::Serialize)]
struct SparseVersionMetadata<'a> {
    name: &'a str,
    version: &'a str,
    #[serde(rename = "publicationStatus", skip_serializing_if = "Option::is_none")]
    publication_status: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deprecated: &'a Option<serde_json::Value>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    dependencies: &'a HashMap<String, String>,
    #[serde(rename = "devDependencies", skip_serializing_if = "HashMap::is_empty")]
    dev_dependencies: &'a HashMap<String, String>,
    #[serde(rename = "peerDependencies", skip_serializing_if = "HashMap::is_empty")]
    peer_dependencies: &'a HashMap<String, String>,
    #[serde(
        rename = "peerDependenciesMeta",
        skip_serializing_if = "HashMap::is_empty"
    )]
    peer_dependencies_meta: &'a HashMap<String, crate::types::PeerDependencyMeta>,
    #[serde(rename = "bundleDependencies", skip_serializing_if = "Vec::is_empty")]
    bundle_dependencies: &'a Vec<String>,
    #[serde(
        rename = "optionalDependencies",
        skip_serializing_if = "HashMap::is_empty"
    )]
    optional_dependencies: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    engines: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    os: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cpu: &'a Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    libc: &'a Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dist: Option<SparseDistInfo<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    readme: &'a Option<String>,
    #[serde(rename = "lpmConfig", skip_serializing_if = "Option::is_none")]
    lpm_config: &'a Option<serde_json::Value>,
    #[serde(rename = "_ecosystem", skip_serializing_if = "Option::is_none")]
    ecosystem: &'a Option<String>,
    #[serde(rename = "_swiftMeta", skip_serializing_if = "Option::is_none")]
    swift_meta: &'a Option<Box<crate::types::SwiftMeta>>,
    #[serde(rename = "_npmUser", skip_serializing_if = "Option::is_none")]
    npm_user: &'a Option<Box<crate::types::NpmUserMetadata>>,
    #[serde(rename = "_behavioralTags", skip_serializing_if = "Option::is_none")]
    behavioral_tags: &'a Option<crate::types::BehavioralTags>,
    #[serde(rename = "_testOnlyTags", skip_serializing_if = "Option::is_none")]
    test_only_tags: &'a Option<Vec<String>>,
    #[serde(rename = "_lifecycleScripts", skip_serializing_if = "Option::is_none")]
    lifecycle_scripts: &'a Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scripts: &'a Option<HashMap<String, String>>,
    #[serde(rename = "hasInstallScript", skip_serializing_if = "Option::is_none")]
    has_install_script: &'a Option<bool>,
    #[serde(rename = "_securityFindings", skip_serializing_if = "Option::is_none")]
    security_findings: &'a Option<Vec<crate::types::SecurityFinding>>,
    #[serde(rename = "_qualityScore", skip_serializing_if = "Option::is_none")]
    quality_score: &'a Option<u32>,
}

impl<'a> From<&'a VersionMetadata> for SparseVersionMetadata<'a> {
    fn from(version_meta: &'a VersionMetadata) -> Self {
        let VersionMetadata {
            name,
            version,
            publication_status,
            description,
            deprecated,
            dependencies,
            dev_dependencies,
            peer_dependencies,
            peer_dependencies_meta,
            bundle_dependencies,
            optional_dependencies,
            engines,
            os,
            cpu,
            libc,
            dist,
            readme,
            lpm_config,
            ecosystem,
            swift_meta,
            npm_user,
            behavioral_tags,
            test_only_tags,
            lifecycle_scripts,
            scripts,
            has_install_script,
            security_findings,
            quality_score,
        } = version_meta;
        Self {
            name: name.as_str(),
            version: version.as_str(),
            publication_status,
            description,
            deprecated,
            dependencies,
            dev_dependencies,
            peer_dependencies,
            peer_dependencies_meta,
            bundle_dependencies,
            optional_dependencies,
            engines,
            os,
            cpu,
            libc,
            dist: dist.as_ref().map(SparseDistInfo::from),
            readme,
            lpm_config,
            ecosystem,
            swift_meta,
            npm_user,
            behavioral_tags,
            test_only_tags,
            lifecycle_scripts,
            scripts,
            has_install_script,
            security_findings,
            quality_score,
        }
    }
}

struct SparseVersionMap<'a>(&'a HashMap<String, VersionMetadata>);

impl serde::Serialize for SparseVersionMap<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            map.serialize_entry(k, &SparseVersionMetadata::from(v))?;
        }
        map.end()
    }
}

#[derive(serde::Serialize)]
struct SparsePackageMetadata<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: &'a Option<String>,
    #[serde(rename = "dist-tags", skip_serializing_if = "HashMap::is_empty")]
    dist_tags: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "sparse_versions_is_empty")]
    versions: SparseVersionMap<'a>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    time: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downloads: &'a Option<u64>,
    #[serde(rename = "distributionMode", skip_serializing_if = "Option::is_none")]
    distribution_mode: &'a Option<String>,
    #[serde(rename = "packageType", skip_serializing_if = "Option::is_none")]
    package_type: &'a Option<String>,
    #[serde(rename = "latestVersion", skip_serializing_if = "Option::is_none")]
    latest_version: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: &'a Option<String>,
}

fn sparse_versions_is_empty(versions: &SparseVersionMap<'_>) -> bool {
    versions.0.is_empty()
}

impl<'a> From<&'a PackageMetadata> for SparsePackageMetadata<'a> {
    fn from(pkg: &'a PackageMetadata) -> Self {
        let PackageMetadata {
            name,
            description,
            modified,
            dist_tags,
            versions,
            time,
            downloads,
            distribution_mode,
            package_type,
            latest_version,
            latest_hint: _,
            ecosystem,
        } = pkg;
        Self {
            name: name.as_str(),
            description,
            modified,
            dist_tags,
            versions: SparseVersionMap(versions),
            time,
            downloads,
            distribution_mode,
            package_type,
            latest_version,
            ecosystem,
        }
    }
}

fn encode_metadata_cache_buffer<T: serde::Serialize + 'static>(
    budget: &Arc<tokio::sync::Semaphore>,
    key: &str,
    freshness: &str,
    etag_str: &str,
    content_id_line: &str,
    metadata: &T,
) -> Result<(MetadataCacheBuffer, usize, bool), Option<BufferLimit>> {
    use std::io::Write as _;

    let prefix = [
        METADATA_CACHE_MAGIC,
        freshness.as_bytes(),
        b"\n",
        etag_str.as_bytes(),
        b"\n",
        content_id_line.as_bytes(),
    ];
    let prefix_len: usize = prefix.iter().map(|part| part.len()).sum();
    let mut content = MetadataCacheBuffer::new(budget, &prefix).map_err(Some)?;
    let serialization =
        tracing::trace_span!(target: "lpm_install_timeline", "metadata_cache_serialization")
            .entered();
    let mut used_json_fallback = false;
    let any_value: &dyn std::any::Any = metadata;
    let msgpack_result = if let Some(pkg) = any_value.downcast_ref::<PackageMetadata>() {
        rmp_serde::encode::write_named(&mut content, &SparsePackageMetadata::from(pkg))
    } else if let Some(ver) = any_value.downcast_ref::<VersionMetadata>() {
        rmp_serde::encode::write_named(&mut content, &SparseVersionMetadata::from(ver))
    } else {
        rmp_serde::encode::write_named(&mut content, metadata)
    };
    if let Err(messagepack_error) = msgpack_result {
        if let Some(limit) = content.exhausted() {
            return Err(Some(limit));
        }
        drop(content);
        content = MetadataCacheBuffer::new(budget, &prefix).map_err(Some)?;
        content
            .write_all(&[METADATA_CACHE_JSON_MARKER])
            .map_err(|_| content.exhausted())?;
        if let Err(json_error) = serde_json::to_writer(&mut content, metadata) {
            if let Some(limit) = content.exhausted() {
                return Err(Some(limit));
            }
            let safe_key = sanitize_cache_key_for_log(key);
            tracing::warn!(
                "metadata cache serialization failed for {safe_key}: MessagePack: {messagepack_error}; JSON: {json_error}"
            );
            return Err(None);
        }
        used_json_fallback = true;
    }
    if content.len() == prefix_len {
        return Err(None);
    }

    tracing::event!(name: "serialized", target: "lpm_install_timeline", tracing::Level::TRACE, bytes = content.len() as u64);
    drop(serialization);
    Ok((content, prefix_len, used_json_fallback))
}

fn compress_metadata_cache_buffer(
    mut content: MetadataCacheBuffer,
    prefix_len: usize,
    used_json_fallback: bool,
    budget: &Arc<tokio::sync::Semaphore>,
    freshness: &str,
    etag_str: &str,
    content_id_line: &str,
) -> MetadataCacheBuffer {
    let payload_len = content.len().saturating_sub(prefix_len);
    if !used_json_fallback && payload_len >= ZSTD_COMPRESS_THRESHOLD {
        let compressed_prefix = [
            METADATA_CACHE_MAGIC,
            freshness.as_bytes(),
            b"\n",
            etag_str.as_bytes(),
            b"\n",
            content_id_line.as_bytes(),
            &[METADATA_CACHE_JSON_MARKER],
        ];
        if let Ok(compressed_buf) = MetadataCacheBuffer::with_limit(
            budget,
            &compressed_prefix,
            content.len().saturating_sub(1),
        ) && let Ok(mut encoder) =
            zstd::stream::write::Encoder::new(compressed_buf, ZSTD_COMPRESS_LEVEL)
            && encoder
                .set_pledged_src_size(Some(payload_len as u64))
                .is_ok()
            && content.write_payload_to(prefix_len, &mut encoder).is_ok()
            && let Ok(compressed) = encoder.finish()
        {
            content = compressed;
        }
    }
    content
}

enum PreparedMetadataCacheAction {
    Skip,
    NoStore {
        path: std::path::PathBuf,
        mutation: Arc<MetadataCacheMutation>,
        revision: u64,
    },
    Write {
        prepared: PreparedMetadataCacheWrite,
        written: MetadataCacheWrite,
    },
}

fn remove_metadata_cache_files_locked(
    path: &std::path::Path,
    mutation: &MetadataCacheMutation,
    revision: u64,
) {
    use std::sync::atomic::Ordering;

    let _operation = mutation
        .operation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if mutation.revision.load(Ordering::Acquire) != revision {
        return;
    }
    for path in [path.to_path_buf(), projection_path(path)] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::debug!(%error, "failed to invalidate metadata cache entry"),
        }
    }
}

struct PreparedMetadataCacheWrite {
    fresh_for: std::time::Duration,
    expires_at: std::time::SystemTime,
    path: std::path::PathBuf,
    mutation: Arc<MetadataCacheMutation>,
    revision: u64,
    etag_str: String,
    freshness: String,
    content_id_line: String,
    history_guard: Option<(Arc<super::history_cache::HistoryCache>, u64)>,
}

fn finish_metadata_cache_write(
    key: &str,
    content: MetadataCacheBuffer,
    prefix_len: usize,
    used_json_fallback: bool,
    budget: &Arc<tokio::sync::Semaphore>,
    prepared: &PreparedMetadataCacheWrite,
) {
    use std::sync::atomic::Ordering;

    let content = compress_metadata_cache_buffer(
        content,
        prefix_len,
        used_json_fallback,
        budget,
        &prepared.freshness,
        &prepared.etag_str,
        &prepared.content_id_line,
    );
    let _operation = prepared
        .mutation
        .operation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if prepared.mutation.revision.load(Ordering::Acquire) == prepared.revision
        && prepared
            .history_guard
            .as_ref()
            .is_none_or(|(hc, generation)| hc.is_generation(*generation))
        && let Err(e) = write_metadata_cache_file(&prepared.path, &content, prepared.expires_at)
    {
        let key_for_log = sanitize_cache_key_for_log(key);
        tracing::warn!("failed to write metadata cache for {key_for_log}: {e}");
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
            std::fs::set_times(
                &path,
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() + METADATA_CACHE_TTL),
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
        let first = MAX_PENDING_METADATA_CACHE_BYTES * 3 / 4;
        let remaining = MAX_PENDING_METADATA_CACHE_BYTES - first;
        let retained = reserve_pending_metadata_cache_bytes(&budget, first)
            .expect("the first write must fit in the byte budget");

        assert!(
            reserve_pending_metadata_cache_bytes(&budget, remaining + 1024 * 1024).is_none(),
            "a queued write must not exceed the remaining byte budget"
        );
        assert_eq!(budget.available_permits(), remaining);

        drop(retained);
        assert_eq!(budget.available_permits(), MAX_PENDING_METADATA_CACHE_BYTES);
    }

    #[tokio::test]
    async fn metadata_cache_persists_packument_larger_than_eight_mib() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        let key = "large-packument-over-8mib";
        let payload = "x".repeat(12 * 1024 * 1024);

        client.write_metadata_cache(key, &payload, Some("\"v-large\""));
        client.flush_pending_cache_writes().await;

        let (cached, etag) = client
            .read_metadata_cache_as::<String>(key)
            .expect("12 MiB packument must persist within the pending cache byte budget");
        assert_eq!(cached.len(), payload.len());
        assert_eq!(etag.as_deref(), Some("\"v-large\""));
        assert_eq!(
            client.pending_cache_write_bytes.available_permits(),
            MAX_PENDING_METADATA_CACHE_BYTES
        );
    }

    #[tokio::test]
    async fn zstd_framed_cache_entries_shrink_large_packuments_and_roundtrip_losslessly() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        let mut versions = HashMap::new();
        let mut time = HashMap::new();
        for patch in 0..80 {
            let version = format!("1.0.{patch}");
            versions.insert(
                version.clone(),
                VersionMetadata {
                    name: "compressible".to_owned(),
                    version: version.clone(),
                    dependencies: HashMap::from([
                        ("dep-alpha".to_owned(), "^1.2.3".to_owned()),
                        ("dep-beta".to_owned(), "^4.5.6".to_owned()),
                    ]),
                    dist: Some(DistInfo {
                        tarball: Some(format!(
                            "https://registry.npmjs.org/compressible/-/compressible-{version}.tgz"
                        )),
                        integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            time.insert(version, format!("2025-01-01T00:00:{:02}Z", patch % 60));
        }
        let metadata = PackageMetadata {
            name: "compressible".to_owned(),
            description: Some("compressible test package".to_owned()),
            modified: Some("2025-01-02T00:00:00Z".to_owned()),
            dist_tags: HashMap::from([("latest".to_owned(), "1.0.79".to_owned())]),
            versions,
            time,
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            latest_hint: Default::default(),
            ecosystem: None,
        };
        let raw_msgpack_len = rmp_serde::to_vec_named(&metadata).unwrap().len();
        assert!(raw_msgpack_len >= ZSTD_COMPRESS_THRESHOLD);

        let key = "compressible-packument";
        client.write_metadata_cache(key, &metadata, Some("\"etag-zstd\""));
        client.flush_pending_cache_writes().await;

        let content = client.read_cache_content(key).unwrap();
        assert_eq!(content.data.first(), Some(&METADATA_CACHE_JSON_MARKER));
        assert_eq!(
            content.data.get(1..1 + ZSTD_FRAME_MAGIC.len()),
            Some(ZSTD_FRAME_MAGIC)
        );
        assert!(
            content.data.len() < raw_msgpack_len / 2,
            "expected zstd cache payload ({}) to be under half raw MessagePack ({})",
            content.data.len(),
            raw_msgpack_len
        );

        let (decoded, etag) = client.read_metadata_cache_async(key).await.unwrap();
        assert_eq!(etag.as_deref(), Some("\"etag-zstd\""));
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&metadata).unwrap()
        );
        let decoded_slice =
            RegistryClient::deserialize_cached_metadata_as::<PackageMetadata>(&content.data)
                .unwrap();
        assert_eq!(decoded_slice.versions.len(), 80);

        let path = client.cache_path(key).unwrap();
        let mut opened = open_metadata_cache_entry(&path).unwrap();
        let single = decode_metadata_cache_payload_with_seed(
            &mut opened.reader,
            super::metadata::version_selection::SingleVersionPackumentSeed {
                expected_name: "compressible".to_owned(),
                target_version: "1.0.42".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(single.versions.len(), 1);
        assert!(single.versions.contains_key("1.0.42"));
        assert_eq!(single.time.len(), 1);
        assert!(single.time.contains_key("1.0.42"));
    }

    #[test]
    fn zstd_framed_cache_payload_rejects_decompression_above_file_cap() {
        use std::io::Write as _;

        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        let path = client.cache_path("zstd-bomb").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let bomb_len = (METADATA_CACHE_FILE_CAP as usize) + 1024;
        let mut compressed = Vec::new();
        {
            let mut encoder = zstd::stream::write::Encoder::new(&mut compressed, 1).unwrap();
            // MessagePack str32 header claiming > METADATA_CACHE_FILE_CAP bytes of 'a'.
            encoder.write_all(&[0xdb]).unwrap();
            encoder.write_all(&(bomb_len as u32).to_be_bytes()).unwrap();
            let block = [b'a'; 64 * 1024];
            let mut remaining = bomb_len;
            while remaining > 0 {
                let n = remaining.min(block.len());
                encoder.write_all(&block[..n]).unwrap();
                remaining -= n;
            }
            encoder.finish().unwrap();
        }
        assert!(compressed.len() < 128 * 1024);

        let mut file_bytes = METADATA_CACHE_MAGIC.to_vec();
        file_bytes.extend_from_slice(b"300\n\n0123456789abcdef0123456789abcdef\n");
        file_bytes.push(METADATA_CACHE_JSON_MARKER);
        file_bytes.extend_from_slice(&compressed);
        std::fs::write(&path, file_bytes).unwrap();
        std::fs::set_times(
            &path,
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() + METADATA_CACHE_TTL),
        )
        .unwrap();

        assert!(
            client
                .read_metadata_cache_as::<String>("zstd-bomb")
                .is_none(),
            "decompression exceeding METADATA_CACHE_FILE_CAP must be treated as a cache miss"
        );
    }

    #[tokio::test]
    async fn metadata_cache_mutations_reclaim_entries_after_writes_complete() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        for index in 0..96 {
            client.write_metadata_cache(
                &format!("pkg-{index}"),
                &serde_json::json!({"i": index}),
                None,
            );
            client.flush_pending_cache_writes().await;
        }
        let retained = client.metadata_cache_mutations.lock().unwrap().len();
        assert!(
            retained < 64,
            "expected completed mutation locks to be pruned below 64, found {retained}"
        );
    }

    #[test]
    fn weak_entry_map_prunes_amortized_logarithmically_when_all_keys_remain_live() {
        let mut map = super::state::WeakEntryMap::<String, ()>::new();
        let mut live = Vec::with_capacity(512);
        for index in 0..512 {
            live.push(map.get_or_insert(&format!("live-{index}"), || Arc::new(())));
        }
        assert_eq!(map.len(), 512);
        assert!(
            map.prune_count() <= 4,
            "expected O(log N) prunes for 512 live entries, got {}",
            map.prune_count()
        );
        drop(live);
        let _ = map.get_or_insert("trigger-cleanup", || Arc::new(()));
        assert!(map.len() < 512);
    }

    #[test]
    fn public_metadata_types_preserve_json_fields_and_positional_msgpack_round_trip() {
        let dist = crate::types::DistInfo {
            tarball: None,
            integrity: Some("sha512-only".to_string()),
            shasum: None,
            unpacked_size: std::num::NonZeroU64::new(4096),
            signatures: None,
            attestations: None,
        };
        let positional = rmp_serde::to_vec(&dist).expect("positional encode");
        let decoded: crate::types::DistInfo =
            rmp_serde::from_slice(&positional).expect("positional decode");
        assert_eq!(decoded.tarball, None);
        assert_eq!(decoded.integrity.as_deref(), Some("sha512-only"));
        assert_eq!(decoded.unpacked_size, std::num::NonZeroU64::new(4096));

        let pkg = PackageMetadata {
            name: "shape-test".to_string(),
            description: None,
            modified: None,
            dist_tags: HashMap::new(),
            versions: HashMap::from([(
                "1.0.0".to_string(),
                VersionMetadata {
                    name: "shape-test".to_string(),
                    version: "1.0.0".to_string(),
                    ..VersionMetadata::default()
                },
            )]),
            time: HashMap::new(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            latest_hint: Default::default(),
            ecosystem: None,
        };
        let json = serde_json::to_value(&pkg).expect("json serialize");
        assert!(
            json.get("description").is_some(),
            "description key must stay present"
        );
        let ver = &json["versions"]["1.0.0"];
        assert!(
            ver.get("dependencies").is_some(),
            "dependencies key must stay present"
        );
        assert!(ver.get("os").is_some(), "os key must stay present");
        assert!(ver.get("dist").is_some(), "dist key must stay present");
    }

    #[tokio::test]
    async fn panicking_cache_serializer_returns_fetched_metadata_without_error() {
        struct PanickingSerialize(String);
        impl serde::Serialize for PanickingSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                panic!("simulated cache serializer panic");
            }
        }

        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        let (returned, written) = client
            .write_metadata_cache_entry_async(
                "panic-pkg",
                PanickingSerialize("payload-kept".to_string()),
                None,
                MetadataCacheDirective::Unspecified,
                None,
            )
            .await
            .expect("best-effort cache write must never fail a successful fetch");
        assert_eq!(returned.0, "payload-kept");
        assert!(written.is_none());
    }

    #[test]
    fn zstd_cache_decoder_rejects_truncated_trailing_and_oversized_window_frames() {
        use std::io::Write as _;

        // Valid compressed payload round-trips cleanly.
        let payload = rmp_serde::to_vec_named(&"hello-zstd".to_string()).unwrap();
        let mut valid_frame = Vec::new();
        {
            let mut enc = zstd::stream::write::Encoder::new(&mut valid_frame, 1).unwrap();
            enc.window_log(ZSTD_WINDOW_LOG_MAX).unwrap();
            enc.write_all(&payload).unwrap();
            enc.finish().unwrap();
        }
        assert_eq!(
            decode_zstd_msgpack_payload::<String>(&valid_frame).as_deref(),
            Some("hello-zstd")
        );

        // Truncated zstd frame must be rejected.
        let truncated = &valid_frame[..valid_frame.len().saturating_sub(4)];
        assert!(decode_zstd_msgpack_payload::<String>(truncated).is_none());

        // Compressed payload with trailing decoded bytes after one MessagePack value must be rejected.
        let mut trailing_frame = Vec::new();
        {
            let mut enc = zstd::stream::write::Encoder::new(&mut trailing_frame, 1).unwrap();
            enc.window_log(ZSTD_WINDOW_LOG_MAX).unwrap();
            enc.write_all(&payload).unwrap();
            enc.write_all(&rmp_serde::to_vec_named(&"extra").unwrap())
                .unwrap();
            enc.finish().unwrap();
        }
        assert!(decode_zstd_msgpack_payload::<String>(&trailing_frame).is_none());

        // Frame requesting a decoder window larger than ZSTD_WINDOW_LOG_MAX must be rejected.
        let mut wide_window_frame = Vec::new();
        {
            let mut enc = zstd::stream::write::Encoder::new(&mut wide_window_frame, 1).unwrap();
            enc.window_log(ZSTD_WINDOW_LOG_MAX + 2).unwrap();
            enc.write_all(&payload).unwrap();
            enc.finish().unwrap();
        }
        assert!(decode_zstd_msgpack_payload::<String>(&wide_window_frame).is_none());
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

    fn package_metadata_fields(metadata: PackageMetadata) {
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

    fn version_metadata_fields(metadata: VersionMetadata) {
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
            test_only_tags: _,
            lifecycle_scripts: _,
            scripts: _,
            has_install_script: _,
            security_findings: _,
            quality_score: _,
            publication_status: _,
        } = metadata;
    }

    fn peer_dependency_meta_fields(metadata: PeerDependencyMeta) {
        let PeerDependencyMeta { optional: _ } = metadata;
    }

    fn behavioral_tags_fields(tags: BehavioralTags) {
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
            custom_license: _,
        } = tags;
    }

    fn security_finding_fields(finding: SecurityFinding) {
        let SecurityFinding {
            severity: _,
            description: _,
            file: _,
        } = finding;
    }

    fn swift_meta_fields(metadata: SwiftMeta) {
        let SwiftMeta {
            products: _,
            platforms: _,
            required_capabilities: _,
            manifest_set: _,
        } = metadata;
    }

    fn swift_manifest_set_fields(set: crate::SwiftManifestSet) {
        let crate::SwiftManifestSet {
            schema_version: _,
            manifests: _,
        } = set;
    }
    fn swift_manifest_fields(manifest: crate::SwiftManifest) {
        let crate::SwiftManifest {
            filename: _,
            tools_version: _,
            products: _,
            platforms: _,
        } = manifest;
    }
    fn swift_product_fields(product: SwiftProduct) {
        let SwiftProduct {
            name: _,
            product_type: _,
            targets: _,
        } = product;
    }

    fn swift_platform_fields(platform: SwiftPlatform) {
        let SwiftPlatform {
            platform_name: _,
            version: _,
        } = platform;
    }

    fn dist_info_fields(dist: DistInfo) {
        let DistInfo {
            tarball: _,
            integrity: _,
            shasum: _,
            unpacked_size: _,
            signatures: _,
            attestations: _,
        } = dist;
    }

    fn npm_user_metadata_fields(metadata: NpmUserMetadata) {
        let NpmUserMetadata {
            trusted_publisher: _,
            approver: _,
        } = metadata;
    }

    fn registry_signature_fields(signature: RegistrySignature) {
        let RegistrySignature { keyid: _, sig: _ } = signature;
    }

    fn attestation_ref_fields(attestation: AttestationRef) {
        let AttestationRef {
            url: _,
            provenance: _,
        } = attestation;
    }

    fn release_time_metadata_fields(metadata: ReleaseTimeMetadata) {
        let ReleaseTimeMetadata {
            name: _,
            time: _,
            versions: _,
        } = metadata;
    }

    fn release_time_version_metadata_fields(metadata: ReleaseTimeVersionMetadata) {
        let ReleaseTimeVersionMetadata {
            os: _,
            cpu: _,
            libc: _,
        } = metadata;
    }

    #[test]
    fn persisted_metadata_schema_fields_are_exhaustive() {
        assert_eq!(METADATA_CACHE_MAGIC, b"LPM-MD-V9\n");
        let _: fn(PackageMetadata) = package_metadata_fields;
        let _: fn(VersionMetadata) = version_metadata_fields;
        let _: fn(PeerDependencyMeta) = peer_dependency_meta_fields;
        let _: fn(BehavioralTags) = behavioral_tags_fields;
        let _: fn(SecurityFinding) = security_finding_fields;
        let _: fn(SwiftMeta) = swift_meta_fields;
        let _: fn(crate::SwiftManifestSet) = swift_manifest_set_fields;
        let _: fn(crate::SwiftManifest) = swift_manifest_fields;
        let _: fn(SwiftProduct) = swift_product_fields;
        let _: fn(SwiftPlatform) = swift_platform_fields;
        let _: fn(DistInfo) = dist_info_fields;
        let _: fn(NpmUserMetadata) = npm_user_metadata_fields;
        let _: fn(RegistrySignature) = registry_signature_fields;
        let _: fn(AttestationRef) = attestation_ref_fields;
        let _: fn(ReleaseTimeMetadata) = release_time_metadata_fields;
        let _: fn(ReleaseTimeVersionMetadata) = release_time_version_metadata_fields;
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
        let cache_key = client.npm_direct_metadata_cache_key(package, PublicNpmAccess::ANONYMOUS);

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
        let cache_key = client.npm_direct_metadata_cache_key(package, PublicNpmAccess::ANONYMOUS);

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

    #[test]
    fn routed_invalidation_removes_seeded_worker_and_custom_metadata() {
        let client = RegistryClient::new()
            .with_base_url("https://lpm.example")
            .with_token("token-a")
            .with_cache_dir(None)
            .clone_with_metadata_memory_cache();
        let pkg = "@lpm.dev/owner.pkg";
        let worker_route = crate::UpstreamRoute::LpmWorker;
        assert!(client.seed_metadata_for_command(pkg, &worker_route, package_metadata(pkg)));
        assert!(
            client
                .npm_metadata_memory_cache(pkg, &worker_route)
                .is_some()
        );
        client.invalidate_routed_metadata_cache(&worker_route, pkg, None);
        assert!(
            client
                .npm_metadata_memory_cache(pkg, &worker_route)
                .is_none(),
            "routed invalidation must evict seeded Worker command metadata"
        );

        let custom_pkg = "custom-pkg";
        let custom_route = crate::UpstreamRoute::Custom {
            target: crate::npmrc::RegistryTarget::from_npmrc_url("https://corp.example/npm")
                .unwrap(),
            auth: None,
        };
        assert!(client.seed_metadata_for_command(
            custom_pkg,
            &custom_route,
            package_metadata(custom_pkg)
        ));
        assert!(
            client
                .npm_metadata_memory_cache(custom_pkg, &custom_route)
                .is_some()
        );
        client.invalidate_routed_metadata_cache(&custom_route, custom_pkg, None);
        assert!(
            client
                .npm_metadata_memory_cache(custom_pkg, &custom_route)
                .is_none(),
            "routed invalidation must evict seeded Custom command metadata"
        );
    }

    #[test]
    fn same_principal_clone_retains_command_cache_and_changed_principal_keeps_caching_enabled() {
        let client_a = RegistryClient::new()
            .with_base_url("https://lpm.example")
            .with_token("token-a")
            .clone_with_metadata_memory_cache();
        let route = crate::UpstreamRoute::LpmWorker;
        let pkg = "@lpm.dev/owner.pkg";
        assert!(client_a.seed_metadata_for_command(pkg, &route, package_metadata(pkg)));

        let same_clone = client_a.clone_with_static_token("token-a");
        assert!(
            same_clone.npm_metadata_memory_cache(pkg, &route).is_some(),
            "reapplying the same static token should retain command metadata cache"
        );

        let diff_clone = client_a.clone_with_static_token("token-b");
        assert!(
            diff_clone.npm_metadata_memory_cache(pkg, &route).is_none(),
            "changed principal must not see previous principal's metadata"
        );
        assert!(
            diff_clone.seed_metadata_for_command(pkg, &route, package_metadata(pkg)),
            "changed principal clone should keep command caching enabled with a fresh isolated cache"
        );
    }

    #[test]
    fn sanitize_cache_key_for_log_preserves_registry_and_package_without_secrets() {
        let rendered = super::sanitize_cache_key_for_log(
            "npm:anon:https://user:secret@corp.example:8443/npm/pkg?sig=topsecret#frag",
        );
        for secret in ["secret", "topsecret", "frag"] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
        assert!(
            rendered.contains("https://corp.example:8443/npm/pkg"),
            "expected registry and package path to survive: {rendered}"
        );

        let worker_rendered = super::sanitize_cache_key_for_log(
            "worker:abc123:31:https://corp.example:8443/lpm:@lpm.dev/owner.pkg",
        );
        assert!(
            worker_rendered.contains("https://corp.example:8443/lpm")
                && worker_rendered.contains("@lpm.dev/owner.pkg"),
            "expected worker key to preserve registry and package: {worker_rendered}"
        );

        let direct_rendered =
            super::sanitize_cache_key_for_log("direct:26:https://registry.npmjs.org:lodash");
        assert!(
            direct_rendered.contains("https://registry.npmjs.org")
                && direct_rendered.contains("lodash"),
            "expected authority-only direct key to preserve registry and package: {direct_rendered}"
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
    let after_etag = &after_freshness[etag_end + 1..];
    let content_id_end = after_etag.iter().position(|&b| b == b'\n')?;
    parse_content_id(&after_etag[..content_id_end])?;
    Some((
        std::time::Duration::from_secs(fresh_for_secs),
        etag,
        &after_etag[content_id_end + 1..],
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
        // A second dispatcher prevents tracing's single-subscriber cache from
        // registering shared callsites through another test's empty dispatcher.
        let _other_dispatcher =
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
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

    #[test]
    fn zstd_cache_frame_uses_compact_window_and_preserves_sparse_and_legacy_named_decode() {
        use std::io::Read as _;

        let dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_cache_dir(Some(dir.path().to_owned()))
            .with_synchronous_cache_writes(true);

        let mut versions = HashMap::new();
        for i in 0..80 {
            let ver = format!("1.0.{i}");
            let mut deps = HashMap::new();
            deps.insert("dep-a".to_string(), "^1.0.0".to_string());
            versions.insert(
                ver.clone(),
                VersionMetadata {
                    name: "sparse-pkg".to_string(),
                    version: ver,
                    description: (i % 2 == 0).then(|| "even description".to_string()),
                    dependencies: deps,
                    dist: Some(crate::types::DistInfo {
                        tarball: Some(format!("https://example.invalid/sparse-pkg-1.0.{i}.tgz")),
                        integrity: Some("sha512-abc".to_string()),
                        shasum: None,
                        unpacked_size: std::num::NonZeroU64::new(1024),
                        signatures: None,
                        attestations: None,
                    }),
                    quality_score: Some(95),
                    ..VersionMetadata::default()
                },
            );
        }
        let mut dist_tags = HashMap::new();
        dist_tags.insert("latest".to_string(), "1.0.79".to_string());
        let pkg = PackageMetadata {
            name: "sparse-pkg".to_string(),
            description: Some("middle field omitted elsewhere".to_string()),
            modified: None,
            dist_tags,
            versions,
            time: HashMap::new(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            latest_hint: crate::types::LatestVersionHint::FromMetadata,
            ecosystem: Some("npm".to_string()),
        };

        client.write_metadata_cache("sparse-pkg", &pkg, None);
        let cache_path = client.cache_path("sparse-pkg").unwrap();
        let mut opened = open_metadata_cache_entry(&cache_path).unwrap();
        let mut payload = Vec::new();
        opened.reader.read_to_end(&mut payload).unwrap();
        assert_eq!(payload[0], METADATA_CACHE_JSON_MARKER);
        assert!(payload[1..].starts_with(ZSTD_FRAME_MAGIC));

        // Verify zstd frame declares single-segment content size (no 8 MiB forced window).
        let frame_header_descriptor = payload[1 + ZSTD_FRAME_MAGIC.len()];
        let single_segment_flag = (frame_header_descriptor & 0x20) != 0;
        assert!(
            single_segment_flag,
            "pledged source size should produce a compact single-segment zstd frame (fhd={frame_header_descriptor:#x})"
        );

        let (decoded, _) = client
            .read_metadata_cache_as::<PackageMetadata>("sparse-pkg")
            .unwrap();
        assert_eq!(decoded.name, "sparse-pkg");
        assert_eq!(decoded.versions.len(), 80);
        assert_eq!(decoded.versions["1.0.0"].quality_score, Some(95));
        assert_eq!(decoded.versions["1.0.1"].description, None);
        assert_eq!(decoded.ecosystem.as_deref(), Some("npm"));

        // Verify full named MessagePack encoding (pre-sparse cache format) still deserializes cleanly.
        let legacy_named = rmp_serde::to_vec_named(&pkg).unwrap();
        let from_legacy: PackageMetadata = rmp_serde::from_slice(&legacy_named).unwrap();
        assert_eq!(from_legacy.name, "sparse-pkg");
        assert_eq!(from_legacy.versions.len(), 80);
        assert_eq!(from_legacy.ecosystem.as_deref(), Some("npm"));
    }

    #[tokio::test]
    async fn async_no_store_directive_invalidates_cached_entry_off_worker_thread() {
        let dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(dir.path().to_owned()));
        let (_, written) = client
            .write_metadata_cache_entry_async(
                "no-store-pkg",
                serde_json::json!({"name": "no-store-pkg"}),
                None,
                MetadataCacheDirective::Unspecified,
                None,
            )
            .await
            .unwrap();
        assert!(written.is_some());
        client.flush_pending_cache_writes().await;
        let path = client.cache_path("no-store-pkg").unwrap();
        assert!(path.exists());

        let (returned, no_store_written) = client
            .write_metadata_cache_entry_async(
                "no-store-pkg",
                serde_json::json!({"name": "no-store-pkg", "fresh": true}),
                None,
                MetadataCacheDirective::NoStore,
                None,
            )
            .await
            .unwrap();
        assert_eq!(returned["fresh"], true);
        assert!(no_store_written.is_none());
        client.flush_pending_cache_writes().await;
        assert!(
            !path.exists(),
            "NoStore directive must remove existing cache file via pending blocking flush"
        );
    }
}
