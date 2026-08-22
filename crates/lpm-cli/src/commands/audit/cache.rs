//! Authenticated behavioral-analysis cache for one project.
//!
//! Cache files live below `LPM_HOME/cache/metadata/audit/`, outside the
//! repository, and carry an HMAC generated from an owner-only local key.
//! Entries are also bound to the current analyzer-input fingerprint.
//! The key excludes repository-supplied state and other user accounts from
//! cache authority; code already running as the same OS user can read it.

use hmac::{Hmac, Mac};
use lpm_security::behavioral::PackageAnalysis;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::discovery::DiscoveredPackage;

type HmacSha256 = Hmac<Sha256>;

/// Current cache format version. Bump when the cache structure changes.
const CACHE_VERSION: u32 = 5;
const CACHE_SECRET_BYTES: usize = 32;
const CACHE_SECRET_FILE_MAX_BYTES: u64 = 128;
const SIGNATURE_HEX_BYTES: usize = 64;
const SIGNATURE_PREFIX: &[u8] = b"{\"signature\":\"";
const PAYLOAD_PREFIX: &[u8] = b"\",\"payload\":";
const PAYLOAD_OFFSET: u64 =
    (SIGNATURE_PREFIX.len() + SIGNATURE_HEX_BYTES + PAYLOAD_PREFIX.len()) as u64;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectAuditCache {
    cache_version: u32,
    behavioral_schema_version: u32,
    manager: String,
    project_id: String,
    entries: BTreeMap<String, CacheEntry>,
    analyses: BTreeMap<String, Arc<PackageAnalysis>>,
    #[serde(skip)]
    dirty: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheEntry {
    name: String,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<lpm_common::PackageInstanceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    patch_sha256: Option<String>,
    input_fingerprint: String,
}

struct CacheContext {
    project_id: String,
    cache_path: PathBuf,
    secret_path: PathBuf,
}

impl ProjectAuditCache {
    pub fn new(project_root: &Path, manager: &str) -> Option<Self> {
        let context = CacheContext::for_project(project_root)?;
        Some(Self {
            cache_version: CACHE_VERSION,
            behavioral_schema_version: lpm_security::behavioral::SCHEMA_VERSION,
            manager: manager.to_string(),
            project_id: context.project_id,
            entries: BTreeMap::new(),
            analyses: BTreeMap::new(),
            dirty: false,
        })
    }

    pub fn read(project_root: &Path, manager: &str) -> Option<Self> {
        let context = CacheContext::for_project(project_root)?;
        let secret = read_cache_secret(&context.secret_path)?;
        let mut cache = match read_signed_cache(&context.cache_path, &secret) {
            Ok(cache) => cache,
            Err(error) => {
                tracing::debug!("discarding invalid behavioral analysis cache: {error}");
                return None;
            }
        };
        if cache.cache_version != CACHE_VERSION {
            return None;
        }
        if cache.behavioral_schema_version != lpm_security::behavioral::SCHEMA_VERSION {
            return None;
        }
        if cache.manager != manager || cache.project_id != context.project_id {
            return None;
        }
        if cache
            .analyses
            .values()
            .any(|analysis| analysis.version != lpm_security::behavioral::SCHEMA_VERSION)
            || cache.entries.values().any(|entry| {
                entry.input_fingerprint.is_empty()
                    || !cache.analyses.contains_key(&entry.input_fingerprint)
            })
        {
            tracing::debug!("discarding unauthenticated behavioral analysis cache");
            return None;
        }

        cache.dirty = false;
        Some(cache)
    }

    pub fn write(&mut self, project_root: &Path) -> Result<(), std::io::Error> {
        if !self.dirty {
            return Ok(());
        }
        let context = CacheContext::for_project(project_root).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot resolve audit cache context",
            )
        })?;
        if self.project_id != context.project_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit cache project identity changed",
            ));
        }
        if let Some(parent) = context.cache_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let secret = get_or_create_cache_secret(&context.secret_path)?;
        lpm_common::write_file_atomic_with(
            &context.cache_path,
            lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
            |file| {
                let signature = {
                    let mut writer = CappedWriter::new(
                        file,
                        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
                        "audit cache exceeds the state-file size limit",
                    );
                    writer.write_all(SIGNATURE_PREFIX)?;
                    writer.write_all(&[b'0'; SIGNATURE_HEX_BYTES])?;
                    writer.write_all(PAYLOAD_PREFIX)?;
                    let signature = {
                        let mut mac = HmacSha256::new_from_slice(&secret)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                        {
                            let payload = PayloadWriter::new(&mut writer, &mut mac);
                            let mut buffered = BufWriter::with_capacity(64 * 1024, payload);
                            serde_json::to_writer(&mut buffered, self).map_err(json_io_error)?;
                            buffered.flush()?;
                        }
                        hex::encode(mac.finalize().into_bytes())
                    };
                    writer.write_all(b"}")?;
                    writer.flush()?;
                    signature
                };
                file.seek(SeekFrom::Start(SIGNATURE_PREFIX.len() as u64))?;
                file.write_all(signature.as_bytes())
            },
        )?;
        self.dirty = false;
        Ok(())
    }

    pub fn get(
        &self,
        key: &str,
        package: &DiscoveredPackage,
        input_fingerprint: &str,
    ) -> Option<Arc<PackageAnalysis>> {
        let entry = self.entries.get(key)?;
        if entry.name != package.name
            || entry.version != package.version
            || entry.instance_id != package.instance_id
            || entry.integrity.as_deref() != package.integrity.as_deref()
            || entry.patch_sha256.as_deref() != package.patch_sha256.as_deref()
            || entry.input_fingerprint != input_fingerprint
        {
            return None;
        }
        self.analyses.get(&entry.input_fingerprint).map(Arc::clone)
    }

    pub fn has_candidate(&self, key: &str, package: &DiscoveredPackage) -> bool {
        self.entries.get(key).is_some_and(|entry| {
            entry.name == package.name
                && entry.version == package.version
                && entry.instance_id == package.instance_id
                && entry.integrity.as_deref() == package.integrity.as_deref()
                && entry.patch_sha256.as_deref() == package.patch_sha256.as_deref()
                && !entry.input_fingerprint.is_empty()
                && self.analyses.contains_key(&entry.input_fingerprint)
        })
    }

    pub fn insert(
        &mut self,
        key: String,
        package: &DiscoveredPackage,
        input_fingerprint: String,
        analysis: Arc<PackageAnalysis>,
    ) {
        self.analyses
            .entry(input_fingerprint.clone())
            .or_insert(analysis);
        self.entries.insert(
            key,
            CacheEntry {
                name: package.name.clone(),
                version: package.version.clone(),
                instance_id: package.instance_id,
                integrity: package.integrity.clone(),
                patch_sha256: package.patch_sha256.clone(),
                input_fingerprint,
            },
        );
        self.dirty = true;
    }

    pub fn retain_active(&mut self, active: &HashSet<&str>) {
        let previous_len = self.entries.len();
        self.entries.retain(|key, _| active.contains(key.as_str()));
        let previous_analyses = self.analyses.len();
        let referenced: HashSet<&str> = self
            .entries
            .values()
            .map(|entry| entry.input_fingerprint.as_str())
            .collect();
        self.analyses
            .retain(|fingerprint, _| referenced.contains(fingerprint.as_str()));
        self.dirty |=
            self.entries.len() != previous_len || self.analyses.len() != previous_analyses;
    }
}

impl CacheContext {
    fn for_project(project_root: &Path) -> Option<Self> {
        let canonical = project_root.canonicalize().ok()?;
        let project_id = format!(
            "{:x}",
            Sha256::digest(canonical.as_os_str().as_encoded_bytes())
        );
        let lpm_root = lpm_common::LpmRoot::from_env().ok()?;
        let root = lpm_root.cache_metadata().join("audit");
        Some(Self {
            cache_path: root.join("projects").join(format!("{project_id}.json")),
            secret_path: root.join("analysis-cache.key"),
            project_id,
        })
    }
}

fn json_io_error(error: serde_json::Error) -> io::Error {
    io::Error::new(
        error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
        error,
    )
}

fn read_signed_cache(path: &Path, secret: &[u8]) -> io::Result<ProjectAuditCache> {
    let mut file = open_cache_file_nofollow(path)?;
    let file_len = file.metadata()?.len();
    let minimum_len = PAYLOAD_OFFSET.saturating_add(2);
    if file_len < minimum_len || file_len > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "behavioral analysis cache has an invalid size",
        ));
    }
    let mut prefix = vec![0u8; PAYLOAD_OFFSET as usize];
    file.read_exact(&mut prefix)?;
    if &prefix[..SIGNATURE_PREFIX.len()] != SIGNATURE_PREFIX
        || &prefix[SIGNATURE_PREFIX.len() + SIGNATURE_HEX_BYTES..] != PAYLOAD_PREFIX
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "behavioral analysis cache has invalid framing",
        ));
    }
    let signature_start = SIGNATURE_PREFIX.len();
    let signature = hex::decode(&prefix[signature_start..signature_start + SIGNATURE_HEX_BYTES])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let payload_len = file_len - PAYLOAD_OFFSET - 1;
    let mac = HmacSha256::new_from_slice(secret)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let (cache, mac) = {
        let reader = MacReader::new(Read::by_ref(&mut file).take(payload_len), mac);
        let mut buffered = BufReader::with_capacity(64 * 1024, reader);
        let cache = serde_json::from_reader(&mut buffered).map_err(json_io_error)?;
        let (payload, mac) = buffered.into_inner().into_parts();
        if payload.limit() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "behavioral analysis cache payload ended early",
            ));
        }
        (cache, mac)
    };
    let mut suffix = [0u8; 1];
    file.read_exact(&mut suffix)?;
    if suffix != [b'}'] || mac.verify_slice(&signature).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "behavioral analysis cache signature is invalid",
        ));
    }
    Ok(cache)
}

fn open_cache_file_nofollow(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "behavioral analysis cache is not a regular file",
        ));
    }
    Ok(file)
}

struct MacReader<R> {
    inner: R,
    mac: HmacSha256,
}

impl<R> MacReader<R> {
    fn new(inner: R, mac: HmacSha256) -> Self {
        Self { inner, mac }
    }

    fn into_parts(self) -> (R, HmacSha256) {
        (self.inner, self.mac)
    }
}

impl<R: Read> Read for MacReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.mac.update(&buffer[..read]);
        Ok(read)
    }
}

struct PayloadWriter<'a, 'b> {
    inner: &'a mut CappedWriter<'b>,
    mac: &'a mut HmacSha256,
}

impl<'a, 'b> PayloadWriter<'a, 'b> {
    fn new(inner: &'a mut CappedWriter<'b>, mac: &'a mut HmacSha256) -> Self {
        Self { inner, mac }
    }
}

impl Write for PayloadWriter<'_, '_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.mac.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn read_cache_secret(path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return None;
        }
    }
    let encoded =
        lpm_common::read_text_file_capped_nofollow(path, CACHE_SECRET_FILE_MAX_BYTES).ok()?;
    let secret = hex::decode(encoded.trim()).ok()?;
    (secret.len() == CACHE_SECRET_BYTES).then_some(secret)
}

fn get_or_create_cache_secret(path: &Path) -> io::Result<Vec<u8>> {
    if let Some(secret) = read_cache_secret(path) {
        return Ok(secret);
    }
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "behavioral analysis cache key is invalid or has unsafe permissions",
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut secret = [0u8; CACHE_SECRET_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .map_err(io::Error::other)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(hex::encode(secret).as_bytes())?;
            file.sync_all()?;
            Ok(secret.to_vec())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_cache_secret(path)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "concurrently created behavioral analysis cache key is invalid",
                )
            }),
        Err(error) => Err(error),
    }
}

struct CappedWriter<'a> {
    inner: &'a mut std::fs::File,
    remaining: u64,
    limit_error: &'static str,
}

impl<'a> CappedWriter<'a> {
    fn new(inner: &'a mut std::fs::File, limit: u64, limit_error: &'static str) -> Self {
        Self {
            inner,
            remaining: limit,
            limit_error,
        }
    }
}

impl Write for CappedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(buffer.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "write buffer length overflow")
        })?;
        if length > self.remaining {
            return Err(io::Error::new(io::ErrorKind::InvalidData, self.limit_error));
        }
        let written = self.inner.write(buffer)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::super::discovery::ScanMode;
    use super::*;
    use lpm_security::behavioral::PackageAnalysis;

    fn empty_analysis() -> PackageAnalysis {
        PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "1970-01-01T00:00:00Z".into(),
            source: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            meta: Default::default(),
        }
    }

    fn package(integrity: Option<&str>, patch_sha256: Option<&str>) -> DiscoveredPackage {
        DiscoveredPackage {
            name: "react".into(),
            version: "18.0.0".into(),
            instance_id: None,
            path: "node_modules/react".into(),
            integrity: integrity.map(str::to_string),
            patch_sha256: patch_sha256.map(str::to_string),
            resolved_url: None,
            local_source_dir: None,
            scan_mode: ScanMode::FullLocal,
            is_dev: false,
            is_optional: false,
            dependencies: Vec::new(),
        }
    }

    fn scoped_lpm_home(path: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([("LPM_HOME", path.as_os_str().to_owned())])
    }

    fn populated_cache(project: &Path, package: &DiscoveredPackage) -> ProjectAuditCache {
        let mut cache = ProjectAuditCache::new(project, "npm").unwrap();
        cache.insert(
            package.analysis_key(),
            package,
            "sha256-input".into(),
            Arc::new(empty_analysis()),
        );
        cache
    }

    #[test]
    fn matching_package_identity_and_input_reuse_analysis() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), Some("sha256-patch"));
        let cache = populated_cache(project.path(), &package);

        assert!(
            cache
                .get(&package.analysis_key(), &package, "sha256-input")
                .is_some()
        );
    }

    #[test]
    fn changed_base_integrity_patch_or_input_rejects_entry() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let original = package(Some("sha512-source"), Some("sha256-patch"));
        let cache = populated_cache(project.path(), &original);
        let changed_integrity = package(Some("sha512-other"), Some("sha256-patch"));
        let changed_patch = package(Some("sha512-source"), Some("sha256-other"));

        assert!(
            cache
                .get(&original.analysis_key(), &changed_integrity, "sha256-input")
                .is_none()
        );
        assert!(
            cache
                .get(&original.analysis_key(), &changed_patch, "sha256-input")
                .is_none()
        );
        assert!(
            cache
                .get(&original.analysis_key(), &original, "sha256-other")
                .is_none()
        );
    }

    #[test]
    fn authenticated_cache_round_trip_preserves_analysis() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();

        let loaded = ProjectAuditCache::read(project.path(), "npm").unwrap();
        assert!(
            loaded
                .get(&package.analysis_key(), &package, "sha256-input")
                .is_some()
        );
    }

    #[test]
    fn cache_payload_omits_discovery_dependency_edges() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let mut package = package(Some("sha512-source"), None);
        package.dependencies = vec![("scheduler".into(), "1.0.0".into())];
        let cache = populated_cache(project.path(), &package);
        let payload = serde_json::to_value(cache).unwrap();

        assert!(!payload.to_string().contains("dependencies"));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();
        let context = CacheContext::for_project(project.path()).unwrap();
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&context.cache_path).unwrap()).unwrap();
        document["payload"]["manager"] = "forged".into();
        std::fs::write(&context.cache_path, serde_json::to_vec(&document).unwrap()).unwrap();

        assert!(ProjectAuditCache::read(project.path(), "npm").is_none());
    }

    #[test]
    fn manager_and_embedded_schema_must_match() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();
        assert!(ProjectAuditCache::read(project.path(), "pnpm").is_none());

        let mut cache = ProjectAuditCache::read(project.path(), "npm").unwrap();
        Arc::make_mut(cache.analyses.values_mut().next().unwrap()).version += 1;
        cache.dirty = true;
        cache.write(project.path()).unwrap();
        assert!(ProjectAuditCache::read(project.path(), "npm").is_none());
    }

    #[test]
    fn identical_input_fingerprints_share_one_cached_analysis() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let first = package(Some("sha512-source"), None);
        let mut second = first.clone();
        second.name = "react-alias".into();
        second.path = "node_modules/react-alias".into();
        let mut cache = populated_cache(project.path(), &first);
        cache.insert(
            second.analysis_key(),
            &second,
            "sha256-input".into(),
            Arc::new(empty_analysis()),
        );

        assert_eq!(cache.entries.len(), 2);
        assert_eq!(cache.analyses.len(), 1);

        cache.write(project.path()).unwrap();
        let loaded = ProjectAuditCache::read(project.path(), "npm").unwrap();
        let first_analysis = loaded
            .get(&first.analysis_key(), &first, "sha256-input")
            .unwrap();
        let second_analysis = loaded
            .get(&second.analysis_key(), &second, "sha256-input")
            .unwrap();
        assert!(Arc::ptr_eq(&first_analysis, &second_analysis));
    }

    #[test]
    fn cache_copied_to_another_project_is_rejected() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let first_project = tempfile::tempdir().unwrap();
        let second_project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(first_project.path(), &package);
        cache.write(first_project.path()).unwrap();
        let first_context = CacheContext::for_project(first_project.path()).unwrap();
        let second_context = CacheContext::for_project(second_project.path()).unwrap();
        std::fs::create_dir_all(second_context.cache_path.parent().unwrap()).unwrap();
        std::fs::copy(first_context.cache_path, second_context.cache_path).unwrap();

        assert!(ProjectAuditCache::read(second_project.path(), "npm").is_none());
    }

    #[test]
    fn unchanged_cache_write_preserves_existing_bytes() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();
        let path = CacheContext::for_project(project.path())
            .unwrap()
            .cache_path;
        let before = std::fs::read(&path).unwrap();
        #[cfg(unix)]
        let before_metadata = std::fs::metadata(&path).unwrap();

        let mut loaded = ProjectAuditCache::read(project.path(), "npm").unwrap();
        loaded.write(project.path()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let after_metadata = std::fs::metadata(&path).unwrap();
            assert_eq!(after_metadata.ino(), before_metadata.ino());
            assert_eq!(after_metadata.mtime(), before_metadata.mtime());
            assert_eq!(after_metadata.mtime_nsec(), before_metadata.mtime_nsec());
        }
    }

    #[test]
    fn stale_entries_are_pruned() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let first = package(Some("sha512-first"), None);
        let mut second = package(Some("sha512-second"), None);
        second.path = "node_modules/second".into();
        second.name = "second".into();
        let mut cache = populated_cache(project.path(), &first);
        cache.insert(
            second.analysis_key(),
            &second,
            "sha256-second".into(),
            Arc::new(empty_analysis()),
        );
        cache.write(project.path()).unwrap();

        let mut loaded = ProjectAuditCache::read(project.path(), "npm").unwrap();
        let first_key = first.analysis_key();
        loaded.retain_active(&HashSet::from([first_key.as_str()]));
        loaded.write(project.path()).unwrap();
        let loaded = ProjectAuditCache::read(project.path(), "npm").unwrap();
        assert_eq!(
            loaded.entries.keys().cloned().collect::<Vec<_>>(),
            vec![first_key]
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_key_and_cache_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();
        let context = CacheContext::for_project(project.path()).unwrap();

        assert_eq!(
            (
                std::fs::metadata(context.secret_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                std::fs::metadata(context.cache_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
            ),
            (0o600, 0o600)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_cache_key_permissions_reject_reads_and_writes() {
        use std::os::unix::fs::PermissionsExt as _;

        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        cache.write(project.path()).unwrap();
        let context = CacheContext::for_project(project.path()).unwrap();
        std::fs::set_permissions(&context.secret_path, std::fs::Permissions::from_mode(0o644))
            .unwrap();

        assert!(ProjectAuditCache::read(project.path(), "npm").is_none());
        cache.dirty = true;
        assert!(cache.write(project.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_write_replaces_destination_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let package = package(Some("sha512-source"), None);
        let mut cache = populated_cache(project.path(), &package);
        let context = CacheContext::for_project(project.path()).unwrap();
        std::fs::create_dir_all(context.cache_path.parent().unwrap()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"sentinel").unwrap();
        symlink(outside.path(), &context.cache_path).unwrap();

        cache.write(project.path()).unwrap();
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"sentinel");
        assert!(
            !std::fs::symlink_metadata(context.cache_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn oversized_write_preserves_previous_authenticated_cache() {
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = scoped_lpm_home(lpm_home.path());
        let project = tempfile::tempdir().unwrap();
        let original_package = package(Some("sha512-source"), None);
        let mut previous = populated_cache(project.path(), &original_package);
        previous.write(project.path()).unwrap();
        let cache_path = CacheContext::for_project(project.path())
            .unwrap()
            .cache_path;
        let previous_bytes = std::fs::read(&cache_path).unwrap();

        let mut oversized = ProjectAuditCache::new(project.path(), "npm").unwrap();
        let mut analysis = empty_analysis();
        analysis.analyzed_at = "x".repeat(lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize);
        let oversized_package = package(Some("sha512-oversized"), None);
        oversized.insert(
            oversized_package.analysis_key(),
            &oversized_package,
            "sha256-oversized".into(),
            Arc::new(analysis),
        );

        let result = oversized.write(project.path());
        assert!(result.is_err());
        assert_eq!(std::fs::read(cache_path).unwrap(), previous_bytes);
    }
}
