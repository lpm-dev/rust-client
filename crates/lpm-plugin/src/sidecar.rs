//! Plugin sidecar metadata (`.lpm-plugin.json`).
//!
//! Lives next to each installed plugin binary at
//! `~/.lpm/plugins/{name}/{version}/{platform}/.lpm-plugin.json`.
//!
//! The sidecar is the source of truth for whether a cached binary may be
//! reused. A bare binary on disk without a valid sidecar is treated as a
//! cache miss — we re-verify rather than trust.
//!
//! Recorded fields lock the binary to its provenance (asset URL, archive
//! checksum, on-disk binary checksum, verification source). The reuse
//! gate validates platform match, verification posture, and on-disk
//! integrity at install time, then a file metadata snapshot on the hot
//! reuse path. If the snapshot is missing or changed, reuse falls back to a
//! full binary hash before refreshing the snapshot.

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Sidecar schema version. Bump when fields change in incompatible ways;
/// older sidecars are then treated as cache misses (we re-verify).
const SCHEMA_VERSION: u32 = 1;

/// Sidecar file name written next to the plugin binary.
pub const SIDECAR_FILE_NAME: &str = ".lpm-plugin.json";

/// How a plugin install was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationSource {
    /// Verified against a SHA-256 checksum bundled with the LPM CLI binary.
    /// Available for the registry's hardcoded `latest_version`.
    Bundled,
    /// Verified against a SHA-256 checksum fetched from the upstream
    /// release sidecar (`<asset_url>.sha256`) at install time.
    Upstream,
    /// Installed without checksum verification because the user opted in
    /// via `LPM_ALLOW_UNVERIFIED_PLUGINS=1`. Reuse of these binaries is
    /// gated on the same env var being set in the consuming process —
    /// the override is a property of the trust posture, not a property
    /// of the binary on disk.
    UnverifiedOverride,
}

/// Sidecar payload. Serialized as pretty JSON so users can inspect by
/// hand if they're debugging a verification issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema_version: u32,
    pub plugin_name: String,
    pub version: String,
    pub platform: String,
    pub asset_name: String,
    pub asset_url: String,
    /// SHA-256 of the downloaded asset (archive for `is_archive: true`,
    /// binary otherwise). This is the byte sequence the bundled or
    /// upstream checksum attests to.
    pub asset_sha256: String,
    /// SHA-256 of the binary file on disk after extraction. Used for
    /// fallback tamper detection when the metadata snapshot is missing or
    /// changed. For non-archive plugins this equals `asset_sha256`; for
    /// archive plugins it differs.
    pub binary_sha256: String,
    /// File metadata observed immediately after verification. This lets the
    /// steady-state reuse path avoid hashing large tool binaries on every
    /// `lpm lint` / `lpm fmt` invocation while still falling back to the
    /// recorded SHA-256 if the file changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_snapshot: Option<BinarySnapshot>,
    pub verification_source: VerificationSource,
    pub verified_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinarySnapshot {
    pub len: u64,
    pub modified_unix_secs: u64,
    pub modified_subsec_nanos: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixBinarySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsBinarySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixBinarySnapshot {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBinarySnapshot {
    pub file_attributes: u32,
    pub creation_time: u64,
    pub change_time: u64,
    pub last_write_time: u64,
    pub volume_serial_number: Option<u32>,
    pub file_index: Option<u64>,
}

impl BinarySnapshot {
    fn from_path(path: &Path) -> std::io::Result<Option<Self>> {
        let metadata = std::fs::metadata(path)?;
        Self::from_metadata(&metadata)
    }

    fn from_metadata(metadata: &std::fs::Metadata) -> std::io::Result<Option<Self>> {
        let modified = metadata.modified()?;
        let Ok(duration) = modified.duration_since(UNIX_EPOCH) else {
            return Ok(None);
        };
        let unix = {
            #[cfg(unix)]
            {
                Some(unix_snapshot(metadata))
            }
            #[cfg(not(unix))]
            {
                None
            }
        };
        let windows = {
            #[cfg(windows)]
            {
                Some(windows_snapshot(metadata))
            }
            #[cfg(not(windows))]
            {
                None
            }
        };
        Ok(Some(Self {
            len: metadata.len(),
            modified_unix_secs: duration.as_secs(),
            modified_subsec_nanos: duration.subsec_nanos(),
            unix,
            windows,
        }))
    }

    fn matches_metadata(self, metadata: &std::fs::Metadata) -> bool {
        Self::from_metadata(metadata)
            .ok()
            .flatten()
            .is_some_and(|current| current == self)
    }
}

#[cfg(unix)]
fn unix_snapshot(metadata: &std::fs::Metadata) -> UnixBinarySnapshot {
    use std::os::unix::fs::MetadataExt;

    UnixBinarySnapshot {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

#[cfg(windows)]
fn windows_snapshot(metadata: &std::fs::Metadata) -> WindowsBinarySnapshot {
    use std::os::windows::fs::MetadataExt;

    WindowsBinarySnapshot {
        file_attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        change_time: metadata.change_time(),
        last_write_time: metadata.last_write_time(),
        volume_serial_number: metadata.volume_serial_number(),
        file_index: metadata.file_index(),
    }
}

impl Sidecar {
    /// Build a fresh sidecar payload.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_name: impl Into<String>,
        version: impl Into<String>,
        platform: impl Into<String>,
        asset_name: impl Into<String>,
        asset_url: impl Into<String>,
        asset_sha256: impl Into<String>,
        binary_sha256: impl Into<String>,
        verification_source: VerificationSource,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            plugin_name: plugin_name.into(),
            version: version.into(),
            platform: platform.into(),
            asset_name: asset_name.into(),
            asset_url: asset_url.into(),
            asset_sha256: asset_sha256.into(),
            binary_sha256: binary_sha256.into(),
            binary_snapshot: None,
            verification_source,
            verified_at_unix: now_unix(),
        }
    }

    pub fn with_current_binary_snapshot(mut self, binary_path: &Path) -> Self {
        self.binary_snapshot = BinarySnapshot::from_path(binary_path).ok().flatten();
        self
    }
}

/// Result of validating a sidecar against the current process state.
#[derive(Debug, PartialEq, Eq)]
pub enum ReuseDecision {
    /// Sidecar is valid for the current request — binary may be reused.
    Hit,
    /// Sidecar absent, malformed, or fails any check — caller must
    /// treat as cache miss and re-verify by downloading fresh.
    Miss(MissReason),
}

/// Why a sidecar didn't qualify for reuse. Surfaced through tracing so
/// users can debug "why did LPM redownload my plugin" cases.
#[derive(Debug, PartialEq, Eq)]
pub enum MissReason {
    /// No sidecar file at the expected path.
    SidecarMissing,
    /// Sidecar JSON couldn't be parsed.
    SidecarMalformed(String),
    /// Sidecar's `schema_version` is from a future or older incompatible release.
    SchemaVersionMismatch { found: u32 },
    /// Sidecar's `platform` differs from the current host. Could happen
    /// when `$LPM_HOME` is shared across architectures (cross-arch CI,
    /// NFS, Docker bind mounts).
    PlatformMismatch { stored: String, current: String },
    /// Sidecar's `plugin_name` / `version` don't match the requested
    /// install. Defends against a sidecar getting moved into the wrong
    /// directory by some external process.
    IdentityMismatch,
    /// Sidecar marks this install as `unverified-override` but the
    /// current process didn't set `LPM_ALLOW_UNVERIFIED_PLUGINS=1`. The
    /// trust override is intentionally non-sticky.
    UnverifiedOverrideRequired,
    /// Binary file referenced by the sidecar doesn't exist on disk.
    BinaryMissing,
    /// On-disk binary's SHA-256 doesn't match the sidecar. Either the
    /// binary was tampered with, or the sidecar was forged.
    BinaryHashMismatch { recorded: String, observed: String },
}

/// Read and validate a sidecar for a specific reuse request.
///
/// Returns [`ReuseDecision::Hit`] only when every gate passes. Any failure
/// returns [`ReuseDecision::Miss`] with a reason — callers should treat
/// that as a cache miss (re-download), not as an error.
pub fn validate_for_reuse(
    sidecar_path: &Path,
    binary_path: &Path,
    requested_plugin: &str,
    requested_version: &str,
    current_platform: &str,
    allow_unverified_override: bool,
) -> ReuseDecision {
    let mut sidecar = match read_sidecar(sidecar_path) {
        Ok(s) => s,
        Err(MissReason::SidecarMissing) => return ReuseDecision::Miss(MissReason::SidecarMissing),
        Err(reason) => return ReuseDecision::Miss(reason),
    };

    if sidecar.schema_version != SCHEMA_VERSION {
        return ReuseDecision::Miss(MissReason::SchemaVersionMismatch {
            found: sidecar.schema_version,
        });
    }

    if sidecar.plugin_name != requested_plugin || sidecar.version != requested_version {
        return ReuseDecision::Miss(MissReason::IdentityMismatch);
    }

    if sidecar.platform != current_platform {
        return ReuseDecision::Miss(MissReason::PlatformMismatch {
            stored: sidecar.platform,
            current: current_platform.to_string(),
        });
    }

    let unverified_override = matches!(
        sidecar.verification_source,
        VerificationSource::UnverifiedOverride
    );
    if unverified_override && !allow_unverified_override {
        return ReuseDecision::Miss(MissReason::UnverifiedOverrideRequired);
    }

    let metadata = match std::fs::metadata(binary_path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return ReuseDecision::Miss(MissReason::BinaryMissing),
    };

    if let Some(snapshot) = sidecar.binary_snapshot
        && snapshot.matches_metadata(&metadata)
    {
        warn_if_unverified_override(&sidecar, sidecar_path, unverified_override);
        return ReuseDecision::Hit;
    }

    let observed = match hash_file(binary_path) {
        Ok(h) => h,
        Err(_) => return ReuseDecision::Miss(MissReason::BinaryMissing),
    };
    if observed != sidecar.binary_sha256 {
        return ReuseDecision::Miss(MissReason::BinaryHashMismatch {
            recorded: sidecar.binary_sha256,
            observed,
        });
    }

    if let Ok(Some(snapshot)) = BinarySnapshot::from_metadata(&metadata)
        && sidecar.binary_snapshot != Some(snapshot)
    {
        sidecar.binary_snapshot = Some(snapshot);
        if let Err(error) = write_atomic(sidecar_path, &sidecar) {
            tracing::debug!(
                sidecar = %sidecar_path.display(),
                %error,
                "failed to refresh plugin sidecar binary snapshot after hash validation"
            );
        }
    }

    // L12: a sidecar tagged UnverifiedOverride was honoured. Each
    // honoured reuse fires this warn so persistent env contamination
    // (`LPM_ALLOW_UNVERIFIED_PLUGINS=1` left in a shell rc) shows
    // up in trace logs every time it grants free pass, rather than
    // being silently respected forever after the initial install.
    warn_if_unverified_override(&sidecar, sidecar_path, unverified_override);

    ReuseDecision::Hit
}

fn warn_if_unverified_override(sidecar: &Sidecar, sidecar_path: &Path, unverified_override: bool) {
    if unverified_override {
        tracing::warn!(
            plugin = %sidecar.plugin_name,
            version = %sidecar.version,
            sidecar = %sidecar_path.display(),
            "honouring unverified-override plugin sidecar (LPM_ALLOW_UNVERIFIED_PLUGINS env); \
             confirm this is expected — a persistent env may be granting silent reuse of \
             a binary installed without signature verification",
        );
    }
}

fn read_sidecar(path: &Path) -> Result<Sidecar, MissReason> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(MissReason::SidecarMissing);
        }
        Err(e) => return Err(MissReason::SidecarMalformed(e.to_string())),
    };
    serde_json::from_slice(&bytes).map_err(|e| MissReason::SidecarMalformed(e.to_string()))
}

/// Write a sidecar atomically (temp file + rename). The temp file name
/// includes the PID so concurrent installers can't collide.
pub fn write_atomic(sidecar_path: &Path, sidecar: &Sidecar) -> Result<(), LpmError> {
    if let Some(parent) = sidecar_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(sidecar)
        .map_err(|e| LpmError::Plugin(format!("failed to serialize sidecar: {e}")))?;

    let tmp = sidecar_path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|e| LpmError::Plugin(format!("failed to write sidecar tmp: {e}")))?;
    std::fs::rename(&tmp, sidecar_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpmError::Plugin(format!("failed to finalize sidecar: {e}"))
    })?;
    Ok(())
}

/// SHA-256 hex digest of a file. Streams in 64 KB chunks so a giant
/// binary doesn't blow the heap.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_binary(path: &Path, bytes: &[u8]) -> String {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn make_sidecar(
        plugin: &str,
        version: &str,
        platform: &str,
        binary_hash: &str,
        source: VerificationSource,
    ) -> Sidecar {
        Sidecar::new(
            plugin,
            version,
            platform,
            "asset.tar.gz",
            "https://example.test/asset.tar.gz",
            "asset_hash_unused_in_reuse",
            binary_hash,
            source,
        )
    }

    fn make_sidecar_with_snapshot(
        plugin: &str,
        version: &str,
        platform: &str,
        binary_hash: &str,
        source: VerificationSource,
        binary_path: &Path,
    ) -> Sidecar {
        make_sidecar(plugin, version, platform, binary_hash, source)
            .with_current_binary_snapshot(binary_path)
    }

    #[test]
    fn hit_when_everything_matches() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"fake oxlint bytes");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(result, ReuseDecision::Hit);
    }

    #[test]
    fn hash_fallback_refreshes_missing_binary_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"fake oxlint bytes");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(result, ReuseDecision::Hit);

        let refreshed: Sidecar =
            serde_json::from_slice(&std::fs::read(&sidecar_path).unwrap()).unwrap();
        assert!(refreshed.binary_snapshot.is_some());
    }

    #[test]
    fn miss_when_sidecar_absent() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_for_reuse(
            &dir.path().join(SIDECAR_FILE_NAME),
            &dir.path().join("oxlint"),
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(result, ReuseDecision::Miss(MissReason::SidecarMissing));
    }

    #[test]
    fn miss_when_platform_differs() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"x");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "linux-x64",
            &hash,
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::PlatformMismatch { .. })
        ));
    }

    #[test]
    fn miss_when_identity_differs() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"x");
        let sidecar = make_sidecar(
            "biome",
            "2.4.10",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(result, ReuseDecision::Miss(MissReason::IdentityMismatch));
    }

    #[test]
    fn miss_when_unverified_override_without_env() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"x");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::UnverifiedOverride,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(
            result,
            ReuseDecision::Miss(MissReason::UnverifiedOverrideRequired)
        );
    }

    #[test]
    fn hit_when_unverified_override_with_env() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"x");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::UnverifiedOverride,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            true,
        );
        assert_eq!(result, ReuseDecision::Hit);
    }

    #[test]
    fn miss_when_binary_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"original bytes");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        // Tamper the binary after the sidecar is written.
        std::fs::write(&bin, b"tampered bytes").unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::BinaryHashMismatch { .. })
        ));
    }

    #[test]
    fn snapshot_mismatch_falls_back_to_hash_and_rejects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let hash = write_binary(&bin, b"original bytes");
        let sidecar = make_sidecar_with_snapshot(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
            &bin,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        std::fs::write(&bin, b"tampered bytes with different length").unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::BinaryHashMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_mismatch_falls_back_to_hash_when_mtime_and_len_match() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let original = b"original bytes";
        let tampered = b"tampered bytes";
        assert_eq!(original.len(), tampered.len());

        let hash = write_binary(&bin, original);
        let original_mtime =
            filetime::FileTime::from_last_modification_time(&std::fs::metadata(&bin).unwrap());
        let sidecar = make_sidecar_with_snapshot(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            &hash,
            VerificationSource::Bundled,
            &bin,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&bin, tampered).unwrap();
        filetime::set_file_mtime(&bin, original_mtime).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::BinaryHashMismatch { .. })
        ));
    }

    #[test]
    fn miss_when_binary_missing_but_sidecar_present() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("oxlint");
        let sidecar = make_sidecar(
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "deadbeef",
            VerificationSource::Bundled,
        );
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        write_atomic(&sidecar_path, &sidecar).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &bin,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert_eq!(result, ReuseDecision::Miss(MissReason::BinaryMissing));
    }

    #[test]
    fn miss_when_sidecar_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        std::fs::write(&sidecar_path, b"{ not json").unwrap();
        let result = validate_for_reuse(
            &sidecar_path,
            &dir.path().join("oxlint"),
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::SidecarMalformed(_))
        ));
    }

    #[test]
    fn miss_when_schema_version_differs() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar_path = dir.path().join(SIDECAR_FILE_NAME);
        // Hand-craft a sidecar with an incompatible schema version.
        let payload = serde_json::json!({
            "schema_version": 999,
            "plugin_name": "oxlint",
            "version": "1.58.0",
            "platform": "darwin-arm64",
            "asset_name": "x",
            "asset_url": "https://example.test/x",
            "asset_sha256": "0",
            "binary_sha256": "0",
            "verification_source": "bundled",
            "verified_at_unix": 0,
        });
        std::fs::write(&sidecar_path, payload.to_string()).unwrap();

        let result = validate_for_reuse(
            &sidecar_path,
            &dir.path().join("oxlint"),
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            false,
        );
        assert!(matches!(
            result,
            ReuseDecision::Miss(MissReason::SchemaVersionMismatch { found: 999 })
        ));
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SIDECAR_FILE_NAME);
        let s1 = make_sidecar(
            "oxlint",
            "1.0.0",
            "darwin-arm64",
            "0",
            VerificationSource::Bundled,
        );
        write_atomic(&path, &s1).unwrap();
        let s2 = make_sidecar(
            "oxlint",
            "2.0.0",
            "darwin-arm64",
            "0",
            VerificationSource::Bundled,
        );
        write_atomic(&path, &s2).unwrap();

        let read: Sidecar = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read.version, "2.0.0");
    }

    #[test]
    fn hash_file_streams_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello world").unwrap();
        let h = hash_file(&path).unwrap();
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
