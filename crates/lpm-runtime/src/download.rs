//! Binary download and extraction for runtime installations.

use crate::bun::{self, BunAsset, BunRelease};
use crate::node::{self, NodeRelease};
use crate::platform::Platform;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

struct RuntimeStagingDir {
    path: PathBuf,
}

impl RuntimeStagingDir {
    fn create(parent: &Path, version: &str) -> Result<Self, LpmError> {
        let path = parent.join(format!(".{version}-installing-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        create_restricted_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RuntimeStagingDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.path.display(),
                "failed to remove runtime staging directory: {error}"
            );
        }
    }
}

fn remove_stale_runtime_staging_dirs(parent: &Path, version: &str) -> Result<(), LpmError> {
    create_restricted_dir(parent)?;
    let prefix = format!(".{version}-installing-");
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn runtime_install_lock_path(target_dir: &Path) -> Result<std::path::PathBuf, LpmError> {
    let parent = target_dir
        .parent()
        .ok_or_else(|| LpmError::Script("invalid runtime path".into()))?;
    let version = target_dir
        .file_name()
        .ok_or_else(|| LpmError::Script("invalid runtime version path".into()))?;
    Ok(parent
        .join(".install-locks")
        .join(format!("{}.lock", version.to_string_lossy())))
}

fn runtime_is_complete(target_dir: &Path, executable_relative_path: &Path) -> bool {
    target_dir.join(executable_relative_path).is_file()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInstallReport {
    /// Installed runtime version without a leading `v`.
    pub version: String,
    /// Number of compressed archive bytes read from the network.
    pub downloaded_bytes: Option<u64>,
    /// Declared compressed archive size from `Content-Length`, when present.
    pub total_bytes: Option<u64>,
    /// SHA-256 checksum that was verified for the downloaded archive.
    pub sha256: Option<String>,
}

impl RuntimeInstallReport {
    fn already_installed(version: &str) -> Self {
        Self {
            version: version.to_string(),
            downloaded_bytes: None,
            total_bytes: None,
            sha256: None,
        }
    }
}

/// Download and install a Node.js release.
///
/// 1. Download the tarball from nodejs.org
/// 2. Extract to a temp directory
/// 3. Move the inner directory to `~/.lpm/runtimes/node/{version}/`
pub async fn install_node(
    client: &reqwest::Client,
    release: &NodeRelease,
    platform: &Platform,
) -> Result<String, LpmError> {
    Ok(install_node_with_report(client, release, platform)
        .await?
        .version)
}

/// Download, verify, extract, and install a Node.js release, returning
/// the facts useful for human progress output.
pub async fn install_node_with_report(
    client: &reqwest::Client,
    release: &NodeRelease,
    platform: &Platform,
) -> Result<RuntimeInstallReport, LpmError> {
    let version = release.version_bare();
    let target_dir = node::node_version_dir(version)?;
    let executable_relative_path = Path::new(if cfg!(windows) {
        "node.exe"
    } else {
        "bin/node"
    });

    if runtime_is_complete(&target_dir, executable_relative_path) {
        tracing::debug!(
            "node {version} already installed at {}",
            target_dir.display()
        );
        return Ok(RuntimeInstallReport::already_installed(version));
    }

    let lock_path = runtime_install_lock_path(&target_dir)?;
    let _install_lock = tokio::task::spawn_blocking(move || {
        lpm_common::acquire_single_file_exclusive_lock(lock_path)
    })
    .await
    .map_err(|error| LpmError::Script(format!("runtime install lock task failed: {error}")))??;
    if runtime_is_complete(&target_dir, executable_relative_path) {
        return Ok(RuntimeInstallReport::already_installed(version));
    }
    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir)?;
    }
    let parent = target_dir
        .parent()
        .ok_or_else(|| LpmError::Script("invalid runtime path".into()))?;
    remove_stale_runtime_staging_dirs(parent, version)?;

    let url = release.download_url(platform);
    tracing::debug!("downloading node {version} from {url}");

    // Download
    let resp = client.get(&url).send().await.map_err(|e| {
        LpmError::Network(format!(
            "failed to download node {version}: {}",
            lpm_http::display_error(&e)
        ))
    })?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("failed to download node {version} from {url}"),
        });
    }

    let (bytes, total_size) = read_download_body(resp, "node", version).await?;

    tracing::debug!(
        "downloaded {} bytes (expected {:?})",
        bytes.len(),
        total_size
    );

    // Verify SHA-256 checksum — hard failure on mismatch
    let sha256 = verify_checksum(client, release, platform, &bytes).await?;

    // Extract tarball
    let staging = RuntimeStagingDir::create(parent, version)?;
    let temp_dir = staging.path();

    // Windows uses .zip, others use .tar.gz
    if platform.os == "win" {
        extract_zip(&bytes, temp_dir)?;
    } else {
        extract_tarball(&bytes, temp_dir)?;
    }

    // The tarball contains a single top-level directory like "node-v22.5.0-darwin-arm64/"
    // We need to move its contents to the final location.
    let inner_dir = find_single_subdir(temp_dir)?;

    // Rename with TOCTOU race recovery
    rename_with_fallback(&inner_dir, &target_dir)?;

    // Clean up temp dir
    tracing::debug!("installed node {version} to {}", target_dir.display());
    Ok(RuntimeInstallReport {
        version: version.to_string(),
        downloaded_bytes: Some(bytes.len() as u64),
        total_bytes: total_size,
        sha256: Some(sha256),
    })
}

/// Download and install a Bun release.
///
/// Bun archives contain a single `bun-<target>/bun` (or `bun.exe`) binary.
/// LPM stores it under `~/.lpm/runtimes/bun/<version>/bin/`.
pub async fn install_bun(
    client: &reqwest::Client,
    release: &BunRelease,
    asset: &BunAsset,
) -> Result<String, LpmError> {
    Ok(install_bun_with_report(client, release, asset)
        .await?
        .version)
}

/// Download, verify, extract, and install a Bun release, returning the
/// facts useful for human progress output.
pub async fn install_bun_with_report(
    client: &reqwest::Client,
    release: &BunRelease,
    asset: &BunAsset,
) -> Result<RuntimeInstallReport, LpmError> {
    let version = release.version_bare();
    let target_dir = bun::bun_version_dir(version)?;
    let binary_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let executable_relative_path = Path::new(if cfg!(windows) {
        "bin/bun.exe"
    } else {
        "bin/bun"
    });

    if runtime_is_complete(&target_dir, executable_relative_path) {
        tracing::debug!(
            "bun {version} already installed at {}",
            target_dir.display()
        );
        return Ok(RuntimeInstallReport::already_installed(version));
    }

    let lock_path = runtime_install_lock_path(&target_dir)?;
    let _install_lock = tokio::task::spawn_blocking(move || {
        lpm_common::acquire_single_file_exclusive_lock(lock_path)
    })
    .await
    .map_err(|error| LpmError::Script(format!("runtime install lock task failed: {error}")))??;
    if runtime_is_complete(&target_dir, executable_relative_path) {
        return Ok(RuntimeInstallReport::already_installed(version));
    }
    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir)?;
    }
    let parent = target_dir
        .parent()
        .ok_or_else(|| LpmError::Script("invalid runtime path".into()))?;
    remove_stale_runtime_staging_dirs(parent, version)?;

    tracing::debug!(
        "downloading bun {version} from {}",
        asset.browser_download_url
    );
    let resp = client
        .get(&asset.browser_download_url)
        .header(reqwest::header::USER_AGENT, "lpm-runtime")
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to download bun {version}: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!(
                "failed to download bun {version} from {}",
                asset.browser_download_url
            ),
        });
    }

    let (bytes, total_size) = read_download_body(resp, "bun", version).await?;

    let sha256 = verify_bun_checksum(client, release, asset, &bytes).await?;

    let staging = RuntimeStagingDir::create(parent, version)?;
    let temp_dir = staging.path();

    let extract_dir = temp_dir.join("extract");
    create_restricted_dir(&extract_dir)?;
    extract_zip(&bytes, &extract_dir)?;

    let inner_dir = find_single_subdir(&extract_dir)?;
    let stage_dir = temp_dir.join("stage");
    let bin_dir = stage_dir.join("bin");
    create_restricted_dir(&bin_dir)?;

    let source_binary = inner_dir.join(binary_name);
    if !source_binary.exists() {
        return Err(LpmError::Script(format!(
            "Bun archive {} did not contain {binary_name}",
            asset.name
        )));
    }
    let staged_binary = bin_dir.join(binary_name);
    std::fs::rename(&source_binary, &staged_binary).or_else(|_| {
        std::fs::copy(&source_binary, &staged_binary).map(|_| {
            let _ = std::fs::remove_file(&source_binary);
        })
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_binary, std::fs::Permissions::from_mode(0o755))?;
    }

    rename_with_fallback(&stage_dir, &target_dir)?;
    tracing::debug!("installed bun {version} to {}", target_dir.display());
    Ok(RuntimeInstallReport {
        version: version.to_string(),
        downloaded_bytes: Some(bytes.len() as u64),
        total_bytes: total_size,
        sha256: Some(sha256),
    })
}

async fn read_download_body(
    mut resp: reqwest::Response,
    runtime: &str,
    version: &str,
) -> Result<(Vec<u8>, Option<u64>), LpmError> {
    let total_size = resp.content_length();
    let capacity = match total_size {
        Some(content_length) => checked_download_size(content_length)?,
        None => 0,
    };

    let mut bytes = Vec::with_capacity(capacity);
    let mut downloaded = 0u64;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read {runtime} download: {e}")))?
    {
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        checked_download_size(downloaded)?;
        bytes.extend_from_slice(&chunk);
    }

    tracing::debug!("read {runtime} {version} download ({} bytes)", bytes.len());
    Ok((bytes, total_size))
}

fn checked_download_size(size: u64) -> Result<usize, LpmError> {
    let size = usize::try_from(size).map_err(|_| {
        LpmError::Script(format!(
            "download size {size} bytes exceeds maximum allowed size of {MAX_DOWNLOAD_SIZE} bytes ({}MB)",
            MAX_DOWNLOAD_SIZE / (1024 * 1024)
        ))
    })?;
    validate_download_size(size)?;
    Ok(size)
}

/// Max decompressed bytes across all entries. Real Node distributions
/// expand to ~150 MB; 1 GiB is several×-headroom but blocks the
/// "small verified tarball expands into unbounded disk usage" shape
/// that the 200 MiB download cap does not address.
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

/// Max bytes per individual entry. A single 256 MiB file inside the
/// tarball is well above anything a legitimate Node tarball carries.
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

/// Max entry count in the archive. Real Node distributions ship a few
/// thousand files; 50 000 is roughly an order of magnitude above the
/// real ceiling and blocks a hostile archive that emits millions of
/// empty entries to exhaust inodes.
const MAX_ENTRY_COUNT: usize = 50_000;

/// Extract a .tar.gz archive with path traversal protection and
/// decompression-bomb caps.
///
/// Each entry is validated to ensure it does not escape the destination directory
/// via `..` path components (zip-slip attack). See CVE-2018-1002200.
fn extract_tarball(data: &[u8], dest: &Path) -> Result<(), LpmError> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    let mut total_bytes: u64 = 0;
    let mut entry_count: usize = 0;

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Script(format!("failed to read tarball entries: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| LpmError::Script(format!("failed to read tarball entry: {e}")))?;

        entry_count += 1;
        if entry_count > MAX_ENTRY_COUNT {
            return Err(LpmError::Script(format!(
                "tarball entry count exceeds {MAX_ENTRY_COUNT}"
            )));
        }

        let entry_size = entry.size();
        if entry_size > MAX_ENTRY_BYTES {
            return Err(LpmError::Script(format!(
                "tarball entry size {entry_size} exceeds per-entry cap of {MAX_ENTRY_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(entry_size);
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(LpmError::Script(format!(
                "tarball cumulative size {total_bytes} exceeds {MAX_EXTRACTED_BYTES} bytes"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| LpmError::Script(format!("failed to read tarball entry path: {e}")))?;

        // Reject any entry containing `..` components (path traversal / zip-slip)
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(LpmError::Script(format!(
                "path traversal detected in tarball entry: {}",
                path.display()
            )));
        }

        entry
            .unpack_in(dest)
            .map_err(|e| LpmError::Script(format!("failed to extract tarball entry: {e}")))?;
    }

    Ok(())
}

/// Extract a .zip archive with path traversal protection and
/// decompression-bomb caps.
///
/// Used for Windows Node.js distributions which are distributed as .zip files.
/// Each entry is validated to ensure it does not escape the destination directory.
fn extract_zip(data: &[u8], dest: &Path) -> Result<(), LpmError> {
    use std::io::Cursor;

    let reader = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| LpmError::Script(format!("failed to open zip archive: {e}")))?;

    if archive.len() > MAX_ENTRY_COUNT {
        return Err(LpmError::Script(format!(
            "zip entry count {} exceeds {MAX_ENTRY_COUNT}",
            archive.len()
        )));
    }

    let mut total_bytes: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| LpmError::Script(format!("failed to read zip entry {i}: {e}")))?;

        let declared = file.size();
        if declared > MAX_ENTRY_BYTES {
            return Err(LpmError::Script(format!(
                "zip entry size {declared} exceeds per-entry cap of {MAX_ENTRY_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(declared);
        if total_bytes > MAX_EXTRACTED_BYTES {
            return Err(LpmError::Script(format!(
                "zip cumulative size {total_bytes} exceeds {MAX_EXTRACTED_BYTES} bytes"
            )));
        }

        let outpath = match file.enclosed_name() {
            Some(path) => dest.join(path),
            None => {
                // enclosed_name() returns None for entries with path traversal
                return Err(LpmError::Script(format!(
                    "path traversal detected in zip entry: {}",
                    file.name()
                )));
            }
        };

        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)
                .map_err(|e| LpmError::Script(format!("failed to extract zip entry: {e}")))?;

            // Set executable permission on Unix for binaries
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }

    Ok(())
}

/// Find the single subdirectory inside a directory.
/// Node.js tarballs always have one top-level dir.
fn find_single_subdir(dir: &Path) -> Result<std::path::PathBuf, LpmError> {
    let mut entries = std::fs::read_dir(dir)?;
    let first = entries
        .next()
        .ok_or_else(|| LpmError::Script("extracted tarball is empty".into()))?
        .map_err(|e| LpmError::Script(format!("failed to read extracted dir: {e}")))?;

    if first.path().is_dir() {
        Ok(first.path())
    } else {
        Err(LpmError::Script(
            "extracted tarball doesn't contain a directory".into(),
        ))
    }
}

/// Maximum download size: 200 MiB.
///
/// Prevents OOM from malicious or unexpectedly large downloads.
const MAX_DOWNLOAD_SIZE: usize = 200 * 1024 * 1024;

/// Validate that a download size is within the allowed limit.
///
/// Called both for the `Content-Length` header (early reject) and
/// after buffering bytes (defence against lying headers / chunked encoding).
fn validate_download_size(size: usize) -> Result<(), LpmError> {
    if size > MAX_DOWNLOAD_SIZE {
        return Err(LpmError::Network(format!(
            "download size {size} bytes exceeds maximum allowed size of {MAX_DOWNLOAD_SIZE} bytes ({}MB)",
            MAX_DOWNLOAD_SIZE / (1024 * 1024)
        )));
    }
    Ok(())
}

/// Compare an expected hex-encoded SHA-256 hash against the SHA-256 of raw bytes.
///
/// Returns `Ok(())` on match, `Err` on mismatch.
fn compare_checksum(expected_hex: &str, actual_bytes: &[u8]) -> Result<(), LpmError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(actual_bytes);
    let actual_hex = format!("{:x}", hasher.finalize());
    let expected_hex = expected_hex.to_ascii_lowercase();

    if actual_hex == expected_hex {
        Ok(())
    } else {
        Err(LpmError::IntegrityMismatch {
            expected: expected_hex,
            actual: actual_hex,
        })
    }
}

/// Create a directory with restricted permissions (0o700 on Unix).
///
/// Ensures that runtime directories are not world-readable.
pub(crate) fn create_restricted_dir(path: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Write data to a file with restricted permissions (0o600 on Unix).
pub(crate) fn write_restricted_file(path: &Path, data: &[u8]) -> Result<(), LpmError> {
    lpm_common::write_file_atomic_with_options(
        path,
        data,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )?;
    Ok(())
}

/// Rename a directory to a target path with TOCTOU race recovery.
///
/// If the rename fails because the target already exists (another process
/// installed the same version concurrently), this is treated as success.
///
/// Cross-filesystem rename
///
/// `std::fs::rename()` fails with `EXDEV` across filesystem boundaries.
/// This is currently safe because the temp dir is always a sibling of the
/// target (both under `~/.lpm/runtimes/node/`), so they are on the same
/// filesystem. If the temp dir location is ever changed, a recursive
/// copy + delete fallback would be needed.
fn rename_with_fallback(source: &Path, target: &Path) -> Result<(), LpmError> {
    if target.exists() {
        // Another process already installed it — success.
        return Ok(());
    }

    match std::fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(_) if target.exists() => {
            // Race condition: rename failed because another process created target
            // between our exists() check and rename(). That's fine — it's installed.
            tracing::debug!(
                "rename failed but target already exists (concurrent install): {}",
                target.display()
            );
            Ok(())
        }
        Err(e) => Err(LpmError::Script(format!(
            "failed to move extracted node to {}: {e}",
            target.display()
        ))),
    }
}

/// Verify downloaded tarball against nodejs.org SHASUMS256.txt.
///
/// Fetches the checksum file, computes SHA-256 of the downloaded bytes,
/// and compares. Returns the verified hash on match.
async fn verify_checksum(
    client: &reqwest::Client,
    release: &node::NodeRelease,
    platform: &Platform,
    data: &[u8],
) -> Result<String, LpmError> {
    let shasums_url = release.shasums_url();

    let resp = client
        .get(&shasums_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to fetch SHASUMS256: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    if !resp.status().is_success() {
        return Err(LpmError::Network(format!(
            "SHASUMS256 returned {}",
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read SHASUMS256: {e}")))?;

    // Find the expected hash for our platform's archive
    let ext = if platform.os == "win" {
        "zip"
    } else {
        "tar.gz"
    };
    let expected_filename = format!("node-{}-{}.{ext}", release.version, platform.node_suffix());

    let expected_hash = body
        .lines()
        .find(|line| line.contains(&expected_filename))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| {
            LpmError::Network(format!(
                "checksum not found for {expected_filename} in SHASUMS256"
            ))
        })?;

    compare_checksum(expected_hash, data)?;
    let expected_hash = expected_hash.to_ascii_lowercase();

    // SHASUMS256.txt is fetched over HTTPS from nodejs.org but the
    // detached `.sig` GPG signature is NOT verified, so a CA-trusted
    // MITM (corporate proxy, mis-issued cert) or a mirror operator
    // can swap both `node-*.tar.gz` AND `SHASUMS256.txt` in lockstep
    // and the hash compare would still pass. Trust is anchored on
    // nodejs.org TLS only — there is no second leg of verification.
    // Operators on hardened CI can pin the expected Node version
    // ahead of time and refuse to install unfamiliar major versions.
    tracing::warn!(
        target: "lpm_runtime::download",
        url = %shasums_url,
        "Node runtime SHASUMS256 verified via upstream HTTPS only — no GPG signature check. Trust is anchored on nodejs.org TLS; a CA-trusted MITM or mirror operator can substitute the asset + checksum together.",
    );

    Ok(expected_hash)
}

async fn verify_bun_checksum(
    client: &reqwest::Client,
    release: &BunRelease,
    asset: &BunAsset,
    data: &[u8],
) -> Result<String, LpmError> {
    let mut verified_hash = None;

    if let Some(expected_hash) = asset
        .digest
        .as_deref()
        .filter(|digest| !digest.trim().is_empty())
        .map(parse_github_sha256_digest)
        .transpose()?
    {
        compare_checksum(&expected_hash, data)?;
        verified_hash = Some(expected_hash);
    }

    if let Some(shasums_url) = release.shasums_url() {
        let resp = client
            .get(shasums_url)
            .header(reqwest::header::USER_AGENT, "lpm-runtime")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                LpmError::Network(format!(
                    "failed to fetch Bun SHASUMS256: {}",
                    lpm_http::display_error(&e)
                ))
            })?;

        if !resp.status().is_success() {
            return Err(LpmError::Network(format!(
                "Bun SHASUMS256 returned {}",
                resp.status()
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| LpmError::Network(format!("failed to read Bun SHASUMS256: {e}")))?;
        let expected_hash = checksum_from_shasums(&body, &asset.name).ok_or_else(|| {
            LpmError::Network(format!(
                "checksum not found for {} in Bun SHASUMS256",
                asset.name
            ))
        })?;
        compare_checksum(&expected_hash, data)?;
        verified_hash = Some(expected_hash);
    }

    verified_hash.ok_or_else(|| {
        LpmError::Network(format!(
            "no SHA-256 checksum available for Bun asset {}",
            asset.name
        ))
    })
}

fn parse_github_sha256_digest(digest: &str) -> Result<String, LpmError> {
    let expected = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| LpmError::Network(format!("unsupported GitHub asset digest: {digest}")))?;
    if expected.len() != 64 || !expected.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(LpmError::Network(format!(
            "invalid SHA-256 digest on GitHub asset: {digest}"
        )));
    }
    Ok(expected.to_ascii_lowercase())
}

fn checksum_from_shasums(body: &str, filename: &str) -> Option<String> {
    body.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let hash = fields.next()?;
            let name = fields.next()?.trim_start_matches('*');
            (name == filename).then(|| hash.to_ascii_lowercase())
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // --- Tar path traversal (zip slip) ---

    /// Helper: build a tar.gz in memory with the given entry paths.
    ///
    /// For paths without `..`, uses the normal tar builder. For paths with `..`
    /// (malicious test entries), constructs raw tar blocks to bypass the builder's
    /// own path validation.
    fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();

        for &(path, data) in entries {
            if path.contains("..") {
                // Build raw tar entry to bypass builder validation
                tar_bytes.extend_from_slice(&build_raw_tar_entry(path, data));
            } else {
                let mut builder = tar::Builder::new(Vec::new());
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, data).unwrap();
                // Get raw bytes without the end-of-archive marker
                let built = builder.into_inner().unwrap();
                // Each entry is header (512) + data (padded to 512). Builder adds
                // 1024 zero bytes at the end as EOF marker; strip those.
                if built.len() > 1024 {
                    tar_bytes.extend_from_slice(&built[..built.len() - 1024]);
                } else {
                    tar_bytes.extend_from_slice(&built);
                }
            }
        }

        // End-of-archive: two 512-byte blocks of zeros
        tar_bytes.extend_from_slice(&[0u8; 1024]);

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    /// Build a raw tar entry with arbitrary path (bypassing validation).
    fn build_raw_tar_entry(path: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];

        // Name field: bytes 0..100
        let path_bytes = path.as_bytes();
        let copy_len = path_bytes.len().min(100);
        header[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

        // Mode field: bytes 100..108 (octal ASCII "0000644\0")
        header[100..108].copy_from_slice(b"0000644\0");

        // UID: bytes 108..116
        header[108..116].copy_from_slice(b"0001000\0");

        // GID: bytes 116..124
        header[116..124].copy_from_slice(b"0001000\0");

        // Size field: bytes 124..136 (octal ASCII, 11 digits + null)
        let size_str = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_str.as_bytes());

        // Mtime: bytes 136..148
        header[136..148].copy_from_slice(b"00000000000\0");

        // Typeflag: byte 156 = '0' (regular file)
        header[156] = b'0';

        // Magic: bytes 257..263 = "ustar\0"
        header[257..263].copy_from_slice(b"ustar\0");

        // Version: bytes 263..265 = "00"
        header[263..265].copy_from_slice(b"00");

        // Compute checksum: bytes 148..156 should be spaces during calculation
        header[148..156].copy_from_slice(b"        ");
        let cksum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{:06o}\0 ", cksum);
        header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

        let mut entry = Vec::with_capacity(512 + data.len().div_ceil(512) * 512);
        entry.extend_from_slice(&header);
        entry.extend_from_slice(data);
        // Pad to 512-byte boundary
        let padding = (512 - (data.len() % 512)) % 512;
        entry.extend_from_slice(&vec![0u8; padding]);
        entry
    }

    fn forged_zip_with_declared_file(path: &str, declared_size: u32) -> Vec<u8> {
        let name = path.as_bytes();
        let name_len = name.len() as u16;
        let mut zip = Vec::new();

        zip.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        zip.extend_from_slice(&20_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(&declared_size.to_le_bytes());
        zip.extend_from_slice(&name_len.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(name);

        let central_offset = zip.len() as u32;
        zip.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        zip.extend_from_slice(&20_u16.to_le_bytes());
        zip.extend_from_slice(&20_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(&declared_size.to_le_bytes());
        zip.extend_from_slice(&name_len.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(&0_u32.to_le_bytes());
        zip.extend_from_slice(name);

        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip.extend_from_slice(&1_u16.to_le_bytes());
        zip.extend_from_slice(&1_u16.to_le_bytes());
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&0_u16.to_le_bytes());
        zip
    }

    #[test]
    fn extract_tarball_rejects_path_traversal() {
        let malicious_tar = build_tar_gz(&[("../escape.txt", b"pwned")]);
        let dest = TempDir::new().unwrap();
        let result = extract_tarball(&malicious_tar, dest.path());
        assert!(
            result.is_err(),
            "extract_tarball must reject path traversal entries"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("path traversal"),
            "error should mention path traversal, got: {err_msg}"
        );
    }

    #[test]
    fn extract_tarball_rejects_nested_traversal() {
        let malicious_tar = build_tar_gz(&[("foo/../../escape.txt", b"pwned")]);
        let dest = TempDir::new().unwrap();
        let result = extract_tarball(&malicious_tar, dest.path());
        assert!(
            result.is_err(),
            "extract_tarball must reject nested path traversal"
        );
    }

    #[test]
    fn extract_zip_rejects_path_traversal() {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("extract");
        std::fs::create_dir_all(&dest).unwrap();
        let buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        writer
            .start_file("../escape.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"pwned").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let result = extract_zip(&zip_data, &dest);

        assert!(result.is_err(), "zip traversal must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("path traversal"),
            "error should mention path traversal, got: {err_msg}"
        );
        assert!(
            !root.path().join("escape.txt").exists(),
            "zip traversal must not write outside the destination"
        );
    }

    #[test]
    fn extract_zip_rejects_oversized_entry_declaration() {
        let zip_data =
            forged_zip_with_declared_file("node-v22.5.0/bin/node", (MAX_ENTRY_BYTES + 1) as u32);
        let dest = TempDir::new().unwrap();

        let err = extract_zip(&zip_data, dest.path()).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("per-entry cap"),
            "zip entry cap rejection should be explicit: {msg}"
        );
        assert!(
            !dest.path().join("node-v22.5.0/bin/node").exists(),
            "no partial zip extract on cap failure"
        );
    }

    #[test]
    fn extract_tarball_allows_normal_entries() {
        let normal_tar = build_tar_gz(&[
            ("mydir/file.txt", b"hello"),
            ("mydir/sub/deep.txt", b"world"),
        ]);
        let dest = TempDir::new().unwrap();
        let result = extract_tarball(&normal_tar, dest.path());
        assert!(
            result.is_ok(),
            "normal tarball should extract fine: {result:?}"
        );
        assert!(dest.path().join("mydir/file.txt").exists());
        assert!(dest.path().join("mydir/sub/deep.txt").exists());
    }

    /// A tar entry whose declared size exceeds the per-entry cap is
    /// rejected before unpack.
    #[test]
    fn extract_tarball_rejects_oversized_entry_declaration() {
        // Build a raw tar entry that declares size > MAX_ENTRY_BYTES
        // but ships only a tiny payload. The cap check fires before
        // unpack so the missing bytes don't matter.
        let mut header = [0u8; 512];
        let path_bytes = b"big.bin";
        header[..path_bytes.len()].copy_from_slice(path_bytes);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0001000\0");
        header[116..124].copy_from_slice(b"0001000\0");
        let size_str = format!("{:011o}\0", MAX_ENTRY_BYTES + 1);
        header[124..136].copy_from_slice(size_str.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let cksum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{:06o}\0 ", cksum);
        header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(&[0u8; 1024]); // EOF
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let dest = TempDir::new().unwrap();
        let err = extract_tarball(&gz_bytes, dest.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-entry cap"),
            "must label per-entry cap rejection: {msg}"
        );
        assert!(
            !dest.path().join("big.bin").exists(),
            "no partial extract on cap failure"
        );
    }

    // --- Checksum failure must be fatal ---

    #[test]
    fn compare_checksum_matching() {
        let data = b"hello world";
        // SHA-256 of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(compare_checksum(expected, data).is_ok());
    }

    #[test]
    fn compare_checksum_mismatch_is_error() {
        let data = b"hello world";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = compare_checksum(wrong, data);
        assert!(result.is_err(), "checksum mismatch must be an error");
        match result.unwrap_err() {
            LpmError::IntegrityMismatch { expected, actual } => {
                assert_eq!(expected, wrong);
                assert_eq!(
                    actual,
                    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
                );
            }
            other => panic!("expected IntegrityMismatch, got: {other:?}"),
        }
    }

    // --- Download size limit ---

    #[test]
    fn validate_download_size_within_limit() {
        assert!(validate_download_size(100 * 1024 * 1024).is_ok());
        assert!(validate_download_size(0).is_ok());
        assert!(validate_download_size(MAX_DOWNLOAD_SIZE).is_ok());
    }

    #[test]
    fn validate_download_size_exceeds_limit() {
        let result = validate_download_size(MAX_DOWNLOAD_SIZE + 1);
        assert!(result.is_err(), "oversized download must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds maximum"), "got: {err_msg}");
    }

    // --- Directory and file permissions ---

    #[cfg(unix)]
    #[test]
    fn create_restricted_dir_sets_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("restricted");
        create_restricted_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "directory should be 0o700, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn write_restricted_file_sets_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("secret.json");
        write_restricted_file(&file, b"{}").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should be 0o600, got {mode:o}");
    }

    // --- TOCTOU race — recovery when target already exists ---

    #[test]
    fn rename_recovery_when_target_exists() {
        // Simulate: rename fails because another process already installed the version.
        // The function should detect that target_dir now exists and return success.
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");

        // Create both source and target (simulating the race)
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("node"), b"binary").unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("node"), b"binary").unwrap();

        // rename_with_fallback should succeed because target already exists
        let result = rename_with_fallback(&source, &target);
        assert!(
            result.is_ok(),
            "should succeed when target already exists: {result:?}"
        );
    }

    #[test]
    fn rename_with_fallback_normal_case() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");

        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("node"), b"binary").unwrap();

        let result = rename_with_fallback(&source, &target);
        assert!(result.is_ok());
        assert!(target.join("node").exists());
    }

    // --- Checksum filename correctness per platform ---

    #[test]
    fn verify_checksum_filename_uses_correct_extension() {
        // The checksum lookup must use .zip for Windows and .tar.gz for others.
        // This test verifies the filename construction logic matches download_url().
        let release = node::NodeRelease {
            version: "v22.5.0".into(),
            date: "2024-07-17".into(),
            lts: node::LtsField::Bool(false),
            dist_base_url: None,
        };

        // Windows: must look for .zip in SHASUMS
        let win_platform = Platform {
            os: "win",
            arch: "x64",
        };
        let win_ext = if win_platform.os == "win" {
            "zip"
        } else {
            "tar.gz"
        };
        let win_filename = format!(
            "node-{}-{}.{win_ext}",
            release.version,
            win_platform.node_suffix()
        );
        assert_eq!(
            win_filename, "node-v22.5.0-win-x64.zip",
            "Windows checksum lookup must search for .zip"
        );

        // macOS: must look for .tar.gz
        let mac_platform = Platform {
            os: "darwin",
            arch: "arm64",
        };
        let mac_ext = if mac_platform.os == "win" {
            "zip"
        } else {
            "tar.gz"
        };
        let mac_filename = format!(
            "node-{}-{}.{mac_ext}",
            release.version,
            mac_platform.node_suffix()
        );
        assert_eq!(
            mac_filename, "node-v22.5.0-darwin-arm64.tar.gz",
            "macOS checksum lookup must search for .tar.gz"
        );

        // Linux: must look for .tar.gz
        let linux_platform = Platform {
            os: "linux",
            arch: "x64",
        };
        let linux_ext = if linux_platform.os == "win" {
            "zip"
        } else {
            "tar.gz"
        };
        let linux_filename = format!(
            "node-{}-{}.{linux_ext}",
            release.version,
            linux_platform.node_suffix()
        );
        assert_eq!(
            linux_filename, "node-v22.5.0-linux-x64.tar.gz",
            "Linux checksum lookup must search for .tar.gz"
        );
    }

    #[test]
    fn parse_github_sha256_digest_accepts_valid_digest() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_github_sha256_digest(digest).unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_github_sha256_digest_rejects_missing_algorithm() {
        let err = parse_github_sha256_digest(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unsupported GitHub asset digest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn checksum_from_shasums_selects_exact_asset_filename() {
        let body = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  bun-linux-x64.zip\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  *bun-linux-x64-musl.zip\n";

        assert_eq!(
            checksum_from_shasums(body, "bun-linux-x64-musl.zip").as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }
}
