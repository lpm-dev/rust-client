//! Download plugin binaries from GitHub Releases.
//!
//! Supports both `.tar.gz` archives (oxlint) and `.zip` archives (oxlint on Windows),
//! as well as direct binary downloads (biome).
//!
//! ## Verification model
//!
//! Every downloaded asset is checksum-verified before being installed.
//! Three sources are tried in order, and one of them MUST succeed unless
//! the user has explicitly opted into unverified installs:
//!
//! 1. **Bundled checksum** — SHA-256 baked into the LPM binary at build
//!    time. Available for the registry's hardcoded `latest_version`.
//! 2. **Upstream checksum** — SHA-256 fetched from a release sidecar
//!    (`<asset_url>.sha256`). Both oxlint (via cargo-dist) and biome
//!    publish these for every released asset, so user-pinned versions
//!    and `lpm plugin update` pulls reach a verified install.
//! 3. **Override** — only if `LPM_ALLOW_UNVERIFIED_PLUGINS=1`. Records
//!    `verification-source: unverified-override` in the sidecar; the
//!    binary cannot be reused by a process that does not also set the
//!    override (so the trust downgrade does not silently stick across
//!    runs).
//!
//! Downloads stream the binary through an exclusively created sibling
//! before atomically replacing the final path. The sidecar is written
//! atomically AFTER the binary replacement so a half-installed binary is
//! never paired with a sidecar declaring it valid.

use crate::registry::{self, PluginDef};
use crate::sidecar::{self, Sidecar, VerificationSource};
use crate::store;
use lpm_common::LpmError;
use lpm_runtime::platform::Platform;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadReport {
    pub asset_sha256: String,
    pub verification_source: VerificationSource,
}

/// Maximum download size: 150 MB. 3x safety margin over largest known plugin (~50 MB biome).
const MAX_PLUGIN_DOWNLOAD_SIZE: usize = 150 * 1024 * 1024;

/// Max bytes for a single extracted plugin binary. Pre-fix the
/// extractor `std::io::copy`-ed the named entry verbatim, so a
/// malicious release could pack a 50 MB compressed archive whose
/// internal entry expands to multi-GB. 200 MiB leaves several×
/// headroom over the largest real plugin (~50 MB biome) while
/// bounding the worst case at extraction time.
const MAX_PLUGIN_EXTRACTED_BYTES: u64 = 200 * 1024 * 1024;

/// Max entries scanned in a plugin archive. Real plugins ship one
/// binary + a license/readme; 1024 entries is roughly two orders of
/// magnitude above what a legitimate plugin tarball or zip carries.
const MAX_PLUGIN_ARCHIVE_ENTRIES: usize = 1024;

/// Maximum size of the upstream checksum sidecar file. The standard
/// `sha256sum` line format is ~70 bytes; 4 KB leaves room for a few
/// alternates (multi-asset listings, BOM, trailing whitespace) without
/// letting a malicious or confused server stream us an unbounded body.
const MAX_CHECKSUM_BODY_SIZE: u64 = 4 * 1024;

/// Env var that opts the user into installing plugins without a
/// verified checksum. Set to `1` or `true`. Recorded on the sidecar
/// and re-checked at every reuse.
pub const ALLOW_UNVERIFIED_ENV: &str = "LPM_ALLOW_UNVERIFIED_PLUGINS";

/// Read [`ALLOW_UNVERIFIED_ENV`] and return whether the user has
/// opted into unverified installs in the current process.
pub fn allow_unverified_override() -> bool {
    std::env::var(ALLOW_UNVERIFIED_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Download and install a plugin binary into the platform-scoped
/// store at `~/.lpm/plugins/{name}/{version}/{platform}/{binary}`,
/// with a sibling `.lpm-plugin.json` sidecar that records the
/// verification result.
///
/// The download is cleaned up on any failure path; a partial install
/// never leaves a binary or sidecar behind that a future run might
/// trust.
pub async fn download_plugin(
    def: &PluginDef,
    version: &str,
    platform: &Platform,
) -> Result<DownloadReport, LpmError> {
    let platform_str = platform.to_string();
    let asset_name = registry::resolve_platform_asset(def, &platform_str).ok_or_else(|| {
        LpmError::Plugin(format!(
            "plugin '{}' has no binary for platform {}",
            def.name, platform_str
        ))
    })?;

    let url = def
        .url_template
        .replace("{version}", version)
        .replace("{platform}", asset_name);

    tracing::debug!("downloading plugin {}@{} from {}", def.name, version, url);

    let client = lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(&url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to download {}: {}",
                def.name,
                lpm_http::display_error(&e)
            ))
        })?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("failed to download {} from {}", def.name, url),
        });
    }

    if let Some(content_length) = resp.content_length()
        && content_length as usize > MAX_PLUGIN_DOWNLOAD_SIZE
    {
        return Err(LpmError::Plugin(format!(
            "plugin '{}' download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            def.name, content_length, MAX_PLUGIN_DOWNLOAD_SIZE
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read {}: {e}", def.name)))?;

    validate_download_size(def.name, bytes.len())?;

    let asset_sha256 = compute_sha256(&bytes);
    tracing::debug!("downloaded {} bytes, sha256: {}", bytes.len(), asset_sha256);

    // --- Verification gate ---
    let allow_override = allow_unverified_override();
    let verification = resolve_verification(
        def,
        version,
        &platform_str,
        &url,
        &asset_sha256,
        &client,
        allow_override,
    )
    .await?;
    match &verification {
        VerificationSource::Bundled => {
            tracing::debug!(
                "plugin {} {} verified against bundled checksum",
                def.name,
                platform_str
            );
        }
        VerificationSource::Upstream => {
            tracing::debug!(
                "plugin {} {} verified against upstream sidecar",
                def.name,
                platform_str
            );
        }
        VerificationSource::UnverifiedOverride => {
            // Loud warning — we want this visible in CI logs and dev
            // sessions so an unverified install is never invisible.
            eprintln!(
                "  \x1b[33m!\x1b[0m {}@{} installed WITHOUT checksum verification \
                 ({}=1). The binary's SHA-256 is recorded as {} for audit; \
                 reuse will require {}=1 on every subsequent run.",
                def.name, version, ALLOW_UNVERIFIED_ENV, asset_sha256, ALLOW_UNVERIFIED_ENV,
            );
        }
    }

    // --- Materialize the binary ---
    let platform_dir = store::plugin_platform_dir(def.name, version, &platform_str)?;
    std::fs::create_dir_all(&platform_dir)?;

    let bin_path = platform_dir.join(def.binary_name);
    let binary_sha256 = lpm_common::write_file_atomic_with(
        &bin_path,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o755),
        |temporary| -> Result<String, LpmError> {
            if def.is_archive {
                if asset_name.ends_with(".zip") || is_zip_magic(&bytes) {
                    extract_binary_from_zip(&bytes, temporary, def.binary_name)?;
                } else {
                    extract_binary_from_tarball(&bytes, temporary, def.binary_name)?;
                }
            } else {
                temporary
                    .write_all(&bytes)
                    .map_err(|e| LpmError::Plugin(format!("failed to write plugin binary: {e}")))?;
            }
            hash_open_file(temporary)
        },
    )?;

    // --- Write sidecar AFTER binary replacement succeeds ---
    let sidecar_path = store::plugin_sidecar_path(def.name, version, &platform_str)?;
    let sidecar = Sidecar::new(
        def.name,
        version,
        &platform_str,
        asset_name,
        &url,
        &asset_sha256,
        &binary_sha256,
        verification,
    )
    .with_current_binary_snapshot(&bin_path);
    if let Err(e) = sidecar::write_atomic(&sidecar_path, &sidecar) {
        // Sidecar write failed but binary is on disk. Roll back the
        // binary so the next run doesn't see a binary without a
        // sidecar (which would also be treated as a cache miss, but
        // leaving stray binaries around is messy).
        let _ = std::fs::remove_file(&bin_path);
        return Err(e);
    }

    // --- Cleanup legacy unscoped binary (only after success) ---
    store::finalize_legacy_cleanup(def.name, version, def.binary_name);

    tracing::debug!(
        "installed plugin {}@{} ({}) to {} (asset sha256: {}, binary sha256: {})",
        def.name,
        version,
        platform_str,
        bin_path.display(),
        asset_sha256,
        binary_sha256,
    );

    Ok(DownloadReport {
        asset_sha256,
        verification_source: verification,
    })
}

fn hash_open_file(file: &mut std::fs::File) -> Result<String, LpmError> {
    file.flush()?;
    file.rewind()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Decide how this download is verified — bundled, upstream-fetched, or
/// override. Errors fail-closed unless `allow_override` is true (which
/// the caller derives from [`ALLOW_UNVERIFIED_ENV`]).
async fn resolve_verification(
    def: &PluginDef,
    version: &str,
    platform_str: &str,
    asset_url: &str,
    actual_sha256: &str,
    client: &reqwest::Client,
    allow_override: bool,
) -> Result<VerificationSource, LpmError> {
    // 1. Bundled — covers the registry's pinned latest_version, the
    //    fast path for the common case where `latest_version` matches
    //    what's actually requested.
    if let Some(expected) = registry::resolve_checksum(def, platform_str)
        && version == def.latest_version
    {
        verify_checksum(def.name, actual_sha256, expected)?;
        return Ok(VerificationSource::Bundled);
    }

    // 2. Upstream — fetch `<asset_url>.sha256` and verify.
    //
    // M19: surface the trust posture. SHA-256 alone matches integrity
    // against whatever the upstream release pipeline produced — if
    // the upstream account is compromised, both the binary AND the
    // sidecar can be swapped together. Sigstore / cosign / GPG
    // verification would close that chain; until that's wired in,
    // an upstream-verified install carries this caveat explicitly.
    let upstream_url = format!("{asset_url}.sha256");
    match fetch_upstream_checksum(client, &upstream_url).await {
        Ok(expected) => {
            verify_checksum(def.name, actual_sha256, &expected)?;
            tracing::warn!(
                target: "lpm_plugin::download",
                plugin = def.name,
                version = version,
                platform = platform_str,
                "plugin verified via upstream `.sha256` sidecar only — no signature/provenance check (M19). Upstream account compromise would substitute binary + sidecar together; trust is anchored on the upstream GitHub release"
            );
            return Ok(VerificationSource::Upstream);
        }
        Err(e) => {
            tracing::debug!(
                "no upstream checksum available for {}@{} ({}): {e}",
                def.name,
                version,
                platform_str,
            );
            // Fall through to override check.
        }
    }

    // 3. Override — only if the user explicitly accepted the risk.
    if allow_override {
        return Ok(VerificationSource::UnverifiedOverride);
    }

    Err(LpmError::Plugin(format!(
        "refusing to install {} {} for {}: no bundled checksum and upstream \
         sidecar {} is unavailable. Update LPM (newer releases ship \
         pinned checksums for newer plugin versions), pin a different \
         version, or set {}=1 to install without verification.",
        def.name, version, platform_str, upstream_url, ALLOW_UNVERIFIED_ENV,
    )))
}

/// Fetch and parse an upstream `<asset>.sha256` sidecar. Accepts both
/// the standard `sha256sum` line format (`<hex>  <filename>`) and a
/// bare-hex line. The body is capped at [`MAX_CHECKSUM_BODY_SIZE`].
async fn fetch_upstream_checksum(
    client: &reqwest::Client,
    sidecar_url: &str,
) -> Result<String, LpmError> {
    let resp = client
        .get(sidecar_url)
        .header("User-Agent", "lpm-cli")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "failed to fetch upstream checksum: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    if !resp.status().is_success() {
        return Err(LpmError::Http {
            status: resp.status().as_u16(),
            message: format!("upstream checksum {sidecar_url} returned {}", resp.status()),
        });
    }

    if let Some(len) = resp.content_length()
        && len > MAX_CHECKSUM_BODY_SIZE
    {
        return Err(LpmError::Plugin(format!(
            "upstream checksum body at {sidecar_url} is {len} bytes, max {MAX_CHECKSUM_BODY_SIZE}"
        )));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("failed to read checksum body: {e}")))?;

    if body.len() as u64 > MAX_CHECKSUM_BODY_SIZE {
        return Err(LpmError::Plugin(format!(
            "upstream checksum body at {sidecar_url} exceeds {MAX_CHECKSUM_BODY_SIZE} bytes"
        )));
    }

    let text = std::str::from_utf8(&body)
        .map_err(|e| LpmError::Plugin(format!("upstream checksum is not UTF-8: {e}")))?;

    parse_sha256_from_checksum_body(text).ok_or_else(|| {
        LpmError::Plugin(format!(
            "could not extract SHA-256 from upstream checksum body at {sidecar_url}"
        ))
    })
}

/// Extract the first lowercase 64-hex-char token from a checksum-file
/// body. Tolerant of either bare hex or `sha256sum` line format
/// (`<hex>  <filename>`). Rejects ambiguity: if multiple distinct
/// 64-hex-char tokens appear, returns `None` rather than guess.
fn parse_sha256_from_checksum_body(text: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for token in text.split_ascii_whitespace() {
        if is_lowercase_sha256_hex(token) {
            match &found {
                None => found = Some(token.to_string()),
                Some(prev) if prev == token => {}
                Some(_) => return None,
            }
        }
    }
    found
}

fn is_lowercase_sha256_hex(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Compute SHA-256 hex digest of data.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify that a computed checksum matches the expected value.
fn verify_checksum(plugin_name: &str, actual: &str, expected: &str) -> Result<(), LpmError> {
    if actual != expected {
        return Err(LpmError::Plugin(format!(
            "checksum mismatch for plugin '{}': expected {}, got {}",
            plugin_name, expected, actual
        )));
    }
    Ok(())
}

/// Validate download size is within limits.
fn validate_download_size(plugin_name: &str, size: usize) -> Result<(), LpmError> {
    if size > MAX_PLUGIN_DOWNLOAD_SIZE {
        return Err(LpmError::Plugin(format!(
            "plugin '{}' download size ({} bytes) exceeds maximum allowed size ({} bytes)",
            plugin_name, size, MAX_PLUGIN_DOWNLOAD_SIZE
        )));
    }
    Ok(())
}

/// Check if bytes start with ZIP magic number (PK\x03\x04).
fn is_zip_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04
}

/// Extract a specific binary from a .tar.gz archive.
fn extract_binary_from_tarball(
    data: &[u8],
    destination: &mut impl Write,
    binary_name: &str,
) -> Result<(), LpmError> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut found_files = Vec::new();
    let archive_limits = lpm_extractor::TarArchiveLimits {
        max_entry_bytes: MAX_PLUGIN_EXTRACTED_BYTES,
        ..lpm_extractor::TarArchiveLimits::new(MAX_PLUGIN_ARCHIVE_ENTRIES)
    };

    let (_, found) = lpm_extractor::visit_tar_archive(decoder, archive_limits, |mut entry| {
        let entry_size = entry.size();
        if entry_size > MAX_PLUGIN_EXTRACTED_BYTES {
            return Err(LpmError::Plugin(format!(
                "plugin archive entry size {entry_size} exceeds per-entry cap of {MAX_PLUGIN_EXTRACTED_BYTES} bytes"
            )));
        }

        let file_name = entry
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        found_files.push(file_name.clone());

        if entry.header().entry_type().is_file()
            && (file_name == binary_name || file_name.starts_with(&format!("{binary_name}-")))
        {
            let mut bounded = std::io::Read::take(&mut entry, MAX_PLUGIN_EXTRACTED_BYTES);
            let copied = std::io::copy(&mut bounded, destination)
                .map_err(|e| LpmError::Plugin(format!("failed to extract {binary_name}: {e}")))?;
            if copied >= MAX_PLUGIN_EXTRACTED_BYTES {
                return Err(LpmError::Plugin(format!(
                    "plugin archive entry expanded beyond {MAX_PLUGIN_EXTRACTED_BYTES} bytes",
                )));
            }
            return Ok(std::ops::ControlFlow::Break(()));
        }
        Ok(std::ops::ControlFlow::Continue(()))
    })?;

    if found.is_some() {
        return Ok(());
    }

    Err(LpmError::Plugin(format!(
        "binary '{}' not found in tar.gz archive. Found: [{}]",
        binary_name,
        found_files.join(", ")
    )))
}

/// Extract a specific binary from a .zip archive.
fn extract_binary_from_zip(
    data: &[u8],
    destination: &mut impl Write,
    binary_name: &str,
) -> Result<(), LpmError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| LpmError::Plugin(format!("failed to open ZIP archive: {e}")))?;

    if archive.len() > MAX_PLUGIN_ARCHIVE_ENTRIES {
        return Err(LpmError::Plugin(format!(
            "plugin ZIP archive exceeds {MAX_PLUGIN_ARCHIVE_ENTRIES} entries (declared {})",
            archive.len(),
        )));
    }

    let mut found_files = Vec::with_capacity(archive.len());
    let mut matched_index = None;
    let executable_name = format!("{binary_name}.exe");
    let versioned_prefix = format!("{binary_name}-");

    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| LpmError::Plugin(format!("failed to read ZIP entry: {e}")))?;

        let declared = entry.size();
        if declared > MAX_PLUGIN_EXTRACTED_BYTES {
            return Err(LpmError::Plugin(format!(
                "plugin ZIP entry size {declared} exceeds per-entry cap of {MAX_PLUGIN_EXTRACTED_BYTES} bytes"
            )));
        }

        let enclosed = entry.enclosed_name().ok_or_else(|| {
            LpmError::Plugin(format!(
                "path traversal detected in plugin ZIP entry: {}",
                entry.name()
            ))
        })?;
        if enclosed.components().count() > lpm_extractor::DEFAULT_MAX_ARCHIVE_PATH_DEPTH {
            return Err(LpmError::Plugin(format!(
                "plugin ZIP entry exceeds the {}-component nesting limit: {}",
                lpm_extractor::DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
                enclosed.display()
            )));
        }
        let file_name = enclosed
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        found_files.push(file_name.clone());

        let is_match = file_name == binary_name
            || file_name == executable_name
            || file_name.starts_with(&versioned_prefix);
        if matched_index.is_none() && is_match && !entry.is_dir() {
            matched_index = Some(i);
        }
    }

    let Some(matched_index) = matched_index else {
        return Err(LpmError::Plugin(format!(
            "binary '{}' not found in ZIP archive. Found: [{}]",
            binary_name,
            found_files.join(", ")
        )));
    };
    let mut entry = archive
        .by_index(matched_index)
        .map_err(|e| LpmError::Plugin(format!("failed to reopen ZIP entry: {e}")))?;
    let mut bounded = std::io::Read::take(&mut entry, MAX_PLUGIN_EXTRACTED_BYTES);
    let copied = std::io::copy(&mut bounded, destination)
        .map_err(|e| LpmError::Plugin(format!("failed to extract {binary_name} from ZIP: {e}")))?;
    if copied >= MAX_PLUGIN_EXTRACTED_BYTES {
        return Err(LpmError::Plugin(format!(
            "plugin ZIP entry expanded beyond {MAX_PLUGIN_EXTRACTED_BYTES} bytes",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_magic_detection() {
        assert!(is_zip_magic(&[0x50, 0x4b, 0x03, 0x04, 0x00]));
        assert!(!is_zip_magic(&[0x1f, 0x8b, 0x08, 0x00])); // gzip
        assert!(!is_zip_magic(&[0x00, 0x00])); // too short
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
    fn extract_from_tarball_lists_files_on_miss() {
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "some-other-file", &data[..])
            .unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let mut destination = Vec::new();
        let err = extract_binary_from_tarball(&gz_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found in tar.gz archive"), "error: {msg}");
        assert!(
            msg.contains("some-other-file"),
            "should list found files: {msg}"
        );
    }

    #[test]
    fn extract_from_zip_lists_files_on_miss() {
        let buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("readme.txt", options).unwrap();
        std::io::Write::write_all(&mut writer, b"hello").unwrap();
        let buf = writer.finish().unwrap();
        let zip_data = buf.into_inner();

        let mut destination = Vec::new();
        let err = extract_binary_from_zip(&zip_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found in ZIP archive"), "error: {msg}");
        assert!(msg.contains("readme.txt"), "should list found files: {msg}");
    }

    // --- Checksum verification ---

    #[test]
    fn checksum_match_succeeds() {
        assert!(verify_checksum("test", "abc123", "abc123").is_ok());
    }

    #[test]
    fn checksum_mismatch_fails() {
        let err = verify_checksum("test", "actual_hash", "expected_hash").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("checksum mismatch"), "error: {msg}");
        assert!(msg.contains("expected_hash"), "error: {msg}");
        assert!(msg.contains("actual_hash"), "error: {msg}");
    }

    // --- Download size limit ---

    #[test]
    fn size_within_limit_succeeds() {
        assert!(validate_download_size("test", 1024).is_ok());
        assert!(validate_download_size("test", MAX_PLUGIN_DOWNLOAD_SIZE).is_ok());
    }

    #[test]
    fn size_exceeds_limit_fails() {
        let err = validate_download_size("test", MAX_PLUGIN_DOWNLOAD_SIZE + 1).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds maximum"), "error: {msg}");
    }

    /// A tarball whose entry header declares a per-entry size above
    /// the cap is refused before any bytes are unpacked.
    #[test]
    fn tarball_extraction_rejects_per_entry_over_cap() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        // Declare a size that exceeds the cap. The data stream is
        // intentionally short — the cap check fires on `entry.size()`
        // before any `copy` happens.
        header.set_size(MAX_PLUGIN_EXTRACTED_BYTES + 1);
        header.set_cksum();
        builder.append_data(&mut header, "oxlint", &[][..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let mut destination = Vec::new();
        let err = extract_binary_from_tarball(&gz_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds per-entry cap"),
            "must refuse with per-entry cap: {msg}"
        );
        assert!(destination.is_empty(), "no partial extract on refusal");
    }

    /// A tarball with too many entries is refused before any entry is
    /// unpacked.
    #[test]
    fn tarball_extraction_rejects_excessive_entry_count() {
        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..(MAX_PLUGIN_ARCHIVE_ENTRIES + 1) {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("f-{i}"), &[][..])
                .unwrap();
        }
        let tar_data = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let mut destination = Vec::new();
        let err = extract_binary_from_tarball(&gz_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds") && msg.contains("entry"),
            "must label entry-count overflow: {msg}"
        );
    }

    #[test]
    fn tarball_extraction_rejects_paths_deeper_than_256_components() {
        let mut path = "a/".repeat(256);
        path.push_str("oxlint");
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, &path, &b"value"[..])
            .unwrap();
        let tar_data = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar_data).unwrap();
        let archive = encoder.finish().unwrap();
        let mut destination = Vec::new();

        let error = extract_binary_from_tarball(&archive, &mut destination, "oxlint")
            .expect_err("an excessively deep plugin archive path must be rejected");

        assert!(
            error.to_string().contains("nesting"),
            "expected nesting-depth limit error, got: {error}"
        );
        assert!(destination.is_empty(), "rejected archive wrote a binary");
    }

    #[test]
    fn zip_extraction_rejects_path_traversal() {
        let root = tempfile::tempdir().unwrap();
        let mut destination = Vec::new();
        let buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        writer
            .start_file("../oxlint", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut writer, b"pwned").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let err = extract_binary_from_zip(&zip_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("path traversal"),
            "zip traversal rejection should be explicit: {msg}"
        );
        assert!(
            destination.is_empty(),
            "no binary should be extracted on refusal"
        );
        assert!(
            !root.path().join("oxlint").exists(),
            "zip traversal must not write outside the destination"
        );
    }

    #[test]
    fn zip_extraction_rejects_paths_deeper_than_256_components() {
        let mut path = "a/".repeat(256);
        path.push_str("oxlint");
        let buffer = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buffer);
        writer
            .start_file(&path, zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut writer, b"value").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let mut destination = Vec::new();

        let error = extract_binary_from_zip(&archive, &mut destination, "oxlint")
            .expect_err("an excessively deep plugin ZIP path must be rejected");

        assert!(
            error.to_string().contains("nesting"),
            "expected nesting-depth limit error, got: {error}"
        );
        assert!(destination.is_empty(), "rejected archive wrote a binary");
    }

    #[test]
    fn zip_extraction_validates_trailing_paths_before_writing_binary() {
        let mut deep_path = "a/".repeat(256);
        deep_path.push_str("other");
        let buffer = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buffer);
        writer
            .start_file("oxlint", zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut writer, b"value").unwrap();
        writer
            .start_file(&deep_path, zip::write::SimpleFileOptions::default())
            .unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let mut destination = Vec::new();

        let error = extract_binary_from_zip(&archive, &mut destination, "oxlint")
            .expect_err("a trailing deep ZIP path must reject the archive");

        assert!(
            error.to_string().contains("nesting"),
            "expected nesting-depth limit error, got: {error}"
        );
        assert!(destination.is_empty(), "rejected archive wrote a binary");
    }

    #[test]
    fn zip_extraction_rejects_excessive_entry_count() {
        let buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let options = zip::write::SimpleFileOptions::default();
        for i in 0..(MAX_PLUGIN_ARCHIVE_ENTRIES + 1) {
            writer.start_file(format!("f-{i}"), options).unwrap();
        }
        let zip_data = writer.finish().unwrap().into_inner();

        let mut destination = Vec::new();
        let err = extract_binary_from_zip(&zip_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds") && msg.contains("entries"),
            "must label ZIP entry-count overflow: {msg}"
        );
    }

    /// ZIP entry declaring oversized payload is rejected on the same
    /// cap as the tar path.
    #[test]
    fn zip_extraction_rejects_per_entry_over_cap() {
        let zip_data =
            forged_zip_with_declared_file("oxlint", (MAX_PLUGIN_EXTRACTED_BYTES + 1) as u32);

        let mut destination = Vec::new();
        let err = extract_binary_from_zip(&zip_data, &mut destination, "oxlint").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("per-entry cap"),
            "must refuse with per-entry cap: {msg}"
        );
        assert!(destination.is_empty(), "no partial extract on refusal");
    }

    // --- SHA-256 computation ---

    #[test]
    fn compute_sha256_deterministic() {
        let hash1 = compute_sha256(b"hello world");
        let hash2 = compute_sha256(b"hello world");
        assert_eq!(hash1, hash2);
        assert_eq!(
            hash1,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn compute_sha256_different_inputs() {
        let hash1 = compute_sha256(b"hello");
        let hash2 = compute_sha256(b"world");
        assert_ne!(hash1, hash2);
    }

    // --- Upstream checksum body parsing ---

    #[test]
    fn parses_bare_hex_line() {
        let body = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9\n";
        assert_eq!(
            parse_sha256_from_checksum_body(body),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".into())
        );
    }

    #[test]
    fn parses_sha256sum_format() {
        let body = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  oxlint-x86_64-apple-darwin.tar.gz\n";
        assert_eq!(
            parse_sha256_from_checksum_body(body),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".into())
        );
    }

    #[test]
    fn parses_with_leading_whitespace() {
        let body = "   b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9   ";
        assert!(parse_sha256_from_checksum_body(body).is_some());
    }

    #[test]
    fn rejects_uppercase_hex() {
        // We hash and store lowercase; tolerating uppercase would let
        // two domains diverge silently.
        let body = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        assert_eq!(parse_sha256_from_checksum_body(body), None);
    }

    #[test]
    fn rejects_short_hex() {
        let body = "abc123";
        assert_eq!(parse_sha256_from_checksum_body(body), None);
    }

    #[test]
    fn rejects_no_hex() {
        let body = "Release notes go here. No checksum.";
        assert_eq!(parse_sha256_from_checksum_body(body), None);
    }

    #[test]
    fn rejects_ambiguous_multiple_distinct_hashes() {
        // Two different 64-hex-char tokens — refuse rather than guess.
        let body = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  one
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  two";
        assert_eq!(parse_sha256_from_checksum_body(body), None);
    }

    #[test]
    fn accepts_repeated_identical_hashes() {
        // Some sidecars include the hash twice (algorithm header line).
        let body = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  asset.tar.gz";
        assert_eq!(
            parse_sha256_from_checksum_body(body),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into())
        );
    }

    // --- Verification decision (resolve_verification + fetch_upstream_checksum) ---

    fn make_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn test_def() -> PluginDef {
        PluginDef {
            name: "testplug",
            binary_name: "testbin",
            latest_version: "1.0.0",
            url_template: "https://example.test/{version}/{platform}",
            platform_map: &[("test-arch", "asset.bin")],
            is_archive: false,
            checksums: &[(
                "test-arch",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        }
    }

    #[tokio::test]
    async fn bundled_path_used_when_version_matches_latest() {
        // No HTTP server needed — bundled checksum should be hit
        // before any upstream fetch is attempted.
        let def = test_def();
        let client = make_test_client();
        let asset_url = "https://nonexistent.invalid/1.0.0/asset.bin";
        let actual = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let result = resolve_verification(
            &def,
            "1.0.0",
            "test-arch",
            asset_url,
            actual,
            &client,
            false,
        )
        .await;
        assert!(matches!(result, Ok(VerificationSource::Bundled)));
    }

    #[tokio::test]
    async fn bundled_path_rejects_mismatched_hash() {
        let def = test_def();
        let client = make_test_client();
        let asset_url = "https://nonexistent.invalid/1.0.0/asset.bin";
        let wrong = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let err =
            resolve_verification(&def, "1.0.0", "test-arch", asset_url, wrong, &client, false)
                .await
                .unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[tokio::test]
    async fn upstream_path_used_for_pinned_non_latest_version() {
        let mock = wiremock::MockServer::start().await;

        let actual = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/0.9.0/asset.bin.sha256"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("{actual}  asset.bin\n")),
            )
            .mount(&mock)
            .await;

        let def = test_def();
        let client = make_test_client();
        let asset_url = format!("{}/0.9.0/asset.bin", mock.uri());

        let result = resolve_verification(
            &def,
            "0.9.0",
            "test-arch",
            &asset_url,
            actual,
            &client,
            false,
        )
        .await;
        assert!(
            matches!(result, Ok(VerificationSource::Upstream)),
            "expected Upstream, got {result:?}"
        );
    }

    #[tokio::test]
    async fn upstream_path_rejects_mismatched_hash() {
        let mock = wiremock::MockServer::start().await;

        let upstream_says = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/0.9.0/asset.bin.sha256"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(upstream_says))
            .mount(&mock)
            .await;

        let def = test_def();
        let client = make_test_client();
        let asset_url = format!("{}/0.9.0/asset.bin", mock.uri());
        let actual = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let err = resolve_verification(
            &def,
            "0.9.0",
            "test-arch",
            &asset_url,
            actual,
            &client,
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[tokio::test]
    async fn no_upstream_no_override_fails_closed() {
        let mock = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/0.9.0/asset.bin.sha256"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let def = test_def();
        let client = make_test_client();
        let asset_url = format!("{}/0.9.0/asset.bin", mock.uri());
        let actual = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let err = resolve_verification(
            &def,
            "0.9.0",
            "test-arch",
            &asset_url,
            actual,
            &client,
            false,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to install"), "msg: {msg}");
        assert!(msg.contains(ALLOW_UNVERIFIED_ENV), "msg: {msg}");
    }

    #[tokio::test]
    async fn no_upstream_with_override_records_unverified() {
        let mock = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/0.9.0/asset.bin.sha256"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let def = test_def();
        let client = make_test_client();
        let asset_url = format!("{}/0.9.0/asset.bin", mock.uri());
        let actual = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let result = resolve_verification(
            &def,
            "0.9.0",
            "test-arch",
            &asset_url,
            actual,
            &client,
            true,
        )
        .await;
        assert!(
            matches!(result, Ok(VerificationSource::UnverifiedOverride)),
            "expected UnverifiedOverride, got {result:?}"
        );
    }

    #[tokio::test]
    async fn upstream_body_too_large_fails_closed() {
        let mock = wiremock::MockServer::start().await;

        // Body well over 4 KB cap.
        let body = "a".repeat(5000);
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/0.9.0/asset.bin.sha256"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(body))
            .mount(&mock)
            .await;

        let def = test_def();
        let client = make_test_client();
        let asset_url = format!("{}/0.9.0/asset.bin", mock.uri());
        let actual = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let err = resolve_verification(
            &def,
            "0.9.0",
            "test-arch",
            &asset_url,
            actual,
            &client,
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("refusing to install"));
    }

    #[test]
    fn allow_unverified_env_parses_truthy_values() {
        // `serial_test`-free: scope mutations to this thread, then revert.
        let key = ALLOW_UNVERIFIED_ENV;
        let prior = std::env::var(key).ok();

        // SAFETY: tests in this crate set this env var only here and do not
        // race with other env-mutating tests in the same process.
        unsafe {
            std::env::set_var(key, "1");
        }
        assert!(allow_unverified_override());
        unsafe {
            std::env::set_var(key, "true");
        }
        assert!(allow_unverified_override());
        unsafe {
            std::env::set_var(key, "TRUE");
        }
        assert!(allow_unverified_override());
        unsafe {
            std::env::set_var(key, "0");
        }
        assert!(!allow_unverified_override());
        unsafe {
            std::env::set_var(key, "false");
        }
        assert!(!allow_unverified_override());
        unsafe {
            std::env::remove_var(key);
        }
        assert!(!allow_unverified_override());

        // Revert to pre-test state.
        match prior {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }
}
