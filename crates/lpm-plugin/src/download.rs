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
//! Downloads use atomic writes: binary is written to a `.tmp` file
//! first, then renamed to the final path. The sidecar is written
//! atomically AFTER the binary rename so a half-installed binary is
//! never paired with a sidecar declaring it valid.

use crate::registry::{self, PluginDef};
use crate::sidecar::{self, Sidecar, VerificationSource};
use crate::store;
use lpm_common::LpmError;
use lpm_runtime::platform::Platform;
use sha2::{Digest, Sha256};

/// Maximum download size: 150 MB. 3x safety margin over largest known plugin (~50 MB biome).
const MAX_PLUGIN_DOWNLOAD_SIZE: usize = 150 * 1024 * 1024;

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
    std::env::var(ALLOW_UNVERIFIED_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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
) -> Result<(), LpmError> {
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let resp = client
        .get(&url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to download {}: {e}", def.name)))?;

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
    let tmp_path = platform_dir.join(format!(".{}.{}.tmp", def.binary_name, std::process::id()));
    let _ = std::fs::remove_file(&tmp_path);

    let extract_result = if def.is_archive {
        if asset_name.ends_with(".zip") || is_zip_magic(&bytes) {
            extract_binary_from_zip(&bytes, &tmp_path, def.binary_name)
        } else {
            extract_binary_from_tarball(&bytes, &tmp_path, def.binary_name)
        }
    } else {
        std::fs::write(&tmp_path, &bytes)
            .map_err(|e| LpmError::Plugin(format!("failed to write plugin binary: {e}")))
    };

    if let Err(e) = extract_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Compute on-disk binary hash before the rename so we can record
    // it on the sidecar. For non-archive plugins this matches
    // `asset_sha256`; for archive plugins it differs.
    let binary_sha256 = match sidecar::hash_file(&tmp_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(LpmError::Plugin(format!(
                "failed to hash extracted binary: {e}"
            )));
        }
    };

    std::fs::rename(&tmp_path, &bin_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        LpmError::Plugin(format!("failed to finalize plugin binary: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // --- Write sidecar AFTER binary rename succeeds ---
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
    );
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

    Ok(())
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
    let upstream_url = format!("{asset_url}.sha256");
    match fetch_upstream_checksum(client, &upstream_url).await {
        Ok(expected) => {
            verify_checksum(def.name, actual_sha256, &expected)?;
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
                "failed to fetch upstream checksum from {sidecar_url}: {e}"
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
    dest_path: &std::path::Path,
    binary_name: &str,
) -> Result<(), LpmError> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    let mut found_files = Vec::new();

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Plugin(format!("failed to read plugin archive: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| LpmError::Plugin(format!("failed to read archive entry: {e}")))?;

        let path = entry
            .path()
            .map_err(|e| LpmError::Plugin(format!("failed to read entry path: {e}")))?;

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        found_files.push(file_name.clone());

        if file_name == binary_name || file_name.starts_with(&format!("{binary_name}-")) {
            let mut output = std::fs::File::create(dest_path)?;
            std::io::copy(&mut entry, &mut output)
                .map_err(|e| LpmError::Plugin(format!("failed to extract {binary_name}: {e}")))?;
            return Ok(());
        }
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
    dest_path: &std::path::Path,
    binary_name: &str,
) -> Result<(), LpmError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| LpmError::Plugin(format!("failed to open ZIP archive: {e}")))?;

    let mut found_files = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| LpmError::Plugin(format!("failed to read ZIP entry: {e}")))?;

        let file_name = entry
            .enclosed_name()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();

        found_files.push(file_name.clone());

        let is_match = file_name == binary_name
            || file_name == format!("{binary_name}.exe")
            || file_name.starts_with(&format!("{binary_name}-"));

        if is_match && !entry.is_dir() {
            let mut output = std::fs::File::create(dest_path)?;
            std::io::copy(&mut entry, &mut output).map_err(|e| {
                LpmError::Plugin(format!("failed to extract {binary_name} from ZIP: {e}"))
            })?;
            return Ok(());
        }
    }

    Err(LpmError::Plugin(format!(
        "binary '{}' not found in ZIP archive. Found: [{}]",
        binary_name,
        found_files.join(", ")
    )))
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

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("binary");
        let err = extract_binary_from_tarball(&gz_data, &dest, "oxlint").unwrap_err();
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

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("binary");
        let err = extract_binary_from_zip(&zip_data, &dest, "oxlint").unwrap_err();
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

    // --- Unique temp file names ---

    #[test]
    fn temp_file_name_contains_pid() {
        let pid = std::process::id();
        let tmp_name = format!(".oxlint.{}.tmp", pid);
        assert!(tmp_name.contains(&pid.to_string()));
        assert_ne!(tmp_name, ".oxlint.tmp");
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
