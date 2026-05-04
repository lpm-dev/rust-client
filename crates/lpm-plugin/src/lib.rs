//! Plugin management for LPM — lazy-download external tool binaries.
//!
//! Plugins are stored globally at `~/.lpm/plugins/{name}/{version}/{platform}/`.
//! Per-project version pinning via `lpm.json` `tools` section.
//!
//! ```text
//! ~/.lpm/plugins/
//!   oxlint/
//!     1.58.0/
//!       darwin-arm64/
//!         oxlint               ← downloaded binary
//!         .lpm-plugin.json     ← sidecar (verification metadata)
//!   biome/
//!     2.4.10/
//!       linux-x64/
//!         biome
//!         .lpm-plugin.json
//!   .version-cache.json        ← approved-version cache (sticky)
//! ```
//!
//! ## Verification
//!
//! Every install is checksum-verified against either a SHA-256 bundled
//! with the LPM binary (for the registry's pinned `latest_version`) or
//! the upstream sidecar at `<asset_url>.sha256` (for any other version,
//! including user-pinned and `lpm plugin update` pulls). Reuse from
//! cache is gated on a sidecar metadata file that re-verifies platform
//! match, on-disk binary integrity, and the trust posture of the
//! current process. Set `LPM_ALLOW_UNVERIFIED_PLUGINS=1` to skip
//! verification — that flag must be set on every reuse, by design.
//!
//! ## Update flow
//!
//! `lpm plugin update` follows a strict peek → install → approve
//! sequence. The version is only persisted in the install-selection
//! cache after a successful verified install, so a transient missing
//! upstream `.sha256`, parse failure, or download failure cannot
//! poison the cache and route every subsequent invocation down a
//! permanently-failing install path.

pub mod download;
pub mod registry;
pub mod sidecar;
pub mod store;
pub mod versions;

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Ensure a plugin is installed for the current platform and return
/// the path to its binary.
///
/// Version resolution:
///   1. If `pinned_version` is provided (from `lpm.json` tools), uses that exact version.
///   2. Otherwise uses `max(hardcoded, approved-cache)` — the hardcoded
///      version from the registry (always verified) or a newer version
///      from a successful past `lpm plugin update`.
///
/// Reuse is gated on the sidecar metadata file, not on bare file
/// existence. Anything that fails the sidecar check (legacy unscoped
/// layout, missing/tampered binary, mismatched platform, retired
/// schema, unverified-override sidecar without the env var set) is
/// treated as a cache miss and re-installed via the full
/// download-and-verify pipeline.
///
/// Set `LPM_FORCE_TOOL_INSTALL=1` to force re-download even on a
/// healthy cache hit (useful for recovering from corrupted installs).
pub async fn ensure_plugin(
    plugin_name: &str,
    pinned_version: Option<&str>,
    auto_download: bool,
) -> Result<PathBuf, LpmError> {
    let def = registry::get_plugin(plugin_name)
        .ok_or_else(|| LpmError::Plugin(format!("unknown plugin: '{plugin_name}'")))?;

    let version = match pinned_version {
        Some(v) => v.to_string(),
        None => versions::get_latest_version(def).await,
    };

    let platform = lpm_runtime::platform::Platform::current()?;
    let platform_str = platform.to_string();

    let force = std::env::var("LPM_FORCE_TOOL_INSTALL")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let bin_path = store::plugin_binary_path(def.name, &version, &platform_str, def.binary_name)?;
    let sidecar_path = store::plugin_sidecar_path(def.name, &version, &platform_str)?;

    // First (unlocked) cache check — the steady-state hot path. Most
    // ensure_plugin calls land here without ever touching the install lock.
    if !force
        && let sidecar::ReuseDecision::Hit = sidecar::validate_for_reuse(
            &sidecar_path,
            &bin_path,
            def.name,
            &version,
            &platform_str,
            download::allow_unverified_override(),
        )
    {
        tracing::debug!("plugin {plugin_name}@{version} ({platform_str}) reused from cache");
        return Ok(bin_path);
    }

    // Cache miss (or forced) — delegate to the shared locked-install
    // helper. Acquires the per-version install lock, re-validates the
    // cache (sibling installer may have populated it while we waited),
    // and only downloads if the second check still misses.
    install_under_lock(def, &version, &platform, plugin_name, force, auto_download).await
}

/// Acquire the per-version install lock and run the install body. The
/// shared entry point used by both [`ensure_plugin`] and [`update_plugin`]
/// so the post-lock revalidation contract is identical for both — without
/// this helper, `update_plugin` would re-download a binary that a sibling
/// `ensure_plugin` had already installed, which on Windows can outright
/// fail (`download::finalize` uses `rename` onto the real path; renaming
/// over a binary that's currently open by the parallel installer's verify
/// step errors out with `OS error 32` / "file in use").
///
/// Without the lock, two parallel installers of the same {name, version}
/// would race on the atomic rename in `download_plugin` and the loser
/// would see a "binary already exists" / sidecar mismatch error.
async fn install_under_lock(
    def: &registry::PluginDef,
    version: &str,
    platform: &lpm_runtime::platform::Platform,
    plugin_name: &str,
    force: bool,
    auto_download: bool,
) -> Result<PathBuf, LpmError> {
    let platform_str = platform.to_string();
    let bin_path = store::plugin_binary_path(def.name, version, &platform_str, def.binary_name)?;
    let sidecar_path = store::plugin_sidecar_path(def.name, version, &platform_str)?;
    let lock_path = store::plugin_install_lock_path(def.name, version)?;

    let body = run_install_locked_body(
        def,
        version,
        platform,
        &platform_str,
        &bin_path,
        &sidecar_path,
        plugin_name,
        force,
        auto_download,
    );
    lpm_common::with_exclusive_lock_async(lock_path, body).await
}

/// The locked install body. Re-validates the cache after acquiring the
/// lock (a sibling installer may have populated it while we waited), and
/// only emits the user-facing "Downloading..." banner after the
/// re-validation confirms we're actually going to download something.
#[allow(clippy::too_many_arguments)]
async fn run_install_locked_body(
    def: &registry::PluginDef,
    version: &str,
    platform: &lpm_runtime::platform::Platform,
    platform_str: &str,
    bin_path: &Path,
    sidecar_path: &Path,
    plugin_name: &str,
    force: bool,
    auto_download: bool,
) -> Result<PathBuf, LpmError> {
    // Double-checked locking: another process may have completed the
    // install while we were waiting on the lock. Return the now-valid
    // cache hit instead of re-downloading.
    if !force
        && let sidecar::ReuseDecision::Hit = sidecar::validate_for_reuse(
            sidecar_path,
            bin_path,
            def.name,
            version,
            platform_str,
            download::allow_unverified_override(),
        )
    {
        tracing::debug!(
            "plugin {plugin_name}@{version} ({platform_str}) populated by sibling install while we waited"
        );
        return Ok(bin_path.to_path_buf());
    }

    if force && bin_path.exists() {
        tracing::debug!("force reinstalling plugin {plugin_name}@{version} ({platform_str})");
        let _ = std::fs::remove_file(bin_path);
        let _ = std::fs::remove_file(sidecar_path);
    }

    let env_auto = std::env::var("LPM_AUTO_DOWNLOAD")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !auto_download && !env_auto {
        eprintln!(
            "  Plugin '{}' not installed. Downloading {} v{} ({})...",
            plugin_name, def.binary_name, version, platform_str,
        );
    }

    download::download_plugin(def, version, platform).await?;

    if bin_path.exists() {
        Ok(bin_path.to_path_buf())
    } else {
        if let Ok(platform_dir) = store::plugin_platform_dir(def.name, version, platform_str) {
            let _ = std::fs::remove_dir_all(&platform_dir);
        }
        Err(LpmError::Plugin(format!(
            "plugin {plugin_name}@{version} downloaded but binary not found at {}. \
             The platform directory has been cleaned. Try again or check the plugin version.",
            bin_path.display()
        )))
    }
}

/// Update a plugin to the latest version GitHub currently lists.
///
/// Strict ordering: peek upstream, then download-and-verify, then —
/// only on success — persist the resolved version to the
/// install-selection cache via [`versions::approve_version`]. A failed
/// install never poisons the cache.
///
/// If the upstream peek itself fails (network error, GitHub rate
/// limit, etc.), falls back to the currently-resolved version
/// (`max(hardcoded, approved-cache)`) and re-runs verification on it
/// — same effect as a no-op when the binary is already on disk.
///
/// Verification is identical to `ensure_plugin` — bundled checksum if
/// available, otherwise upstream sidecar, otherwise refuse unless
/// `LPM_ALLOW_UNVERIFIED_PLUGINS=1`.
pub async fn update_plugin(plugin_name: &str) -> Result<String, LpmError> {
    let def = registry::get_plugin(plugin_name)
        .ok_or_else(|| LpmError::Plugin(format!("unknown plugin: '{plugin_name}'")))?;

    // Per-name update lock around the whole peek → install → approve
    // sequence. Per-version install locks (used by `ensure_plugin`'s
    // install branch) are insufficient here because the cache write
    // happens on the resolved version — two concurrent updates of the
    // same plugin to different upstream versions could otherwise
    // interleave their `approve_version` writes and downgrade each
    // other's resolved version. The per-name scope makes the entire
    // resolve-and-record atomic for that plugin.
    let lock_path = store::plugin_update_lock_path(def.name)?;
    lpm_common::with_exclusive_lock_async(lock_path, run_update_under_lock(def)).await
}

async fn run_update_under_lock(def: &registry::PluginDef) -> Result<String, LpmError> {
    let target = match versions::peek_latest_from_github(def).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "  \x1b[33m⚠\x1b[0m Failed to check for {} updates: {e}",
                def.name,
            );
            // Fall back to the already-resolved version. Re-running
            // ensure-style verification on the existing binary is a
            // no-op when it's already healthy on disk.
            versions::get_latest_version(def).await
        }
    };

    let platform = lpm_runtime::platform::Platform::current()?;

    // Route through the shared `install_under_lock` so the post-lock
    // revalidation contract is identical to `ensure_plugin`'s. Without
    // routing through the same helper, a sibling `ensure_plugin` could
    // populate the cache for `{def.name, target}` between an inline
    // pre-check here and the lock acquisition, and `update_plugin`
    // would re-download wastefully (or, on Windows, fail outright on
    // the rename when the parallel installer has the binary open).
    //
    // `auto_download = true` so the locked body's "Downloading..."
    // banner doesn't fire — `lpm plugin update` is an explicit
    // user-initiated install and the command's own surface owns the
    // user-facing progress text.
    install_under_lock(def, &target, &platform, def.name, false, true).await?;

    // Install succeeded (or the locked body short-circuited on a
    // valid cache hit) — only NOW persist the cache. A download or
    // verification failure above returns Err and the cache is not
    // touched, so the next invocation falls back to whatever was
    // approved before (or the bundled latest_version if nothing was).
    //
    // Cache-write failure must propagate: the install is on disk, but
    // without a cache update unpinned ensure_plugin still resolves to
    // the older approved version. That's a partial failure the user
    // needs to see — `Err` reports it; the binary stays in the store
    // and a follow-up `lpm plugin update` will retry the approval.
    versions::approve_version(def.name, &target)?;

    Ok(target)
}

/// Find the newest installed version of a plugin whose binary is
/// **trusted** for use on the current platform. Returns
/// `(version, binary_path)` on hit.
///
/// Trust is determined by [`sidecar::validate_for_reuse`] — the same
/// gate `ensure_plugin` runs. A version is skipped if its sidecar is
/// missing, malformed, schema-mismatched, identity-mismatched, marked
/// `unverified-override` without `LPM_ALLOW_UNVERIFIED_PLUGINS=1` set
/// in the current process, or if the on-disk binary's SHA-256 doesn't
/// match what the sidecar recorded. Bare-binary existence is not
/// enough — invoking an untrusted plugin binary from `lpm doctor` (the
/// primary caller) would undercut the verification model.
///
/// Picking `list_installed_versions().first()` would also be wrong for
/// two unrelated reasons: (1) it sorts lexicographically (so `1.10.0`
/// ranks below `1.2.0`), and (2) the alphabetically-first version may
/// not have a binary for the current platform under the
/// platform-scoped layout.
pub fn find_installed_for_current_platform(
    plugin_name: &str,
    binary_name: &str,
) -> Option<(String, PathBuf)> {
    let plugins_root = store::plugins_dir().ok()?;
    let platform = lpm_runtime::platform::Platform::current().ok()?.to_string();
    find_installed_for_current_platform_at(
        &plugins_root,
        plugin_name,
        binary_name,
        &platform,
        download::allow_unverified_override(),
    )
}

/// Path-injected variant of [`find_installed_for_current_platform`] for
/// unit testing without env var manipulation.
fn find_installed_for_current_platform_at(
    plugins_root: &Path,
    plugin_name: &str,
    binary_name: &str,
    platform: &str,
    allow_unverified_override: bool,
) -> Option<(String, PathBuf)> {
    let plugin_dir = plugins_root.join(plugin_name);
    if !plugin_dir.exists() {
        return None;
    }

    let mut versions: Vec<String> = std::fs::read_dir(&plugin_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    // Sort newest-first by best-effort semver.
    versions.sort_by(|a, b| {
        if versions::is_newer_semver(a, b) {
            std::cmp::Ordering::Less
        } else if versions::is_newer_semver(b, a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });

    for v in versions {
        let platform_dir = plugin_dir.join(&v).join(platform);
        let bin = platform_dir.join(binary_name);
        let sidecar_path = platform_dir.join(sidecar::SIDECAR_FILE_NAME);
        if matches!(
            sidecar::validate_for_reuse(
                &sidecar_path,
                &bin,
                plugin_name,
                &v,
                platform,
                allow_unverified_override,
            ),
            sidecar::ReuseDecision::Hit,
        ) {
            return Some((v, bin));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Install a fake plugin binary + valid sidecar at the requested
    /// path. Mirrors what `download_plugin` would write after a
    /// successful verified install. Returns the binary path.
    fn install_fake(
        root: &Path,
        plugin: &str,
        version: &str,
        platform: &str,
        binary: &str,
        source: sidecar::VerificationSource,
    ) -> PathBuf {
        let dir = root.join(plugin).join(version).join(platform);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join(binary);
        let bytes = format!("fake {plugin} {version} {platform} bytes");
        std::fs::write(&bin, bytes.as_bytes()).unwrap();

        let hash = format!("{:x}", Sha256::digest(bytes.as_bytes()));
        let s = sidecar::Sidecar::new(
            plugin,
            version,
            platform,
            "fake-asset.bin",
            "https://example.test/fake-asset.bin",
            &hash,
            &hash,
            source,
        );
        sidecar::write_atomic(&dir.join(sidecar::SIDECAR_FILE_NAME), &s).unwrap();
        bin
    }

    /// Install a binary WITHOUT a sidecar — simulates the legacy
    /// pre-verification layout that should now be treated as untrusted.
    fn install_bare_binary(
        root: &Path,
        plugin: &str,
        version: &str,
        platform: &str,
        binary: &str,
    ) -> PathBuf {
        let dir = root.join(plugin).join(version).join(platform);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join(binary);
        std::fs::write(&bin, b"untrusted bytes").unwrap();
        bin
    }

    #[test]
    fn find_installed_returns_none_when_plugin_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_installed_for_current_platform_at(
            dir.path(),
            "oxlint",
            "oxlint",
            "darwin-arm64",
            false,
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_installed_returns_none_when_no_versions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("oxlint")).unwrap();
        let result = find_installed_for_current_platform_at(
            dir.path(),
            "oxlint",
            "oxlint",
            "darwin-arm64",
            false,
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_installed_picks_newest_when_all_have_current_platform() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for v in &["1.57.0", "1.58.0", "1.59.0"] {
            install_fake(
                root,
                "oxlint",
                v,
                "darwin-arm64",
                "oxlint",
                sidecar::VerificationSource::Bundled,
            );
        }

        let (version, _path) =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false)
                .unwrap();
        assert_eq!(version, "1.59.0");
    }

    #[test]
    fn find_installed_uses_semver_sort_not_lexicographic() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Lexicographic order would pick 1.2.0 over 1.10.0.
        for v in &["1.2.0", "1.10.0"] {
            install_fake(
                root,
                "oxlint",
                v,
                "darwin-arm64",
                "oxlint",
                sidecar::VerificationSource::Bundled,
            );
        }

        let (version, _path) =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false)
                .unwrap();
        assert_eq!(
            version, "1.10.0",
            "should pick semver-newest, not lex-newest"
        );
    }

    #[test]
    fn find_installed_skips_versions_missing_current_platform() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Newest version only has linux-x64; older versions have darwin-arm64.
        install_fake(
            root,
            "oxlint",
            "1.59.0",
            "linux-x64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );
        install_fake(
            root,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );
        install_fake(
            root,
            "oxlint",
            "1.57.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );

        let (version, path) =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false)
                .unwrap();
        assert_eq!(version, "1.58.0");
        assert!(path.ends_with("oxlint/1.58.0/darwin-arm64/oxlint"));
    }

    #[test]
    fn find_installed_returns_none_when_no_version_has_current_platform() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        install_fake(
            root,
            "oxlint",
            "1.59.0",
            "linux-x64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );
        install_fake(
            root,
            "oxlint",
            "1.58.0",
            "linux-arm64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );

        let result =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false);
        assert!(result.is_none());
    }

    // --- Sidecar trust gating ---

    #[test]
    fn find_installed_skips_bare_binary_without_sidecar() {
        // Pre-sidecar layout (or any binary written without going
        // through download_plugin) is not trusted — doctor must not
        // exec it. Without a fallback, the result is None.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        install_bare_binary(root, "oxlint", "1.58.0", "darwin-arm64", "oxlint");

        let result =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false);
        assert!(
            result.is_none(),
            "a bare binary with no sidecar must not be considered trusted"
        );
    }

    #[test]
    fn find_installed_falls_back_to_older_when_newest_lacks_sidecar() {
        // Newest version has no sidecar (e.g., a partially-completed
        // install or an older legacy install). Older verified version
        // exists. find_installed must skip the untrusted candidate
        // and fall back to the trusted one.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        install_bare_binary(root, "oxlint", "1.59.0", "darwin-arm64", "oxlint");
        install_fake(
            root,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );

        let (version, _path) =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false)
                .unwrap();
        assert_eq!(
            version, "1.58.0",
            "must skip the untrusted newer install and pick the trusted older one"
        );
    }

    #[test]
    fn find_installed_skips_tampered_binary() {
        // Sidecar is valid but the binary on disk has been replaced
        // since install. validate_for_reuse catches this.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let bin = install_fake(
            root,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::Bundled,
        );
        // Tamper after the sidecar is written.
        std::fs::write(&bin, b"swapped contents").unwrap();

        let result =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false);
        assert!(
            result.is_none(),
            "binary tampered after install must not be considered trusted"
        );
    }

    #[test]
    fn find_installed_skips_unverified_override_without_env() {
        // User installed under LPM_ALLOW_UNVERIFIED_PLUGINS=1 once.
        // Doctor running without the env var must NOT exec it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        install_fake(
            root,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::UnverifiedOverride,
        );

        let result =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", false);
        assert!(
            result.is_none(),
            "unverified-override sidecar must not be honored when the env var is unset"
        );
    }

    #[test]
    fn find_installed_honors_unverified_override_when_env_set() {
        // Same setup, but the doctor process did set the env var. The
        // sidecar gate respects the same opt-in semantics here as in
        // ensure_plugin.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        install_fake(
            root,
            "oxlint",
            "1.58.0",
            "darwin-arm64",
            "oxlint",
            sidecar::VerificationSource::UnverifiedOverride,
        );

        let (version, _path) =
            find_installed_for_current_platform_at(root, "oxlint", "oxlint", "darwin-arm64", true)
                .unwrap();
        assert_eq!(version, "1.58.0");
    }
}
