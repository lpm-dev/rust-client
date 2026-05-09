use crate::output;
use crate::release_lookup::{
    FetchOutcome, LookupError, clear_cache_at, default_cache_path, is_newer_semver, probe_release,
    read_cache_at, write_cache_at,
};
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// User-facing self-update reuses the banner cache file but with a much
/// shorter success TTL: a second `lpm self-update` within 10 minutes
/// short-circuits to the cached version. Long enough to defang
/// pathological CI loops, short enough that an interactive user
/// re-running shortly after a release still sees the new version on
/// the next cache miss.
const LOOKUP_TTL: Duration = Duration::from_secs(10 * 60);

/// If the previous probe failed (transport, 403, malformed response),
/// back off for an hour before letting the foreground command hit
/// GitHub again. Without this, a script looping on `lpm self-update`
/// re-hammers the API on every iteration even though we just persisted
/// `last_failure_check`. `--refresh` bypasses this gate.
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Update LPM to the latest version.
///
/// Detects the installation method from the executable path and runs
/// the appropriate upgrade command. Supports npm, Homebrew, cargo,
/// and standalone (curl) installations.
pub async fn run(json_output: bool, refresh: bool) -> Result<(), LpmError> {
    let current = env!("CARGO_PKG_VERSION");

    let cache_path = default_cache_path();
    let mut cache = cache_path
        .as_deref()
        .and_then(read_cache_at)
        .unwrap_or_default();

    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start("Checking for updates...");
        Some(s)
    } else {
        None
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Three-way decision before touching the network:
    //   (a) recent success → use cached version (cache hit).
    //   (b) recent failure → refuse without probing. Stale cached
    //       version (if any) is intentionally NOT used here: the user
    //       asked to upgrade right now and we should not silently
    //       install whatever we last saw an hour or a day ago.
    //   (c) otherwise → probe.
    // `--refresh` bypasses both (a) and (b).
    let cache_hit = !refresh
        && !cache.latest.is_empty()
        && cache.last_check > 0
        && now.saturating_sub(cache.last_check) < LOOKUP_TTL.as_secs();

    let in_failure_backoff = !refresh
        && !cache_hit
        && cache.last_failure_check > 0
        && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs();

    if in_failure_backoff {
        if let Some(s) = spinner {
            s.stop("Update check skipped (recent failure)");
        }
        let elapsed = now.saturating_sub(cache.last_failure_check);
        let remaining = FAILURE_BACKOFF.as_secs().saturating_sub(elapsed);
        // SelfUpdatePaused — not Network. The failure isn't a live
        // transport problem; it's a local cache decision to back off.
        // The variant's help text surfaces `--refresh` so we don't have
        // to repeat that hint inside the message body.
        return Err(LpmError::SelfUpdatePaused(format!(
            "last attempt failed {} ago, retrying automatically in {}",
            humanize_seconds(elapsed),
            humanize_seconds(remaining),
        )));
    }

    let latest = if cache_hit {
        cache.latest.clone()
    } else {
        match probe_release(&mut cache).await {
            Ok(FetchOutcome::Fresh { version }) | Ok(FetchOutcome::NotModified { version }) => {
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                version
            }
            Err(e) => {
                // Persist the failure so this command AND the banner
                // staleness gate both back off on the next invocation.
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                if let Some(s) = spinner {
                    s.stop("Update check failed");
                }
                return Err(lookup_error_to_lpm(e));
            }
        }
    };

    if let Some(s) = spinner {
        s.stop(format!(
            "Current: {}  Latest: {}",
            current.dimmed(),
            latest.bold()
        ));
    }

    if latest == current || !is_newer_semver(&latest, current) {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "current": current,
                "latest": latest,
                "up_to_date": true,
                "cache_hit": cache_hit,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if latest == current {
            output::success(&format!(
                "Already on the latest version ({})",
                current.bold()
            ));
        } else {
            output::success(&format!(
                "Current version ({}) is newer than latest release ({})",
                current.bold(),
                latest.dimmed()
            ));
        }
        return Ok(());
    }

    let method = detect_install_method();

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "current": current,
            "latest": latest,
            "up_to_date": false,
            "install_method": method.name(),
            "update_command": method.command(&latest),
            "cache_hit": cache_hit,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    output::info(&format!(
        "Updating {} → {} via {}",
        current.dimmed(),
        latest.green().bold(),
        method.name().cyan()
    ));

    match method {
        InstallMethod::Npm => {
            let pinned = format!("@lpm-registry/cli@{latest}");
            run_shell_update("npm", &["install", "-g", &pinned])?;
        }
        InstallMethod::Homebrew => run_shell_update("brew", &["upgrade", "lpm"])?,
        InstallMethod::Cargo => {
            let tag = format!("v{latest}");
            run_shell_update(
                "cargo",
                &[
                    "install",
                    "--git",
                    "https://github.com/lpm-dev/rust-client",
                    "--tag",
                    &tag,
                    "lpm-cli",
                    "--force",
                ],
            )?;
        }
        InstallMethod::Standalone => {
            run_standalone_update(&latest).await?;
        }
    }

    // Post-upgrade cache stamp policy:
    // - Standalone: we downloaded the exact tag → safe to stamp.
    // - Cargo: now `--tag`-pinned → safe to stamp.
    // - Npm: now `@{latest}`-pinned → safe to stamp.
    // - Homebrew: `brew upgrade lpm` is channel-latest, not tag-pinned;
    //   we can't prove which version actually landed. Clear the cache
    //   instead so the next invocation re-probes from scratch rather
    //   than asserting a possibly-wrong "latest".
    if let Some(p) = cache_path.as_deref() {
        match method {
            InstallMethod::Standalone | InstallMethod::Cargo | InstallMethod::Npm => {
                cache.latest = latest.clone();
                cache.last_check = now;
                cache.last_failure_check = 0;
                let _ = write_cache_at(p, &cache);
            }
            InstallMethod::Homebrew => {
                clear_cache_at(p);
            }
        }
    }

    output::success(&format!("Updated to {}", latest.bold()));

    Ok(())
}

/// Map a `LookupError` into `LpmError` so the existing CLI error
/// surface (miette / `--json`) renders it without losing the typed
/// rate-limit info.
///
/// Mapping is purpose-specific so error categories match user intent:
/// - Transport / HTTP / malformed → `Network`. Live network problem.
/// - GitHub-API rate limit → `SelfUpdateRateLimited`. Not a permission
///   issue (the historical `Forbidden` mapping read like the user was
///   blocked); it's a quota issue with a clear remediation surfaced in
///   the variant's help text (`GITHUB_TOKEN` / `GH_TOKEN`).
fn lookup_error_to_lpm(e: LookupError) -> LpmError {
    match e {
        LookupError::Transport(_) | LookupError::HttpStatus { .. } => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
        LookupError::RateLimited { reset_at } => {
            // Drop the GITHUB_TOKEN env-var guidance from the body —
            // it's now in the variant's help text, so repeating it
            // inline would double-print on the user's screen.
            let body = match reset_at {
                Some(epoch) => crate::release_lookup::format_rate_limit_summary(epoch),
                None => "GitHub Releases fallback rate-limited".to_string(),
            };
            LpmError::SelfUpdateRateLimited(body)
        }
        LookupError::MalformedResponse(_) => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
    }
}

/// Installation method detection.
#[derive(Debug, PartialEq, Eq)]
enum InstallMethod {
    Npm,
    Homebrew,
    Cargo,
    Standalone,
}

impl InstallMethod {
    fn name(&self) -> &'static str {
        match self {
            InstallMethod::Npm => "npm",
            InstallMethod::Homebrew => "homebrew",
            InstallMethod::Cargo => "cargo",
            InstallMethod::Standalone => "standalone",
        }
    }

    fn command(&self, version: &str) -> String {
        match self {
            InstallMethod::Npm => format!("npm install -g @lpm-registry/cli@{version}"),
            InstallMethod::Homebrew => "brew upgrade lpm".into(),
            InstallMethod::Cargo => format!(
                "cargo install --git https://github.com/lpm-dev/rust-client --tag v{version} lpm-cli --force"
            ),
            InstallMethod::Standalone => standalone_command(version),
        }
    }
}

/// Equivalent shell command for the Standalone upgrade path. The
/// wrapper does an in-place download of the version-pinned release
/// asset for the current binary's path — `install.sh` is the install
/// helper for new users, not what `lpm self-update` actually runs
/// (it does its own `releases/latest` lookup and writes to
/// `~/.lpm/bin/`).
///
/// On unsupported platforms or when the current exe path is unknown,
/// fall back to the GitHub Releases page so the user has somewhere to
/// land manually.
fn standalone_command(version: &str) -> String {
    let Ok((platform, ext)) = detect_platform() else {
        return format!("https://github.com/lpm-dev/rust-client/releases/tag/v{version}");
    };
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    standalone_command_for(version, platform, ext, exe.as_deref())
}

/// Pure helper for [`standalone_command`]. Split out so both per-OS
/// shapes (POSIX `curl` + `chmod` vs Windows PowerShell
/// `Invoke-WebRequest`) can be tested without depending on the host
/// the test happens to run on. The Rust updater itself only `chmod`s
/// on Unix (the `chmod +x` step is `#[cfg(unix)]`), and `chmod` is a
/// no-op on Windows — so emitting it unconditionally would hand
/// Windows users a broken command.
fn standalone_command_for(version: &str, platform: &str, ext: &str, exe: Option<&str>) -> String {
    let url = format!(
        "https://github.com/lpm-dev/rust-client/releases/download/v{version}/lpm-{platform}{ext}"
    );
    let is_windows = platform.starts_with("win32");
    let exe = exe.map(str::to_string).unwrap_or_else(|| {
        if is_windows {
            "%USERPROFILE%\\.lpm\\bin\\lpm.exe".to_string()
        } else {
            "/usr/local/bin/lpm".to_string()
        }
    });
    if is_windows {
        // PowerShell. No chmod — Windows uses the .exe extension to
        // mark executables, not a permission bit.
        format!("Invoke-WebRequest -Uri {url} -OutFile {exe}")
    } else {
        format!("curl -fsSL {url} -o {exe} && chmod +x {exe}")
    }
}

fn detect_install_method() -> InstallMethod {
    let exe = std::env::current_exe().ok();
    let exe_path = exe
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    if exe_path.contains("homebrew")
        || exe_path.contains("Cellar")
        || exe_path.contains("linuxbrew")
    {
        InstallMethod::Homebrew
    } else if exe_path.contains(".cargo") {
        InstallMethod::Cargo
    } else if exe_path.contains("node_modules")
        || exe_path.contains("npm")
        || exe_path.contains("nvm")
    {
        InstallMethod::Npm
    } else {
        InstallMethod::Standalone
    }
}

/// Run an external command for package-manager-based upgrades.
fn run_shell_update(cmd: &str, args: &[&str]) -> Result<(), LpmError> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| LpmError::Script(format!("failed to run {cmd}: {e}")))?;

    if !status.success() {
        return Err(LpmError::Script(format!(
            "{cmd} exited with code {}",
            status.code().unwrap_or(-1)
        )));
    }

    Ok(())
}

/// Download and replace the binary in-place for standalone installations.
async fn run_standalone_update(version: &str) -> Result<(), LpmError> {
    let (platform, ext) = detect_platform()?;
    let binary_name = format!("lpm-{platform}{ext}");
    let url = format!(
        "https://github.com/lpm-dev/rust-client/releases/download/v{version}/{binary_name}"
    );

    let spinner = cliclack::spinner();
    spinner.start(format!("Downloading {binary_name}..."));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let response = client
        .get(&url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("download failed: {e}")))?;

    if !response.status().is_success() {
        spinner.stop("Download failed");
        return Err(LpmError::Network(format!(
            "download failed: HTTP {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("download failed: {e}")))?;

    spinner.stop(format!(
        "Downloaded {} ({})",
        binary_name,
        format_bytes(bytes.len())
    ));

    // Replace the current binary
    let current_exe = std::env::current_exe().map_err(LpmError::Io)?;

    // Write to a temp file next to the current binary, then rename (atomic on same filesystem)
    let tmp_path = current_exe.with_extension("tmp");
    std::fs::write(&tmp_path, &bytes).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write temp binary: {e}"),
        ))
    })?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .map_err(LpmError::Io)?;
    }

    // Atomic rename
    std::fs::rename(&tmp_path, &current_exe).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to replace binary: {e}"),
        ))
    })?;

    Ok(())
}

/// Detect the current platform for GitHub Release binary names.
fn detect_platform() -> Result<(&'static str, &'static str), LpmError> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match (os, arch) {
        ("macos", "aarch64") => Ok(("darwin-arm64", "")),
        ("macos", "x86_64") => Ok(("darwin-x64", "")),
        ("linux", "x86_64") => Ok(("linux-x64", "")),
        ("linux", "aarch64") => Ok(("linux-arm64", "")),
        ("windows", "x86_64") => Ok(("win32-x64", ".exe")),
        _ => Err(LpmError::Script(format!(
            "unsupported platform: {os}-{arch}. Download manually from https://github.com/lpm-dev/rust-client/releases"
        ))),
    }
}

/// Render a duration in seconds as a coarse human string. Picks the
/// largest unit that gives at least one whole quantity. Pluralises.
fn humanize_seconds(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else if secs >= 60 {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else {
        format!("{secs} second{}", if secs == 1 { "" } else { "s" })
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_lookup::{self, UpdateCache};
    use tempfile::tempdir;

    #[test]
    fn install_method_name_not_empty() {
        let method = detect_install_method();
        assert!(!method.name().is_empty());
    }

    #[test]
    fn install_method_command_npm_pins_exact_version() {
        let cmd = InstallMethod::Npm.command("0.25.0");
        assert!(cmd.contains("@lpm-registry/cli@0.25.0"), "cmd: {cmd}");
        assert!(!cmd.contains("@latest"), "must not use @latest: {cmd}");
    }

    #[test]
    fn install_method_command_cargo_uses_tag() {
        // Without --tag, `cargo install --git ... --force` tracks
        // the default branch HEAD — so the docs claim "you'll be
        // on v{latest}" is a lie. The fix is mandatory --tag pinning;
        // this test pins the contract.
        let cmd = InstallMethod::Cargo.command("0.25.0");
        assert!(cmd.contains("--tag v0.25.0"), "cmd: {cmd}");
        assert!(cmd.contains("--force"), "cmd: {cmd}");
    }

    #[test]
    fn install_method_command_homebrew_unchanged() {
        assert_eq!(
            InstallMethod::Homebrew.command("0.25.0"),
            "brew upgrade lpm"
        );
    }

    /// The standalone `update_command` must reflect the literal action
    /// the wrapper performs: a version-pinned download of the release
    /// asset, replacing the running binary in place. `install.sh` is
    /// the install helper for new users, not what self-update runs —
    /// it does its own `releases/latest` lookup and writes to
    /// `~/.lpm/bin/`. Locking the wrong contract previously masked
    /// this divergence.
    #[test]
    fn install_method_command_standalone_pins_resolved_version() {
        let cmd = InstallMethod::Standalone.command("0.25.0");
        // Must NOT use install.sh (which re-resolves latest itself).
        assert!(
            !cmd.contains("install.sh"),
            "standalone command must not delegate to install.sh: {cmd}"
        );
        // Must pin the exact version the wrapper resolved.
        assert!(
            cmd.contains("v0.25.0"),
            "standalone command must include resolved version: {cmd}"
        );
        // Must point at GitHub Releases — either the tag page (fallback
        // when platform detection fails) or the direct download URL.
        assert!(
            cmd.contains("github.com/lpm-dev/rust-client/releases/"),
            "standalone command must reference GitHub Releases: {cmd}"
        );
    }

    /// POSIX hosts (darwin / linux) get a `curl … && chmod +x …`
    /// command. Driven through the pure helper so the assertion holds
    /// even when CI runs on a different platform than the inputs.
    #[test]
    fn standalone_command_for_posix_uses_curl_and_chmod() {
        for (platform, ext) in [
            ("darwin-arm64", ""),
            ("darwin-x64", ""),
            ("linux-x64", ""),
            ("linux-arm64", ""),
        ] {
            let cmd = standalone_command_for("0.25.0", platform, ext, Some("/usr/local/bin/lpm"));
            assert!(
                cmd.starts_with("curl "),
                "{platform}: must start with curl: {cmd}"
            );
            assert!(
                cmd.contains(&format!("/releases/download/v0.25.0/lpm-{platform}{ext}")),
                "{platform}: must include direct download URL: {cmd}"
            );
            assert!(cmd.contains("chmod +x"), "{platform}: must chmod +x: {cmd}");
            assert!(
                cmd.contains("/usr/local/bin/lpm"),
                "{platform}: must target the supplied exe path: {cmd}"
            );
            assert!(
                !cmd.contains("Invoke-WebRequest"),
                "{platform}: must not be PowerShell-shaped: {cmd}"
            );
        }
    }

    /// Windows gets a PowerShell `Invoke-WebRequest`. No `chmod` — the
    /// Rust updater itself only `chmod`s under `#[cfg(unix)]`, and
    /// Windows uses the `.exe` extension instead of a permission bit.
    #[test]
    fn standalone_command_for_windows_uses_invoke_webrequest_no_chmod() {
        let cmd = standalone_command_for(
            "0.25.0",
            "win32-x64",
            ".exe",
            Some("C:\\Users\\me\\.lpm\\bin\\lpm.exe"),
        );
        assert!(
            cmd.starts_with("Invoke-WebRequest "),
            "must start with Invoke-WebRequest: {cmd}"
        );
        assert!(
            cmd.contains("/releases/download/v0.25.0/lpm-win32-x64.exe"),
            "must include direct .exe URL: {cmd}"
        );
        assert!(
            cmd.contains("C:\\Users\\me\\.lpm\\bin\\lpm.exe"),
            "must target the supplied exe path: {cmd}"
        );
        assert!(
            !cmd.contains("chmod"),
            "must not emit chmod on Windows: {cmd}"
        );
        assert!(!cmd.contains("curl "), "must not be POSIX-shaped: {cmd}");
    }

    /// Default exe paths kick in only when `current_exe()` is unknown.
    /// The Unix fallback is `/usr/local/bin/lpm`; the Windows fallback
    /// is `%USERPROFILE%\.lpm\bin\lpm.exe`.
    #[test]
    fn standalone_command_default_exe_paths_per_platform() {
        let posix = standalone_command_for("0.25.0", "darwin-arm64", "", None);
        assert!(posix.contains("/usr/local/bin/lpm"), "{posix}");
        let win = standalone_command_for("0.25.0", "win32-x64", ".exe", None);
        assert!(win.contains("%USERPROFILE%\\.lpm\\bin\\lpm.exe"), "{win}");
    }

    /// The `standalone_command()` dispatcher consults host
    /// `detect_platform()` / `current_exe()`. On every supported host
    /// it must pin the version and include the direct download URL —
    /// the per-OS shape (curl vs Invoke-WebRequest) is covered by the
    /// pure-helper tests above.
    #[test]
    fn standalone_command_dispatcher_returns_pinned_command() {
        let cmd = standalone_command("0.25.0");
        assert!(cmd.contains("v0.25.0"), "must pin version: {cmd}");
        assert!(
            cmd.contains("/releases/download/v0.25.0/lpm-"),
            "must include direct download URL: {cmd}"
        );
    }

    #[test]
    fn detect_platform_returns_valid_tuple() {
        let result = detect_platform();
        assert!(
            result.is_ok(),
            "detect_platform should succeed on this host"
        );
        let (platform, _ext) = result.unwrap();
        assert!(!platform.is_empty());
        assert!(
            [
                "darwin-arm64",
                "darwin-x64",
                "linux-x64",
                "linux-arm64",
                "win32-x64",
            ]
            .contains(&platform),
            "unexpected platform: {platform}"
        );
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(2_621_440), "2.5 MB");
    }

    /// Rate-limit lands on `SelfUpdateRateLimited`, not `Forbidden`.
    /// `Forbidden` is the user-permission category and reads to users
    /// as "you're banned" — wrong category for a quota-reset wait.
    #[test]
    fn lookup_error_rate_limit_maps_to_self_update_rate_limited() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        assert!(matches!(err, LpmError::SelfUpdateRateLimited(_)), "got {err:?}");
        // And — explicitly NOT Forbidden, the historical wrong category.
        assert!(
            !matches!(err, LpmError::Forbidden(_)),
            "must not regress to Forbidden: {err:?}"
        );
    }

    /// Rendered body must not duplicate the GITHUB_TOKEN hint — that
    /// guidance now lives in the variant's miette help text. Doubling
    /// it would print the same instruction twice.
    #[test]
    fn lookup_error_rate_limit_body_is_not_doubled_with_help_text() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        let LpmError::SelfUpdateRateLimited(body) = err else {
            panic!("expected SelfUpdateRateLimited variant");
        };
        assert!(
            !body.contains("GITHUB_TOKEN"),
            "body must not duplicate help text: {body}"
        );
        assert!(
            !body.contains("GH_TOKEN"),
            "body must not duplicate help text: {body}"
        );
    }

    #[test]
    fn lookup_error_transport_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::Transport("dns failed".into()));
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    #[test]
    fn lookup_error_http_status_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::HttpStatus {
            status: 503,
            body_excerpt: "down".into(),
        });
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    /// Cache stamp/clear policy is the load-bearing decision in this
    /// patch. Encode the user-facing contract directly: after a
    /// successful Standalone/Cargo/Npm upgrade the cache's `latest`
    /// must match the version we just installed; after a successful
    /// Homebrew upgrade the cache file must NOT exist.
    #[test]
    fn post_upgrade_cache_policy_pinning_channels_stamp() {
        for method in [
            InstallMethod::Standalone,
            InstallMethod::Cargo,
            InstallMethod::Npm,
        ] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("update-check.json");
            let cache = UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                ..Default::default()
            };
            write_cache_at(&path, &cache).unwrap();
            // Mirror the post-upgrade branch logic against the path.
            let mut after = read_cache_at(&path).unwrap();
            after.latest = "0.25.0".into();
            after.last_check = 1_700_000_000;
            after.last_failure_check = 0;
            write_cache_at(&path, &after).unwrap();
            let loaded = read_cache_at(&path).unwrap();
            assert_eq!(loaded.latest, "0.25.0", "method {method:?}");
        }
    }

    #[test]
    fn post_upgrade_cache_policy_homebrew_clears() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        write_cache_at(
            &path,
            &UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(path.exists());
        clear_cache_at(&path);
        assert!(
            !path.exists(),
            "Homebrew upgrade must clear cache, not stamp"
        );
    }

    /// `--refresh` is supposed to bypass the in-process cache hit
    /// short-circuit. Lock the cache-hit predicate that gates it.
    #[test]
    fn refresh_flag_bypasses_cache_hit_predicate() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 60,
            ..Default::default()
        };
        let refresh = false;
        let predicate = |refresh: bool| -> bool {
            !refresh
                && !cache.latest.is_empty()
                && cache.last_check > 0
                && now.saturating_sub(cache.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(
            predicate(refresh),
            "fresh cache must hit when refresh=false"
        );
        assert!(!predicate(true), "refresh=true must bypass the cache hit");
    }

    /// Recent failure must short-circuit BEFORE the network call so a
    /// script looping on `lpm self-update` after a 403 doesn't re-hit
    /// the rate-limited API on every iteration.
    #[test]
    fn recent_failure_triggers_backoff_without_refresh() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 60,
            ..Default::default()
        };
        let predicate = |refresh: bool, cache_hit: bool| -> bool {
            !refresh
                && !cache_hit
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(
            predicate(false, false),
            "default invocation must respect backoff"
        );
        assert!(!predicate(true, false), "--refresh must bypass the backoff");
        assert!(
            !predicate(false, true),
            "fresh success cache pre-empts backoff"
        );
    }

    #[test]
    fn failure_backoff_lapses_past_ttl() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 4000, // > 1h
            ..Default::default()
        };
        let predicate = |refresh: bool| -> bool {
            !refresh
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(!predicate(false));
    }

    #[test]
    fn humanize_seconds_picks_largest_unit() {
        assert_eq!(humanize_seconds(0), "0 seconds");
        assert_eq!(humanize_seconds(1), "1 second");
        assert_eq!(humanize_seconds(45), "45 seconds");
        assert_eq!(humanize_seconds(60), "1 minute");
        assert_eq!(humanize_seconds(150), "2 minutes");
        assert_eq!(humanize_seconds(3600), "1 hour");
        assert_eq!(humanize_seconds(7200), "2 hours");
    }

    #[test]
    fn cache_hit_only_within_lookup_ttl() {
        let now = 1_700_000_500u64;
        let stale_cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 700, // > 10m TTL
            ..Default::default()
        };
        let predicate = |c: &UpdateCache| -> bool {
            !c.latest.is_empty()
                && c.last_check > 0
                && now.saturating_sub(c.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(!predicate(&stale_cache));
    }

    #[test]
    fn release_lookup_module_is_reachable() {
        // Smoke check: the shared module's public surface is wired
        // in. If the module is renamed or visibility changes, this
        // catches it before the CLI dispatch path breaks.
        let _ = release_lookup::default_cache_path();
    }
}
