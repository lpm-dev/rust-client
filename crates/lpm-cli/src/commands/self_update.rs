use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::process::Command;

const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/lpm-dev/rust-client/releases/latest";

/// Update LPM to the latest version.
///
/// Detects the installation method from the executable path and runs
/// the appropriate upgrade command. Supports npm, Homebrew, cargo,
/// and standalone (curl) installations.
pub async fn run(json_output: bool) -> Result<(), LpmError> {
    let current = env!("CARGO_PKG_VERSION");

    // Fetch latest version
    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start("Checking for updates...");
        Some(s)
    } else {
        None
    };

    let latest = fetch_latest_version()
        .await
        .map_err(|e| LpmError::Network(format!("failed to check for updates: {e}")))?;

    if let Some(s) = spinner {
        s.stop(format!(
            "Current: {}  Latest: {}",
            current.dimmed(),
            latest.bold()
        ));
    }

    if latest == current {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "current": current,
                "latest": latest,
                "up_to_date": true,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::success(&format!(
                "Already on the latest version ({})",
                current.bold()
            ));
        }
        return Ok(());
    }

    if !is_newer(&latest, current) {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "current": current,
                "latest": latest,
                "up_to_date": true,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
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
            run_shell_update("npm", &["install", "-g", "@lpm-registry/cli@latest"])?
        }
        InstallMethod::Homebrew => run_shell_update("brew", &["upgrade", "lpm"])?,
        InstallMethod::Cargo => {
            run_shell_update(
                "cargo",
                &[
                    "install",
                    "--git",
                    "https://github.com/lpm-dev/rust-client",
                    "lpm-cli",
                    "--force",
                ],
            )?;
        }
        InstallMethod::Standalone => {
            run_standalone_update(&latest).await?;
        }
    }

    output::success(&format!("Updated to {}", latest.bold()));

    Ok(())
}

/// Installation method detection.
#[derive(Debug)]
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

    fn command(&self, _version: &str) -> String {
        match self {
            InstallMethod::Npm => "npm install -g @lpm-registry/cli@latest".into(),
            InstallMethod::Homebrew => "brew upgrade lpm".into(),
            InstallMethod::Cargo => {
                "cargo install --git https://github.com/lpm-dev/rust-client lpm-cli --force".into()
            }
            InstallMethod::Standalone => "curl -fsSL https://lpm.dev/install.sh | sh".into(),
        }
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

    // Clear the update cache so the banner disappears
    if let Some(home) = dirs::home_dir() {
        let _ = std::fs::remove_file(home.join(".lpm").join("update-check.json"));
    }

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

/// Simple semver comparison: is `a` newer than `b`?
fn is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            *parts.first().unwrap_or(&0),
            *parts.get(1).unwrap_or(&0),
            *parts.get(2).unwrap_or(&0),
        )
    };
    parse(a) > parse(b)
}

/// Fetch the latest version from GitHub Releases.
async fn fetch_latest_version() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp: serde_json::Value = client
        .get(GITHUB_RELEASES_URL)
        .header("User-Agent", "lpm-cli")
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?
        .json()
        .await?;

    let tag = resp
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or("no tag_name in GitHub release")?;

    Ok(tag.strip_prefix('v').unwrap_or(tag).to_string())
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

    #[test]
    fn is_newer_major() {
        assert!(is_newer("2.0.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "2.0.0"));
    }

    #[test]
    fn is_newer_minor() {
        assert!(is_newer("1.2.0", "1.1.0"));
        assert!(!is_newer("1.1.0", "1.2.0"));
    }

    #[test]
    fn is_newer_patch() {
        assert!(is_newer("1.0.2", "1.0.1"));
        assert!(!is_newer("1.0.1", "1.0.2"));
    }

    #[test]
    fn is_newer_equal() {
        assert!(!is_newer("1.0.0", "1.0.0"));
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
        // Should match one of the known patterns
        assert!(
            [
                "darwin-arm64",
                "darwin-x64",
                "linux-x64",
                "linux-arm64",
                "win32-x64"
            ]
            .contains(&platform),
            "unexpected platform: {platform}"
        );
    }

    #[test]
    fn install_method_name_not_empty() {
        let method = detect_install_method();
        assert!(!method.name().is_empty());
    }

    #[test]
    fn install_method_command_contains_lpm() {
        let method = detect_install_method();
        let cmd = method.command("1.0.0");
        // Every update command should reference lpm in some form
        assert!(
            cmd.contains("lpm") || cmd.contains("rust-client"),
            "command should reference lpm: {cmd}"
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
}
