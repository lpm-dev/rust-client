use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::PathBuf;

const APP_NAME: &str = "LPM Vault.app";
const GITHUB_REPO: &str = "lpm-dev/lpm-vault";
const VERSION_CACHE_FILE: &str = "vault-version-check.json";
const CACHE_TTL_SECS: u64 = 86400; // 24 hours

/// Run the `lpm vault` command.
pub async fn run(action: &str, json_output: bool) -> Result<(), LpmError> {
    #[cfg(not(target_os = "macos"))]
    {
        return Err(LpmError::Script(
            "LPM Vault is macOS only. Linux and Windows are not yet supported.".into(),
        ));
    }

    #[cfg(target_os = "macos")]
    match action {
        "" | "open" => run_open(json_output).await,
        "update" => run_update(json_output).await,
        "version" => run_version(json_output).await,
        _ => Err(LpmError::Script(format!(
            "unknown vault action '{action}'. Available: open (default), update, version"
        ))),
    }
}

/// Open the vault app (auto-install if not found).
#[cfg(target_os = "macos")]
async fn run_open(json_output: bool) -> Result<(), LpmError> {
    let app_path = match find_app() {
        Some(path) => {
            // Check for updates (non-blocking, cached)
            if let Some(notice) = check_update_cached()
                && !json_output
            {
                output::warn(&notice);
            }
            path
        }
        None => {
            if json_output {
                download_and_install().await?
            } else {
                output::info(&format!("{APP_NAME} is not installed"));
                let confirm = cliclack::confirm("Download and install?")
                    .initial_value(true)
                    .interact()
                    .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
                if !confirm {
                    output::info("cancelled");
                    return Ok(());
                }
                download_and_install().await?
            }
        }
    };

    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "status": "opening", "path": app_path.display().to_string()})
        );
    } else {
        output::info(&format!("opening {}", APP_NAME.bold()));
    }

    open_app(&app_path)?;
    Ok(())
}

/// Check for updates and download if available.
#[cfg(target_os = "macos")]
async fn run_update(json_output: bool) -> Result<(), LpmError> {
    let installed_version = get_installed_version();
    let latest = fetch_latest_version().await?;

    let needs_update = match &installed_version {
        Some(v) => v != &latest,
        None => true,
    };

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "installed": installed_version,
                "latest": latest,
                "update_available": needs_update,
            })
        );
        if needs_update {
            download_and_install().await?;
        }
        return Ok(());
    }

    output::field(
        "installed",
        installed_version.as_deref().unwrap_or("not installed"),
    );
    output::field("latest", &latest);

    if !needs_update {
        output::success("already up to date");
        return Ok(());
    }

    let confirm = cliclack::confirm(format!("Update to {latest}?"))
        .initial_value(true)
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;

    if !confirm {
        output::info("cancelled");
        return Ok(());
    }

    let app_path = download_and_install().await?;
    output::success(&format!("updated to {latest}"));
    open_app(&app_path)?;

    Ok(())
}

/// Show installed version.
#[cfg(target_os = "macos")]
async fn run_version(json_output: bool) -> Result<(), LpmError> {
    let installed = get_installed_version();

    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "installed": installed})
        );
    } else {
        match installed {
            Some(v) => output::field("installed", &v),
            None => output::field("installed", &"not found".dimmed().to_string()),
        }
    }

    Ok(())
}

// ── Download & Install ─────────────────────────────────────────────

/// Download the latest release from GitHub and install to ~/Applications/.
#[cfg(target_os = "macos")]
async fn download_and_install() -> Result<PathBuf, LpmError> {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("lpm-cli")
        .build()
        .map_err(|e| LpmError::Network(format!("http client: {e}")))?;

    // Fetch latest release from GitHub API
    let api_url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let response = http_client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to fetch release info: {e}")))?;

    if !response.status().is_success() {
        return Err(LpmError::Network(format!(
            "GitHub API returned {}. Is the repo public?",
            response.status()
        )));
    }

    let release: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("failed to parse release: {e}")))?;

    let tag = release["tag_name"]
        .as_str()
        .ok_or_else(|| LpmError::Network("no tag_name in release".into()))?;

    // Find asset for current architecture
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let asset_name = format!("LPM Vault-darwin-{arch}.zip");

    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| LpmError::Network("no assets in release".into()))?;

    let download_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| {
            LpmError::Network(format!("asset '{asset_name}' not found in release {tag}"))
        })?;

    let version = tag.strip_prefix('v').unwrap_or(tag);
    output::info(&format!("downloading {} v{}...", APP_NAME, version.bold()));

    // Download zip
    let bytes = http_client
        .get(download_url)
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("download failed: {e}")))?
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("download read failed: {e}")))?;

    // Install
    let install_dir = app_install_dir();
    std::fs::create_dir_all(&install_dir)?;

    let temp_zip = install_dir.join("_vault_download.zip");
    std::fs::write(&temp_zip, &bytes)?;

    // Remove existing app
    let app_path = install_dir.join(APP_NAME);
    if app_path.exists() {
        std::fs::remove_dir_all(&app_path)
            .map_err(|e| LpmError::Script(format!("failed to remove old app: {e}")))?;
    }

    // Extract with ditto (preserves macOS metadata and code signatures)
    let status = std::process::Command::new("ditto")
        .args([
            "-xk",
            temp_zip.to_str().unwrap(),
            install_dir.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| LpmError::Script(format!("extraction failed: {e}")))?;

    // Clean up temp zip
    std::fs::remove_file(&temp_zip).ok();

    if !status.success() {
        return Err(LpmError::Script("failed to extract app zip".into()));
    }

    if !app_path.exists() {
        return Err(LpmError::Script(format!(
            "extraction succeeded but {APP_NAME} not found at {}",
            app_path.display()
        )));
    }

    // Clear Gatekeeper quarantine (since app is not notarized yet)
    let _ = std::process::Command::new("xattr")
        .args(["-cr", app_path.to_str().unwrap()])
        .status();

    // Update version cache
    update_version_cache(version);

    output::success(&format!(
        "installed {} v{} to {}",
        APP_NAME,
        version.bold(),
        install_dir.display().to_string().dimmed()
    ));

    Ok(app_path)
}

/// Fetch the latest version tag from GitHub API.
#[cfg(target_os = "macos")]
async fn fetch_latest_version() -> Result<String, LpmError> {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("lpm-cli")
        .build()
        .map_err(|e| LpmError::Network(format!("http client: {e}")))?;

    let api_url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let response = http_client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to check updates: {e}")))?;

    if !response.status().is_success() {
        return Err(LpmError::Network(format!(
            "GitHub API returned {}",
            response.status()
        )));
    }

    let release: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Network(format!("failed to parse release: {e}")))?;

    let tag = release["tag_name"]
        .as_str()
        .ok_or_else(|| LpmError::Network("no tag_name in release".into()))?;

    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    update_version_cache(&version);

    Ok(version)
}

// ── Helpers ────────────────────────────────────────────────────────

/// Find the app in common install locations.
fn find_app() -> Option<PathBuf> {
    let locations = [
        app_install_dir().join(APP_NAME),
        PathBuf::from("/Applications").join(APP_NAME),
    ];

    locations.into_iter().find(|p| p.exists())
}

/// The preferred install directory.
fn app_install_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("Applications")
}

/// Open the app using macOS `open` command.
fn open_app(path: &PathBuf) -> Result<(), LpmError> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|e| LpmError::Script(format!("failed to open {APP_NAME}: {e}")))?;
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        output::warn(&format!("{APP_NAME} is macOS only"));
    }

    Ok(())
}

/// Read the installed app version from Info.plist.
fn get_installed_version() -> Option<String> {
    let app_path = find_app()?;
    let plist_path = app_path.join("Contents/Info.plist");

    if !plist_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&plist_path).ok()?;
    let key = "CFBundleShortVersionString";
    let pos = content.find(key)?;
    let after = &content[pos + key.len()..];
    let start = after.find("<string>")? + 8;
    let end = after.find("</string>")?;
    Some(after[start..end].to_string())
}

/// Check for update from cache (non-blocking, returns notice string if update available).
fn check_update_cached() -> Option<String> {
    let cache_path = dirs::home_dir()?.join(".lpm").join(VERSION_CACHE_FILE);
    if !cache_path.exists() {
        return None;
    }

    let modified = cache_path.metadata().ok()?.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    if age > std::time::Duration::from_secs(CACHE_TTL_SECS) {
        return None;
    }

    let content = std::fs::read_to_string(&cache_path).ok()?;
    let cached: serde_json::Value = serde_json::from_str(&content).ok()?;
    let latest = cached.get("latest")?.as_str()?;
    let installed = get_installed_version()?;

    if latest != installed {
        Some(format!(
            "Vault app update available: {installed} → {latest}. Run `lpm vault update`"
        ))
    } else {
        None
    }
}

/// Write latest version to cache file.
fn update_version_cache(version: &str) {
    let Some(cache_dir) = dirs::home_dir().map(|h| h.join(".lpm")) else {
        return;
    };
    std::fs::create_dir_all(&cache_dir).ok();
    let cache_path = cache_dir.join(VERSION_CACHE_FILE);
    let json = serde_json::json!({"latest": version});
    std::fs::write(cache_path, json.to_string()).ok();
}
