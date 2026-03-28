use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/lpm-dev/rust-client/releases/latest";
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Path to the update check cache file.
fn cache_path() -> Option<PathBuf> {
	dirs::home_dir().map(|h| h.join(".lpm").join("update-check.json"))
}

/// Read the cached update info and return a notice if outdated.
/// This is instant (no network) — called before the command runs.
pub fn read_cached_notice() -> Option<String> {
	let path = cache_path()?;
	let content = std::fs::read_to_string(&path).ok()?;
	let data: serde_json::Value = serde_json::from_str(&content).ok()?;

	let latest = data.get("latest").and_then(|v| v.as_str()).unwrap_or("");
	let current = env!("CARGO_PKG_VERSION");

	if !latest.is_empty() && latest != current && is_newer(latest, current) {
		Some(format_notice(current, latest))
	} else {
		None
	}
}

/// Refresh the cache if stale. Called after the command completes.
/// Makes one HTTP request with a 3s timeout, at most once per 24h.
pub async fn refresh_cache_if_stale() {
	let path = match cache_path() {
		Some(p) => p,
		None => return,
	};

	// Check if cache is fresh
	let needs_check = match std::fs::read_to_string(&path) {
		Ok(content) => {
			let data: serde_json::Value = match serde_json::from_str(&content) {
				Ok(d) => d,
				Err(_) => return,
			};
			let last_check = data
				.get("lastCheck")
				.and_then(|v| v.as_u64())
				.unwrap_or(0);
			let now = SystemTime::now()
				.duration_since(SystemTime::UNIX_EPOCH)
				.unwrap()
				.as_secs();
			now - last_check > CHECK_INTERVAL.as_secs()
		}
		Err(_) => true, // No cache file
	};

	if !needs_check {
		return;
	}

	// Fetch latest version from GitHub Releases (not npm)
	let latest = match fetch_latest_version().await {
		Ok(v) => v,
		Err(_) => return, // Silent failure — network issues are not user's problem
	};

	let now = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs();

	let data = serde_json::json!({
		"latest": latest,
		"lastCheck": now,
	});

	let _ = std::fs::write(&path, serde_json::to_string(&data).unwrap());
}

/// Fetch the latest version from GitHub Releases.
async fn fetch_latest_version() -> Result<String, Box<dyn std::error::Error>> {
	let client = reqwest::Client::builder()
		.timeout(FETCH_TIMEOUT)
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
		.ok_or("no tag_name field")?;

	// Parse version from tag: "v0.5.0" → "0.5.0"
	let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
	Ok(version)
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

/// Detect how LPM was installed and return the appropriate update command.
fn detect_update_command() -> &'static str {
	let exe = std::env::current_exe().ok();
	let exe_path = exe
		.as_ref()
		.map(|p| p.to_string_lossy().to_string())
		.unwrap_or_default();

	if exe_path.contains("homebrew") || exe_path.contains("Cellar") || exe_path.contains("linuxbrew") {
		"brew upgrade lpm"
	} else if exe_path.contains(".cargo") {
		"cargo install --git https://github.com/lpm-dev/rust-client lpm-cli"
	} else if exe_path.contains("node_modules") || exe_path.contains("npm") {
		"npm install -g @lpm-registry/cli"
	} else {
		// Direct binary install (curl, GitHub Releases download)
		"curl -fsSL https://lpm.dev/install.sh | sh"
	}
}

fn format_notice(current: &str, latest: &str) -> String {
	let update_cmd = detect_update_command();
	format!(
		"\n  {} Update available: {} → {}\n  Run {} to update\n",
		"⬆".yellow(),
		current.dimmed(),
		latest.green().bold(),
		update_cmd.cyan(),
	)
}
