//! Security policies for LPM package installation.
//!
//! Key policies (following pnpm v10 and Bun best practices):
//!
//! 1. **Lifecycle scripts blocked by default** — `preinstall`, `install`, `postinstall`
//!    scripts are NOT executed unless the package is in `trustedDependencies`.
//!    This prevents supply chain attacks via malicious postinstall scripts.
//!
//! 2. **Trusted dependencies allowlist** — packages in `"lpm": { "trustedDependencies": [...] }`
//!    in package.json are allowed to run lifecycle scripts.
//!
//! 3. **Minimum release age** (future) — block packages published less than 24h ago.
//!
//! # TODOs
//! - [ ] `minimumReleaseAge` (default: 24h) — block very new releases
//! - [ ] SLSA provenance verification
//! - [ ] Sigstore signature verification
//! - [ ] Supply chain attack detection (typosquatting, dependency confusion)
//! - [ ] Audit integration with OSV database

use std::collections::HashSet;
use std::path::Path;

/// Lifecycle script names that are blocked by default.
const BLOCKED_SCRIPTS: &[&str] = &[
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"uninstall",
	"postuninstall",
];

/// Security policy for a project, derived from package.json's `"lpm"` config.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
	/// Packages explicitly trusted to run lifecycle scripts.
	pub trusted_dependencies: HashSet<String>,
	/// Minimum age in seconds before a release is installable (default: 86400 = 24h).
	/// Set to 0 to disable. Protects against compromised publish tokens being used
	/// to push malicious versions that get installed before detection.
	pub minimum_release_age_secs: u64,
}

impl SecurityPolicy {
	/// Default minimum release age: 24 hours (matches pnpm v10 default).
	const DEFAULT_MIN_RELEASE_AGE: u64 = 86400;

	/// Create a default policy (nothing trusted — all scripts blocked, 24h release age).
	pub fn default_policy() -> Self {
		SecurityPolicy {
			trusted_dependencies: HashSet::new(),
			minimum_release_age_secs: Self::DEFAULT_MIN_RELEASE_AGE,
		}
	}

	/// Load policy from a project's package.json.
	///
	/// Reads `"lpm": { "trustedDependencies": ["esbuild", "sharp"] }`.
	pub fn from_package_json(pkg_json_path: &Path) -> Self {
		let content = match std::fs::read_to_string(pkg_json_path) {
			Ok(c) => c,
			Err(_) => return Self::default_policy(),
		};

		let doc: serde_json::Value = match serde_json::from_str(&content) {
			Ok(v) => v,
			Err(_) => return Self::default_policy(),
		};

		let trusted = doc
			.get("lpm")
			.and_then(|lpm| lpm.get("trustedDependencies"))
			.and_then(|td| td.as_array())
			.map(|arr| {
				arr.iter()
					.filter_map(|v| v.as_str().map(|s| s.to_string()))
					.collect::<HashSet<String>>()
			})
			.unwrap_or_default();

		let min_age = doc
			.get("lpm")
			.and_then(|lpm| lpm.get("minimumReleaseAge"))
			.and_then(|v| v.as_u64())
			.unwrap_or(Self::DEFAULT_MIN_RELEASE_AGE);

		SecurityPolicy {
			trusted_dependencies: trusted,
			minimum_release_age_secs: min_age,
		}
	}

	/// Check if a package is allowed to run lifecycle scripts.
	pub fn can_run_scripts(&self, package_name: &str) -> bool {
		self.trusted_dependencies.contains(package_name)
	}

	/// Check if a package release is too new to install based on minimumReleaseAge.
	///
	/// `published_at` should be an ISO 8601 timestamp string.
	/// Returns `Some(remaining_secs)` if the release is too new, `None` if it's ok.
	pub fn check_release_age(&self, published_at: &str) -> Option<u64> {
		if self.minimum_release_age_secs == 0 {
			return None;
		}

		// Parse ISO 8601 timestamp (basic: check if it's within the age window)
		// We use a simple approach: parse the timestamp and compare with current time
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		// Try to parse ISO 8601 date (e.g., "2026-03-23T10:32:13.938Z")
		// Simple parser: extract year, month, day, hour, minute, second
		let parts: Vec<&str> = published_at.split(&['T', '-', ':', '.', 'Z'][..]).collect();
		if parts.len() < 6 {
			return None; // Can't parse, allow
		}

		let year: i64 = parts[0].parse().ok()?;
		let month: i64 = parts[1].parse().ok()?;
		let day: i64 = parts[2].parse().ok()?;
		let hour: i64 = parts[3].parse().ok()?;
		let minute: i64 = parts[4].parse().ok()?;
		let second: i64 = parts[5].parse().ok()?;

		// Approximate Unix timestamp (not accounting for leap seconds)
		let days_from_epoch = (year - 1970) * 365 + (year - 1969) / 4
			+ [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][(month - 1) as usize]
			+ day - 1;
		let published_epoch = (days_from_epoch * 86400 + hour * 3600 + minute * 60 + second) as u64;

		if now > published_epoch {
			let age = now - published_epoch;
			if age < self.minimum_release_age_secs {
				return Some(self.minimum_release_age_secs - age);
			}
		}

		None
	}

	/// Check if a script name is a lifecycle script that should be blocked.
	pub fn is_blocked_script(script_name: &str) -> bool {
		BLOCKED_SCRIPTS.contains(&script_name)
	}

	/// Scan a package's `package.json` for lifecycle scripts.
	/// Returns the names of scripts that would be blocked.
	pub fn detect_lifecycle_scripts(pkg_json_path: &Path) -> Vec<String> {
		let content = match std::fs::read_to_string(pkg_json_path) {
			Ok(c) => c,
			Err(_) => return vec![],
		};

		let doc: serde_json::Value = match serde_json::from_str(&content) {
			Ok(v) => v,
			Err(_) => return vec![],
		};

		doc.get("scripts")
			.and_then(|s| s.as_object())
			.map(|scripts| {
				scripts
					.keys()
					.filter(|name| Self::is_blocked_script(name))
					.cloned()
					.collect()
			})
			.unwrap_or_default()
	}
}

/// Result of scanning all installed packages for lifecycle scripts.
#[derive(Debug)]
pub struct ScriptAuditResult {
	/// Packages with blocked lifecycle scripts.
	pub blocked: Vec<BlockedPackage>,
	/// Packages trusted to run scripts.
	pub trusted: Vec<String>,
}

/// A package that has lifecycle scripts but is not trusted.
#[derive(Debug)]
pub struct BlockedPackage {
	pub name: String,
	pub scripts: Vec<String>,
}

/// Scan all installed packages in node_modules/.lpm/ for lifecycle scripts.
///
/// Returns an audit result showing which packages have scripts and whether
/// they're trusted or blocked.
pub fn audit_lifecycle_scripts(
	project_dir: &Path,
	policy: &SecurityPolicy,
) -> ScriptAuditResult {
	let lpm_dir = project_dir.join("node_modules").join(".lpm");
	let mut blocked = Vec::new();
	let mut trusted = Vec::new();

	if !lpm_dir.exists() {
		return ScriptAuditResult { blocked, trusted };
	}

	let entries = match std::fs::read_dir(&lpm_dir) {
		Ok(e) => e,
		Err(_) => return ScriptAuditResult { blocked, trusted },
	};

	for entry in entries.flatten() {
		let pkg_dir = entry.path().join("node_modules");
		if !pkg_dir.exists() {
			continue;
		}

		// Each dir inside is the actual package
		let inner_entries = match std::fs::read_dir(&pkg_dir) {
			Ok(e) => e,
			Err(_) => continue,
		};

		for inner in inner_entries.flatten() {
			let pkg_json = inner.path().join("package.json");
			if !pkg_json.exists() {
				continue;
			}

			let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
			if scripts.is_empty() {
				continue;
			}

			let pkg_name = inner.file_name().to_string_lossy().to_string();

			if policy.can_run_scripts(&pkg_name) {
				trusted.push(pkg_name);
			} else {
				blocked.push(BlockedPackage {
					name: pkg_name,
					scripts,
				});
			}
		}
	}

	ScriptAuditResult { blocked, trusted }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_policy_blocks_all() {
		let policy = SecurityPolicy::default_policy();
		assert!(!policy.can_run_scripts("esbuild"));
		assert!(!policy.can_run_scripts("sharp"));
	}

	#[test]
	fn trusted_deps_can_run_scripts() {
		let mut policy = SecurityPolicy::default_policy();
		policy.trusted_dependencies.insert("esbuild".to_string());

		assert!(policy.can_run_scripts("esbuild"));
		assert!(!policy.can_run_scripts("sharp"));
	}

	#[test]
	fn blocked_script_detection() {
		assert!(SecurityPolicy::is_blocked_script("postinstall"));
		assert!(SecurityPolicy::is_blocked_script("preinstall"));
		assert!(SecurityPolicy::is_blocked_script("install"));
		assert!(!SecurityPolicy::is_blocked_script("build"));
		assert!(!SecurityPolicy::is_blocked_script("test"));
		assert!(!SecurityPolicy::is_blocked_script("start"));
	}

	#[test]
	fn detect_scripts_from_package_json() {
		let dir = tempfile::tempdir().unwrap();
		let pkg_json = dir.path().join("package.json");
		std::fs::write(
			&pkg_json,
			r#"{"scripts":{"postinstall":"node setup.js","build":"tsc","preinstall":"echo hi"}}"#,
		)
		.unwrap();

		let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
		assert!(scripts.contains(&"postinstall".to_string()));
		assert!(scripts.contains(&"preinstall".to_string()));
		assert!(!scripts.contains(&"build".to_string()));
	}

	#[test]
	fn load_policy_from_package_json() {
		let dir = tempfile::tempdir().unwrap();
		let pkg_json = dir.path().join("package.json");
		std::fs::write(
			&pkg_json,
			r#"{"name":"test","lpm":{"trustedDependencies":["esbuild","sharp"]}}"#,
		)
		.unwrap();

		let policy = SecurityPolicy::from_package_json(&pkg_json);
		assert!(policy.can_run_scripts("esbuild"));
		assert!(policy.can_run_scripts("sharp"));
		assert!(!policy.can_run_scripts("malware"));
	}
}
