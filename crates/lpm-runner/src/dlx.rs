//! `lpm dlx` — utilities for running packages without installing them.
//!
//! Cache management, package name parsing, and binary execution.
//! The install step is handled in the CLI layer (self-hosted via LPM's resolver/store/linker).

use crate::bin_path;
use crate::shell::{self, ShellCommand};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default cache TTL in seconds (24 hours).
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Get the dlx cache directory for a given package spec.
///
/// Returns `~/.lpm/dlx-cache/{hash}/` where hash is derived from the package spec.
pub fn dlx_cache_dir(package_spec: &str) -> Result<PathBuf, LpmError> {
	let lpm_home = dirs_home()?.join(".lpm").join("dlx-cache");

	// Simple hash of the package spec for cache key
	let hash = simple_hash(package_spec);
	Ok(lpm_home.join(hash))
}

/// Check if a cached dlx installation is still fresh.
///
/// Returns `true` if the cache exists and was modified within `ttl_secs`.
pub fn is_cache_fresh(cache_dir: &Path, ttl_secs: u64) -> bool {
	let bin_dir = cache_dir.join("node_modules").join(".bin");
	if !bin_dir.is_dir() {
		return false;
	}

	// Check mtime of the package.json (written at install time)
	let pkg_json = cache_dir.join("package.json");
	match std::fs::metadata(&pkg_json) {
		Ok(meta) => {
			if let Ok(modified) = meta.modified() {
				let age = std::time::SystemTime::now()
					.duration_since(modified)
					.unwrap_or_default();
				age.as_secs() < ttl_secs
			} else {
				false
			}
		}
		Err(_) => false,
	}
}

/// Touch the cache to reset the TTL (called after successful install).
pub fn touch_cache(cache_dir: &Path) {
	let pkg_json = cache_dir.join("package.json");
	if pkg_json.exists() {
		// Update mtime by rewriting the file
		if let Ok(content) = std::fs::read_to_string(&pkg_json) {
			let _ = std::fs::write(&pkg_json, content);
		}
	}
}

/// Parse a package spec into (name, version_spec).
///
/// Examples:
/// - `"cowsay"` → `("cowsay", "*")`
/// - `"cowsay@1.0.0"` → `("cowsay", "1.0.0")`
/// - `"create-next-app@latest"` → `("create-next-app", "latest")`
/// - `"@scope/pkg"` → `("@scope/pkg", "*")`
/// - `"@scope/pkg@2.0"` → `("@scope/pkg", "2.0")`
pub fn parse_package_spec(spec: &str) -> (String, String) {
	if spec.starts_with('@') {
		// Scoped package: @scope/name or @scope/name@version
		// Find the second '@' (version separator) — skip the leading '@'
		let rest = &spec[1..];
		if let Some(at_pos) = rest.find('@') {
			let name = &spec[..at_pos + 1]; // includes leading @
			let version = &rest[at_pos + 1..];
			(name.to_string(), version.to_string())
		} else {
			// No version — @scope/name
			(spec.to_string(), "*".to_string())
		}
	} else if let Some(at_pos) = spec.find('@') {
		// Unscoped: name@version
		let name = &spec[..at_pos];
		let version = &spec[at_pos + 1..];
		(name.to_string(), version.to_string())
	} else {
		// No version
		(spec.to_string(), "*".to_string())
	}
}

/// Extract the binary name from a package spec.
///
/// Strips scope and version: `@scope/foo@1.0` → `foo`, `cowsay@2` → `cowsay`.
pub fn bin_name_from_spec(spec: &str) -> &str {
	let (name, _) = parse_package_spec(spec);
	// Strip scope — find the last '/' in the name part
	let name_part = if name.contains('/') {
		name.rsplit('/').next().unwrap_or(&name)
	} else {
		&name
	};
	// Since parse_package_spec returns owned strings, we need to work with the original spec
	let name_str = if spec.starts_with('@') {
		let rest = &spec[1..];
		if let Some(slash_pos) = rest.find('/') {
			let after_slash = &rest[slash_pos + 1..];
			// Strip version if present
			if let Some(at_pos) = after_slash.find('@') {
				&after_slash[..at_pos]
			} else {
				after_slash
			}
		} else {
			spec
		}
	} else {
		// Unscoped — strip version
		if let Some(at_pos) = spec.find('@') {
			&spec[..at_pos]
		} else {
			spec
		}
	};
	name_str
}

/// Execute the dlx binary from the cache directory.
///
/// Builds PATH with the cache's `.bin` dir prepended and spawns the binary.
pub fn exec_dlx_binary(
	project_dir: &Path,
	cache_dir: &Path,
	package_spec: &str,
	extra_args: &[String],
) -> Result<(), LpmError> {
	let bin_dir = cache_dir.join("node_modules").join(".bin");
	let bin_name = bin_name_from_spec(package_spec);

	let mut cmd_parts = vec![bin_name.to_string()];
	for arg in extra_args {
		cmd_parts.push(arg.clone());
	}
	let full_cmd = cmd_parts.join(" ");

	// Build PATH with the dlx cache's .bin prepended
	let mut path_parts = vec![bin_dir.to_string_lossy().to_string()];

	// Also include the project's .bin dirs
	let project_bin_dirs = bin_path::find_bin_dirs(project_dir);
	for d in &project_bin_dirs {
		path_parts.push(d.to_string_lossy().to_string());
	}

	let existing_path = std::env::var("PATH").unwrap_or_default();
	if !existing_path.is_empty() {
		path_parts.push(existing_path);
	}

	let separator = if cfg!(windows) { ";" } else { ":" };
	let path = path_parts.join(separator);

	let no_envs = HashMap::new();
	let status = shell::spawn_shell(&ShellCommand {
		command: &full_cmd,
		cwd: project_dir,
		path: &path,
		envs: &no_envs,
	})?;

	if !status.success() {
		std::process::exit(shell::exit_code(&status));
	}

	Ok(())
}

/// Simple string hash for cache directory naming.
pub fn simple_hash(s: &str) -> String {
	use std::hash::{Hash, Hasher};
	let mut hasher = std::collections::hash_map::DefaultHasher::new();
	s.hash(&mut hasher);
	format!("{:016x}", hasher.finish())
}

/// Get the user's home directory.
fn dirs_home() -> Result<PathBuf, LpmError> {
	dirs::home_dir().ok_or_else(|| {
		LpmError::Script("could not determine home directory".into())
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn dlx_cache_dir_is_stable() {
		let dir1 = dlx_cache_dir("cowsay").unwrap();
		let dir2 = dlx_cache_dir("cowsay").unwrap();
		assert_eq!(dir1, dir2);
	}

	#[test]
	fn dlx_cache_dir_differs_for_different_specs() {
		let dir1 = dlx_cache_dir("cowsay").unwrap();
		let dir2 = dlx_cache_dir("cowsay@1.0.0").unwrap();
		assert_ne!(dir1, dir2);
	}

	#[test]
	fn simple_hash_deterministic() {
		assert_eq!(simple_hash("test"), simple_hash("test"));
		assert_ne!(simple_hash("a"), simple_hash("b"));
	}

	// --- parse_package_spec tests ---

	#[test]
	fn parse_unscoped_no_version() {
		let (name, ver) = parse_package_spec("cowsay");
		assert_eq!(name, "cowsay");
		assert_eq!(ver, "*");
	}

	#[test]
	fn parse_unscoped_with_version() {
		let (name, ver) = parse_package_spec("cowsay@1.0.0");
		assert_eq!(name, "cowsay");
		assert_eq!(ver, "1.0.0");
	}

	#[test]
	fn parse_unscoped_latest() {
		let (name, ver) = parse_package_spec("create-next-app@latest");
		assert_eq!(name, "create-next-app");
		assert_eq!(ver, "latest");
	}

	#[test]
	fn parse_scoped_no_version() {
		let (name, ver) = parse_package_spec("@angular/cli");
		assert_eq!(name, "@angular/cli");
		assert_eq!(ver, "*");
	}

	#[test]
	fn parse_scoped_with_version() {
		let (name, ver) = parse_package_spec("@angular/cli@17.0.0");
		assert_eq!(name, "@angular/cli");
		assert_eq!(ver, "17.0.0");
	}

	#[test]
	fn parse_scoped_latest() {
		let (name, ver) = parse_package_spec("@sveltejs/kit@latest");
		assert_eq!(name, "@sveltejs/kit");
		assert_eq!(ver, "latest");
	}

	// --- bin_name_from_spec tests ---

	#[test]
	fn bin_name_unscoped() {
		assert_eq!(bin_name_from_spec("cowsay"), "cowsay");
		assert_eq!(bin_name_from_spec("cowsay@1.0"), "cowsay");
	}

	#[test]
	fn bin_name_scoped() {
		assert_eq!(bin_name_from_spec("@angular/cli"), "cli");
		assert_eq!(bin_name_from_spec("@angular/cli@17.0"), "cli");
		assert_eq!(bin_name_from_spec("@sveltejs/kit@latest"), "kit");
	}

	// --- is_cache_fresh tests ---

	#[test]
	fn cache_fresh_no_dir() {
		let dir = tempfile::tempdir().unwrap();
		assert!(!is_cache_fresh(dir.path(), 3600));
	}

	#[test]
	fn cache_fresh_with_recent_install() {
		let dir = tempfile::tempdir().unwrap();
		let bin_dir = dir.path().join("node_modules/.bin");
		std::fs::create_dir_all(&bin_dir).unwrap();
		std::fs::write(dir.path().join("package.json"), "{}").unwrap();

		assert!(is_cache_fresh(dir.path(), 3600));
	}

	#[test]
	fn cache_stale_zero_ttl() {
		let dir = tempfile::tempdir().unwrap();
		let bin_dir = dir.path().join("node_modules/.bin");
		std::fs::create_dir_all(&bin_dir).unwrap();
		std::fs::write(dir.path().join("package.json"), "{}").unwrap();

		// With 0 TTL, cache is always stale
		assert!(!is_cache_fresh(dir.path(), 0));
	}
}
