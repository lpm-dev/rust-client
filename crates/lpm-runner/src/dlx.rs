//! `lpm dlx` — run a package binary without installing it into the project.
//!
//! Creates a temporary directory, installs the package there, and executes
//! its bin entry. The temp directory is cached by package spec for reuse.
//!
//! Equivalent to `npx`, `pnpm dlx`, `bunx`.

use crate::bin_path;
use crate::shell::{self, ShellCommand};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Get the dlx cache directory for a given package spec.
///
/// Returns `~/.lpm/dlx-cache/{hash}/` where hash is derived from the package spec.
pub fn dlx_cache_dir(package_spec: &str) -> Result<PathBuf, LpmError> {
	let lpm_home = dirs_home()?.join(".lpm").join("dlx-cache");

	// Simple hash of the package spec for cache key
	let hash = simple_hash(package_spec);
	Ok(lpm_home.join(hash))
}

/// Run a package binary without installing it into the project.
///
/// # Arguments
/// * `project_dir` — the current working directory (for context)
/// * `package_spec` — package to run (e.g., "cowsay", "create-next-app@latest")
/// * `extra_args` — additional arguments passed to the binary
pub fn dlx(
	project_dir: &Path,
	package_spec: &str,
	extra_args: &[String],
) -> Result<(), LpmError> {
	let cache_dir = dlx_cache_dir(package_spec)?;
	let bin_dir = cache_dir.join("node_modules").join(".bin");

	// Check if already cached (has node_modules/.bin)
	let needs_install = !bin_dir.is_dir();

	if needs_install {
		std::fs::create_dir_all(&cache_dir).map_err(|e| {
			LpmError::Script(format!("failed to create dlx cache dir: {e}"))
		})?;

		// Create a minimal package.json so npm/node can work
		let pkg_json = cache_dir.join("package.json");
		std::fs::write(&pkg_json, r#"{"private": true}"#).map_err(|e| {
			LpmError::Script(format!("failed to create package.json for dlx: {e}"))
		})?;

		// Install the package using npm (dlx doesn't require lpm registry)
		// This is a pragmatic choice — dlx packages are typically npm packages
		let install_cmd = format!("npm install --no-save {package_spec}");
		let path = std::env::var("PATH").unwrap_or_default();

		let no_envs = HashMap::new();
		let status = shell::spawn_shell(&ShellCommand {
			command: &install_cmd,
			cwd: &cache_dir,
			path: &path,
			envs: &no_envs,
		})?;

		if !status.success() {
			// Clean up failed install
			let _ = std::fs::remove_dir_all(&cache_dir);
			return Err(LpmError::Script(format!(
				"failed to install '{package_spec}' for dlx"
			)));
		}
	}

	// Extract the package name (without version) for bin lookup
	let pkg_name = package_spec
		.split('@')
		.next()
		.unwrap_or(package_spec);
	let pkg_name = if package_spec.starts_with('@') {
		// Scoped package: @scope/name@version → @scope/name
		let without_prefix = &package_spec[1..];
		if let Some(idx) = without_prefix.find('@') {
			&package_spec[..idx + 1]
		} else {
			package_spec
		}
	} else {
		pkg_name
	};

	// Build the command: the package name as a binary (found via PATH)
	// Strip scope for the binary name (e.g., @scope/foo → foo)
	let bin_name = pkg_name.rsplit('/').next().unwrap_or(pkg_name);

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
fn simple_hash(s: &str) -> String {
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
}
