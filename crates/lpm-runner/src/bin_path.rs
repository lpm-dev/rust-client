//! Discover `node_modules/.bin` directories and build an augmented PATH.
//!
//! Walks up from the project directory to find all `node_modules/.bin` dirs,
//! supporting monorepo layouts where workspace root also has a `.bin` dir.

use std::path::{Path, PathBuf};

/// Discover all `node_modules/.bin` directories from `start_dir` upward.
///
/// Returns paths ordered from most specific (project-level) to least specific
/// (workspace root), which is the correct precedence for PATH.
///
/// Walks up the directory tree like Node.js module resolution — doesn't stop
/// at intermediate dirs without package.json (e.g., `packages/` in monorepos).
/// Stops at the first directory that has a `node_modules/.bin` AND a workspace
/// indicator (package.json with workspaces or pnpm-workspace.yaml), or at the
/// filesystem root.
pub fn find_bin_dirs(start_dir: &Path) -> Vec<PathBuf> {
	let mut bin_dirs = Vec::new();
	let mut current = start_dir.to_path_buf();

	loop {
		let bin_dir = current.join("node_modules").join(".bin");
		if bin_dir.is_dir() {
			bin_dirs.push(bin_dir);
		}

		// If this directory is a workspace root, we've reached the top
		if is_workspace_root(&current) {
			break;
		}

		// Stop at filesystem root
		if !current.pop() {
			break;
		}
	}

	bin_dirs
}

/// Check if a directory is a workspace root (has workspaces config).
fn is_workspace_root(dir: &Path) -> bool {
	// Check pnpm-workspace.yaml
	if dir.join("pnpm-workspace.yaml").exists() {
		return true;
	}

	// Check package.json for workspaces field
	let pkg_json = dir.join("package.json");
	if let Ok(content) = std::fs::read_to_string(&pkg_json) {
		if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) {
			return doc.get("workspaces").is_some();
		}
	}

	false
}

/// Build a PATH string with managed runtime and `node_modules/.bin` directories prepended.
///
/// Order (highest priority first):
/// 1. `node_modules/.bin` dirs (project-level, then workspace root)
/// 2. Managed Node.js runtime bin dir (if version is pinned and installed)
/// 3. Existing system PATH
pub fn build_path_with_bins(start_dir: &Path) -> String {
	let bin_dirs = find_bin_dirs(start_dir);
	let existing_path = std::env::var("PATH").unwrap_or_default();
	let separator = if cfg!(windows) { ";" } else { ":" };

	let mut parts: Vec<String> = bin_dirs
		.iter()
		.map(|p| p.to_string_lossy().to_string())
		.collect();

	// Check for a managed Node.js runtime and prepend its bin dir
	if let Some(runtime_bin) = detect_managed_runtime_bin(start_dir) {
		parts.push(runtime_bin);
	}

	if !existing_path.is_empty() {
		parts.push(existing_path);
	}

	parts.join(separator)
}

/// Detect if the project has a pinned Node.js version that is installed locally.
///
/// If found, returns the path to the managed runtime's `bin/` directory.
/// Messaging is handled by `ensure_runtime()` in the CLI layer — this function
/// is a silent PATH builder.
fn detect_managed_runtime_bin(project_dir: &Path) -> Option<String> {
	let detected = lpm_runtime::detect::detect_node_version(project_dir)?;

	// For simple version specs (just a number like "22" or "22.5.0"), check if installed
	let spec = &detected.spec;

	// Strip range operators for lookup — we only auto-switch for pinned/simple specs
	let clean_spec = spec
		.trim_start_matches(">=")
		.trim_start_matches("^")
		.trim_start_matches("~")
		.trim_start_matches('>');

	// Try to find an installed version matching this spec
	let installed = lpm_runtime::node::list_installed().ok()?;
	let matched = lpm_runtime::node::find_matching_installed(clean_spec, &installed)?;

	let bin_dir = lpm_runtime::node::node_bin_dir(&matched).ok()?;
	if bin_dir.exists() {
		tracing::debug!(
			"using managed node {} (from {})",
			matched,
			detected.source
		);
		Some(bin_dir.to_string_lossy().to_string())
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn find_bin_dirs_single_project() {
		let dir = tempfile::tempdir().unwrap();
		let bin = dir.path().join("node_modules/.bin");
		fs::create_dir_all(&bin).unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();

		let dirs = find_bin_dirs(dir.path());
		assert_eq!(dirs.len(), 1);
		assert_eq!(dirs[0], bin);
	}

	#[test]
	fn find_bin_dirs_monorepo() {
		let root = tempfile::tempdir().unwrap();
		let root_bin = root.path().join("node_modules/.bin");
		fs::create_dir_all(&root_bin).unwrap();
		fs::write(root.path().join("package.json"), r#"{"workspaces":["packages/*"]}"#).unwrap();

		let pkg_dir = root.path().join("packages/my-app");
		let pkg_bin = pkg_dir.join("node_modules/.bin");
		fs::create_dir_all(&pkg_bin).unwrap();
		fs::write(pkg_dir.join("package.json"), "{}").unwrap();

		let dirs = find_bin_dirs(&pkg_dir);
		// Should find both: package-level first, then root
		assert_eq!(dirs.len(), 2);
		assert_eq!(dirs[0], pkg_bin);
		assert_eq!(dirs[1], root_bin);
	}

	#[test]
	fn find_bin_dirs_no_bin_dir() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		// No node_modules/.bin exists

		let dirs = find_bin_dirs(dir.path());
		assert!(dirs.is_empty());
	}

	#[test]
	fn build_path_prepends_bins() {
		let dir = tempfile::tempdir().unwrap();
		let bin = dir.path().join("node_modules/.bin");
		fs::create_dir_all(&bin).unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();

		let path = build_path_with_bins(dir.path());
		assert!(path.starts_with(&bin.to_string_lossy().to_string()));
	}
}
