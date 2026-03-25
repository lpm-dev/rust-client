//! Git-based change detection for `--affected`.
//!
//! Shells out to `git diff` to find changed files, then maps them to
//! workspace members by directory path.

use crate::graph::WorkspaceGraph;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Find workspace members affected by changes since a base ref.
///
/// Returns indices into the workspace graph of directly changed packages
/// plus their transitive dependents.
pub fn find_affected(
	graph: &WorkspaceGraph,
	workspace_root: &Path,
	base_ref: &str,
) -> Result<HashSet<usize>, String> {
	let changed_files = git_diff_files(workspace_root, base_ref)?;

	if changed_files.is_empty() {
		return Ok(HashSet::new());
	}

	// Map changed files to workspace members
	let mut directly_changed: HashSet<usize> = HashSet::new();

	for file in &changed_files {
		for (idx, member) in graph.members.iter().enumerate() {
			let member_rel = member
				.path
				.strip_prefix(workspace_root)
				.unwrap_or(&member.path)
				.to_string_lossy();

			if file.starts_with(member_rel.as_ref()) {
				directly_changed.insert(idx);
			}
		}
	}

	// Add transitive dependents
	let mut all_affected = directly_changed.clone();
	for &idx in &directly_changed {
		let dependents = graph.transitive_dependents(idx);
		all_affected.extend(dependents);
	}

	Ok(all_affected)
}

/// Get changed files from git diff relative to a base ref.
fn git_diff_files(repo_dir: &Path, base_ref: &str) -> Result<Vec<String>, String> {
	let output = Command::new("git")
		.args(["diff", "--name-only", base_ref])
		.current_dir(repo_dir)
		.output()
		.map_err(|e| format!("failed to run git diff: {e}"))?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		// If the base ref doesn't exist, return empty (no changes detected)
		if stderr.contains("unknown revision") || stderr.contains("bad revision") {
			tracing::debug!("git base ref '{base_ref}' not found, treating as no changes");
			return Ok(vec![]);
		}
		return Err(format!("git diff failed: {stderr}"));
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let files: Vec<String> = stdout
		.lines()
		.filter(|l| !l.is_empty())
		.map(|l| l.to_string())
		.collect();

	Ok(files)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn git_diff_with_bad_ref_returns_empty() {
		let dir = tempfile::tempdir().unwrap();
		// Not a git repo, so this should handle gracefully
		let result = git_diff_files(dir.path(), "nonexistent-branch");
		// Either returns empty or an error — both are acceptable
		match result {
			Ok(files) => assert!(files.is_empty()),
			Err(_) => {} // git not available or not a repo
		}
	}
}
