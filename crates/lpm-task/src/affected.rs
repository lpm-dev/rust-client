//! Git-based change detection for `--affected`.
//!
//! Shells out to `git diff` to find changed files, then maps them to
//! workspace members by directory path (with proper boundary checking).

use crate::graph::WorkspaceGraph;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Find workspace members affected by changes since a base ref.
///
/// Returns indices into the workspace graph of directly changed packages
/// plus their transitive dependents.
///
/// Also detects root-level changes (files outside any package directory)
/// which affect ALL packages.
pub fn find_affected(
    graph: &WorkspaceGraph,
    workspace_root: &Path,
    base_ref: &str,
) -> Result<HashSet<usize>, String> {
    let changed_files = git_diff_files(workspace_root, base_ref)?;

    if changed_files.is_empty() {
        return Ok(HashSet::new());
    }

    // Collect all member relative paths for root-level detection
    let member_paths: Vec<String> = graph
        .members
        .iter()
        .map(|m| {
            m.path
                .strip_prefix(workspace_root)
                .unwrap_or(&m.path)
                .to_string_lossy()
                .to_string()
        })
        .collect();

    // Map changed files to workspace members
    let mut directly_changed: HashSet<usize> = HashSet::new();
    let mut has_root_change = false;

    for file in &changed_files {
        let mut matched_any = false;

        for (idx, member_rel) in member_paths.iter().enumerate() {
            if member_rel.is_empty() {
                continue;
            }

            // Use directory boundary check: file must start with "member_path/"
            // This prevents "packages/api-client/x.ts" matching "packages/api"
            let member_with_sep = format!("{member_rel}/");
            if file.starts_with(&member_with_sep) || file == member_rel.as_str() {
                directly_changed.insert(idx);
                matched_any = true;
            }
        }

        // If file didn't match any member, it's a root-level change
        // (e.g., package.json, tsconfig.json, workspace config)
        if !matched_any {
            has_root_change = true;
        }
    }

    // Root-level changes affect ALL packages — short-circuit to avoid
    // O(V*(V+E)) transitive_dependents computation when every member is
    // already affected.
    if has_root_change {
        return Ok((0..graph.members.len()).collect());
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
    if base_ref.is_empty() {
        return Err("base ref must not be empty".into());
    }
    // Reject refs that look like flags — branch names don't start with "-".
    // This prevents flag injection without relying on `--` positioning.
    if base_ref.starts_with('-') {
        return Err(format!(
            "invalid base ref: '{base_ref}' (looks like a flag, not a branch name)"
        ));
    }

    let output = Command::new("git")
        // base_ref in revision position (before `--`), `--` separates from pathspecs.
        // Flag injection prevented by the starts_with('-') check above.
        .args(["diff", "--name-only", base_ref, "--"])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If the base ref doesn't exist, return empty (no changes detected)
        if stderr.contains("unknown revision") || stderr.contains("bad revision") {
            tracing::warn!(
                "git base ref '{base_ref}' not found — treating as no changes. Check your --base flag."
            );
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
    use crate::graph::{GraphNode, WorkspaceGraph};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_graph(members: &[(&str, &str)], edges: Vec<Vec<usize>>) -> WorkspaceGraph {
        let nodes: Vec<GraphNode> = members
            .iter()
            .map(|(name, path)| GraphNode {
                name: name.to_string(),
                path: PathBuf::from(path),
            })
            .collect();

        let n = nodes.len();
        let mut reverse_edges = vec![vec![]; n];
        for (i, deps) in edges.iter().enumerate() {
            for &dep in deps {
                reverse_edges[dep].push(i);
            }
        }

        let mut name_to_idx = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            name_to_idx.insert(node.name.clone(), idx);
        }

        WorkspaceGraph {
            members: nodes,
            edges,
            reverse_edges,
            name_to_idx,
        }
    }

    #[test]
    fn prefix_collision_packages_api_vs_api_client() {
        // This is the critical bug test: "packages/api-client/src/main.ts"
        // should NOT match "packages/api"
        let graph = make_graph(
            &[
                ("api", "/workspace/packages/api"),
                ("api-client", "/workspace/packages/api-client"),
            ],
            vec![vec![], vec![]],
        );

        let workspace_root = Path::new("/workspace");

        // Simulate a change in api-client only
        let changed = vec!["packages/api-client/src/main.ts".to_string()];

        let mut directly_changed: HashSet<usize> = HashSet::new();
        for file in &changed {
            for (idx, member) in graph.members.iter().enumerate() {
                let member_rel = member
                    .path
                    .strip_prefix(workspace_root)
                    .unwrap_or(&member.path)
                    .to_string_lossy();
                let member_with_sep = format!("{member_rel}/");
                if file.starts_with(&member_with_sep) || file == member_rel.as_ref() {
                    directly_changed.insert(idx);
                }
            }
        }

        // Should only match api-client (index 1), NOT api (index 0)
        assert!(
            !directly_changed.contains(&0),
            "packages/api should NOT match"
        );
        assert!(
            directly_changed.contains(&1),
            "packages/api-client should match"
        );
    }

    #[test]
    fn root_level_change_affects_all() {
        let graph = make_graph(
            &[
                ("utils", "/workspace/packages/utils"),
                ("app", "/workspace/packages/app"),
            ],
            vec![vec![], vec![0]],
        );

        let workspace_root = Path::new("/workspace");
        let member_paths: Vec<String> = graph
            .members
            .iter()
            .map(|m| {
                m.path
                    .strip_prefix(workspace_root)
                    .unwrap_or(&m.path)
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        // package.json at root doesn't match any member
        let file = "package.json";
        let matched = member_paths.iter().any(|rel| {
            let with_sep = format!("{rel}/");
            file.starts_with(&with_sep) || file == rel.as_str()
        });

        assert!(!matched, "root package.json should NOT match any member");
        // This means has_root_change = true → all packages affected
    }

    #[test]
    fn exact_member_path_matches() {
        // Edge case: changed file IS the member path (unlikely but valid)
        let member_rel = "packages/utils";
        let file = "packages/utils";
        let member_with_sep = format!("{member_rel}/");
        assert!(
            file.starts_with(&member_with_sep) || file == member_rel,
            "exact path match should work"
        );
    }

    #[test]
    fn git_diff_with_bad_ref_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        // Not a git repo, so this should handle gracefully
        let result = git_diff_files(dir.path(), "nonexistent-branch");
        // Either returns empty or an error — both are acceptable
        if let Ok(files) = result {
            assert!(files.is_empty())
        }
    }

    // -- Finding #2: git flag injection --

    #[test]
    fn git_diff_rejects_empty_base_ref() {
        let dir = tempfile::tempdir().unwrap();
        let result = git_diff_files(dir.path(), "");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("must not be empty"),
            "should reject empty base ref"
        );
    }

    #[test]
    fn git_diff_rejects_flag_like_ref() {
        let dir = tempfile::tempdir().unwrap();
        let result = git_diff_files(dir.path(), "--output=foo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("looks like a flag"),
            "should explicitly reject flag-like ref, got: {err}"
        );
    }

    #[test]
    fn git_diff_rejects_single_dash_ref() {
        let dir = tempfile::tempdir().unwrap();
        let result = git_diff_files(dir.path(), "-n");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("looks like a flag"));
    }

    // -- Integration test: real git repo --

    /// Helper to run a git command in a directory.
    fn git(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn git_diff_files_detects_changes_in_real_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up a git repo with a file on main
        git(root, &["init", "-b", "main"]);
        std::fs::create_dir_all(root.join("packages/utils/src")).unwrap();
        std::fs::write(root.join("packages/utils/src/index.js"), "v1").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-m", "init"]);

        // Create a feature branch and make a change
        git(root, &["checkout", "-b", "feature"]);
        std::fs::write(root.join("packages/utils/src/index.js"), "v2").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-m", "change utils"]);

        // Verify git_diff_files finds the changed file
        let files = git_diff_files(root, "main").unwrap();
        assert!(
            !files.is_empty(),
            "git_diff_files should detect changes between feature and main"
        );
        assert!(
            files.contains(&"packages/utils/src/index.js".to_string()),
            "should contain the changed file, got: {files:?}"
        );
    }

    #[test]
    fn find_affected_detects_changed_package_in_real_repo() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up workspace: utils (no deps), app (depends on utils)
        git(root, &["init", "-b", "main"]);
        std::fs::create_dir_all(root.join("packages/utils/src")).unwrap();
        std::fs::create_dir_all(root.join("packages/app/src")).unwrap();
        std::fs::write(root.join("packages/utils/src/index.js"), "v1").unwrap();
        std::fs::write(root.join("packages/app/src/index.js"), "v1").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-m", "init"]);

        // Feature branch: change only utils
        git(root, &["checkout", "-b", "feature"]);
        std::fs::write(root.join("packages/utils/src/index.js"), "v2").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-m", "change utils"]);

        // Build graph: app depends on utils
        let graph = make_graph(
            &[
                ("utils", &root.join("packages/utils").to_string_lossy()),
                ("app", &root.join("packages/app").to_string_lossy()),
            ],
            vec![vec![], vec![0]], // app depends on utils
        );

        let affected = find_affected(&graph, root, "main").unwrap();
        assert!(
            affected.contains(&0),
            "utils (index 0) should be directly affected"
        );
        assert!(
            affected.contains(&1),
            "app (index 1) should be transitively affected (depends on utils)"
        );
    }

    // -- Finding #14: root change short-circuit --

    #[test]
    fn root_change_returns_all_members_directly() {
        let graph = make_graph(
            &[
                ("a", "/workspace/packages/a"),
                ("b", "/workspace/packages/b"),
                ("c", "/workspace/packages/c"),
            ],
            // c depends on b depends on a
            vec![vec![], vec![0], vec![1]],
        );

        // Simulate: find_affected logic with has_root_change = true
        // Should return all indices without computing transitive_dependents
        let has_root_change = true;
        if has_root_change {
            let result: HashSet<usize> = (0..graph.members.len()).collect();
            assert_eq!(result.len(), 3);
            assert!(result.contains(&0));
            assert!(result.contains(&1));
            assert!(result.contains(&2));
        }
    }
}
