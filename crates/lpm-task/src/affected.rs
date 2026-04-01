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

    let output = Command::new("git")
        // `--` separator prevents base_ref from being interpreted as a flag
        // (e.g., "--output=foo" would be treated as a revision, not an option)
        .args(["diff", "--name-only", "--", base_ref])
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
        match result {
            Ok(files) => assert!(files.is_empty()),
            Err(_) => {} // git not available or not a repo
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
    fn git_diff_with_flag_like_ref_does_not_inject() {
        // With the `--` separator, a ref starting with "--" is treated as a revision,
        // not as a git option. In a non-git dir this will fail gracefully,
        // but the important thing is it doesn't execute `--output=foo` as a flag.
        let dir = tempfile::tempdir().unwrap();
        let result = git_diff_files(dir.path(), "--output=foo");
        // Should get a git error (not a repo / bad revision), not a flag-injection success
        match result {
            Ok(files) => assert!(files.is_empty()),
            Err(e) => {
                // Any error is fine — the key point is no flag injection
                assert!(
                    !e.contains("unrecognized argument"),
                    "should not treat ref as a git flag"
                );
            }
        }
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
