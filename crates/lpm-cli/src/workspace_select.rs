//! Workspace target selection shared by every workspace-aware command.
//!
//! `lpm run`, `lpm lint`, `lpm fmt`, `lpm check`, `lpm test`, and `lpm bench`
//! all need to translate `--all` / `--filter` / `--affected` into a set of
//! workspace member indices. This module owns that translation so every
//! consumer sees identical filter semantics.
//!
//! Execution policy (parallelism, topology, JSON envelope shape) lives in
//! each command's own dispatch path — only the selection step is shared.

use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::Path;

/// Compute the workspace target set from the CLI flags. Wraps the shared
/// `FilterEngine` so every consumer sees identical filter semantics.
///
/// Composition rules:
///
/// - **No filter, no `--affected`** (caller already verified workspace mode is
///   active via `--all`): every member.
/// - **`--affected` only**: directly changed packages plus their transitive
///   dependents via `find_affected`. This matches the pre-existing contract.
/// - **`--filter <expr>...`**: parsed and evaluated through `FilterEngine`.
///   Multi-filter unions are handled inside the engine.
/// - **`--filter` AND `--affected`**: union of both target sets — `--affected`
///   is treated as an implicit additional positive filter.
pub fn select_workspace_target_set(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    workspace_root: &Path,
    filters: &[String],
    affected: bool,
    base_ref: &str,
) -> Result<HashSet<usize>, LpmError> {
    use lpm_task::filter::{FilterEngine, FilterExpr};

    if filters.is_empty() && !affected {
        return Ok((0..ws_graph.len()).collect());
    }

    let engine = FilterEngine::new(ws_graph, workspace_root);

    let mut exprs: Vec<FilterExpr> = Vec::with_capacity(filters.len() + 1);
    for raw in filters {
        let parsed = FilterEngine::parse(raw).map_err(|e| {
            LpmError::Script(format!(
                "invalid --filter {raw:?}: {e}\n  \
                 (substring matching is not supported; use a glob like '*{raw}*' \
                 if you intended a partial match.)"
            ))
        })?;
        exprs.push(parsed);
    }

    let affected_set: HashSet<usize> = if affected {
        lpm_task::affected::find_affected(ws_graph, workspace_root, base_ref)
            .map_err(LpmError::Script)?
    } else {
        HashSet::new()
    };

    let filter_target: HashSet<usize> = if exprs.is_empty() {
        HashSet::new()
    } else {
        engine
            .evaluate(&exprs)
            .map_err(|e| LpmError::Script(format!("filter error: {e}")))?
            .into_iter()
            .collect()
    };

    let mut target_set: HashSet<usize> = filter_target;
    target_set.extend(affected_set);
    Ok(target_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_task::graph::{GraphNode, WorkspaceGraph};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_workspace_graph() -> WorkspaceGraph {
        let members = vec![
            GraphNode {
                name: "pkg-a".into(),
                path: PathBuf::from("packages/pkg-a"),
            },
            GraphNode {
                name: "pkg-b".into(),
                path: PathBuf::from("packages/pkg-b"),
            },
            GraphNode {
                name: "tooling-app".into(),
                path: PathBuf::from("apps/tooling-app"),
            },
        ];
        let edges = vec![vec![], vec![0], vec![1]];
        let reverse_edges = vec![vec![1], vec![2], vec![]];
        let name_to_idx = HashMap::from([
            ("pkg-a".to_string(), 0usize),
            ("pkg-b".to_string(), 1usize),
            ("tooling-app".to_string(), 2usize),
        ]);
        WorkspaceGraph {
            members,
            edges,
            reverse_edges,
            name_to_idx,
        }
    }

    #[test]
    fn no_filter_no_affected_returns_all_members() {
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(&graph, Path::new("."), &[], false, "main")
            .expect("no-filter no-affected mode should succeed");
        assert_eq!(result, HashSet::from([0usize, 1, 2]));
    }

    #[test]
    fn exact_name_filter_selects_one_member() {
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["pkg-b".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([1usize]));
    }

    #[test]
    fn glob_filter_matches_multiple_members() {
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["pkg-*".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([0usize, 1]));
    }

    #[test]
    fn d2_substring_no_longer_matches() {
        // D2 REGRESSION: bare `pkg` must NOT substring-match `pkg-a`/`pkg-b`.
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["pkg".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert!(
            result.is_empty(),
            "D2: bare 'pkg' must NOT match 'pkg-a' / 'pkg-b' via substring (use 'pkg-*' instead)"
        );
    }

    #[test]
    fn d2_invalid_syntax_error_message_suggests_glob() {
        let graph = make_workspace_graph();
        let err = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["foo!bar".to_string()],
            false,
            "main",
        )
        .expect_err("invalid syntax must error");
        let msg = err.to_string();
        assert!(
            msg.contains("substring matching is not supported") && msg.contains("glob"),
            "error must mention the substring → glob migration, got: {msg}"
        );
    }

    #[test]
    fn multi_filter_unions_results() {
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["pkg-a".to_string(), "tooling-app".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([0usize, 2]));
    }

    #[test]
    fn forward_dependents_closure() {
        // ...pkg-a expands to {pkg-a, pkg-b, tooling-app}
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["...pkg-a".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([0usize, 1, 2]));
    }

    #[test]
    fn deps_closure() {
        // tooling-app... = {tooling-app, pkg-b, pkg-a}
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["tooling-app...".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([0usize, 1, 2]));
    }

    #[test]
    fn exclude_subtracts_from_union() {
        // pkg-* + tooling-app − pkg-a = {pkg-b, tooling-app}
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &[
                "pkg-*".to_string(),
                "tooling-app".to_string(),
                "!pkg-a".to_string(),
            ],
            false,
            "main",
        )
        .unwrap();
        assert_eq!(result, HashSet::from([1usize, 2]));
    }

    #[test]
    fn filter_returns_empty_for_no_match() {
        // Empty result is OK at this layer (caller handles --fail-if-no-match)
        let graph = make_workspace_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &["does-not-exist".to_string()],
            false,
            "main",
        )
        .unwrap();
        assert!(result.is_empty());
    }
}
