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
/// - **`--filter-prod <expr>...`**: same parser, but closure operators walk
///   only production graph edges.
/// - **`--filter` AND `--affected`**: union of both target sets — `--affected`
///   is treated as an implicit additional positive filter.
pub fn select_workspace_target_set(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    workspace_root: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    affected: bool,
    base_ref: &str,
) -> Result<HashSet<usize>, LpmError> {
    if filters.is_empty() && filter_prod.is_empty() && !affected {
        return Ok((0..ws_graph.len()).collect());
    }

    let exprs = parse_filter_set(filters, false)?;
    let prod_exprs = parse_filter_set(filter_prod, true)?;
    let needs_changed_files = affected
        || exprs
            .iter()
            .any(lpm_task::filter::FilterExpr::contains_git_ref)
        || prod_exprs
            .iter()
            .any(lpm_task::filter::FilterExpr::contains_git_ref);
    let changed_files_ignore_patterns =
        if needs_changed_files || !changed_files_ignore_pattern.is_empty() {
            crate::workspace_filter_config::resolve_changed_files_ignore_patterns(
                workspace_root,
                changed_files_ignore_pattern,
            )?
        } else {
            Vec::new()
        };

    let affected_set: HashSet<usize> = if affected {
        lpm_task::affected::find_affected_with_options(
            ws_graph,
            workspace_root,
            base_ref,
            lpm_task::affected::AffectedOptions {
                changed_files_ignore_patterns: &changed_files_ignore_patterns,
            },
        )
        .map_err(LpmError::Script)?
    } else {
        HashSet::new()
    };

    let mut target_set = evaluate_filter_set(
        ws_graph,
        workspace_root,
        &exprs,
        false,
        &changed_files_ignore_patterns,
    )?;
    target_set.extend(evaluate_filter_set(
        ws_graph,
        workspace_root,
        &prod_exprs,
        true,
        &changed_files_ignore_patterns,
    )?);
    target_set.extend(affected_set);
    Ok(target_set)
}

fn parse_filter_set(
    filters: &[String],
    follow_prod_deps_only: bool,
) -> Result<Vec<lpm_task::filter::FilterExpr>, LpmError> {
    use lpm_task::filter::FilterEngine;
    let flag_name = if follow_prod_deps_only {
        "--filter-prod"
    } else {
        "--filter"
    };
    let mut exprs = Vec::with_capacity(filters.len());
    for raw in filters {
        let parsed = FilterEngine::parse(raw).map_err(|e| {
            LpmError::Script(format!(
                "invalid {flag_name} {raw:?}: {e}\n  \
                 (substring matching is not supported; use a glob like '*{raw}*' \
                 if you intended a partial match.)"
            ))
        })?;
        exprs.push(parsed);
    }
    Ok(exprs)
}

fn evaluate_filter_set(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    workspace_root: &Path,
    filters: &[lpm_task::filter::FilterExpr],
    follow_prod_deps_only: bool,
    changed_files_ignore_patterns: &[String],
) -> Result<HashSet<usize>, LpmError> {
    use lpm_task::filter::{FilterEngine, FilterOptions};

    if filters.is_empty() {
        return Ok(HashSet::new());
    }

    let engine = FilterEngine::with_options(
        ws_graph,
        workspace_root,
        FilterOptions {
            follow_prod_deps_only,
            changed_files_ignore_patterns,
        },
    );
    Ok(engine
        .evaluate(filters)
        .map_err(|e| LpmError::Script(format!("filter error: {e}")))?
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_task::graph::{DependencyEdge, DependencyKind, GraphNode, WorkspaceGraph};
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
        let (dependency_edges, reverse_dependency_edges) = typed_dependency_edges(&edges);
        let name_to_idx = HashMap::from([
            ("pkg-a".to_string(), 0usize),
            ("pkg-b".to_string(), 1usize),
            ("tooling-app".to_string(), 2usize),
        ]);
        WorkspaceGraph {
            members,
            edges,
            reverse_edges,
            dependency_edges,
            reverse_dependency_edges,
            name_to_idx,
        }
    }

    fn typed_dependency_edges(
        edges: &[Vec<usize>],
    ) -> (Vec<Vec<DependencyEdge>>, Vec<Vec<DependencyEdge>>) {
        let mut dependency_edges = vec![vec![]; edges.len()];
        let mut reverse_dependency_edges = vec![vec![]; edges.len()];
        for (idx, deps) in edges.iter().enumerate() {
            for &dep in deps {
                dependency_edges[idx].push(DependencyEdge {
                    target: dep,
                    kind: DependencyKind::Dependency,
                });
                reverse_dependency_edges[dep].push(DependencyEdge {
                    target: idx,
                    kind: DependencyKind::Dependency,
                });
            }
        }
        (dependency_edges, reverse_dependency_edges)
    }

    fn make_filter_prod_graph() -> WorkspaceGraph {
        let members = vec![
            GraphNode {
                name: "project-2".into(),
                path: PathBuf::from("packages/project-2"),
            },
            GraphNode {
                name: "project-3".into(),
                path: PathBuf::from("packages/project-3"),
            },
            GraphNode {
                name: "project-1".into(),
                path: PathBuf::from("packages/project-1"),
            },
            GraphNode {
                name: "project-4".into(),
                path: PathBuf::from("packages/project-4"),
            },
        ];
        let edges = vec![vec![], vec![0], vec![1], vec![1]];
        let reverse_edges = vec![vec![1], vec![2, 3], vec![], vec![]];
        let dependency_edges = vec![
            vec![],
            vec![DependencyEdge {
                target: 0,
                kind: DependencyKind::Dependency,
            }],
            vec![DependencyEdge {
                target: 1,
                kind: DependencyKind::Dependency,
            }],
            vec![DependencyEdge {
                target: 1,
                kind: DependencyKind::DevDependency,
            }],
        ];
        let reverse_dependency_edges = vec![
            vec![DependencyEdge {
                target: 1,
                kind: DependencyKind::Dependency,
            }],
            vec![
                DependencyEdge {
                    target: 2,
                    kind: DependencyKind::Dependency,
                },
                DependencyEdge {
                    target: 3,
                    kind: DependencyKind::DevDependency,
                },
            ],
            vec![],
            vec![],
        ];
        let name_to_idx = HashMap::from([
            ("project-2".to_string(), 0usize),
            ("project-3".to_string(), 1usize),
            ("project-1".to_string(), 2usize),
            ("project-4".to_string(), 3usize),
        ]);
        WorkspaceGraph {
            members,
            edges,
            reverse_edges,
            dependency_edges,
            reverse_dependency_edges,
            name_to_idx,
        }
    }

    #[test]
    fn no_filter_no_affected_returns_all_members() {
        let graph = make_workspace_graph();
        let result =
            select_workspace_target_set(&graph, Path::new("."), &[], &[], &[], false, "main")
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
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
            &[],
            &[],
            false,
            "main",
        )
        .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn filter_prod_closure_omits_dev_dependency_dependents() {
        let graph = make_filter_prod_graph();
        let result = select_workspace_target_set(
            &graph,
            Path::new("."),
            &[],
            &["...project-3".to_string()],
            &[],
            false,
            "main",
        )
        .unwrap();

        assert_eq!(result, HashSet::from([1usize, 2]));
    }
}
