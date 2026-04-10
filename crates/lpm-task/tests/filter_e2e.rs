//! Phase 32 Phase 1 M9: end-to-end integration test for the filter engine.
//!
//! Drives the full pipeline from on-disk workspace discovery through
//! `WorkspaceGraph` construction, parsing, evaluation, and topological
//! ordering. Uses real filesystem fixtures rather than synthetic in-memory
//! `Workspace` structs so the path canonicalization, member discovery, and
//! workspace-protocol resolution all run for real.
//!
//! This is the canonical "did the whole thing work" check that lands at
//! the end of Phase 1. If the engine ever drifts from `lpm run --filter`,
//! one of these tests should catch it.

use lpm_task::filter::FilterEngine;
use lpm_task::graph::WorkspaceGraph;
use std::fs;
use std::path::PathBuf;

/// Create a real on-disk workspace at `root` with the given members.
/// Each member is `(name, deps)` — `deps` are workspace member names.
fn write_workspace(root: &std::path::Path, members: &[(&str, &[&str])]) {
    fs::create_dir_all(root).unwrap();
    let pkg_globs: Vec<String> = members
        .iter()
        .map(|(name, _)| format!("packages/{name}"))
        .collect();
    let root_pkg = serde_json::json!({
        "name": "monorepo",
        "private": true,
        "workspaces": pkg_globs,
    });
    fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();

    for (name, deps) in members {
        let dir = root.join(format!("packages/{name}"));
        fs::create_dir_all(&dir).unwrap();
        let mut deps_map = serde_json::Map::new();
        for d in *deps {
            deps_map.insert((*d).to_string(), serde_json::json!("*"));
        }
        let pkg = serde_json::json!({
            "name": name,
            "version": "0.0.0",
            "dependencies": deps_map,
        });
        fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        // Add a stub source file so paths exist on disk
        fs::write(dir.join("index.js"), "module.exports = {};").unwrap();
    }
}

/// Helper: discover the on-disk workspace and build a graph + engine.
fn open_workspace(root: PathBuf) -> (lpm_workspace::Workspace, WorkspaceGraph) {
    let workspace = lpm_workspace::discover_workspace(&root)
        .expect("workspace discovery failed")
        .expect("no workspace found");
    let graph = WorkspaceGraph::from_workspace(&workspace);
    (workspace, graph)
}

#[test]
fn e2e_exact_name_filter_selects_one_real_member() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("auth", &[]), ("ui", &[]), ("web", &["auth", "ui"])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("auth").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(graph.members[result[0]].name, "auth");
}

#[test]
fn e2e_glob_filter_matches_multiple_real_members() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[
            ("ui-button", &[]),
            ("ui-card", &[]),
            ("auth", &[]),
            ("web", &["auth"]),
        ],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("ui-*").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();
    let names: Vec<&str> = result.iter().map(|&i| graph.members[i].name.as_str()).collect();

    assert_eq!(names.len(), 2);
    assert!(names.contains(&"ui-button"));
    assert!(names.contains(&"ui-card"));
}

#[test]
fn e2e_with_deps_closure_pulls_real_transitive_dependencies() {
    let tmp = tempfile::tempdir().unwrap();
    // web → auth → utils
    write_workspace(
        tmp.path(),
        &[
            ("utils", &[]),
            ("auth", &["utils"]),
            ("web", &["auth"]),
            ("unrelated", &[]),
        ],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("web...").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();
    let names: Vec<&str> = result.iter().map(|&i| graph.members[i].name.as_str()).collect();

    assert_eq!(names.len(), 3);
    assert!(names.contains(&"web"));
    assert!(names.contains(&"auth"));
    assert!(names.contains(&"utils"));
    assert!(!names.contains(&"unrelated"));
}

#[test]
fn e2e_topological_ordering_dependencies_first() {
    // utils → auth → web. Result must put utils first, web last.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[
            ("utils", &[]),
            ("auth", &["utils"]),
            ("web", &["auth"]),
        ],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("web...").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();
    let order: Vec<&str> = result.iter().map(|&i| graph.members[i].name.as_str()).collect();

    let pos = |name| order.iter().position(|n| *n == name).unwrap();
    assert!(pos("utils") < pos("auth"), "utils must come before auth");
    assert!(pos("auth") < pos("web"), "auth must come before web");
}

#[test]
fn e2e_path_glob_matches_real_directory_layout() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("foo", &[]), ("bar", &[]), ("baz", &[])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    // ./packages/* matches everything in the packages directory
    let exprs = vec![FilterEngine::parse("./packages/*").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();
    assert_eq!(result.len(), 3, "all three members live under ./packages");
}

#[test]
fn e2e_path_exact_matches_one_directory() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("foo", &[]), ("bar", &[])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("{./packages/foo}").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(graph.members[result[0]].name, "foo");
}

#[test]
fn e2e_exclusion_subtracts_from_real_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("foo", &[]), ("bar", &[]), ("baz", &[])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![
        FilterEngine::parse("./packages/*").unwrap(),
        FilterEngine::parse("!bar").unwrap(),
    ];
    let result = engine.evaluate(&exprs).unwrap();
    let names: Vec<&str> = result.iter().map(|&i| graph.members[i].name.as_str()).collect();

    assert_eq!(names.len(), 2);
    assert!(names.contains(&"foo"));
    assert!(names.contains(&"baz"));
    assert!(!names.contains(&"bar"));
}

#[test]
fn e2e_explain_returns_full_trace_for_real_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("utils", &[]), ("auth", &["utils"]), ("web", &["auth"])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("web...").unwrap()];
    let explain = engine.explain(&exprs).unwrap();

    assert_eq!(explain.selected.len(), 3);
    assert_eq!(explain.traces.len(), 3);
    assert!(explain.notes.is_empty(), "non-empty result has no notes");
}

#[test]
fn e2e_d2_substring_break_yields_empty_for_partial_name() {
    // D2 regression: pre-Phase-32, `core` would have substring-matched
    // `auth-core`. Now it must return empty.
    let tmp = tempfile::tempdir().unwrap();
    write_workspace(
        tmp.path(),
        &[("auth-core", &[]), ("ui-core", &[]), ("web", &[])],
    );

    let (workspace, graph) = open_workspace(tmp.path().to_path_buf());
    let engine = FilterEngine::new(&graph, &workspace.root);

    let exprs = vec![FilterEngine::parse("core").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();

    assert!(
        result.is_empty(),
        "D2: bare 'core' must NOT substring-match 'auth-core' / 'ui-core'"
    );

    // Verify the explicit glob form still works for users migrating
    let exprs = vec![FilterEngine::parse("*-core").unwrap()];
    let result = engine.evaluate(&exprs).unwrap();
    assert_eq!(
        result.len(),
        2,
        "explicit '*-core' glob is the documented migration path"
    );
}
