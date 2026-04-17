use crate::graph_render::{self, DepGraph, RenderOptions};
use crate::output;
use crate::overrides_state;
use lpm_common::LpmError;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

/// Run the `lpm graph` command.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    project_dir: &Path,
    package: Option<&str>,
    why: Option<&str>,
    format: &str,
    max_depth: Option<usize>,
    filter: Option<&str>,
    prod_only: bool,
    dev_only: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    // Load lockfile
    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path)
            .map_err(|e| LpmError::Script(format!("failed to read lockfile: {e}")))?
    } else {
        return Err(LpmError::Script(
            "no lpm.lock found. Run `lpm install` first to generate the lockfile.".into(),
        ));
    };

    // Read package.json once, reuse for both direct deps and root name
    let pkg_json_path = project_dir.join("package.json");
    let pkg_json: Option<serde_json::Value> = if pkg_json_path.exists() {
        let content = std::fs::read_to_string(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        Some(
            serde_json::from_str(&content)
                .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?,
        )
    } else {
        None
    };

    let direct_deps = if let Some(ref pkg) = pkg_json {
        let mut deps = HashSet::new();
        if !dev_only && let Some(d) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            for key in d.keys() {
                deps.insert(key.clone());
            }
        }
        if !prod_only && let Some(d) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
            for key in d.keys() {
                deps.insert(key.clone());
            }
        }
        deps
    } else {
        // No package.json — treat all lockfile packages as roots
        lockfile.packages.iter().map(|p| p.name.clone()).collect()
    };

    // Get root package name from the already-parsed package.json
    let root_name = if let Some(ref pkg) = pkg_json {
        let name = pkg
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("project");
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        format!("{name}@{version}")
    } else {
        "project@0.0.0".to_string()
    };

    // Build graph
    let mut graph = DepGraph::from_lockfile(&lockfile.packages, &direct_deps, &root_name);

    // When filtering by --prod or --dev, prune transitive deps that are no longer reachable
    if prod_only || dev_only {
        prune_unreachable(&mut graph);

        // Check for empty result after pruning
        if graph.stats.total_packages == 0 {
            let dep_type = if prod_only { "production" } else { "dev" };
            output::warn(&format!("no {dep_type} dependencies found."));
            return Ok(());
        }
    }

    // If a specific package was requested, filter the graph to its subtree
    if let Some(pkg_name) = package {
        let subtree_root = find_package_key(&graph, pkg_name);
        match subtree_root {
            Some(key) => {
                restrict_to_subtree(&mut graph, &key);
            }
            None => {
                return Err(LpmError::Script(format!(
                    "package '{pkg_name}' is not in your dependency tree."
                )));
            }
        }
    }

    // Apply --filter at the graph level so ALL renderers see the filtered graph
    if let Some(f) = filter {
        let has_match = graph
            .nodes
            .values()
            .any(|n| !n.is_root && n.name.contains(f));
        if !has_match {
            output::warn(&format!("no packages matching '{f}' in dependency tree."));
            return Ok(());
        }
        graph_render::filter_graph(&mut graph, f);
        recompute_stats(&mut graph);
    }

    // **Phase 32 Phase 5** — load the persisted override apply trace
    // (if any) so `--why` and the JSON output can decorate paths with
    // the override that touched the package. The state file lives at
    // `<project_dir>/.lpm/overrides-state.json` and is written by
    // `lpm install` after every fresh resolution. A missing state file
    // (no overrides ever applied) is the silent default.
    let overrides_state = overrides_state::read_state(project_dir);

    // **Phase 32 Phase 6** — same pattern for the patch apply trace.
    // The state file lives at `<project_dir>/.lpm/patch-state.json`.
    let patch_state = crate::patch_state::read_state(project_dir);

    // Handle --why
    if let Some(target) = why {
        if json_output {
            println!(
                "{}",
                graph_render::render_why_json(
                    &graph,
                    target,
                    overrides_state.as_ref(),
                    patch_state.as_ref()
                )
            );
        } else {
            print!(
                "{}",
                graph_render::render_why(
                    &graph,
                    target,
                    overrides_state.as_ref(),
                    patch_state.as_ref()
                )
            );
        }
        return Ok(());
    }

    // Render based on format
    let options = RenderOptions {
        max_depth,
        filter: None, // already applied at graph level
    };

    match format {
        "tree" | "" => {
            let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
            print!("{}", graph_render::render_tree(&graph, &options, use_color));
        }
        "dot" => {
            print!("{}", graph_render::render_dot(&graph));
        }
        "mermaid" => {
            print!("{}", graph_render::render_mermaid(&graph));
        }
        "json" => {
            println!("{}", graph_render::render_json(&graph));
        }
        "stats" => {
            print!("{}", graph_render::render_stats(&graph));
        }
        "html" => {
            let html = graph_render::render_html(&graph);
            let out_dir = project_dir.join(".lpm");
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| LpmError::Script(format!("failed to create .lpm dir: {e}")))?;
            let out_path = out_dir.join("graph.html");
            std::fs::write(&out_path, &html)
                .map_err(|e| LpmError::Script(format!("failed to write graph.html: {e}")))?;

            let size = html.len();
            output::success(&format!(
                "generated {} ({} KB)",
                out_path.display(),
                size / 1024,
            ));

            // Open in browser
            let _ = open::that(&out_path);
        }
        _ => {
            return Err(LpmError::Script(format!(
                "unknown format '{format}'. Available: tree, dot, mermaid, json, stats, html"
            )));
        }
    }

    Ok(())
}

/// Find a package key in the graph by name (with or without version).
/// Matches "express" → first node named "express", or "express@4.22.1" → exact key.
fn find_package_key(graph: &DepGraph, query: &str) -> Option<String> {
    // Try exact key match first (name@version)
    if graph.nodes.contains_key(query) {
        return Some(query.to_string());
    }

    // Try name-only match — return the shallowest (most direct) match
    let mut best: Option<(String, usize)> = None;
    for (key, node) in &graph.nodes {
        if node.name == query && !node.is_root {
            match &best {
                Some((_, d)) if node.depth < *d => {
                    best = Some((key.clone(), node.depth));
                }
                None => {
                    best = Some((key.clone(), node.depth));
                }
                _ => {}
            }
        }
    }
    best.map(|(k, _)| k)
}

/// Restrict the graph to only the subtree rooted at the given key.
fn restrict_to_subtree(graph: &mut DepGraph, subtree_root: &str) {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(subtree_root.to_string());

    while let Some(key) = queue.pop_front() {
        if !reachable.insert(key.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get(&key) {
            for dep_key in &node.dependencies {
                if !reachable.contains(dep_key) {
                    queue.push_back(dep_key.clone());
                }
            }
        }
    }

    graph.nodes.retain(|k, _| reachable.contains(k));

    // Make the subtree root act as the new root
    if let Some(node) = graph.nodes.get_mut(subtree_root) {
        node.is_root = true;
        node.depth = 0;
    }
    graph.roots = vec![subtree_root.to_string()];

    // Recompute depths via BFS from new root
    let mut visited = HashSet::new();
    let mut bfs_queue = VecDeque::new();
    bfs_queue.push_back((subtree_root.to_string(), 0_usize));

    while let Some((key, depth)) = bfs_queue.pop_front() {
        if !visited.insert(key.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get_mut(&key) {
            node.depth = depth;
            for dep_key in &node.dependencies.clone() {
                if !visited.contains(dep_key) {
                    bfs_queue.push_back((dep_key.clone(), depth + 1));
                }
            }
        }
    }

    // Recompute stats
    recompute_stats(graph);
}

/// Remove nodes not reachable from the root.
/// This ensures that when --prod or --dev filters direct deps,
/// transitive dependencies of excluded packages are also removed.
fn prune_unreachable(graph: &mut DepGraph) {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();

    // Start BFS from all root nodes
    for root_key in &graph.roots {
        queue.push_back(root_key.clone());
    }

    while let Some(key) = queue.pop_front() {
        if !reachable.insert(key.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get(&key) {
            for dep_key in &node.dependencies {
                if !reachable.contains(dep_key) {
                    queue.push_back(dep_key.clone());
                }
            }
        }
    }

    graph.nodes.retain(|k, _| reachable.contains(k));
    recompute_stats(graph);
}

/// Recompute graph stats after mutation (pruning or subtree restriction).
fn recompute_stats(graph: &mut DepGraph) {
    let lpm_count = graph
        .nodes
        .values()
        .filter(|n| n.registry == graph_render::Registry::Lpm)
        .count();
    let npm_count = graph
        .nodes
        .values()
        .filter(|n| n.registry == graph_render::Registry::Npm)
        .count();
    let max_depth = graph.nodes.values().map(|n| n.depth).max().unwrap_or(0);

    // Recompute duplicates
    let mut name_versions: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for node in graph.nodes.values() {
        name_versions
            .entry(node.name.clone())
            .or_default()
            .push(node.version.clone());
    }
    let mut duplicates = Vec::new();
    for (name, versions) in &name_versions {
        let mut sorted = versions.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() > 1 {
            duplicates.push((name.clone(), sorted));
        }
    }
    duplicates.sort_by(|a, b| a.0.cmp(&b.0));

    // Count root nodes to exclude from total
    let root_count = graph.nodes.values().filter(|n| n.is_root).count();

    graph.stats = graph_render::GraphStats {
        total_packages: graph.nodes.len().saturating_sub(root_count),
        lpm_packages: lpm_count,
        npm_packages: npm_count,
        max_depth,
        duplicates,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_render::DepGraph;
    use lpm_lockfile::LockedPackage;

    fn test_packages() -> Vec<LockedPackage> {
        vec![
            LockedPackage {
                name: "express".into(),
                version: "4.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec!["accepts@1.0.0".into()],
                alias_dependencies: vec![],
            },
            LockedPackage {
                name: "accepts".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
            },
            LockedPackage {
                name: "test-lib".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec!["test-util@1.0.0".into()],
                alias_dependencies: vec![],
            },
            LockedPackage {
                name: "test-util".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
            },
        ]
    }

    /// --prod should prune transitive deps of dev-only packages.
    #[test]
    fn prune_unreachable_removes_dev_transitive_deps() {
        let prod_deps: HashSet<String> = ["express"].iter().map(|s| s.to_string()).collect();
        let mut graph = DepGraph::from_lockfile(&test_packages(), &prod_deps, "my-app@1.0.0");

        // Before pruning, orphaned dev deps exist
        assert!(graph.nodes.contains_key("test-lib@1.0.0"));
        assert!(graph.nodes.contains_key("test-util@1.0.0"));

        prune_unreachable(&mut graph);

        // After pruning, dev deps and their transitive deps are gone
        assert!(!graph.nodes.contains_key("test-lib@1.0.0"));
        assert!(!graph.nodes.contains_key("test-util@1.0.0"));
        // Prod deps remain
        assert!(graph.nodes.contains_key("express@4.0.0"));
        assert!(graph.nodes.contains_key("accepts@1.0.0"));
        assert!(graph.nodes.contains_key("my-app@1.0.0"));
        assert_eq!(graph.stats.total_packages, 2); // excludes synthetic root
    }

    /// --dev should prune production deps and their transitive deps.
    #[test]
    fn prune_unreachable_removes_prod_transitive_deps() {
        let dev_deps: HashSet<String> = ["test-lib"].iter().map(|s| s.to_string()).collect();
        let mut graph = DepGraph::from_lockfile(&test_packages(), &dev_deps, "my-app@1.0.0");

        prune_unreachable(&mut graph);

        // Prod deps should be gone
        assert!(!graph.nodes.contains_key("express@4.0.0"));
        assert!(!graph.nodes.contains_key("accepts@1.0.0"));
        // Dev deps remain
        assert!(graph.nodes.contains_key("test-lib@1.0.0"));
        assert!(graph.nodes.contains_key("test-util@1.0.0"));
        assert_eq!(graph.stats.total_packages, 2);
    }

    /// find_package_key should match by exact key or by name.
    #[test]
    fn find_package_key_by_name_and_exact() {
        let all_deps: HashSet<String> = ["express", "test-lib"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let graph = DepGraph::from_lockfile(&test_packages(), &all_deps, "my-app@1.0.0");

        // Exact key match
        assert_eq!(
            find_package_key(&graph, "express@4.0.0"),
            Some("express@4.0.0".into())
        );

        // Name-only match
        assert_eq!(
            find_package_key(&graph, "accepts"),
            Some("accepts@1.0.0".into())
        );

        // No match
        assert_eq!(find_package_key(&graph, "lodash"), None);

        // Should not match root node
        assert_eq!(find_package_key(&graph, "my-app"), None);
    }

    /// restrict_to_subtree should keep only the package and its transitive deps.
    #[test]
    fn restrict_to_subtree_keeps_only_descendants() {
        let all_deps: HashSet<String> = ["express", "test-lib"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut graph = DepGraph::from_lockfile(&test_packages(), &all_deps, "my-app@1.0.0");

        restrict_to_subtree(&mut graph, "express@4.0.0");

        // express is now root
        assert!(graph.nodes["express@4.0.0"].is_root);
        assert_eq!(graph.nodes["express@4.0.0"].depth, 0);

        // accepts is a child of express
        assert!(graph.nodes.contains_key("accepts@1.0.0"));
        assert_eq!(graph.nodes["accepts@1.0.0"].depth, 1);

        // test-lib and test-util are gone
        assert!(!graph.nodes.contains_key("test-lib@1.0.0"));
        assert!(!graph.nodes.contains_key("test-util@1.0.0"));
        assert!(!graph.nodes.contains_key("my-app@1.0.0"));

        // Stats are correct
        assert_eq!(graph.stats.total_packages, 1); // accepts only (express is root)
    }

    // ── Integration tests: real fixture lockfile ─────────────────────

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/graph-project")
    }

    fn load_fixture_graph() -> DepGraph {
        let dir = fixture_path();
        let lockfile = lpm_lockfile::Lockfile::read_from_file(&dir.join("lpm.lock")).unwrap();
        let content = std::fs::read_to_string(dir.join("package.json")).unwrap();
        let pkg: serde_json::Value = serde_json::from_str(&content).unwrap();
        let mut deps = HashSet::new();
        if let Some(d) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            for key in d.keys() {
                deps.insert(key.clone());
            }
        }
        if let Some(d) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
            for key in d.keys() {
                deps.insert(key.clone());
            }
        }
        let name = pkg["name"].as_str().unwrap();
        let version = pkg["version"].as_str().unwrap();
        DepGraph::from_lockfile(&lockfile.packages, &deps, &format!("{name}@{version}"))
    }

    #[test]
    fn fixture_graph_loads_correctly() {
        let graph = load_fixture_graph();
        // 8 real packages: express, accepts, debug, ms@2.0.0, ms@2.1.3,
        // mime-types, neo.highlight, vitest
        assert_eq!(graph.stats.total_packages, 8);
        assert_eq!(graph.stats.lpm_packages, 1);
        assert!(graph.nodes.contains_key("graph-test-project@1.0.0"));
        assert!(graph.nodes["graph-test-project@1.0.0"].is_root);
    }

    #[test]
    fn fixture_graph_has_duplicates() {
        let graph = load_fixture_graph();
        assert_eq!(graph.stats.duplicates.len(), 1);
        assert_eq!(graph.stats.duplicates[0].0, "ms");
    }

    #[test]
    fn fixture_tree_output() {
        let graph = load_fixture_graph();
        let tree = graph_render::render_tree(&graph, &RenderOptions::default(), false);
        assert!(tree.contains("express@4.22.1"));
        assert!(tree.contains("@lpm.dev/neo.highlight@1.1.1"));
        assert!(tree.contains("vitest@1.6.0"));
        assert!(tree.contains("8 packages"));
    }

    #[test]
    fn fixture_json_output() {
        let graph = load_fixture_graph();
        let json = graph_render::render_json(&graph);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["packages"].as_u64().unwrap(), 8);
        assert_eq!(parsed["root"].as_str().unwrap(), "graph-test-project@1.0.0");
        assert!(parsed["nodes"].as_array().unwrap().len() > 8); // includes root node
        assert!(!parsed["edges"].as_array().unwrap().is_empty());
    }

    #[test]
    fn fixture_dot_output() {
        let graph = load_fixture_graph();
        let dot = graph_render::render_dot(&graph);
        assert!(dot.starts_with("digraph deps {"));
        assert!(dot.contains("express"));
        assert!(dot.contains("->"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn fixture_mermaid_output() {
        let graph = load_fixture_graph();
        let mermaid = graph_render::render_mermaid(&graph);
        assert!(mermaid.starts_with("graph LR"));
        assert!(mermaid.contains("-->"));
        // IDs should not contain @ or .
        for line in mermaid.lines() {
            if line.contains("-->") {
                assert!(
                    !line.contains('@'),
                    "Mermaid edge IDs must not contain @: {line}"
                );
            }
        }
    }

    #[test]
    fn fixture_stats_output() {
        let graph = load_fixture_graph();
        let stats = graph_render::render_stats(&graph);
        assert!(stats.contains("8 packages"));
        assert!(stats.contains("1 LPM"));
        assert!(stats.contains("Duplicates: 1"));
    }

    #[test]
    fn fixture_html_output() {
        let graph = load_fixture_graph();
        let html = graph_render::render_html(&graph);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("LPM Dependency Graph"));
        // Stats should be HTML-escaped in the header
        assert!(html.contains("8 packages"));
        // JSON data should be embedded
        assert!(html.contains("express"));
    }

    #[test]
    fn fixture_why_transitive() {
        let graph = load_fixture_graph();
        let why = graph_render::render_why(&graph, "ms", None, None);
        assert!(why.contains("required by"));
        assert!(why.contains("→"));
        // ms has two reachable versions
        assert!(why.contains("2 versions installed"));
    }

    #[test]
    fn fixture_why_direct() {
        let graph = load_fixture_graph();
        let why = graph_render::render_why(&graph, "express", None, None);
        assert!(why.contains("direct dependency"));
        assert!(why.contains("required by"));
    }

    #[test]
    fn fixture_why_not_found() {
        let graph = load_fixture_graph();
        let why = graph_render::render_why(&graph, "lodash", None, None);
        assert!(why.contains("not in your dependency tree"));
    }

    #[test]
    fn fixture_depth_limit() {
        let graph = load_fixture_graph();
        let opts = RenderOptions {
            max_depth: Some(2),
            ..Default::default()
        };
        let tree = graph_render::render_tree(&graph, &opts, false);
        assert!(tree.contains("express@4.22.1"), "direct dep should show");
        // ms is depth 3+ (root→express→debug→ms), should NOT appear
        assert!(!tree.contains("ms@2.0.0"), "deep dep should be hidden");
    }

    /// Helper: apply graph-level filter (matches what `run()` does).
    fn apply_filter(graph: &mut DepGraph, filter: &str) {
        graph_render::filter_graph(graph, filter);
        recompute_stats(graph);
    }

    #[test]
    fn fixture_filter_tree() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let tree = graph_render::render_tree(&graph, &RenderOptions::default(), false);
        assert!(tree.contains("debug@2.6.9"), "matched node should show");
        assert!(tree.contains("express"), "parent of match should show");
        assert!(
            !tree.contains("neo.highlight"),
            "unrelated subtree should be hidden: {tree}"
        );
        assert!(
            !tree.contains("vitest"),
            "unrelated subtree should be hidden: {tree}"
        );
    }

    #[test]
    fn fixture_filter_json() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let json = graph_render::render_json(&graph);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let nodes = parsed["nodes"].as_array().unwrap();
        let node_names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();
        assert!(
            node_names.contains(&"debug"),
            "JSON should contain matched node: {node_names:?}"
        );
        assert!(
            node_names.contains(&"express"),
            "JSON should contain parent of match: {node_names:?}"
        );
        assert!(
            !node_names.contains(&"vitest"),
            "JSON should not contain unrelated nodes: {node_names:?}"
        );
        assert!(
            !node_names.contains(&"@lpm.dev/neo.highlight"),
            "JSON should not contain unrelated nodes: {node_names:?}"
        );
    }

    #[test]
    fn fixture_filter_dot() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let dot = graph_render::render_dot(&graph);
        assert!(dot.contains("debug"), "DOT should contain matched node");
        assert!(
            dot.contains("express"),
            "DOT should contain parent of match"
        );
        assert!(
            !dot.contains("vitest"),
            "DOT should not contain unrelated nodes: {dot}"
        );
        assert!(
            !dot.contains("neo.highlight"),
            "DOT should not contain unrelated nodes: {dot}"
        );
    }

    #[test]
    fn fixture_filter_mermaid() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let mermaid = graph_render::render_mermaid(&graph);
        assert!(
            mermaid.contains("debug"),
            "Mermaid should contain matched node"
        );
        assert!(
            mermaid.contains("express"),
            "Mermaid should contain parent of match"
        );
        assert!(
            !mermaid.contains("vitest"),
            "Mermaid should not contain unrelated nodes: {mermaid}"
        );
    }

    #[test]
    fn fixture_filter_stats() {
        let mut graph = load_fixture_graph();
        let before = graph.stats.total_packages;
        apply_filter(&mut graph, "debug");
        let after = graph.stats.total_packages;
        assert!(
            after < before,
            "filter should reduce package count: before={before}, after={after}"
        );
        let stats = graph_render::render_stats(&graph);
        assert!(
            !stats.contains("8 packages"),
            "stats should reflect filtered count: {stats}"
        );
    }

    #[test]
    fn fixture_filter_html() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let html = graph_render::render_html(&graph);
        assert!(html.contains("debug"), "HTML should contain matched node");
        assert!(
            !html.contains("vitest"),
            "HTML should not contain unrelated nodes"
        );
    }

    #[test]
    fn filter_keeps_matched_nodes_subtree() {
        // When filtering for "debug", its dep "ms" should also be included
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        assert!(
            graph.nodes.contains_key("ms@2.0.0"),
            "filter should keep deps of matched node (debug→ms)"
        );
    }

    #[test]
    fn fixture_prod_only() {
        // Verify fixture loads without error (also exercises the graph builder)
        let _full_graph = load_fixture_graph();

        // Build with prod-only
        let dir = fixture_path();
        let lockfile = lpm_lockfile::Lockfile::read_from_file(&dir.join("lpm.lock")).unwrap();
        let prod_deps: HashSet<String> = ["express", "@lpm.dev/neo.highlight"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut prod_graph =
            DepGraph::from_lockfile(&lockfile.packages, &prod_deps, "graph-test-project@1.0.0");
        prune_unreachable(&mut prod_graph);

        // vitest and ms@2.1.3 should be gone (dev deps)
        assert!(!prod_graph.nodes.contains_key("vitest@1.6.0"));
        assert!(!prod_graph.nodes.contains_key("ms@2.1.3"));
        // express and its transitive deps should remain
        assert!(prod_graph.nodes.contains_key("express@4.22.1"));
        assert!(prod_graph.nodes.contains_key("debug@2.6.9"));
    }

    #[test]
    fn fixture_package_subtree() {
        let _full_graph = load_fixture_graph();
        let dir = fixture_path();
        let lockfile = lpm_lockfile::Lockfile::read_from_file(&dir.join("lpm.lock")).unwrap();
        let all_deps: HashSet<String> = ["express", "@lpm.dev/neo.highlight", "vitest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut sub_graph =
            DepGraph::from_lockfile(&lockfile.packages, &all_deps, "graph-test-project@1.0.0");
        restrict_to_subtree(&mut sub_graph, "express@4.22.1");

        // express is now root
        assert!(sub_graph.nodes["express@4.22.1"].is_root);
        // vitest and neo.highlight are gone
        assert!(!sub_graph.nodes.contains_key("vitest@1.6.0"));
        assert!(!sub_graph.nodes.contains_key("@lpm.dev/neo.highlight@1.1.1"));
        // express's transitive deps remain
        assert!(sub_graph.nodes.contains_key("debug@2.6.9"));
        assert!(sub_graph.nodes.contains_key("ms@2.0.0"));
    }

    #[test]
    fn fixture_no_lockfile_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        // Create a package.json but no lockfile
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = rt.block_on(run(
            dir.path(),
            None,
            None,
            "tree",
            None,
            None,
            false,
            false,
            false,
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no lpm.lock found"),
            "should error about missing lockfile: {err}"
        );
    }
}
