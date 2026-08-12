use crate::graph_render::{self, DepGraph};
use crate::install_ui;
use crate::overrides_state;
use lpm_common::LpmError;
use std::collections::{HashSet, VecDeque};
use std::io::{BufWriter, Write};
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
    no_open: bool,
) -> Result<(), LpmError> {
    // `--no-open` only governs the post-write browser launch under
    // `--format html`. For any other format the flag is a silent no-op,
    // which masks user mistakes (e.g. `lpm graph --no-open` without
    // `--format html`). Surface a one-line warning so the user sees the
    // flag has no effect in this configuration. Suppressed under --json
    // to keep the JSON contract clean.
    if no_open && format != "html" && !json_output {
        install_ui::warn(
            "--no-open has no effect without `--format html` (other formats write to stdout).",
        );
    }

    // Load lockfile
    let lockfile = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .map_err(|e| {
            LpmError::Script(format!(
                "no usable lpm.lock found. Run `lpm install` first: {e}"
            ))
        })?
        .lockfile;

    // Read package.json once, reuse for both direct deps and root name
    let pkg_json_path = project_dir.join("package.json");
    let pkg_json: Option<serde_json::Value> = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => Some(
            serde_json::from_str(&content)
                .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?,
        ),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };

    let direct_deps = if let Some(ref pkg) = pkg_json {
        let mut deps = HashSet::new();
        if !dev_only && let Some(d) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            for key in d.keys() {
                deps.insert(key.clone());
            }
        }
        if !dev_only && let Some(d) = pkg.get("optionalDependencies").and_then(|d| d.as_object()) {
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

    let mut graph = build_graph(&lockfile, &direct_deps, &root_name, pkg_json.is_some());

    // When filtering by --prod or --dev, prune transitive deps that are no longer reachable
    if prod_only || dev_only {
        prune_unreachable(&mut graph);

        // Check for empty result after pruning
        if graph.stats.total_packages == 0 {
            let dep_type = if prod_only { "production" } else { "dev" };
            install_ui::warn_untrusted(&format!("No {dep_type} dependencies found"));
            return Ok(());
        }
    }

    // If a specific package was requested, filter the graph to its subtree
    if let Some(pkg_name) = package {
        match find_package_key(&graph, pkg_name) {
            Ok(Some(key)) => {
                restrict_to_subtree(&mut graph, &key);
            }
            Ok(None) => {
                return Err(LpmError::Script(format!(
                    "package '{pkg_name}' is not in your dependency tree."
                )));
            }
            Err(choices) => {
                return Err(LpmError::Script(format!(
                    "package selector '{pkg_name}' matches multiple dependency contexts. Use one exact key: {}",
                    choices.join(", ")
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
            install_ui::warn_untrusted(&format!("No packages matching '{f}' in dependency tree"));
            return Ok(());
        }
        graph_render::filter_graph(&mut graph, f);
        graph_render::recompute_stats(&mut graph);
    }

    // Apply --depth at the graph level so every renderer (tree, dot,
    // mermaid, json, stats, html) honors the same truncated set. Done
    // after subtree restriction and filter so depth is measured against
    // whatever ended up rooted at depth 0.
    if let Some(max) = max_depth {
        graph_render::prune_to_depth(&mut graph, max);
        graph_render::recompute_stats(&mut graph);
    }

    // load the persisted override apply trace
    // (if any) so `--why` and the JSON output can decorate paths with
    // the override that touched the package. The state file lives at
    // `<project_dir>/.lpm/overrides-state.json` and is written by
    // `lpm install` after every fresh resolution. A missing state file
    // (no overrides ever applied) is the silent default.
    let overrides_state = overrides_state::read_state(project_dir);

    // same pattern for the patch apply trace.
    // The state file lives at `<project_dir>/.lpm/patch-state.json`.
    let patch_state = crate::patch_state::read_state(project_dir);

    // Handle --why
    if let Some(target) = why {
        let stdout = std::io::stdout();
        let mut output = BufWriter::new(stdout.lock());
        if json_output {
            graph_render::write_why_json(
                &mut output,
                &graph,
                target,
                overrides_state.as_ref(),
                patch_state.as_ref(),
            )
            .map_err(|e| LpmError::Script(format!("failed to serialize graph why JSON: {e}")))?;
        } else {
            graph_render::write_why(
                &mut output,
                &graph,
                target,
                overrides_state.as_ref(),
                patch_state.as_ref(),
            )
            .map_err(|e| LpmError::Script(format!("failed to write graph why output: {e}")))?;
        }
        output
            .flush()
            .map_err(|e| LpmError::Script(format!("failed to write graph why output: {e}")))?;
        return Ok(());
    }

    // Render based on format. `--filter` and `--depth` were already
    // applied above as graph-level mutations, so every renderer below
    // receives the same pruned graph.
    match format {
        "tree" | "" => {
            let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout())
                && lpm_common::color::enabled();
            print!("{}", graph_render::render_tree(&graph, use_color));
            if !json_output {
                match max_depth {
                    Some(depth) => {
                        install_ui::done_untrusted(&format!(
                            "Rendered dependency tree (depth {depth})"
                        ));
                    }
                    None => install_ui::done("Rendered dependency tree"),
                }
            }
        }
        "dot" => {
            print!("{}", graph_render::render_dot(&graph));
        }
        "mermaid" => {
            print!("{}", graph_render::render_mermaid(&graph));
        }
        "json" => {
            let stdout = std::io::stdout();
            let mut output = BufWriter::new(stdout.lock());
            graph_render::write_json(&mut output, &graph)
                .map_err(|e| LpmError::Script(format!("failed to serialize graph JSON: {e}")))?;
            output
                .flush()
                .map_err(|e| LpmError::Script(format!("failed to write graph JSON: {e}")))?;
        }
        "stats" => {
            print!("{}", graph_render::render_stats(&graph));
        }
        "html" => {
            let out_dir = project_dir.join(".lpm");
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| LpmError::Script(format!("failed to create .lpm dir: {e}")))?;
            let out_path = out_dir.join("graph.html");
            lpm_common::write_file_atomic_with(
                &out_path,
                lpm_common::AtomicWriteOptions::new(),
                |file| {
                    graph_render::write_html(file, &graph).map_err(|error| {
                        LpmError::Script(format!("failed to render graph HTML: {error}"))
                    })
                },
            )?;
            let html_size = std::fs::metadata(&out_path).map_err(LpmError::Io)?.len();

            install_ui::done_line(crate::install_ui::terminal_line!(
                "Generated {} ({})",
                out_path.display().to_string(),
                format_byte_size(html_size),
            ));

            // Open in browser unless suppressed (headless / CI).
            if !no_open && open::that(&out_path).is_err() && !json_output {
                install_ui::warn("Could not open browser automatically");
                println!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "  Open this file manually: {}",
                        out_path.display().to_string()
                    )
                );
            }
        }
        _ => {
            return Err(LpmError::Script(format!(
                "unknown format '{format}'. Available: tree, dot, mermaid, json, stats, html"
            )));
        }
    }

    Ok(())
}

fn build_graph(
    lockfile: &lpm_lockfile::Lockfile,
    direct_deps: &HashSet<String>,
    root_name: &str,
    has_package_manifest: bool,
) -> DepGraph {
    if has_package_manifest
        && lockfile.metadata.lockfile_version
            >= lpm_lockfile::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
    {
        DepGraph::from_lockfile_with_root_resolutions(
            &lockfile.packages,
            direct_deps,
            &lockfile.root_resolutions,
            root_name,
        )
    } else {
        DepGraph::from_lockfile(&lockfile.packages, direct_deps, root_name)
    }
}

/// Find a package key in the graph by name (with or without version).
/// Matches "express" or "express@4.22.1" and resolves ties deterministically.
fn find_package_key(graph: &DepGraph, query: &str) -> Result<Option<String>, Vec<String>> {
    if graph.nodes.get(query).is_some_and(|node| !node.is_root) {
        return Ok(Some(query.to_string()));
    }

    let coordinate = query
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty());
    let mut matches: Vec<(&String, &graph_render::DepNode)> = graph
        .nodes
        .iter()
        .filter(|(_, node)| {
            !node.is_root
                && coordinate.map_or_else(
                    || node.name == query,
                    |(name, version)| node.name == name && node.version == version,
                )
        })
        .collect();
    matches.sort_unstable_by(|(left_key, left), (right_key, right)| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left_key.cmp(right_key))
    });
    if coordinate.is_some() && matches.len() > 1 {
        return Err(matches.into_iter().map(|(key, _)| key.clone()).collect());
    }
    Ok(matches.first().map(|(key, _)| (*key).clone()))
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
        }
        if let Some(node) = graph.nodes.get(&key) {
            for dep_key in &node.dependencies {
                if !visited.contains(dep_key) {
                    bfs_queue.push_back((dep_key.clone(), depth + 1));
                }
            }
        }
    }

    // Recompute stats
    graph_render::recompute_stats(graph);
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
    graph_render::recompute_stats(graph);
}

/// Format a byte count as a short human-readable string. Uses 1024-based
/// units to match `du -h` / file managers; switches unit at the natural
/// boundary so a 900-byte HTML never reads as "0 KB".
fn format_byte_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_render::DepGraph;
    use lpm_lockfile::LockedPackage;

    fn test_packages() -> Vec<LockedPackage> {
        vec![
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "express".into(),
                version: "4.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["accepts@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "accepts".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "test-lib".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["test-util@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "test-util".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
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
            Ok(Some("express@4.0.0".into()))
        );

        // Name-only match
        assert_eq!(
            find_package_key(&graph, "accepts"),
            Ok(Some("accepts@1.0.0".into()))
        );

        // No match
        assert_eq!(find_package_key(&graph, "lodash"), Ok(None));

        // Should not match root node
        assert_eq!(find_package_key(&graph, "my-app"), Ok(None));
    }

    #[test]
    fn find_package_key_does_not_select_project_root_by_exact_coordinate() {
        let direct_deps: HashSet<String> = ["express"].into_iter().map(str::to_string).collect();
        let graph = DepGraph::from_lockfile(&test_packages(), &direct_deps, "my-app@1.0.0");

        assert_eq!(find_package_key(&graph, "my-app@1.0.0"), Ok(None));
    }

    #[test]
    fn find_package_key_rejects_ambiguous_public_coordinate_for_contextual_instances() {
        let source = "registry+https://registry.npmjs.org";
        let first_id =
            lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/first/plugin");
        let second_id =
            lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/second/plugin");
        let packages = vec![
            LockedPackage {
                instance_id: Some(first_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(second_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
        ];
        let graph = DepGraph::from_lockfile(
            &packages,
            &HashSet::from(["plugin".to_string()]),
            "app@1.0.0",
        );
        let mut expected_keys = [
            format!("plugin@1.0.0#{first_id}"),
            format!("plugin@1.0.0#{second_id}"),
        ];
        expected_keys.sort_unstable();

        assert_eq!(
            find_package_key(&graph, "plugin@1.0.0"),
            Err(expected_keys.to_vec())
        );
    }

    #[test]
    fn find_package_key_name_ties_use_the_lexicographically_first_key() {
        let packages: Vec<LockedPackage> = (0..16)
            .map(|version| LockedPackage {
                name: "plugin".into(),
                version: format!("{version:02}.0.0"),
                ..Default::default()
            })
            .collect();
        let graph = DepGraph::from_lockfile(
            &packages,
            &HashSet::from(["plugin".to_string()]),
            "app@1.0.0",
        );

        assert_eq!(
            find_package_key(&graph, "plugin"),
            Ok(Some("plugin@00.0.0".to_string()))
        );
    }

    #[test]
    fn graph_without_package_manifest_roots_every_exact_package_instance() {
        let source = "registry+https://registry.npmjs.org";
        let parent_id =
            lpm_common::PackageInstanceId::derive("parent", "1.0.0", source, "root/parent");
        let leaf_id =
            lpm_common::PackageInstanceId::derive("leaf", "1.0.0", source, "root/parent/leaf");
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.packages = vec![
            LockedPackage {
                instance_id: Some(leaf_id),
                name: "leaf".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(parent_id),
                name: "parent".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["leaf@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([("leaf".into(), leaf_id)]),
                ..Default::default()
            },
        ];
        lockfile.root_resolutions.insert(
            "parent".into(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(parent_id),
                package: "parent".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
            },
        );
        let all_package_names = HashSet::from(["leaf".to_string(), "parent".to_string()]);

        let graph = build_graph(&lockfile, &all_package_names, "project@0.0.0", false);

        assert_eq!(
            graph.nodes["project@0.0.0"].dependencies,
            vec!["leaf@1.0.0".to_string(), "parent@1.0.0".to_string()]
        );
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
        assert_eq!(graph.stats.total_packages, 2);
        assert_eq!(graph.stats.npm_packages, 2);
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
        let tree = graph_render::render_tree(&graph, false);
        assert!(tree.contains("express@4.22.1"));
        assert!(tree.contains("@lpm.dev/neo.highlight@1.1.1"));
        assert!(tree.contains("vitest@1.6.0"));
        assert!(tree.contains("8 packages"));
    }

    #[test]
    fn fixture_json_output() {
        let graph = load_fixture_graph();
        let json = graph_render::render_json(&graph).expect("render graph JSON");
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
        let html = graph_render::render_html(&graph).expect("render graph HTML");
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
        let mut graph = load_fixture_graph();
        // --depth 2 keeps root + direct deps (express, neo.highlight, vitest)
        graph_render::prune_to_depth(&mut graph, 2);
        graph_render::recompute_stats(&mut graph);
        let tree = graph_render::render_tree(&graph, false);
        assert!(tree.contains("express@4.22.1"), "direct dep should show");
        // ms is at depth 3+ (root→express→debug→ms), should NOT appear
        assert!(!tree.contains("ms@2.0.0"), "deep dep should be hidden");
    }

    /// Depth-prune is applied at the graph level so non-tree formats see
    /// the same truncated set. Regression for the bug where `--depth N`
    /// only pruned the tree renderer and left dot/json/html unaffected.
    #[test]
    fn fixture_depth_limit_applies_to_json_format() {
        let mut graph = load_fixture_graph();
        graph_render::prune_to_depth(&mut graph, 2);
        graph_render::recompute_stats(&mut graph);
        let json = graph_render::render_json(&graph).expect("render graph JSON");
        assert!(json.contains("express"), "direct dep should be in JSON");
        // ms is depth 3+; before the fix this would still appear in JSON.
        assert!(
            !json.contains("\"ms\""),
            "deep dep should be pruned from JSON: {json}"
        );
        // Stats reflect the pruned graph, not the original.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["packages"].as_u64().unwrap() < 8,
            "package count should drop after depth prune: {json}"
        );
    }

    /// Helper: apply graph-level filter (matches what `run()` does).
    fn apply_filter(graph: &mut DepGraph, filter: &str) {
        graph_render::filter_graph(graph, filter);
        graph_render::recompute_stats(graph);
    }

    #[test]
    fn fixture_filter_tree() {
        let mut graph = load_fixture_graph();
        apply_filter(&mut graph, "debug");
        let tree = graph_render::render_tree(&graph, false);
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
        let json = graph_render::render_json(&graph).expect("render graph JSON");
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
        let html = graph_render::render_html(&graph).expect("render graph HTML");
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
            false, // no_open
        ));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no lpm.lock found"),
            "should error about missing lockfile: {err}"
        );
    }
}
