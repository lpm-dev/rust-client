use crate::graph_render::{self, DepGraph, RenderOptions};
use crate::output;
use lpm_common::LpmError;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

/// Run the `lpm graph` command.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    project_dir: &Path,
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

    // Read package.json for direct deps
    let pkg_json_path = project_dir.join("package.json");
    let direct_deps = if pkg_json_path.exists() {
        let content = std::fs::read_to_string(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        let pkg: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

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

    // Get root package name
    let root_name = if pkg_json_path.exists() {
        let content = std::fs::read_to_string(&pkg_json_path).unwrap_or_default();
        let pkg: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
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
    }

    // Handle --why
    if let Some(target) = why {
        if json_output {
            println!("{}", graph_render::render_why_json(&graph, target));
        } else {
            print!("{}", graph_render::render_why(&graph, target));
        }
        return Ok(());
    }

    // Render based on format
    let options = RenderOptions {
        max_depth,
        filter: filter.map(|s| s.to_string()),
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

    // Recompute stats after pruning
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

    graph.stats = graph_render::GraphStats {
        total_packages: graph.nodes.len().saturating_sub(1), // exclude synthetic root
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

    /// Finding #9: --prod should prune transitive deps of dev-only packages.
    #[test]
    fn prune_unreachable_removes_dev_transitive_deps() {
        let packages = vec![
            LockedPackage {
                name: "express".into(),
                version: "4.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec!["accepts@1.0.0".into()],
            },
            LockedPackage {
                name: "accepts".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec![],
            },
            LockedPackage {
                name: "test-lib".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec!["test-util@1.0.0".into()],
            },
            LockedPackage {
                name: "test-util".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                dependencies: vec![],
            },
        ];

        // Simulate --prod: only production deps
        let prod_deps: HashSet<String> = ["express"].iter().map(|s| s.to_string()).collect();
        let mut graph = DepGraph::from_lockfile(&packages, &prod_deps, "my-app@1.0.0");

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
}
