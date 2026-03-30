//! Dependency graph data model and renderers.
//!
//! Builds a dependency graph from the lockfile and renders it in multiple formats:
//! tree (terminal), DOT (Graphviz), Mermaid, JSON, stats, and HTML.

use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum number of paths returned by `find_all_paths` / `dfs_paths` to prevent
/// exponential blowup on diamond-heavy graphs.
const MAX_PATHS: usize = 100;

/// A node in the dependency graph.
#[derive(Debug, Clone)]
pub struct DepNode {
	pub name: String,
	pub version: String,
	pub registry: Registry,
	pub depth: usize,
	pub is_direct: bool,
	pub is_duplicate: bool,
	pub is_root: bool,
	pub dependencies: Vec<String>, // "name@version" keys
}

/// Which registry a package comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum Registry {
	Lpm,
	Npm,
	Unknown,
}

/// Statistics about the dependency graph.
#[derive(Debug, Clone)]
pub struct GraphStats {
	pub total_packages: usize,
	pub lpm_packages: usize,
	pub npm_packages: usize,
	pub max_depth: usize,
	pub duplicates: Vec<(String, Vec<String>)>, // (name, [versions])
}

/// The full dependency graph.
pub struct DepGraph {
	/// Map of "name@version" → node.
	pub nodes: HashMap<String, DepNode>,
	/// Root package keys (direct dependencies).
	pub roots: Vec<String>,
	/// Computed stats.
	pub stats: GraphStats,
}

/// Options for rendering.
pub struct RenderOptions {
	pub max_depth: Option<usize>,
	pub filter: Option<String>,
}

impl Default for RenderOptions {
	fn default() -> Self {
		Self {
			max_depth: None,
			filter: None,
		}
	}
}

// ── Graph Construction ─────────────────────────────────────────────

impl DepGraph {
	/// Build a dependency graph from lockfile packages and direct dependency names.
	/// `root_name` is the project name from package.json (e.g., "my-app@1.0.0").
	pub fn from_lockfile(
		packages: &[lpm_lockfile::LockedPackage],
		direct_dep_names: &HashSet<String>,
		root_name: &str,
	) -> Self {
		let mut nodes = HashMap::new();

		// Index all packages by "name@version"
		for pkg in packages {
			let key = format!("{}@{}", pkg.name, pkg.version);
			let registry = match pkg.source.as_deref() {
				Some(s) if s.contains("lpm.dev") => Registry::Lpm,
				Some(s) if s.contains("npmjs.org") => Registry::Npm,
				_ => Registry::Unknown,
			};

			nodes.insert(
				key.clone(),
				DepNode {
					name: pkg.name.clone(),
					version: pkg.version.clone(),
					registry,
					depth: 0,
					is_direct: direct_dep_names.contains(&pkg.name),
					is_duplicate: false,
					is_root: false,
					dependencies: pkg.dependencies.clone(),
				},
			);
		}

		// Create synthetic root node pointing to all direct deps
		let root_key = root_name.to_string();
		let direct_dep_keys: Vec<String> = nodes
			.iter()
			.filter(|(_, n)| n.is_direct)
			.map(|(k, _)| k.clone())
			.collect();

		nodes.insert(
			root_key.clone(),
			DepNode {
				name: root_name.split('@').next().unwrap_or(root_name).to_string(),
				version: root_name.split('@').last().unwrap_or("0.0.0").to_string(),
				registry: Registry::Unknown,
				depth: 0,
				is_direct: false,
				is_duplicate: false,
				is_root: true,
				dependencies: direct_dep_keys,
			},
		);

		let roots = vec![root_key];

		// BFS to compute depths
		let mut queue: VecDeque<(String, usize)> = VecDeque::new();
		let mut visited: HashSet<String> = HashSet::new();

		for root in &roots {
			queue.push_back((root.clone(), 1));
		}

		while let Some((key, depth)) = queue.pop_front() {
			if visited.contains(&key) {
				continue;
			}
			visited.insert(key.clone());

			if let Some(node) = nodes.get_mut(&key) {
				node.depth = depth;
				for dep_key in &node.dependencies.clone() {
					if !visited.contains(dep_key) {
						queue.push_back((dep_key.clone(), depth + 1));
					}
				}
			}
		}

		// Find duplicates (same name, different versions)
		let mut name_versions: HashMap<String, Vec<String>> = HashMap::new();
		for node in nodes.values() {
			name_versions
				.entry(node.name.clone())
				.or_default()
				.push(node.version.clone());
		}

		let mut duplicates = Vec::new();
		for (name, versions) in &name_versions {
			if versions.len() > 1 {
				let mut sorted = versions.clone();
				sorted.sort();
				sorted.dedup();
				if sorted.len() > 1 {
					duplicates.push((name.clone(), sorted.clone()));
					// Mark nodes as duplicate
					for v in &sorted {
						let key = format!("{name}@{v}");
						if let Some(node) = nodes.get_mut(&key) {
							node.is_duplicate = true;
						}
					}
				}
			}
		}
		duplicates.sort_by(|a, b| a.0.cmp(&b.0));

		let max_depth = nodes.values().map(|n| n.depth).max().unwrap_or(0);
		let lpm_count = nodes.values().filter(|n| n.registry == Registry::Lpm).count();
		let npm_count = nodes.values().filter(|n| n.registry == Registry::Npm).count();

		let stats = GraphStats {
			total_packages: nodes.len().saturating_sub(1), // exclude synthetic root
			lpm_packages: lpm_count,
			npm_packages: npm_count,
			max_depth,
			duplicates,
		};

		DepGraph {
			nodes,
			roots,
			stats,
		}
	}

	/// Find all paths from any root to a package by name.
	pub fn find_paths(&self, target_name: &str) -> Vec<Vec<String>> {
		let target_keys: Vec<&String> = self
			.nodes
			.keys()
			.filter(|k| k.split('@').next() == Some(target_name) || k.starts_with(&format!("{target_name}@")))
			.collect();

		if target_keys.is_empty() {
			return vec![];
		}

		let mut all_paths = Vec::new();

		for root_key in &self.roots {
			for target_key in &target_keys {
				let mut paths = Vec::new();
				let mut current_path = vec![root_key.clone()];
				let mut visited = HashSet::new();
				self.dfs_paths(root_key, target_key, &mut current_path, &mut visited, &mut paths);
				all_paths.extend(paths);
			}
		}

		all_paths
	}

	fn dfs_paths(
		&self,
		current: &str,
		target: &str,
		path: &mut Vec<String>,
		visited: &mut HashSet<String>,
		results: &mut Vec<Vec<String>>,
	) {
		if results.len() >= MAX_PATHS {
			return;
		}

		if current == target {
			results.push(path.clone());
			return;
		}

		if visited.contains(current) {
			return;
		}
		visited.insert(current.to_string());

		if let Some(node) = self.nodes.get(current) {
			for dep_key in &node.dependencies {
				if results.len() >= MAX_PATHS {
					break;
				}
				path.push(dep_key.clone());
				self.dfs_paths(dep_key, target, path, visited, results);
				path.pop();
			}
		}

		visited.remove(current);
	}
}

// ── Tree Renderer ──────────────────────────────────────────────────

pub fn render_tree(graph: &DepGraph, options: &RenderOptions, use_color: bool) -> String {
	let mut output = String::new();

	let mut sorted_roots = graph.roots.clone();
	sorted_roots.sort();

	for (i, root_key) in sorted_roots.iter().enumerate() {
		let is_last = i == sorted_roots.len() - 1;
		render_tree_node(graph, root_key, "", is_last, 1, options, use_color, &mut HashSet::new(), &mut output);
	}

	// Stats line
	output.push('\n');
	let dup_info = if graph.stats.duplicates.is_empty() {
		String::new()
	} else {
		let names: Vec<String> = graph.stats.duplicates.iter().map(|(n, _)| n.clone()).collect();
		format!(", {} duplicates ({})", graph.stats.duplicates.len(), names.join(", "))
	};
	output.push_str(&format!(
		"{} packages, max depth {}{}\n",
		graph.stats.total_packages, graph.stats.max_depth, dup_info,
	));

	output
}

fn render_tree_node(
	graph: &DepGraph,
	key: &str,
	prefix: &str,
	is_last: bool,
	depth: usize,
	options: &RenderOptions,
	use_color: bool,
	visited: &mut HashSet<String>,
	output: &mut String,
) {
	if let Some(max) = options.max_depth {
		if depth > max {
			return;
		}
	}

	let connector = if depth == 1 {
		""
	} else if is_last {
		"└── "
	} else {
		"├── "
	};

	let node = match graph.nodes.get(key) {
		Some(n) => n,
		None => return,
	};

	// Apply filter: skip subtrees that don't contain the filter target
	if let Some(ref filter) = options.filter {
		if !node.is_root && !subtree_contains(graph, key, filter, &mut HashSet::new()) {
			return;
		}
	}

	let label = format!("{}@{}", node.name, node.version);
	let colored_label = if use_color {
		if node.is_duplicate {
			format!("\x1b[33m{label}\x1b[0m") // yellow for duplicates
		} else if node.registry == Registry::Lpm {
			format!("\x1b[32m{label}\x1b[0m") // green for LPM
		} else {
			label.clone()
		}
	} else {
		label.clone()
	};

	let circular = if visited.contains(key) { " (circular)" } else { "" };

	output.push_str(&format!("{prefix}{connector}{colored_label}{circular}\n"));

	if visited.contains(key) {
		return;
	}
	visited.insert(key.to_string());

	let child_prefix = if depth == 1 {
		"".to_string()
	} else if is_last {
		format!("{prefix}    ")
	} else {
		format!("{prefix}│   ")
	};

	let deps = &node.dependencies;
	for (i, dep_key) in deps.iter().enumerate() {
		let is_last_child = i == deps.len() - 1;
		render_tree_node(graph, dep_key, &child_prefix, is_last_child, depth + 1, options, use_color, visited, output);
	}

	visited.remove(key);
}

/// Check if a node or any of its descendants contain the filter string in their name.
/// Uses backtracking (removes from visited after recursion) so that sibling subtrees
/// sharing a common descendant can each independently find it.
fn subtree_contains(graph: &DepGraph, key: &str, filter: &str, visited: &mut HashSet<String>) -> bool {
	if !visited.insert(key.to_string()) {
		return false;
	}

	if graph.nodes.get(key).map_or(false, |n| n.name.contains(filter)) {
		visited.remove(key);
		return true;
	}

	let result = if let Some(node) = graph.nodes.get(key) {
		node.dependencies.iter().any(|dep_key| subtree_contains(graph, dep_key, filter, visited))
	} else {
		false
	};

	visited.remove(key);
	result
}

// ── Escape Helpers ─────────────────────────────────────────────────

/// Escape a string for safe embedding in HTML content.
fn html_escape(s: &str) -> String {
	s.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&#39;")
}

/// Escape a string for safe use in DOT quoted strings.
fn dot_escape(s: &str) -> String {
	s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape a string for safe use in Mermaid label text.
fn mermaid_escape(s: &str) -> String {
	s.replace('"', "#quot;").replace(']', "#93;")
}

// ── DOT Renderer ───────────────────────────────────────────────────

pub fn render_dot(graph: &DepGraph) -> String {
	let mut output = String::from("digraph deps {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\", fontsize=10];\n\n");

	// Sort keys for deterministic output (HashMap iteration order varies between runs)
	let mut sorted_keys: Vec<&String> = graph.nodes.keys().collect();
	sorted_keys.sort();

	// Nodes with colors
	for key in &sorted_keys {
		let node = &graph.nodes[*key];
		let color = match (&node.registry, node.is_duplicate) {
			(_, true) => "#f59e0b",
			(Registry::Lpm, _) => "#10b981",
			_ => "#6b7280",
		};
		output.push_str(&format!("  \"{}\" [color=\"{}\"];\n", dot_escape(key), color));
	}

	output.push('\n');

	// Edges (sorted for deterministic output)
	for key in &sorted_keys {
		let node = &graph.nodes[*key];
		for dep_key in &node.dependencies {
			output.push_str(&format!("  \"{}\" -> \"{}\";\n", dot_escape(key), dot_escape(dep_key)));
		}
	}

	output.push_str("}\n");
	output
}

// ── Mermaid Renderer ───────────────────────────────────────────────

pub fn render_mermaid(graph: &DepGraph) -> String {
	let mut output = String::from("graph LR\n");

	// Sanitize node IDs for Mermaid (no @ or . in IDs)
	let sanitize = |s: &str| -> String {
		s.replace('@', "_at_").replace('.', "_").replace('/', "_")
	};

	// Sort keys for deterministic output
	let mut sorted_keys: Vec<&String> = graph.nodes.keys().collect();
	sorted_keys.sort();

	// Define nodes once (avoids verbose redefinition on every edge)
	for key in &sorted_keys {
		let id = sanitize(key);
		output.push_str(&format!("  {id}[\"{}\"]\n", mermaid_escape(key)));
	}
	output.push('\n');

	// Edges (reference by ID only)
	for key in &sorted_keys {
		let node = &graph.nodes[*key];
		let from_id = sanitize(key);
		for dep_key in &node.dependencies {
			let to_id = sanitize(dep_key);
			output.push_str(&format!("  {from_id} --> {to_id}\n"));
		}
	}

	// Style LPM packages and duplicates
	for key in &sorted_keys {
		let node = &graph.nodes[*key];
		if node.registry == Registry::Lpm {
			output.push_str(&format!("  style {} fill:#10b981,color:#fff\n", sanitize(key)));
		} else if node.is_duplicate {
			output.push_str(&format!("  style {} fill:#f59e0b,color:#fff\n", sanitize(key)));
		}
	}

	output
}

// ── JSON Renderer ──────────────────────────────────────────────────

pub fn render_json(graph: &DepGraph) -> String {
	let nodes: Vec<serde_json::Value> = graph
		.nodes
		.iter()
		.map(|(key, node)| {
			serde_json::json!({
				"key": key,
				"name": node.name,
				"version": node.version,
				"registry": match node.registry {
					Registry::Lpm => "lpm",
					Registry::Npm => "npm",
					Registry::Unknown => "unknown",
				},
				"depth": node.depth,
				"is_direct": node.is_direct,
				"is_duplicate": node.is_duplicate,
				"is_root": node.is_root,
				"dependency_count": node.dependencies.len(),
				"deps": node.dependencies,
			})
		})
		.collect();

	let edges: Vec<serde_json::Value> = graph
		.nodes
		.iter()
		.flat_map(|(key, node)| {
			node.dependencies.iter().map(move |dep| {
				serde_json::json!({ "from": key, "to": dep })
			})
		})
		.collect();

	let duplicates: Vec<serde_json::Value> = graph
		.stats
		.duplicates
		.iter()
		.map(|(name, versions)| {
			serde_json::json!({ "name": name, "versions": versions })
		})
		.collect();

	serde_json::to_string_pretty(&serde_json::json!({
		"success": true,
		"packages": graph.stats.total_packages,
		"lpm_packages": graph.stats.lpm_packages,
		"npm_packages": graph.stats.npm_packages,
		"max_depth": graph.stats.max_depth,
		"duplicates": duplicates,
		"nodes": nodes,
		"edges": edges,
	}))
	.unwrap_or_else(|e| {
		eprintln!("  \x1b[31m✖\x1b[0m failed to serialize graph JSON: {e}");
		"{}".to_string()
	})
}

// ── Stats Renderer ─────────────────────────────────────────────────

pub fn render_stats(graph: &DepGraph) -> String {
	let mut output = String::new();

	output.push_str(&format!(
		"{} packages ({} LPM, {} npm)\n",
		graph.stats.total_packages, graph.stats.lpm_packages, graph.stats.npm_packages,
	));
	output.push_str(&format!("Max depth: {}\n", graph.stats.max_depth));

	if graph.stats.duplicates.is_empty() {
		output.push_str("Duplicates: none\n");
	} else {
		output.push_str(&format!("Duplicates: {}\n", graph.stats.duplicates.len()));
		for (name, versions) in &graph.stats.duplicates {
			let version_list = versions.iter().map(|v| format!("{name}@{v}")).collect::<Vec<_>>().join(", ");
			output.push_str(&format!("  {version_list}\n"));
		}
	}

	output
}

// ── Why Renderer ───────────────────────────────────────────────────

pub fn render_why(graph: &DepGraph, target_name: &str) -> String {
	// Check if it's a direct dep
	for node in graph.nodes.values() {
		if node.name == target_name && node.is_direct {
			let key = format!("{}@{}", node.name, node.version);
			return format!(
				"{target_name} is a direct dependency.\n\n  root → {key}\n"
			);
		}
	}

	let paths = graph.find_paths(target_name);

	if paths.is_empty() {
		return format!("{target_name} is not in your dependency tree.\n");
	}

	let mut output = format!(
		"{target_name} is required by {} path(s):\n\n",
		paths.len()
	);

	for path in &paths {
		let display = path
			.iter()
			.map(|k| {
				graph
					.nodes
					.get(k)
					.map(|n| format!("{}@{}", n.name, n.version))
					.unwrap_or_else(|| k.clone())
			})
			.collect::<Vec<_>>()
			.join(" → ");
		output.push_str(&format!("  root → {display}\n"));
	}

	// Check for multiple versions
	let versions: HashSet<&str> = paths
		.iter()
		.filter_map(|p| p.last())
		.filter_map(|k| graph.nodes.get(k))
		.filter(|n| n.name == target_name)
		.map(|n| n.version.as_str())
		.collect();

	if versions.len() > 1 {
		output.push_str(&format!(
			"\n{} versions installed (duplicate)\n",
			versions.len()
		));
	}

	output
}

// ── Why JSON ───────────────────────────────────────────────────────

pub fn render_why_json(graph: &DepGraph, target_name: &str) -> String {
	let paths = graph.find_paths(target_name);

	let json_paths: Vec<Vec<String>> = paths
		.iter()
		.map(|p| {
			p.iter()
				.map(|k| {
					graph
						.nodes
						.get(k)
						.map(|n| format!("{}@{}", n.name, n.version))
						.unwrap_or_else(|| k.clone())
				})
				.collect()
		})
		.collect();

	serde_json::to_string_pretty(&serde_json::json!({
		"success": true,
		"target": target_name,
		"found": !paths.is_empty(),
		"path_count": paths.len(),
		"paths": json_paths,
	}))
	.unwrap_or_else(|e| {
		eprintln!("  \x1b[31m✖\x1b[0m failed to serialize why JSON: {e}");
		"{}".to_string()
	})
}

// ── HTML Renderer ──────────────────────────────────────────────────

pub fn render_html(graph: &DepGraph) -> String {
	let json_data = render_json(graph);
	let stats = render_stats(graph).replace('\n', " | ");
	let stats = stats.trim_end_matches(" | ");

	// Sanitize JSON for safe embedding in <script> tag.
	// Replace all `</` sequences (case-insensitive attack vector for </script>, </SCRIPT>, etc.)
	let safe_json = json_data.replace("</", "<\\/");

	// HTML-escape the stats string to prevent XSS via package names
	let safe_stats = html_escape(stats);

	include_str!("templates/graph.html")
		.replace("__GRAPH_DATA__", &safe_json)
		.replace("__STATS__", &safe_stats)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use lpm_lockfile::LockedPackage;

	fn mock_packages() -> Vec<LockedPackage> {
		vec![
			LockedPackage {
				name: "express".into(),
				version: "4.22.1".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec!["accepts@1.3.8".into(), "debug@2.6.9".into()],
			},
			LockedPackage {
				name: "accepts".into(),
				version: "1.3.8".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec!["mime-types@2.1.35".into()],
			},
			LockedPackage {
				name: "debug".into(),
				version: "2.6.9".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec!["ms@2.0.0".into()],
			},
			LockedPackage {
				name: "ms".into(),
				version: "2.0.0".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "ms".into(),
				version: "2.1.3".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "mime-types".into(),
				version: "2.1.35".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "@lpm.dev/neo.highlight".into(),
				version: "1.1.1".into(),
				source: Some("registry+https://lpm.dev".into()),
				integrity: None,
				dependencies: vec![],
			},
		]
	}

	fn direct_deps() -> HashSet<String> {
		["express", "@lpm.dev/neo.highlight"]
			.iter()
			.map(|s| s.to_string())
			.collect()
	}

	#[test]
	fn build_graph_from_lockfile() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		// 7 real packages (synthetic root excluded from count)
		assert_eq!(graph.stats.total_packages, 7);
		assert_eq!(graph.stats.lpm_packages, 1);
		assert_eq!(graph.stats.npm_packages, 6);
		assert!(graph.stats.max_depth > 0);
		// Root node exists
		assert!(graph.nodes.contains_key("test-app@1.0.0"));
		assert!(graph.nodes["test-app@1.0.0"].is_root);
	}

	#[test]
	fn detect_duplicates() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		assert_eq!(graph.stats.duplicates.len(), 1);
		assert_eq!(graph.stats.duplicates[0].0, "ms");
		assert_eq!(graph.stats.duplicates[0].1.len(), 2);
	}

	#[test]
	fn tree_output_has_box_drawing() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let tree = render_tree(&graph, &RenderOptions::default(), false);
		assert!(tree.contains("├──") || tree.contains("└──"), "tree should have box-drawing: {tree}");
		assert!(tree.contains("express@4.22.1"));
		assert!(tree.contains("packages"));
	}

	#[test]
	fn dot_output_valid() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let dot = render_dot(&graph);
		assert!(dot.starts_with("digraph deps {"));
		assert!(dot.contains("->"));
		assert!(dot.ends_with("}\n"));
	}

	#[test]
	fn mermaid_output_valid() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let mermaid = render_mermaid(&graph);
		assert!(mermaid.starts_with("graph LR"));
		assert!(mermaid.contains("-->"));
	}

	#[test]
	fn json_output_parseable() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let json = render_json(&graph);
		let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed["packages"].as_u64().unwrap(), 7); // excludes synthetic root
		assert!(parsed["nodes"].as_array().unwrap().len() > 0);
		assert!(parsed["edges"].as_array().unwrap().len() > 0);
		// Root node should be in the JSON
		let root = parsed["nodes"].as_array().unwrap().iter()
			.find(|n| n["is_root"].as_bool() == Some(true));
		assert!(root.is_some(), "root node should be in JSON");
	}

	#[test]
	fn stats_output() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let stats = render_stats(&graph);
		assert!(stats.contains("7 packages"));
		assert!(stats.contains("1 LPM"));
		assert!(stats.contains("Duplicates: 1"));
	}

	#[test]
	fn why_transitive_dep() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let why = render_why(&graph, "ms");
		assert!(why.contains("required by"));
		assert!(why.contains("→"));
	}

	#[test]
	fn why_not_found() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let why = render_why(&graph, "lodash");
		assert!(why.contains("not in your dependency tree"));
	}

	#[test]
	fn why_direct_dep() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let why = render_why(&graph, "express");
		assert!(why.contains("direct dependency"));
	}

	#[test]
	fn html_has_max_force_nodes_check() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		assert!(
			html.contains("MAX_FORCE_NODES"),
			"HTML template should contain MAX_FORCE_NODES guard for large graphs"
		);
		assert!(
			html.contains("layered layout"),
			"HTML template should mention layered layout fallback"
		);
	}

	#[test]
	fn html_mousemove_has_passive_true() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		// The mousemove addEventListener should close with }, {passive: true});
		assert!(
			html.contains("'mousemove'"),
			"should have mousemove listener"
		);
		// Find the next "Mouse up" comment after mousemove to bound the search
		let mousemove_idx = html.find("'mousemove'").unwrap();
		let next_section = html[mousemove_idx..]
			.find("// Mouse up")
			.map(|i| mousemove_idx + i)
			.unwrap_or(html.len());
		let mousemove_section = &html[mousemove_idx..next_section];
		assert!(
			mousemove_section.contains("{passive: true}"),
			"mousemove listener should have {{passive: true}}"
		);
	}

	#[test]
	fn html_resize_has_passive_true() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		let resize_idx = html.find("'resize'").expect("should have resize listener");
		let after_resize = &html[resize_idx..];
		// Resize handler is simple, find closing within 500 chars
		let section = &after_resize[..after_resize.len().min(500)];
		assert!(
			section.contains("{passive: true}"),
			"resize listener should have {{passive: true}}"
		);
	}

	#[test]
	fn html_wheel_not_passive() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		let wheel_idx = html.find("'wheel'").expect("should have wheel listener");
		let after_wheel = &html[wheel_idx..];
		let section = &after_wheel[..after_wheel.len().min(500)];
		assert!(
			section.contains("{passive: false}"),
			"wheel listener must NOT be passive (calls preventDefault)"
		);
	}

	#[test]
	fn html_contains_data() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		assert!(html.contains("<!DOCTYPE html>"));
		assert!(html.contains("express"));
		assert!(html.contains("LPM Dependency Graph"));
	}

	#[test]
	fn filter_shows_matching_subtrees() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let opts = RenderOptions {
			filter: Some("ms".into()),
			..Default::default()
		};
		let tree = render_tree(&graph, &opts, false);
		// "ms" is under express→debug→ms, so express and debug should appear
		assert!(tree.contains("express"), "filter should show parent of matching node: {tree}");
		assert!(tree.contains("ms@2.0.0"), "filter should show matching node: {tree}");
		// neo.highlight has no "ms" in its subtree, so it should be filtered out
		assert!(!tree.contains("neo.highlight"), "filter should hide non-matching subtrees: {tree}");
	}

	#[test]
	fn depth_limit() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		// depth 2 = root + direct deps (express, neo.highlight)
		let opts = RenderOptions { max_depth: Some(2), ..Default::default() };
		let tree = render_tree(&graph, &opts, false);
		assert!(tree.contains("express@4.22.1"), "should show direct dep: {tree}");
		assert!(tree.contains("test-app"), "should show root: {tree}");
		// ms is depth 4 (root→express→debug→ms), should NOT appear
		assert!(!tree.contains("ms@2.0.0"), "should not show deep transitive dep: {tree}");
	}

	// ── Finding #1: XSS via unescaped __STATS__ in HTML ──────────────

	#[test]
	fn html_escapes_xss_in_stats() {
		// Create a duplicate-triggering package with XSS name so the name appears in stats
		let packages = vec![
			LockedPackage {
				name: "<img src=x onerror=alert(1)>".into(),
				version: "1.0.0".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "<img src=x onerror=alert(1)>".into(),
				version: "2.0.0".into(),
				source: Some("registry+https://registry.npmjs.org".into()),
				integrity: None,
				dependencies: vec![],
			},
		];
		let direct: HashSet<String> = ["<img src=x onerror=alert(1)>"]
			.iter()
			.map(|s| s.to_string())
			.collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		let html = render_html(&graph);
		// The stats div should not contain raw HTML tags
		let stats_div_start = html.find("class=\"stats\">").unwrap();
		let stats_div_end = html[stats_div_start..].find("</div>").unwrap() + stats_div_start;
		let stats_content = &html[stats_div_start..stats_div_end];
		assert!(
			!stats_content.contains("<img"),
			"stats div must not contain raw HTML tags: {stats_content}"
		);
		assert!(
			stats_content.contains("&lt;img"),
			"stats div should contain escaped HTML: {stats_content}"
		);
	}

	// ── Finding #2: XSS via innerHTML in tooltip ─────────────────────

	#[test]
	fn html_tooltip_uses_textcontent_not_innerhtml() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let html = render_html(&graph);
		assert!(
			!html.contains(".meta').innerHTML") && !html.contains(".meta\").innerHTML"),
			"tooltip must not use innerHTML (XSS risk)"
		);
		assert!(
			html.contains("textContent") || html.contains("createElement"),
			"tooltip should use textContent or createElement for safe DOM building"
		);
	}

	// ── Finding #3: Exponential path blowup in dfs_paths ─────────────

	#[test]
	fn find_paths_limits_to_max_paths() {
		// Build a diamond-chain graph that would create 2^N paths without limit.
		let mut packages = Vec::new();
		let mut root_deps = Vec::new();

		let depth = 16;
		for i in 0..depth {
			let shared_key = format!("shared-{i}@1.0.0");
			let a_key = format!("branch-{i}-a@1.0.0");
			let b_key = format!("branch-{i}-b@1.0.0");

			let next_deps = if i + 1 < depth {
				vec![
					format!("branch-{}-a@1.0.0", i + 1),
					format!("branch-{}-b@1.0.0", i + 1),
				]
			} else {
				vec!["target@1.0.0".into()]
			};

			packages.push(LockedPackage {
				name: format!("branch-{i}-a"),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![shared_key.clone()],
			});
			packages.push(LockedPackage {
				name: format!("branch-{i}-b"),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![shared_key.clone()],
			});
			packages.push(LockedPackage {
				name: format!("shared-{i}"),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: next_deps,
			});

			if i == 0 {
				root_deps.push(a_key);
				root_deps.push(b_key);
			}
		}
		packages.push(LockedPackage {
			name: "target".into(),
			version: "1.0.0".into(),
			source: None,
			integrity: None,
			dependencies: vec![],
		});

		let direct: HashSet<String> = root_deps
			.iter()
			.map(|s| s.split('@').next().unwrap().to_string())
			.collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

		let start = std::time::Instant::now();
		let paths = graph.find_paths("target");
		let elapsed = start.elapsed();

		assert!(
			paths.len() <= MAX_PATHS,
			"should cap at MAX_PATHS, got {}",
			paths.len()
		);
		assert!(
			elapsed.as_secs() < 2,
			"should complete quickly, took {:?}",
			elapsed
		);
	}

	// ── Finding #5: DOT unescaped quotes in node names ───────────────

	#[test]
	fn dot_escapes_quotes_in_names() {
		let packages = vec![LockedPackage {
			name: "foo\"bar\\baz".into(),
			version: "1.0.0".into(),
			source: None,
			integrity: None,
			dependencies: vec![],
		}];
		let direct: HashSet<String> = ["foo\"bar\\baz"].iter().map(|s| s.to_string()).collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		let dot = render_dot(&graph);
		assert!(
			dot.contains(r#"foo\"bar\\baz"#),
			"DOT output should escape quotes and backslashes: {dot}"
		);
	}

	// ── Finding #6: Mermaid unescaped quotes in labels ────────────────

	#[test]
	fn mermaid_escapes_quotes_and_brackets() {
		let packages = vec![LockedPackage {
			name: "foo\"bar]baz".into(),
			version: "1.0.0".into(),
			source: None,
			integrity: None,
			dependencies: vec![],
		}];
		let direct: HashSet<String> = ["foo\"bar]baz"].iter().map(|s| s.to_string()).collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		let mermaid = render_mermaid(&graph);
		let label_lines: Vec<&str> = mermaid.lines().filter(|l| l.contains("foo")).collect();
		for line in &label_lines {
			if line.contains('[') {
				assert!(
					line.contains("#quot;") && line.contains("#93;"),
					"Mermaid label should use entity escapes: {line}"
				);
			}
		}
	}

	// ── Finding #7: Incomplete </script> case escaping ────────────────

	#[test]
	fn html_escapes_all_script_closing_tags() {
		let packages = vec![LockedPackage {
			name: "pkg</SCRIPT>test".into(),
			version: "1.0.0".into(),
			source: None,
			integrity: None,
			dependencies: vec![],
		}];
		let direct: HashSet<String> = ["pkg</SCRIPT>test"].iter().map(|s| s.to_string()).collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		let html = render_html(&graph);
		// Check within the <script> tag specifically
		let script_start = html.find("<script>").unwrap();
		let script_end = html.rfind("</script>").unwrap();
		let script_body = &html[script_start + 8..script_end];
		assert!(
			!script_body.contains("</SCRIPT>") && !script_body.contains("</Script>"),
			"script body must not contain any case variant of closing script tag"
		);
	}

	// ── Finding #8: --filter misses diamond-pattern matches ───────────

	#[test]
	fn filter_finds_match_through_both_diamond_branches() {
		let packages = vec![
			LockedPackage {
				name: "branch-a".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec!["shared-target@1.0.0".into()],
			},
			LockedPackage {
				name: "branch-b".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec!["shared-target@1.0.0".into()],
			},
			LockedPackage {
				name: "shared-target".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![],
			},
		];
		let direct: HashSet<String> = ["branch-a", "branch-b"]
			.iter()
			.map(|s| s.to_string())
			.collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		let opts = RenderOptions {
			filter: Some("shared-target".into()),
			..Default::default()
		};
		let tree = render_tree(&graph, &opts, false);
		assert!(
			tree.contains("branch-a"),
			"branch-a should appear (leads to match): {tree}"
		);
		assert!(
			tree.contains("branch-b"),
			"branch-b should appear (leads to match): {tree}"
		);
		assert!(tree.contains("shared-target"), "shared-target should appear: {tree}");
	}

	// ── Finding #10: Stats include synthetic root ─────────────────────

	#[test]
	fn stats_exclude_synthetic_root() {
		let packages = vec![
			LockedPackage {
				name: "a".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "b".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![],
			},
			LockedPackage {
				name: "c".into(),
				version: "1.0.0".into(),
				source: None,
				integrity: None,
				dependencies: vec![],
			},
		];
		let direct: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
		let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
		assert_eq!(
			graph.stats.total_packages, 3,
			"stats should report 3 packages, not 4 (root excluded)"
		);
		let stats = render_stats(&graph);
		assert!(stats.contains("3 packages"), "stats text should say 3 packages: {stats}");
	}

	// ── Finding #11: Color check on stdout, output to String ──────────

	#[test]
	fn render_tree_no_ansi_when_color_disabled() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let tree = render_tree(&graph, &RenderOptions::default(), false);
		assert!(
			!tree.contains("\x1b["),
			"should have no ANSI codes when use_color=false: {tree}"
		);
	}

	#[test]
	fn render_tree_has_ansi_when_color_enabled() {
		let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
		let tree = render_tree(&graph, &RenderOptions::default(), true);
		assert!(
			tree.contains("\x1b["),
			"should have ANSI codes when use_color=true: {tree}"
		);
	}

	// ── Escape helper unit tests ──────────────────────────────────────

	#[test]
	fn html_escape_covers_all_chars() {
		assert_eq!(html_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#39;");
		assert_eq!(html_escape("safe text"), "safe text");
	}

	#[test]
	fn dot_escape_covers_backslash_and_quote() {
		assert_eq!(dot_escape(r#"a"b\c"#), r#"a\"b\\c"#);
	}

	#[test]
	fn mermaid_escape_covers_quote_and_bracket() {
		assert_eq!(mermaid_escape(r#"a"b]c"#), "a#quot;b#93;c");
	}
}
