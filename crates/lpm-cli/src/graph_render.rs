//! Dependency graph data model and renderers.
//!
//! Builds a dependency graph from the lockfile and renders it in multiple formats:
//! tree (terminal), DOT (Graphviz), Mermaid, JSON, stats, and HTML.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Write};

use lpm_common::sanitize_terminal_inline;
use serde::Serialize;
use serde::ser::{SerializeSeq, SerializeStruct};

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
///
/// `max_depth` is **1-based** to match the user-facing `--depth N` flag
/// contract: the project root is level 1, direct deps are level 2, one
/// transitive layer beyond is level 3. An empty graph has `max_depth = 0`.
/// This matches `from_lockfile` and `recompute_stats` (both convert the
/// 0-based BFS `node.depth` to the 1-based level by adding 1) so the
/// number rendered into stats / json / html / tree summaries matches what
/// the user typed for `--depth`.
#[derive(Debug, Clone)]
pub struct GraphStats {
    pub total_packages: usize,
    pub lpm_packages: usize,
    pub npm_packages: usize,
    pub max_depth: usize,
    pub duplicates: Vec<(String, Vec<String>)>, // (name, [versions])
}

/// Convert the BFS `node.depth` set into the 1-based depth level shown
/// in user-facing summaries. Empty graph stays at 0; root-only graph
/// reports 1; deeper trees report `max(node.depth) + 1`.
fn level_from_node_depths<'a>(depths: impl Iterator<Item = &'a usize>) -> usize {
    depths.max().map_or(0, |d| d + 1)
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

            let mut dependencies = pkg.dependencies.clone();
            dependencies.sort_unstable();

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
                    dependencies,
                },
            );
        }

        // Create synthetic root node pointing to all direct deps
        let root_key = root_name.to_string();
        let mut direct_dep_keys: Vec<String> = nodes
            .iter()
            .filter(|(_, n)| n.is_direct)
            .map(|(k, _)| k.clone())
            .collect();
        direct_dep_keys.sort_unstable();

        nodes.insert(
            root_key.clone(),
            DepNode {
                name: root_name.split('@').next().unwrap_or(root_name).to_string(),
                version: root_name
                    .split('@')
                    .next_back()
                    .unwrap_or("0.0.0")
                    .to_string(),
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
            queue.push_back((root.clone(), 0));
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

        // 1-based to match the `--depth N` flag contract (root = 1).
        let max_depth = level_from_node_depths(nodes.values().map(|n| &n.depth));
        let lpm_count = nodes
            .values()
            .filter(|n| n.registry == Registry::Lpm)
            .count();
        let npm_count = nodes
            .values()
            .filter(|n| n.registry == Registry::Npm)
            .count();

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

    fn path_summary(&self, target_name: &str) -> PathSummary {
        let mut versions = HashSet::new();
        let path_count = self.visit_paths(target_name, |path| {
            if let Some(node) = path.last().and_then(|key| self.nodes.get(*key)) {
                versions.insert(node.version.as_str());
            }
            true
        });

        PathSummary {
            path_count,
            version_count: versions.len(),
        }
    }

    fn visit_paths<'graph, F>(&'graph self, target_name: &str, visitor: F) -> usize
    where
        F: FnMut(&[&'graph str]) -> bool,
    {
        let mut roots: Vec<&str> = self.roots.iter().map(String::as_str).collect();
        roots.sort_unstable();

        let mut target_keys: Vec<&str> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.name == target_name)
            .map(|(key, _)| key.as_str())
            .collect();
        target_keys.sort_unstable();

        let mut traversal = PathTraversal::new(self.stats.max_depth.max(1), visitor);

        for root_key in roots {
            for target_key in &target_keys {
                traversal.reset(root_key);
                if !self.dfs_paths(root_key, target_key, &mut traversal) {
                    return traversal.path_count;
                }
            }
        }

        traversal.path_count
    }

    fn dfs_paths<'graph, F>(
        &'graph self,
        current: &'graph str,
        target: &str,
        traversal: &mut PathTraversal<'graph, F>,
    ) -> bool
    where
        F: FnMut(&[&'graph str]) -> bool,
    {
        if current == target {
            traversal.path_count += 1;
            return (traversal.visitor)(&traversal.path);
        }

        if !traversal.visited.insert(current) {
            return true;
        }

        if let Some(node) = self.nodes.get(current) {
            for dep_key in &node.dependencies {
                traversal.path.push(dep_key);
                if !self.dfs_paths(dep_key, target, traversal) {
                    return false;
                }
                traversal.path.pop();
            }
        }

        traversal.visited.remove(current);
        true
    }
}

struct PathTraversal<'graph, F> {
    path: Vec<&'graph str>,
    visited: HashSet<&'graph str>,
    path_count: usize,
    visitor: F,
}

impl<'graph, F> PathTraversal<'graph, F> {
    fn new(initial_capacity: usize, visitor: F) -> Self {
        Self {
            path: Vec::with_capacity(initial_capacity),
            visited: HashSet::with_capacity(initial_capacity),
            path_count: 0,
            visitor,
        }
    }

    fn reset(&mut self, root_key: &'graph str) {
        self.path.clear();
        self.path.push(root_key);
        self.visited.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathSummary {
    path_count: usize,
    version_count: usize,
}

// ── Tree Renderer ──────────────────────────────────────────────────

pub fn render_tree(graph: &DepGraph, use_color: bool) -> String {
    let mut output = String::new();

    let mut sorted_roots = graph.roots.clone();
    sorted_roots.sort();

    for (i, root_key) in sorted_roots.iter().enumerate() {
        let is_last = i == sorted_roots.len() - 1;
        render_tree_node(
            graph,
            root_key,
            "",
            is_last,
            1,
            use_color,
            &mut HashSet::new(),
            &mut output,
        );
    }

    // Stats line
    output.push('\n');
    let dup_info = if graph.stats.duplicates.is_empty() {
        String::new()
    } else {
        let mut names = String::new();
        for (index, (name, _)) in graph.stats.duplicates.iter().enumerate() {
            if index > 0 {
                names.push_str(", ");
            }
            names.push_str(&sanitize_terminal_inline(name));
        }
        format!(", {} duplicates ({})", graph.stats.duplicates.len(), names)
    };
    output.push_str(&format!(
        "{} packages, max depth {}{}\n",
        graph.stats.total_packages, graph.stats.max_depth, dup_info,
    ));

    output
}

#[allow(clippy::too_many_arguments)]
fn render_tree_node(
    graph: &DepGraph,
    key: &str,
    prefix: &str,
    is_last: bool,
    depth: usize,
    use_color: bool,
    visited: &mut HashSet<String>,
    output: &mut String,
) {
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

    let colored_label = render_tree_label(node, use_color);

    let circular = if visited.contains(key) {
        color_tree_meta(" (circular)", use_color)
    } else {
        String::new()
    };

    output.push_str(&format!(
        "{}{}{}{}\n",
        color_tree_meta(prefix, use_color),
        color_tree_meta(connector, use_color),
        colored_label,
        circular
    ));

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
        render_tree_node(
            graph,
            dep_key,
            &child_prefix,
            is_last_child,
            depth + 1,
            use_color,
            visited,
            output,
        );
    }

    visited.remove(key);
}

fn render_tree_label(node: &DepNode, use_color: bool) -> String {
    let name = sanitize_terminal_inline(&node.name);
    let version = sanitize_terminal_inline(&node.version);
    format!(
        "{}{}{}",
        name,
        color_tree_meta("@", use_color),
        color_tree_version(&version, use_color)
    )
}

fn color_tree_meta(text: &str, use_color: bool) -> String {
    if use_color && !text.is_empty() {
        format!("\x1b[2m{text}\x1b[22m")
    } else {
        text.to_string()
    }
}

fn color_tree_version(text: &str, use_color: bool) -> String {
    if use_color {
        format!("\x1b[33m{text}\x1b[39m")
    } else {
        text.to_string()
    }
}

// ── Graph-level filter ────────────────────────────────────────────

/// Remove nodes that are not on any path from a root to a node whose name
/// contains `filter`. Keeps the root and all ancestors/descendants of
/// matching nodes. Recomputes edges (removes dangling deps) and stats.
pub fn filter_graph(graph: &mut DepGraph, filter: &str) {
    // Collect the set of nodes to keep: root nodes + nodes that are ancestors of
    // a match (i.e., their subtree contains a match).
    let mut keep = HashSet::new();

    for root_key in &graph.roots {
        // Root always stays
        keep.insert(root_key.clone());
        mark_matching_subtrees(graph, root_key, filter, &mut keep, &mut HashSet::new());
    }

    // Remove non-kept nodes
    graph.nodes.retain(|k, _| keep.contains(k));

    // Remove dangling edges from remaining nodes
    for node in graph.nodes.values_mut() {
        node.dependencies.retain(|dep_key| keep.contains(dep_key));
    }
}

/// DFS walk: if this node or any descendant contains `filter`, add this node
/// (and the chain leading to it) to `keep`. Returns true when the subtree
/// contains a match.
fn mark_matching_subtrees(
    graph: &DepGraph,
    key: &str,
    filter: &str,
    keep: &mut HashSet<String>,
    visited: &mut HashSet<String>,
) -> bool {
    if !visited.insert(key.to_string()) {
        // Already visited — return whether we already decided to keep it
        return keep.contains(key);
    }

    let node = match graph.nodes.get(key) {
        Some(n) => n,
        None => {
            visited.remove(key);
            return false;
        }
    };

    let self_matches = node.name.contains(filter);

    // Check children (need to clone deps to avoid borrow conflict)
    // Walk every child; do NOT use `.any()` here. `.any()` short-circuits
    // on the first true, which silently drops sibling branches in a
    // diamond pattern (root → {a, b} → shared-target). When `a` matches,
    // `b` would never be visited and gets pruned even though its subtree
    // also contains the target. Each child must be evaluated for its own
    // sake so its mark / keep_subtree side effects fire.
    let deps = node.dependencies.clone();
    let mut child_matches = false;
    for dep_key in &deps {
        if mark_matching_subtrees(graph, dep_key, filter, keep, visited) {
            child_matches = true;
        }
    }

    visited.remove(key);

    if self_matches || child_matches {
        keep.insert(key.to_string());
        // Also ensure the matched node's full subtree is kept (so the user
        // can see the dependencies of the matched package)
        if self_matches {
            keep_subtree(graph, key, keep);
        }
        true
    } else {
        false
    }
}

/// Recursively add all descendants of `key` to `keep`.
fn keep_subtree(graph: &DepGraph, key: &str, keep: &mut HashSet<String>) {
    if let Some(node) = graph.nodes.get(key) {
        for dep_key in &node.dependencies {
            if keep.insert(dep_key.clone()) {
                keep_subtree(graph, dep_key, keep);
            }
        }
    }
}

// ── Graph-level depth limit ───────────────────────────────────────

/// Drop nodes deeper than `max_depth` from the graph. The contract matches
/// `lpm graph --depth N`: the project root counts as level 1, direct deps
/// as level 2, and so on. `--depth 1` keeps just the root, `--depth 2` keeps
/// root + direct deps, `--depth 3` keeps one transitive layer beyond.
///
/// Applied at the graph level (vs. inside the tree renderer) so every
/// renderer — tree, dot, mermaid, json, stats, html — sees the same pruned
/// graph. The caller is responsible for calling `recompute_stats` afterward
/// so the summary line / `stats` / `html` header reflect the pruned counts.
///
/// Implemented as a BFS from `graph.roots` rather than reading
/// `node.depth` directly. `from_lockfile`'s BFS leaves orphan packages
/// (lockfile entries with no parent) at the default `depth = 0`, which
/// would otherwise survive a `--depth 1` even though they are not in the
/// reachable dependency tree.
pub fn prune_to_depth(graph: &mut DepGraph, max_depth: usize) {
    let mut keep: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    for root_key in &graph.roots {
        queue.push_back((root_key.clone(), 0));
    }

    while let Some((key, bfs_depth)) = queue.pop_front() {
        if bfs_depth >= max_depth {
            continue;
        }
        if !keep.insert(key.clone()) {
            continue;
        }
        if let Some(node) = graph.nodes.get(&key) {
            for dep_key in &node.dependencies {
                queue.push_back((dep_key.clone(), bfs_depth + 1));
            }
        }
    }

    graph.nodes.retain(|k, _| keep.contains(k));

    for node in graph.nodes.values_mut() {
        node.dependencies.retain(|dep_key| keep.contains(dep_key));
    }
}

/// Recompute graph stats after a mutation (filter, depth-prune,
/// subtree restriction, unreachable prune). Counts exclude synthetic
/// root nodes so `total_packages` is the user-meaningful count.
pub fn recompute_stats(graph: &mut DepGraph) {
    let lpm_count = graph
        .nodes
        .values()
        .filter(|n| n.registry == Registry::Lpm)
        .count();
    let npm_count = graph
        .nodes
        .values()
        .filter(|n| n.registry == Registry::Npm)
        .count();
    // 1-based to match the `--depth N` flag contract (root = 1).
    let max_depth = level_from_node_depths(graph.nodes.values().map(|n| &n.depth));

    let mut name_versions: HashMap<String, Vec<String>> = HashMap::new();
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

    let root_count = graph.nodes.values().filter(|n| n.is_root).count();

    graph.stats = GraphStats {
        total_packages: graph.nodes.len().saturating_sub(root_count),
        lpm_packages: lpm_count,
        npm_packages: npm_count,
        max_depth,
        duplicates,
    };
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
/// Mermaid uses `["label"]` syntax, so we must escape `"` and `]` which would
/// break out of the label. Also escape `<`, `>`, `{`, `}`, `(`, `)` which are
/// Mermaid node-shape delimiters.
fn mermaid_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace(']', "&#93;")
        .replace('[', "&#91;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('{', "&#123;")
        .replace('}', "&#125;")
        .replace('(', "&#40;")
        .replace(')', "&#41;")
}

// ── DOT Renderer ───────────────────────────────────────────────────

pub fn render_dot(graph: &DepGraph) -> String {
    let mut output = String::from(
        "digraph deps {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\", fontsize=10];\n\n",
    );

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
        output.push_str(&format!(
            "  \"{}\" [color=\"{}\"];\n",
            dot_escape(key),
            color
        ));
    }

    output.push('\n');

    // Edges (sorted for deterministic output)
    for key in &sorted_keys {
        let node = &graph.nodes[*key];
        for dep_key in &node.dependencies {
            output.push_str(&format!(
                "  \"{}\" -> \"{}\";\n",
                dot_escape(key),
                dot_escape(dep_key)
            ));
        }
    }

    output.push_str("}\n");
    output
}

// ── Mermaid Renderer ───────────────────────────────────────────────

pub fn render_mermaid(graph: &DepGraph) -> String {
    let mut output = String::from("graph LR\n");

    // Sanitize node IDs for Mermaid — only allow alphanumeric + underscore.
    // Everything else is replaced with underscore to prevent Mermaid parse errors.
    let sanitize = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
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
            output.push_str(&format!(
                "  style {} fill:#10b981,color:#fff\n",
                sanitize(key)
            ));
        } else if node.is_duplicate {
            output.push_str(&format!(
                "  style {} fill:#f59e0b,color:#fff\n",
                sanitize(key)
            ));
        }
    }

    output
}

// ── JSON Renderer ──────────────────────────────────────────────────

pub fn render_json(graph: &DepGraph) -> Result<String, serde_json::Error> {
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
            node.dependencies
                .iter()
                .map(move |dep| serde_json::json!({ "from": key, "to": dep }))
        })
        .collect();

    let duplicates: Vec<serde_json::Value> = graph
        .stats
        .duplicates
        .iter()
        .map(|(name, versions)| serde_json::json!({ "name": name, "versions": versions }))
        .collect();

    let root_name = graph
        .roots
        .first()
        .and_then(|k| graph.nodes.get(k))
        .map(|n| format!("{}@{}", n.name, n.version))
        .unwrap_or_default();

    serde_json::to_string_pretty(&serde_json::json!({
        "success": true,
        "root": root_name,
        "packages": graph.stats.total_packages,
        "lpm_packages": graph.stats.lpm_packages,
        "npm_packages": graph.stats.npm_packages,
        "max_depth": graph.stats.max_depth,
        "duplicates": duplicates,
        "nodes": nodes,
        "edges": edges,
    }))
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
            let name = sanitize_terminal_inline(name);
            let mut version_list = String::new();
            for (index, version) in versions.iter().enumerate() {
                if index > 0 {
                    version_list.push_str(", ");
                }
                version_list.push_str(&name);
                version_list.push('@');
                version_list.push_str(&sanitize_terminal_inline(version));
            }
            output.push_str(&format!("  {version_list}\n"));
        }
    }

    output
}

// ── Why Renderer ───────────────────────────────────────────────────

pub fn write_why<W: Write>(
    mut writer: W,
    graph: &DepGraph,
    target_name: &str,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> io::Result<()> {
    let target_display = sanitize_terminal_inline(target_name);
    let is_direct = graph
        .nodes
        .values()
        .any(|n| n.name == target_name && n.is_direct);
    let summary = graph.path_summary(target_name);

    if summary.path_count == 0 {
        writeln!(writer, "{target_display} is not in your dependency tree.")?;
        return Ok(());
    }

    if is_direct {
        writeln!(writer, "{target_display} is a direct dependency.\n")?;
    }

    writeln!(
        writer,
        "{target_display} is required by {} path(s):\n",
        summary.path_count
    )?;

    let mut write_error = None;
    let rendered_path_count = graph.visit_paths(target_name, |path| {
        let result = (|| -> io::Result<()> {
            writer.write_all(b"  ")?;
            for (index, key) in path.iter().enumerate() {
                if index > 0 {
                    writer.write_all(" → ".as_bytes())?;
                }
                if let Some(node) = graph.nodes.get(*key) {
                    write!(
                        writer,
                        "{}@{}",
                        sanitize_terminal_inline(&node.name),
                        sanitize_terminal_inline(&node.version)
                    )?;
                } else {
                    writer.write_all(sanitize_terminal_inline(key).as_bytes())?;
                }
            }
            writeln!(writer)
        })();

        match result {
            Ok(()) => true,
            Err(error) => {
                write_error = Some(error);
                false
            }
        }
    });
    if let Some(error) = write_error {
        return Err(error);
    }
    debug_assert_eq!(rendered_path_count, summary.path_count);

    if summary.version_count > 1 {
        writeln!(
            writer,
            "\n{} versions installed (duplicate)",
            summary.version_count
        )?;
    }

    if let Some(state) = overrides_state {
        let has_matching_override = state.applied.iter().any(|hit| hit.package == target_name);
        if has_matching_override {
            writeln!(writer, "\nOverrides applied to this package:")?;
            for hit in state
                .applied
                .iter()
                .filter(|hit| hit.package == target_name)
            {
                let parent_suffix = match &hit.via_parent {
                    Some(parent) => {
                        format!(", reached through {}", sanitize_terminal_inline(parent))
                    }
                    None => String::new(),
                };
                let from_version = sanitize_terminal_inline(&hit.from_version);
                let to_version = sanitize_terminal_inline(&hit.to_version);
                let source_display = hit.source_display();
                let source_display = sanitize_terminal_inline(&source_display);
                writeln!(
                    writer,
                    "  {} → {} (via {}{parent_suffix})",
                    from_version, to_version, source_display,
                )?;
            }
        }
    }

    if let Some(state) = patch_state {
        let has_matching_patch = state.applied.iter().any(|hit| hit.name == target_name);
        if has_matching_patch {
            writeln!(writer, "\nPatches applied to this package:")?;
            for hit in state.applied.iter().filter(|hit| hit.name == target_name) {
                let total = hit.files_modified + hit.files_added + hit.files_deleted;
                let file_part = if total > 0 {
                    format!("{} file{}, ", total, if total == 1 { "" } else { "s" })
                } else {
                    String::new()
                };
                let integrity_part = match &hit.original_integrity {
                    Some(integ) => {
                        let integ = sanitize_terminal_inline(integ);
                        format!("originalIntegrity {}", truncate_integrity(&integ))
                    }
                    None => "originalIntegrity recorded".to_string(),
                };
                let patch_path = sanitize_terminal_inline(&hit.patch_path);
                writeln!(writer, "  {} ({}{})", patch_path, file_part, integrity_part,)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn render_why(
    graph: &DepGraph,
    target_name: &str,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> String {
    let mut output = Vec::new();
    write_why(
        &mut output,
        graph,
        target_name,
        overrides_state,
        patch_state,
    )
    .expect("write graph why output");
    String::from_utf8(output).expect("graph why output must be UTF-8")
}

/// Truncate an SRI integrity hash for compact human-readable display.
/// Keeps the algorithm prefix + the first 16 base64 chars + ellipsis.
/// Strings shorter than the threshold are returned as-is.
///
/// introduced so
/// `lpm graph --why` can display real integrity hashes inline without
/// blowing out terminal width. Full hash is still available in JSON
/// output via `applied_patches[i].original_integrity`.
fn truncate_integrity(integrity: &str) -> String {
    // `sha512-` prefix is 7 chars; keep 7 + 16 base64 = 23 chars then "…".
    const KEEP: usize = 23;
    if integrity.len() <= KEEP {
        integrity.to_string()
    } else {
        // Char-boundary safe: SRI hashes are pure ASCII so byte slicing
        // never lands inside a multi-byte sequence, but we use char_indices
        // for defense in depth.
        let cut = integrity
            .char_indices()
            .nth(KEEP)
            .map_or(integrity.len(), |(i, _)| i);
        format!("{}…", &integrity[..cut])
    }
}

// ── Why JSON ───────────────────────────────────────────────────────

pub fn write_why_json<W: Write>(
    mut writer: W,
    graph: &DepGraph,
    target_name: &str,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> Result<(), serde_json::Error> {
    let summary = graph.path_summary(target_name);
    let override_hits: Vec<serde_json::Value> = overrides_state
        .map(|s| {
            s.applied
                .iter()
                .filter(|h| h.package == target_name)
                .map(|h| {
                    serde_json::json!({
                        "raw_key": h.raw_key,
                        "source": h.source,
                        "package": h.package,
                        "from_version": h.from_version,
                        "to_version": h.to_version,
                        "via_parent": h.via_parent,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let patch_hits: Vec<serde_json::Value> = patch_state
        .map(|s| {
            s.applied
                .iter()
                .filter(|h| h.name == target_name)
                .map(|h| {
                    serde_json::json!({
                        "raw_key": h.raw_key,
                        "name": h.name,
                        "version": h.version,
                        "patch_path": h.patch_path,
                        "original_integrity": h.original_integrity,
                        "locations": h.locations,
                        "files_modified": h.files_modified,
                        "files_added": h.files_added,
                        "files_deleted": h.files_deleted,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let output = WhyJson {
        graph,
        target_name,
        summary,
        override_hits: &override_hits,
        patch_hits: &patch_hits,
    };
    serde_json::to_writer_pretty(&mut writer, &output)?;
    writer.write_all(b"\n").map_err(serde_json::Error::io)
}

struct WhyJson<'graph, 'value> {
    graph: &'graph DepGraph,
    target_name: &'value str,
    summary: PathSummary,
    override_hits: &'value [serde_json::Value],
    patch_hits: &'value [serde_json::Value],
}

// The explicit serializer keeps the JSON field names stable while `paths`
// writes one visited path at a time instead of materializing the full array.
impl Serialize for WhyJson<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut output = serializer.serialize_struct("WhyJson", 7)?;
        output.serialize_field("success", &true)?;
        output.serialize_field("target", self.target_name)?;
        output.serialize_field("found", &(self.summary.path_count > 0))?;
        output.serialize_field("path_count", &self.summary.path_count)?;
        output.serialize_field(
            "paths",
            &WhyJsonPaths {
                graph: self.graph,
                target_name: self.target_name,
                path_count: self.summary.path_count,
            },
        )?;
        output.serialize_field("applied_overrides", self.override_hits)?;
        output.serialize_field("applied_patches", self.patch_hits)?;
        output.end()
    }
}

struct WhyJsonPaths<'graph, 'value> {
    graph: &'graph DepGraph,
    target_name: &'value str,
    path_count: usize,
}

impl Serialize for WhyJsonPaths<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut paths = serializer.serialize_seq(Some(self.path_count))?;
        let mut serialization_error = None;
        let serialized_path_count = self.graph.visit_paths(self.target_name, |path| {
            match paths.serialize_element(&WhyJsonPath {
                graph: self.graph,
                path,
            }) {
                Ok(()) => true,
                Err(error) => {
                    serialization_error = Some(error);
                    false
                }
            }
        });

        if let Some(error) = serialization_error {
            return Err(error);
        }
        debug_assert_eq!(serialized_path_count, self.path_count);
        paths.end()
    }
}

struct WhyJsonPath<'graph, 'path> {
    graph: &'graph DepGraph,
    path: &'path [&'graph str],
}

impl Serialize for WhyJsonPath<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut path = serializer.serialize_seq(Some(self.path.len()))?;
        for key in self.path {
            if let Some(node) = self.graph.nodes.get(*key) {
                path.serialize_element(&format!("{}@{}", node.name, node.version))?;
            } else {
                path.serialize_element(key)?;
            }
        }
        path.end()
    }
}

#[cfg(test)]
fn render_why_json(
    graph: &DepGraph,
    target_name: &str,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> Result<String, serde_json::Error> {
    let mut output = Vec::new();
    write_why_json(
        &mut output,
        graph,
        target_name,
        overrides_state,
        patch_state,
    )?;
    Ok(String::from_utf8(output).expect("graph why JSON must be UTF-8"))
}

// ── HTML Renderer ──────────────────────────────────────────────────

pub fn render_html(graph: &DepGraph) -> Result<String, serde_json::Error> {
    let json_data = render_json(graph)?;
    let stats = render_stats(graph).replace('\n', " | ");
    let stats = stats.trim_end_matches(" | ");

    // Sanitize JSON for safe embedding in <script> tag.
    // Replace all `</` sequences (case-insensitive attack vector for </script>, </SCRIPT>, etc.)
    let safe_json = json_data.replace("</", "<\\/");

    // HTML-escape the stats string to prevent XSS via package names
    let safe_stats = html_escape(stats);

    Ok(include_str!("templates/graph.html")
        .replace("__GRAPH_DATA__", &safe_json)
        .replace("__STATS__", &safe_stats))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_lockfile::LockedPackage;

    const HOSTILE_TERMINAL_FIELD: &str =
        "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";

    fn assert_hostile_terminal_field_is_inline_safe(context: &str, rendered: &str) {
        assert!(
            rendered.contains("safe?FORGED?rewritten?end"),
            "{context} must preserve readable graph text without forged rows, got:\n{rendered}"
        );
        for attacker_fragment in [
            "\nFORGED", "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{007f}", "\u{0090}", "\u{009c}",
            "hidden",
        ] {
            assert!(
                !rendered.contains(attacker_fragment),
                "{context} retained attacker fragment {attacker_fragment:?}:\n{rendered}"
            );
        }
    }

    fn mock_packages() -> Vec<LockedPackage> {
        vec![
            LockedPackage {
                name: "express".into(),
                version: "4.22.1".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["accepts@1.3.8".into(), "debug@2.6.9".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "accepts".into(),
                version: "1.3.8".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["mime-types@2.1.35".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "debug".into(),
                version: "2.6.9".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["ms@2.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "ms".into(),
                version: "2.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "ms".into(),
                version: "2.1.3".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "mime-types".into(),
                version: "2.1.35".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "@lpm.dev/neo.highlight".into(),
                version: "1.1.1".into(),
                source: Some("registry+https://lpm.dev".into()),
                integrity: None,
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
                tarball: None,
            },
        ]
    }

    fn direct_deps() -> HashSet<String> {
        ["express", "@lpm.dev/neo.highlight"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn package(name: &str, dependencies: &[&str]) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).to_string())
                .collect(),
            alias_dependencies: Vec::new(),
            peers: Vec::new(),
            tarball: None,
        }
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
        let tree = render_tree(&graph, false);
        assert!(
            tree.contains("├──") || tree.contains("└──"),
            "tree should have box-drawing: {tree}"
        );
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
        let json = render_json(&graph).expect("render graph JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["packages"].as_u64().unwrap(), 7); // excludes synthetic root
        assert!(!parsed["nodes"].as_array().unwrap().is_empty());
        assert!(!parsed["edges"].as_array().unwrap().is_empty());
        // Root node should be in the JSON
        let root = parsed["nodes"]
            .as_array()
            .unwrap()
            .iter()
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

    /// Regression: the displayed `Max depth` is 1-based to match the
    /// user-facing `--depth N` contract (root = level 1, direct = level 2).
    /// Before the fix, `recompute_stats` derived `max_depth` from raw
    /// `node.depth` (0-based BFS depth), so `lpm graph --format stats
    /// --depth 2` reported "Max depth: 1" — read as a contract violation
    /// against the docs that said level 2 == direct deps.
    #[test]
    fn stats_max_depth_is_one_based_after_prune() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        // --depth 2: root + direct deps. Highest node-depth is 1 (direct),
        // user-facing level is 2.
        prune_to_depth(&mut graph, 2);
        recompute_stats(&mut graph);
        assert_eq!(
            graph.stats.max_depth, 2,
            "stats.max_depth should match the --depth flag input (1-based)"
        );

        let stats = render_stats(&graph);
        assert!(
            stats.contains("Max depth: 2"),
            "stats text should display 1-based level matching --depth: {stats}"
        );

        let json = render_json(&graph).expect("render graph JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["max_depth"].as_u64(),
            Some(2),
            "json max_depth must mirror the 1-based stats value: {json}"
        );

        let html = render_html(&graph).expect("render graph HTML");
        assert!(
            html.contains("Max depth: 2"),
            "html stats summary must use the 1-based level"
        );
    }

    /// Boundary cases for the 1-based level conversion.
    #[test]
    fn stats_max_depth_root_only_and_empty() {
        // Root only — pruned to --depth 1 keeps just the synthetic root.
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        prune_to_depth(&mut graph, 1);
        recompute_stats(&mut graph);
        assert_eq!(
            graph.stats.max_depth, 1,
            "root-only graph reports 1 level (the project itself)"
        );

        // Empty — pruned to --depth 0 drops everything.
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        prune_to_depth(&mut graph, 0);
        recompute_stats(&mut graph);
        assert_eq!(
            graph.stats.max_depth, 0,
            "empty graph reports 0 levels (nothing rendered)"
        );
    }

    #[test]
    fn why_transitive_dep() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let why = render_why(&graph, "ms", None, None);
        assert!(why.contains("required by"));
        assert!(why.contains("→"));
    }

    #[test]
    fn why_not_found() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let why = render_why(&graph, "lodash", None, None);
        assert!(why.contains("not in your dependency tree"));
    }

    #[test]
    fn why_direct_dep() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let why = render_why(&graph, "express", None, None);
        assert!(why.contains("direct dependency"));
    }

    #[test]
    fn html_has_max_force_nodes_check() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
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
        let html = render_html(&graph).expect("render graph HTML");
        // The mousemove addEventListener should close with }, {passive: true});
        assert!(
            html.contains("'mousemove'"),
            "should have mousemove listener"
        );
        // Find the next "Mouse up" comment after mousemove to bound the search
        let mousemove_idx = html.find("'mousemove'").unwrap();
        let next_section = html[mousemove_idx..]
            .find("// Mouse up")
            .map_or(html.len(), |i| mousemove_idx + i);
        let mousemove_section = &html[mousemove_idx..next_section];
        assert!(
            mousemove_section.contains("{passive: true}"),
            "mousemove listener should have {{passive: true}}"
        );
    }

    #[test]
    fn html_resize_has_passive_true() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
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
        let html = render_html(&graph).expect("render graph HTML");
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
        let html = render_html(&graph).expect("render graph HTML");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("express"));
        assert!(html.contains("LPM Dependency Graph"));
    }

    #[test]
    fn filter_shows_matching_subtrees() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        filter_graph(&mut graph, "ms");
        let tree = render_tree(&graph, false);
        // "ms" is under express→debug→ms, so express and debug should appear
        assert!(
            tree.contains("express"),
            "filter should show parent of matching node: {tree}"
        );
        assert!(
            tree.contains("ms@2.0.0"),
            "filter should show matching node: {tree}"
        );
        // neo.highlight has no "ms" in its subtree, so it should be filtered out
        assert!(
            !tree.contains("neo.highlight"),
            "filter should hide non-matching subtrees: {tree}"
        );
    }

    #[test]
    fn depth_limit() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        // --depth 2 keeps root + direct deps (express, neo.highlight)
        prune_to_depth(&mut graph, 2);
        let tree = render_tree(&graph, false);
        assert!(
            tree.contains("express@4.22.1"),
            "should show direct dep: {tree}"
        );
        assert!(tree.contains("test-app"), "should show root: {tree}");
        // ms is depth 3+ (root→express→debug→ms), should NOT appear
        assert!(
            !tree.contains("ms@2.0.0"),
            "should not show deep transitive dep: {tree}"
        );
    }

    /// Regression: `--depth N` was historically only honored by the tree
    /// renderer; dot/json/mermaid/stats/html silently rendered the full
    /// graph. After the fix it is applied at the graph level so every
    /// renderer sees the truncated set, including the duplicates summary
    /// embedded in the HTML header.
    #[test]
    fn depth_limit_applies_to_all_formats() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        prune_to_depth(&mut graph, 2);
        // Mirror the production command flow: stats must be recomputed
        // after a graph mutation or stale duplicate / count info leaks
        // into the stats / html surfaces.
        recompute_stats(&mut graph);

        // dot
        let dot = render_dot(&graph);
        assert!(dot.contains("express"), "dot should keep direct dep");
        assert!(
            !dot.contains("ms@2.0.0"),
            "dot should drop deep transitive: {dot}"
        );

        // mermaid
        let mermaid = render_mermaid(&graph);
        assert!(
            mermaid.contains("express"),
            "mermaid should keep direct dep"
        );
        assert!(
            !mermaid.contains("ms@2.0.0"),
            "mermaid should drop deep transitive"
        );

        // json
        let json = render_json(&graph).expect("render graph JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let names: Vec<&str> = parsed["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"express"),
            "json should keep direct dep: {names:?}"
        );
        assert!(
            !names.contains(&"ms"),
            "json should drop deep transitive: {names:?}"
        );

        // html — stats summary embedded in the page header reflects the
        // pruned graph, not the original duplicate set.
        let html = render_html(&graph).expect("render graph HTML");
        assert!(html.contains("express"), "html should keep direct dep");
        assert!(
            !html.contains("ms@2.0.0"),
            "html should drop deep transitive"
        );
    }

    /// Regression: pruning to depth 1 keeps just the root node. The
    /// historical inline-tree-only check returned early on depth=1 before
    /// drawing anything; the graph-level prune yields the same shape.
    #[test]
    fn depth_one_keeps_only_root() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        prune_to_depth(&mut graph, 1);
        // Only the synthetic root remains (depth 0).
        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.nodes.contains_key("test-app@1.0.0"));
    }

    // ── XSS via unescaped __STATS__ in HTML ──────────────

    #[test]
    fn html_escapes_xss_in_stats() {
        // Create a duplicate-triggering package with XSS name so the name appears in stats
        let packages = vec![
            LockedPackage {
                name: "<img src=x onerror=alert(1)>".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "<img src=x onerror=alert(1)>".into(),
                version: "2.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
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
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["<img src=x onerror=alert(1)>"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
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

    // ── XSS via innerHTML in tooltip ─────────────────────

    #[test]
    fn html_tooltip_uses_textcontent_not_innerhtml() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
        assert!(
            !html.contains(".meta').innerHTML") && !html.contains(".meta\").innerHTML"),
            "tooltip must not use innerHTML (XSS risk)"
        );
        assert!(
            html.contains("textContent") || html.contains("createElement"),
            "tooltip should use textContent or createElement for safe DOM building"
        );
    }

    // ── Exponential path blowup in dfs_paths ─────────────

    #[test]
    fn visit_paths_returns_every_path_with_storage_bounded_by_depth() {
        let mut packages = Vec::new();
        let mut root_deps = Vec::new();

        let depth = 7;
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
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec![shared_key.clone()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            });
            packages.push(LockedPackage {
                name: format!("branch-{i}-b"),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec![shared_key.clone()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            });
            packages.push(LockedPackage {
                name: format!("shared-{i}"),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: next_deps,
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
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
            tarball: None,
        });

        let direct: HashSet<String> = root_deps
            .iter()
            .map(|s| s.split('@').next().unwrap().to_string())
            .collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        let mut callback_count = 0;
        let mut max_path_len = 0;
        let path_count = graph.visit_paths("target", |path| {
            callback_count += 1;
            max_path_len = max_path_len.max(path.len());
            true
        });

        assert_eq!(
            (path_count, callback_count, max_path_len),
            (1 << depth, 1 << depth, depth * 2 + 2)
        );
    }

    #[test]
    fn visit_paths_terminates_cycles_without_losing_acyclic_paths() {
        let packages = vec![
            package("a", &["target@1.0.0", "b@1.0.0"]),
            package("b", &["target@1.0.0", "a@1.0.0"]),
            package("target", &[]),
        ];
        let direct = HashSet::from(["a".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        let path_count = graph.visit_paths("target", |_| true);

        assert_eq!(path_count, 2);
    }

    #[test]
    fn visit_paths_orders_target_versions_and_edges_lexically() {
        let mut target_v2 = package("target", &[]);
        target_v2.version = "2.0.0".into();
        let packages = vec![
            package("zeta", &["target@2.0.0", "target@1.0.0"]),
            package("alpha", &["target@2.0.0", "target@1.0.0"]),
            package("target", &[]),
            target_v2,
        ];
        let direct = HashSet::from(["zeta".to_string(), "alpha".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let mut paths = Vec::new();

        graph.visit_paths("target", |path| {
            paths.push(path.to_vec());
            true
        });

        assert_eq!(
            paths,
            vec![
                vec!["app@1.0.0", "alpha@1.0.0", "target@1.0.0"],
                vec!["app@1.0.0", "zeta@1.0.0", "target@1.0.0"],
                vec!["app@1.0.0", "alpha@1.0.0", "target@2.0.0"],
                vec!["app@1.0.0", "zeta@1.0.0", "target@2.0.0"],
            ]
        );
    }

    // ── DOT unescaped quotes in node names ───────────────

    #[test]
    fn dot_escapes_quotes_in_names() {
        let packages = vec![LockedPackage {
            name: "foo\"bar\\baz".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["foo\"bar\\baz"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let dot = render_dot(&graph);
        assert!(
            dot.contains(r#"foo\"bar\\baz"#),
            "DOT output should escape quotes and backslashes: {dot}"
        );
    }

    // ── Mermaid unescaped quotes in labels ────────────────

    #[test]
    fn mermaid_escapes_quotes_and_brackets() {
        let packages = vec![LockedPackage {
            name: "foo\"bar]baz".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["foo\"bar]baz"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let mermaid = render_mermaid(&graph);
        let label_lines: Vec<&str> = mermaid.lines().filter(|l| l.contains("foo")).collect();
        for line in &label_lines {
            if line.contains('[') {
                assert!(
                    line.contains("&quot;") && line.contains("&#93;"),
                    "Mermaid label should use standard HTML entity escapes: {line}"
                );
            }
        }
    }

    // ── Incomplete </script> case escaping ────────────────

    #[test]
    fn html_escapes_all_script_closing_tags() {
        let packages = vec![LockedPackage {
            name: "pkg</SCRIPT>test".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["pkg</SCRIPT>test"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
        // Check within the <script> tag specifically
        let script_start = html.find("<script>").unwrap();
        let script_end = html.rfind("</script>").unwrap();
        let script_body = &html[script_start + 8..script_end];
        assert!(
            !script_body.contains("</SCRIPT>") && !script_body.contains("</Script>"),
            "script body must not contain any case variant of closing script tag"
        );
    }

    // ── --filter misses diamond-pattern matches ───────────

    #[test]
    fn filter_finds_match_through_both_diamond_branches() {
        let packages = vec![
            LockedPackage {
                name: "branch-a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["shared-target@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "branch-b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["shared-target@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "shared-target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["branch-a", "branch-b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        filter_graph(&mut graph, "shared-target");
        let tree = render_tree(&graph, false);
        assert!(
            tree.contains("branch-a"),
            "branch-a should appear (leads to match): {tree}"
        );
        assert!(
            tree.contains("branch-b"),
            "branch-b should appear (leads to match): {tree}"
        );
        assert!(
            tree.contains("shared-target"),
            "shared-target should appear: {tree}"
        );
    }

    // ── Stats include synthetic root ─────────────────────

    #[test]
    fn stats_exclude_synthetic_root() {
        let packages = vec![
            LockedPackage {
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "c".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        assert_eq!(
            graph.stats.total_packages, 3,
            "stats should report 3 packages, not 4 (root excluded)"
        );
        let stats = render_stats(&graph);
        assert!(
            stats.contains("3 packages"),
            "stats text should say 3 packages: {stats}"
        );
    }

    // ── Color check on stdout, output to String ──────────

    #[test]
    fn render_tree_no_ansi_when_color_disabled() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let tree = render_tree(&graph, false);
        assert!(
            !tree.contains("\x1b["),
            "should have no ANSI codes when use_color=false: {tree}"
        );
    }

    #[test]
    fn render_tree_sanitizes_package_name_and_version_fields() {
        let mut packages = mock_packages();
        packages[0].name = HOSTILE_TERMINAL_FIELD.to_string();
        packages[0].version = HOSTILE_TERMINAL_FIELD.to_string();
        let direct = HashSet::from([HOSTILE_TERMINAL_FIELD.to_string()]);
        let mut graph = DepGraph::from_lockfile(&packages, &direct, "test-app@1.0.0");
        graph.stats.duplicates = vec![(
            HOSTILE_TERMINAL_FIELD.to_string(),
            vec!["1.0.0".to_string(), "2.0.0".to_string()],
        )];

        let tree = render_tree(&graph, false);

        assert_hostile_terminal_field_is_inline_safe("graph tree output", &tree);
    }

    #[test]
    fn render_tree_sanitizes_package_fields_before_lpm_styling() {
        let mut packages = mock_packages();
        packages[0].name = HOSTILE_TERMINAL_FIELD.to_string();
        packages[0].version = HOSTILE_TERMINAL_FIELD.to_string();
        let direct = HashSet::from([HOSTILE_TERMINAL_FIELD.to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "test-app@1.0.0");

        let tree = render_tree(&graph, true);

        assert!(
            tree.contains("\u{1b}[33msafe?FORGED?rewritten?end\u{1b}[39m"),
            "LPM version styling must wrap the sanitized value: {tree}"
        );
        assert!(!tree.contains("\u{1b}]52"));
        assert!(!tree.contains("\nFORGED"));
        assert!(!tree.contains("hidden"));
    }

    #[test]
    fn render_stats_sanitizes_duplicate_package_fields() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        graph.stats.duplicates = vec![(
            HOSTILE_TERMINAL_FIELD.to_string(),
            vec![HOSTILE_TERMINAL_FIELD.to_string(), "2.0.0".to_string()],
        )];

        let stats = render_stats(&graph);

        assert_hostile_terminal_field_is_inline_safe("graph stats output", &stats);
    }

    #[test]
    fn render_tree_has_ansi_when_color_enabled() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let tree = render_tree(&graph, true);
        assert!(
            tree.contains("\x1b["),
            "should have ANSI codes when use_color=true: {tree}"
        );
        assert!(
            tree.contains("\x1b[2m@\x1b[22m") && tree.contains("\x1b[33m1.0.0\x1b[39m"),
            "tree color should dim @ separators and color version targets yellow: {tree}"
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
    fn mermaid_escape_covers_all_special_chars() {
        assert_eq!(mermaid_escape(r#"a"b]c"#), "a&quot;b&#93;c");
        assert_eq!(mermaid_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(mermaid_escape("a(b)c"), "a&#40;b&#41;c");
        assert_eq!(mermaid_escape("a{b}c"), "a&#123;b&#125;c");
        assert_eq!(mermaid_escape("a[b&c"), "a&#91;b&amp;c");
    }

    // ── Depth accounting ────────────────────────────────────

    #[test]
    fn root_node_has_depth_zero() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        assert_eq!(
            graph.nodes["test-app@1.0.0"].depth, 0,
            "root node should have depth 0"
        );
    }

    #[test]
    fn direct_deps_have_depth_one() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        assert_eq!(
            graph.nodes["express@4.22.1"].depth, 1,
            "direct dep should have depth 1"
        );
        assert_eq!(
            graph.nodes["@lpm.dev/neo.highlight@1.1.1"].depth, 1,
            "direct dep should have depth 1"
        );
    }

    #[test]
    fn transitive_deps_have_correct_depth() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        // express→debug→ms, so ms is depth 3
        assert_eq!(graph.nodes["debug@2.6.9"].depth, 2);
        assert_eq!(graph.nodes["ms@2.0.0"].depth, 3);
    }

    // ── render_why shows all paths for direct deps ──────────

    #[test]
    fn why_direct_dep_also_shows_path() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let why = render_why(&graph, "express", None, None);
        assert!(
            why.contains("direct dependency"),
            "should mention direct dep: {why}"
        );
        assert!(why.contains("required by"), "should also show paths: {why}");
        assert!(why.contains("→"), "should contain path arrows: {why}");
    }

    #[test]
    fn render_why_sanitizes_package_names_and_versions_in_paths() {
        let mut packages = mock_packages();
        packages[0].name = HOSTILE_TERMINAL_FIELD.to_string();
        packages[0].version = HOSTILE_TERMINAL_FIELD.to_string();
        let direct = HashSet::from([HOSTILE_TERMINAL_FIELD.to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "test-app@1.0.0");

        let why = render_why(&graph, HOSTILE_TERMINAL_FIELD, None, None);

        assert_hostile_terminal_field_is_inline_safe("graph why path output", &why);
    }

    // ── JSON root field ─────────────────────────────────────

    #[test]
    fn json_output_has_root_field() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let json = render_json(&graph).expect("render graph JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["root"].as_str().unwrap(),
            "test-app@1.0.0",
            "JSON should have root field"
        );
    }

    // ── Mermaid sanitize whitelist ──────────────────────────

    #[test]
    fn mermaid_sanitize_replaces_special_chars() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let mermaid = render_mermaid(&graph);
        // @ and . should be replaced in IDs (not in labels)
        let id_lines: Vec<&str> = mermaid.lines().filter(|l| l.contains("-->")).collect();
        for line in &id_lines {
            // IDs in edge lines should not contain @ or .
            let parts: Vec<&str> = line.trim().split("-->").collect();
            for part in parts {
                let id = part.trim();
                assert!(
                    !id.contains('@') && !id.contains('.'),
                    "Mermaid IDs should not contain @ or .: {id}"
                );
            }
        }
    }

    #[test]
    fn mermaid_sanitize_handles_parentheses_in_name() {
        let packages = vec![LockedPackage {
            name: "foo(bar)".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["foo(bar)"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let mermaid = render_mermaid(&graph);
        // IDs should not contain parentheses (would be interpreted as node shape)
        let id_lines: Vec<&str> = mermaid.lines().filter(|l| l.contains("-->")).collect();
        for line in &id_lines {
            let parts: Vec<&str> = line.trim().split("-->").collect();
            for part in parts {
                let id = part.trim();
                assert!(
                    !id.contains('(') && !id.contains(')'),
                    "Mermaid IDs must not contain parentheses: {id}"
                );
            }
        }
        // But labels should contain escaped parentheses
        let label_lines: Vec<&str> = mermaid
            .lines()
            .filter(|l| l.contains("foo"))
            .filter(|l| l.contains('['))
            .collect();
        assert!(
            !label_lines.is_empty(),
            "should have label definitions for foo"
        );
        for line in &label_lines {
            assert!(
                line.contains("&#40;") && line.contains("&#41;"),
                "Mermaid label should escape parentheses: {line}"
            );
        }
    }

    // ── HTML template property names match JSON ─────────────

    #[test]
    fn html_uses_snake_case_properties() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");

        // Should NOT contain camelCase property access on data objects
        assert!(
            !html.contains(".isRoot"),
            "HTML should use .is_root not .isRoot for property access"
        );
        assert!(
            !html.contains(".dependencyCount"),
            "HTML should use .dependency_count not .dependencyCount"
        );

        // Should contain the correct snake_case property references
        assert!(html.contains(".is_root"), "HTML should reference .is_root");
        assert!(
            html.contains(".dependency_count") || html.contains("dependency_count"),
            "HTML should reference dependency_count"
        );
    }

    // ── Search debounce ─────────────────────────────────────

    #[test]
    fn html_search_has_debounce() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let html = render_html(&graph).expect("render graph HTML");
        assert!(
            html.contains("setTimeout"),
            "search should use setTimeout for debounce"
        );
        assert!(
            html.contains("clearTimeout"),
            "search should clear previous timer"
        );
    }

    // ── Registry::Unknown handling ──────────────────────────

    #[test]
    fn unknown_registry_handled() {
        let packages = vec![LockedPackage {
            name: "private-pkg".into(),
            version: "1.0.0".into(),
            source: Some("registry+https://custom.registry.com".into()),
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["private-pkg"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        assert_eq!(
            graph.nodes["private-pkg@1.0.0"].registry,
            Registry::Unknown,
            "custom registry should be Unknown"
        );

        // Should not count as LPM or npm
        assert_eq!(graph.stats.lpm_packages, 0);
        assert_eq!(graph.stats.npm_packages, 0);

        // All renderers should handle it without panic
        let _tree = render_tree(&graph, false);
        let _dot = render_dot(&graph);
        let _mermaid = render_mermaid(&graph);
        let _json = render_json(&graph).expect("render graph JSON");
        let _stats = render_stats(&graph);
        let _html = render_html(&graph).expect("render graph HTML");
    }

    // ── why with multiple versions ───────────────────────────

    #[test]
    fn why_shows_multiple_version_note() {
        // Create a graph where two versions of "ms" are both reachable
        let packages = vec![
            LockedPackage {
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["ms@2.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["ms@2.1.3".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "ms".into(),
                version: "2.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "ms".into(),
                version: "2.1.3".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let why = render_why(&graph, "ms", None, None);
        assert!(
            why.contains("2 versions installed"),
            "should note multiple versions: {why}"
        );
    }

    #[test]
    fn why_json_output() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let json = render_why_json(&graph, "ms", None, None).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["target"].as_str().unwrap(), "ms");
        assert!(parsed["found"].as_bool().unwrap());
        assert!(parsed["path_count"].as_u64().unwrap() > 0);
        assert!(!parsed["paths"].as_array().unwrap().is_empty());
    }

    #[test]
    fn why_json_not_found() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let json = render_why_json(&graph, "lodash", None, None).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!parsed["found"].as_bool().unwrap());
        assert_eq!(parsed["path_count"].as_u64().unwrap(), 0);
    }

    // ── `--why` decorates with override traces ─

    /// Build a synthetic OverridesState containing a single hit. The
    /// helper avoids constructing through the resolver, since this test
    /// is purely about render_why's decoration logic.
    fn fake_overrides_state(
        package: &str,
        from: &str,
        to: &str,
        via_parent: Option<&str>,
    ) -> crate::overrides_state::OverridesState {
        crate::overrides_state::OverridesState {
            state_version: crate::overrides_state::OVERRIDES_STATE_VERSION,
            fingerprint: "sha256-test".to_string(),
            captured_at: "T00:00:00Z".to_string(),
            parsed: vec![],
            applied: vec![lpm_resolver::OverrideHit {
                raw_key: package.to_string(),
                source: lpm_resolver::OverrideSource::LpmOverrides,
                package: package.to_string(),
                from_version: from.to_string(),
                to_version: to.to_string(),
                via_parent: via_parent.map(str::to_string),
            }],
        }
    }

    #[test]
    fn render_why_decorates_with_override_trace() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_overrides_state("ms", "2.0.0", "2.1.3", None);
        let why = render_why(&graph, "ms", Some(&state), None);
        assert!(
            why.contains("Overrides applied to this package"),
            "should include override section: {why}"
        );
        assert!(why.contains("2.0.0 → 2.1.3"), "should show from→to: {why}");
        assert!(
            why.contains("lpm.overrides.ms"),
            "should reference source: {why}"
        );
    }

    #[test]
    fn render_why_decorates_with_path_selector_trace() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_overrides_state("ms", "2.0.0", "2.1.3", Some("debug"));
        let why = render_why(&graph, "ms", Some(&state), None);
        assert!(
            why.contains("reached through debug"),
            "should include parent context: {why}"
        );
    }

    #[test]
    fn render_why_sanitizes_override_trace_fields() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_overrides_state(
            "ms",
            HOSTILE_TERMINAL_FIELD,
            HOSTILE_TERMINAL_FIELD,
            Some(HOSTILE_TERMINAL_FIELD),
        );

        let why = render_why(&graph, "ms", Some(&state), None);

        assert_hostile_terminal_field_is_inline_safe("graph override trace", &why);
    }

    #[test]
    fn render_why_skips_override_section_when_no_match() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        // Override is for a different package; should not appear in `ms`'s why output.
        let state = fake_overrides_state("express", "4.0.0", "5.0.0", None);
        let why = render_why(&graph, "ms", Some(&state), None);
        assert!(
            !why.contains("Overrides applied to this package"),
            "should NOT include override section when no hits match: {why}"
        );
    }

    #[test]
    fn render_why_json_includes_applied_overrides_field() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_overrides_state("ms", "2.0.0", "2.1.3", Some("debug"));
        let json =
            render_why_json(&graph, "ms", Some(&state), None).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed["applied_overrides"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"].as_str().unwrap(), "ms");
        assert_eq!(arr[0]["from_version"].as_str().unwrap(), "2.0.0");
        assert_eq!(arr[0]["to_version"].as_str().unwrap(), "2.1.3");
        assert_eq!(arr[0]["via_parent"].as_str().unwrap(), "debug");
    }

    #[test]
    fn render_why_json_empty_applied_overrides_when_no_state() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let json = render_why_json(&graph, "ms", None, None).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed["applied_overrides"].as_array().unwrap();
        assert!(arr.is_empty());
    }

    // ── `--why` decorates with patch traces ───

    /// Build a synthetic PatchState containing a single hit.
    fn fake_patch_state(name: &str) -> crate::patch_state::PatchState {
        crate::patch_state::PatchState {
            state_version: crate::patch_state::PATCH_STATE_VERSION,
            fingerprint: "sha256-fake-patch".to_string(),
            captured_at: "T00:00:00Z".to_string(),
            parsed: vec![],
            applied: vec![crate::patch_state::AppliedPatchHit {
                raw_key: format!("{name}@1.2.3"),
                name: name.to_string(),
                version: "1.2.3".to_string(),
                patch_path: format!("patches/{name}@1.2.3.patch"),
                original_integrity: Some(
                    "sha512-FakeBaselineIntegrityForUnitTestsOnly0000000000".to_string(),
                ),
                locations: vec![format!(
                    "node_modules/.lpm/{name}@1.2.3/node_modules/{name}"
                )],
                files_modified: 2,
                files_added: 0,
                files_deleted: 0,
            }],
        }
    }

    #[test]
    fn render_why_decorates_with_patch_trace() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_patch_state("ms");
        let why = render_why(&graph, "ms", None, Some(&state));
        assert!(
            why.contains("Patches applied to this package"),
            "should include patches section: {why}"
        );
        assert!(
            why.contains("patches/ms@1.2.3.patch"),
            "should reference patch path: {why}"
        );
        assert!(
            why.contains("2 files"),
            "should report file count from the hit: {why}"
        );
        // the actual
        // integrity hash must appear (truncated to KEEP chars + ellipsis),
        // not the legacy placeholder "originalIntegrity recorded".
        assert!(
            why.contains("sha512-FakeBaselineInte"),
            "should surface the truncated integrity hash: {why}"
        );
        assert!(
            why.contains("…"),
            "long integrity must be truncated with ellipsis: {why}"
        );
        assert!(
            !why.contains("originalIntegrity recorded"),
            "must NOT emit the legacy placeholder when integrity is known: {why}"
        );
    }

    #[test]
    fn render_why_sanitizes_patch_trace_fields() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let mut state = fake_patch_state("ms");
        state.applied[0].patch_path = HOSTILE_TERMINAL_FIELD.to_string();
        state.applied[0].original_integrity = Some(HOSTILE_TERMINAL_FIELD.to_string());

        let why = render_why(&graph, "ms", None, Some(&state));

        assert_hostile_terminal_field_is_inline_safe("graph patch trace", &why);
    }

    #[test]
    fn render_why_falls_back_to_placeholder_when_integrity_missing() {
        // State files written before this field existed have
        // `original_integrity == None`. The render must degrade
        // gracefully to the legacy placeholder rather than crash or
        // omit the section.
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = crate::patch_state::PatchState {
            state_version: crate::patch_state::PATCH_STATE_VERSION,
            fingerprint: "sha256-legacy".to_string(),
            captured_at: "T00:00:00Z".to_string(),
            parsed: vec![],
            applied: vec![crate::patch_state::AppliedPatchHit {
                raw_key: "ms@1.2.3".to_string(),
                name: "ms".to_string(),
                version: "1.2.3".to_string(),
                patch_path: "patches/ms@1.2.3.patch".to_string(),
                original_integrity: None, // legacy state file
                locations: vec![],
                files_modified: 1,
                files_added: 0,
                files_deleted: 0,
            }],
        };
        let why = render_why(&graph, "ms", None, Some(&state));
        assert!(why.contains("Patches applied to this package"));
        assert!(
            why.contains("originalIntegrity recorded"),
            "legacy state files (no integrity) should fall back to placeholder: {why}"
        );
    }

    #[test]
    fn render_why_omits_zero_file_count_in_decoration() {
        // when
        // `files_modified + files_added + files_deleted == 0` (e.g.,
        // legacy entries with no recorded counts), the human render
        // should NOT print "0 files" — that's noise. The integrity
        // alone is enough to show "this package is patched".
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = crate::patch_state::PatchState {
            state_version: crate::patch_state::PATCH_STATE_VERSION,
            fingerprint: "sha256-zero".to_string(),
            captured_at: "T00:00:00Z".to_string(),
            parsed: vec![],
            applied: vec![crate::patch_state::AppliedPatchHit {
                raw_key: "ms@1.2.3".to_string(),
                name: "ms".to_string(),
                version: "1.2.3".to_string(),
                patch_path: "patches/ms@1.2.3.patch".to_string(),
                original_integrity: Some("sha512-Tt8hFWlAbCdEfGhIjKlMn".to_string()),
                locations: vec![],
                files_modified: 0,
                files_added: 0,
                files_deleted: 0,
            }],
        };
        let why = render_why(&graph, "ms", None, Some(&state));
        assert!(why.contains("Patches applied to this package"));
        assert!(
            !why.contains("0 file"),
            "must not print '0 files' noise: {why}"
        );
    }

    #[test]
    fn render_why_skips_patch_section_when_no_match() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        // Patch hit is for a different package
        let state = fake_patch_state("express");
        let why = render_why(&graph, "ms", None, Some(&state));
        assert!(
            !why.contains("Patches applied to this package"),
            "should NOT include patch section when no hits match: {why}"
        );
    }

    #[test]
    fn render_why_json_includes_applied_patches_field() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let state = fake_patch_state("ms");
        let json =
            render_why_json(&graph, "ms", None, Some(&state)).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed["applied_patches"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"].as_str().unwrap(), "ms");
        assert_eq!(arr[0]["version"].as_str().unwrap(), "1.2.3");
        assert_eq!(
            arr[0]["patch_path"].as_str().unwrap(),
            "patches/ms@1.2.3.patch"
        );
        assert_eq!(arr[0]["files_modified"].as_u64().unwrap(), 2);
        // the full
        // (untruncated) integrity hash must be present in JSON output
        // so agents can use it directly without re-reading
        // package.json.
        assert_eq!(
            arr[0]["original_integrity"].as_str().unwrap(),
            "sha512-FakeBaselineIntegrityForUnitTestsOnly0000000000"
        );
    }

    #[test]
    fn render_why_json_empty_applied_patches_when_no_state() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let json = render_why_json(&graph, "ms", None, None).expect("render graph why JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed["applied_patches"].as_array().unwrap();
        assert!(arr.is_empty());
    }

    // ── Circular dependency handling ────────────────────────

    #[test]
    fn tree_handles_circular_deps() {
        let packages = vec![
            LockedPackage {
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["b@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["a@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let tree = render_tree(&graph, false);
        assert!(
            tree.contains("(circular)"),
            "should mark circular dependency: {tree}"
        );
    }

    // ── No source field ─────────────────────────────────────

    #[test]
    fn no_source_field_defaults_to_unknown() {
        let packages = vec![LockedPackage {
            name: "local-pkg".into(),
            version: "0.1.0".into(),
            source: None,
            integrity: None,
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
            tarball: None,
        }];
        let direct: HashSet<String> = ["local-pkg"].iter().map(|s| s.to_string()).collect();
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        assert_eq!(graph.nodes["local-pkg@0.1.0"].registry, Registry::Unknown);
    }

    // ── Graph-level filter ──────────────────────────────────

    #[test]
    fn filter_graph_removes_unmatched_subtrees() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");

        // Filter for "ms" — should keep root, express, debug, ms
        // but remove neo.highlight, accepts, mime-types
        filter_graph(&mut graph, "ms");

        assert!(
            graph.nodes.contains_key("test-app@1.0.0"),
            "root should stay"
        );
        assert!(
            graph.nodes.contains_key("express@4.22.1"),
            "ancestor of match should stay"
        );
        assert!(
            graph.nodes.contains_key("debug@2.6.9"),
            "ancestor of match should stay"
        );
        assert!(
            graph.nodes.contains_key("ms@2.0.0"),
            "matched node should stay"
        );
        assert!(
            !graph.nodes.contains_key("@lpm.dev/neo.highlight@1.1.1"),
            "unrelated subtree should be removed"
        );
        // mime-types is under accepts which is under express, but not on the path to ms
        assert!(
            !graph.nodes.contains_key("mime-types@2.1.35"),
            "non-matching sibling branch should be removed"
        );
    }

    #[test]
    fn filter_graph_keeps_matched_nodes_deps() {
        // Create a graph where the matched node has its own deps
        let packages = vec![
            LockedPackage {
                name: "parent".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["target@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,
                dependencies: vec!["child-of-target@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            LockedPackage {
                name: "child-of-target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
            LockedPackage {
                name: "unrelated".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
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
                tarball: None,
            },
        ];
        let direct: HashSet<String> = ["parent", "unrelated"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        filter_graph(&mut graph, "target");

        assert!(graph.nodes.contains_key("target@1.0.0"), "matched node");
        assert!(
            graph.nodes.contains_key("child-of-target@1.0.0"),
            "matched node's deps should be kept"
        );
        assert!(
            graph.nodes.contains_key("parent@1.0.0"),
            "ancestor of match"
        );
        assert!(
            !graph.nodes.contains_key("unrelated@1.0.0"),
            "unrelated package should be removed"
        );
    }

    #[test]
    fn filter_graph_json_reflects_filtered_state() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        filter_graph(&mut graph, "ms");

        let json = render_json(&graph).expect("render graph JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let nodes = parsed["nodes"].as_array().unwrap();
        let names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();

        assert!(names.contains(&"ms"), "JSON should contain matched node");
        assert!(names.contains(&"debug"), "JSON should contain ancestor");
        assert!(
            !names.contains(&"@lpm.dev/neo.highlight"),
            "JSON should not contain unrelated: {names:?}"
        );
    }

    #[test]
    fn filter_graph_dot_reflects_filtered_state() {
        let mut graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        filter_graph(&mut graph, "ms");

        let dot = render_dot(&graph);
        assert!(dot.contains("ms"), "DOT should contain matched node");
        assert!(dot.contains("debug"), "DOT should contain ancestor");
        assert!(
            !dot.contains("neo.highlight"),
            "DOT should not contain unrelated: {dot}"
        );
    }
}
