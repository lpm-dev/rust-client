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
    is_project_root: bool,
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

fn recompute_duplicate_state(nodes: &mut HashMap<String, DepNode>) -> Vec<(String, Vec<String>)> {
    let mut name_versions: HashMap<&str, HashSet<&str>> = HashMap::with_capacity(nodes.len());
    for node in nodes.values().filter(|node| !node.is_project_root) {
        name_versions
            .entry(node.name.as_str())
            .or_default()
            .insert(node.version.as_str());
    }

    let mut duplicates = Vec::new();
    for (name, versions) in name_versions {
        if versions.len() > 1 {
            let mut sorted: Vec<String> = versions.into_iter().map(str::to_owned).collect();
            sorted.sort_unstable();
            duplicates.push((name.to_owned(), sorted));
        }
    }
    duplicates.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    let duplicate_names: HashSet<&str> = duplicates.iter().map(|(name, _)| name.as_str()).collect();
    for node in nodes.values_mut() {
        node.is_duplicate = !node.is_project_root && duplicate_names.contains(node.name.as_str());
    }

    duplicates
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
    #[cfg(test)]
    pub fn from_lockfile_with_root_resolutions(
        packages: &[lpm_lockfile::LockedPackage],
        direct_dep_names: &HashSet<String>,
        root_resolutions: &lpm_lockfile::RootResolutions,
        root_name: &str,
    ) -> Self {
        Self::from_lockfile_inner(
            packages,
            direct_dep_names,
            Some(root_resolutions),
            root_name,
        )
    }

    /// Build a dependency graph from lockfile packages and direct dependency names.
    /// `root_name` is the project name from package.json (e.g., "my-app@1.0.0").
    #[cfg(test)]
    pub fn from_lockfile(
        packages: &[lpm_lockfile::LockedPackage],
        direct_dep_names: &HashSet<String>,
        root_name: &str,
    ) -> Self {
        Self::from_lockfile_inner(packages, direct_dep_names, None, root_name)
    }

    #[cfg(test)]
    fn from_lockfile_inner(
        packages: &[lpm_lockfile::LockedPackage],
        direct_dep_names: &HashSet<String>,
        root_resolutions: Option<&lpm_lockfile::RootResolutions>,
        root_name: &str,
    ) -> Self {
        let direct_indices = packages
            .iter()
            .enumerate()
            .filter_map(|(index, package)| {
                let direct = root_resolutions.map_or_else(
                    || direct_dep_names.contains(&package.name),
                    |resolutions| {
                        resolutions.iter().any(|(local, root)| {
                            direct_dep_names.contains(local)
                                && root.instance_id.is_some()
                                && root.instance_id == package.instance_id
                        })
                    },
                );
                direct.then_some(index)
            })
            .collect();
        let indexes = crate::commands::manifest_metadata::graph::PackageIndexes::new(packages);
        let adjacency =
            crate::commands::manifest_metadata::graph::package_adjacency(packages, &indexes);
        Self::from_indexed_packages(packages, &direct_indices, &adjacency, root_name)
    }

    pub(crate) fn from_indexed_packages(
        packages: &[lpm_lockfile::LockedPackage],
        direct_indices: &HashSet<usize>,
        adjacency: &[Vec<usize>],
        root_name: &str,
    ) -> Self {
        let mut nodes = HashMap::with_capacity(packages.len() + 1);
        let mut coordinate_counts = HashMap::with_capacity(packages.len());
        for package in packages {
            *coordinate_counts
                .entry((package.name.as_str(), package.version.as_str()))
                .or_insert(0_usize) += 1;
        }
        let mut package_keys = Vec::with_capacity(packages.len());
        for (index, package) in packages.iter().enumerate() {
            let base = format!("{}@{}", package.name, package.version);
            let key = if coordinate_counts[&(package.name.as_str(), package.version.as_str())] > 1 {
                match package.instance_id {
                    Some(instance_id) => format!("{base}#{instance_id}"),
                    None => format!("{base}#{}", index + 1),
                }
            } else {
                base
            };
            package_keys.push(key);
        }

        for (index, pkg) in packages.iter().enumerate() {
            let registry = pkg
                .source
                .as_deref()
                .and_then(|source| source.strip_prefix("registry+"))
                .and_then(|source| reqwest::Url::parse(source).ok())
                .map_or(Registry::Unknown, |url| {
                    match (url.scheme(), url.host_str()) {
                        ("http" | "https", Some("lpm.dev")) => Registry::Lpm,
                        ("http" | "https", Some("npmjs.org" | "registry.npmjs.org")) => {
                            Registry::Npm
                        }
                        _ => Registry::Unknown,
                    }
                });

            let mut dependencies: Vec<_> = adjacency[index]
                .iter()
                .map(|&target| package_keys[target].clone())
                .collect();
            dependencies.sort_unstable();
            dependencies.dedup();

            nodes.insert(
                package_keys[index].clone(),
                DepNode {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    registry,
                    depth: 0,
                    is_direct: direct_indices.contains(&index),
                    is_duplicate: false,
                    is_root: false,
                    is_project_root: false,
                    dependencies,
                },
            );
        }

        // Create synthetic root node pointing to all direct deps
        let mut root_key = root_name.to_string();
        if nodes.contains_key(&root_key) {
            let mut suffix = 1_usize;
            loop {
                let candidate = format!("{root_name}#project-{suffix}");
                if !nodes.contains_key(&candidate) {
                    root_key = candidate;
                    break;
                }
                suffix += 1;
            }
        }
        let mut direct_dep_keys: Vec<String> = nodes
            .iter()
            .filter(|(_, n)| n.is_direct)
            .map(|(k, _)| k.clone())
            .collect();
        direct_dep_keys.sort_unstable();

        let (root_package_name, root_version) = root_name
            .rsplit_once('@')
            .filter(|(name, version)| !name.is_empty() && !version.is_empty())
            .unwrap_or((root_name, "0.0.0"));
        nodes.insert(
            root_key.clone(),
            DepNode {
                name: root_package_name.to_string(),
                version: root_version.to_string(),
                registry: Registry::Unknown,
                depth: 0,
                is_direct: false,
                is_duplicate: false,
                is_root: true,
                is_project_root: true,
                dependencies: direct_dep_keys,
            },
        );

        let roots = vec![root_key];

        recompute_depths(&mut nodes, &roots);

        let duplicates = recompute_duplicate_state(&mut nodes);

        // 1-based to match the `--depth N` flag contract (root = 1).
        let max_depth = level_from_node_depths(nodes.values().map(|n| &n.depth));
        let lpm_count = nodes
            .values()
            .filter(|n| !n.is_project_root && n.registry == Registry::Lpm)
            .count();
        let npm_count = nodes
            .values()
            .filter(|n| !n.is_project_root && n.registry == Registry::Npm)
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

    /// The paths from the graph's roots to every package named
    /// `target_name`, collecting at most `limit` of them (all when `None`).
    pub(crate) fn why_paths(&self, target_name: &str, limit: Option<usize>) -> WhyPaths<'_> {
        self.why_paths_within(target_name, limit, CYCLIC_PATH_SEARCH_BUDGET)
    }

    fn why_paths_within(
        &self,
        target_name: &str,
        limit: Option<usize>,
        cyclic_search_budget: u64,
    ) -> WhyPaths<'_> {
        let index = GraphIndex::new(self);
        let mut roots: Vec<usize> = self
            .roots
            .iter()
            .filter_map(|root| index.position(root))
            .collect();
        roots.sort_unstable();
        roots.dedup();
        let mut targets: Vec<TargetPaths> = (0..index.keys.len())
            .filter(|&node| {
                let node = &self.nodes[index.keys[node]];
                !node.is_project_root && node.name == target_name
            })
            .map(|target| TargetPaths::new(&index, &roots, target))
            .collect();

        let mut report = WhyPaths {
            nodes: Vec::new(),
            ends: Vec::new(),
            count: 0,
            count_exact: true,
            search_stopped: false,
            limit_reached: false,
            version_count: targets.iter().filter(|target| target.reachable()).count(),
            #[cfg(test)]
            expanded_edges: 0,
        };
        let mut remaining = limit.unwrap_or(usize::MAX);
        let mut budget = cyclic_search_budget;
        let mut search = PathSearch::new(index.keys.len());
        for &root in &roots {
            for target in &mut targets {
                if !target.relevant[root] {
                    continue;
                }
                let cyclic = target.exact_count.is_none();
                if remaining == 0 {
                    target.complete &= !cyclic;
                    continue;
                }
                if cyclic && budget == 0 {
                    target.complete = false;
                    continue;
                }
                let outcome = search.run(
                    &index,
                    &target.relevant,
                    root,
                    target.node,
                    cyclic.then_some(&mut budget),
                    |path| {
                        target.found += 1;
                        if remaining == 0 {
                            return std::ops::ControlFlow::Break(());
                        }
                        report
                            .nodes
                            .extend(path.iter().map(|&node| index.keys[node]));
                        report.ends.push(report.nodes.len());
                        remaining -= 1;
                        if remaining == 0 && !cyclic {
                            std::ops::ControlFlow::Break(())
                        } else {
                            std::ops::ControlFlow::Continue(())
                        }
                    },
                );
                #[cfg(test)]
                {
                    report.expanded_edges += search.expanded_edges;
                }
                match outcome {
                    SearchOutcome::Finished => {}
                    SearchOutcome::Stopped => target.complete = false,
                    SearchOutcome::OutOfBudget => {
                        target.complete = false;
                        report.search_stopped = true;
                    }
                }
            }
        }

        for target in &mut targets {
            if !target.reachable() {
                continue;
            }
            let count = match target.exact_count {
                Some(count) => {
                    report.count_exact &= !target.saturated;
                    count
                }
                None => {
                    if target.found == 0 && remaining > 0 {
                        let path = target.shortest_path(&index, &roots);
                        report
                            .nodes
                            .extend(path.iter().map(|&node| index.keys[node]));
                        report.ends.push(report.nodes.len());
                        remaining -= 1;
                        target.found = 1;
                    }
                    report.count_exact &= target.complete;
                    target.found.max(1)
                }
            };
            report.count = report.count.saturating_add(count);
        }
        report.limit_reached = limit.is_some() && remaining == 0;
        report
    }
}

/// How many paths a why command shows unless told otherwise.
pub const DEFAULT_WHY_PATH_LIMIT: usize = 1_000;

/// How many dependency edges the search for paths may follow through a part
/// of the graph that has a cycle. Where there is no cycle the search follows
/// only edges that lead to the target, so its work is bounded by the paths
/// it collects; with a cycle, a search can reach a package whose only way on
/// to the target passes through the path it is on.
const CYCLIC_PATH_SEARCH_BUDGET: u64 = 1 << 24;

/// The paths from a graph's roots to the packages a why command names, in
/// the order the command shows them: by root, then by target key, then by
/// each node's dependencies in order.
pub(crate) struct WhyPaths<'graph> {
    /// The keys of every collected path, one path after another.
    nodes: Vec<&'graph str>,
    /// Where each collected path ends in `nodes`.
    ends: Vec<usize>,
    /// Every path, when `count_exact`, otherwise a lower bound.
    count: u64,
    /// False when a part of the graph with a cycle kept some paths from
    /// being tried, or the count passed `u64::MAX`.
    count_exact: bool,
    /// The search through a part of the graph with a cycle used its budget.
    search_stopped: bool,
    /// The collected paths used up a limit.
    limit_reached: bool,
    /// How many versions of the package some path reaches.
    version_count: usize,
    #[cfg(test)]
    expanded_edges: u64,
}

impl<'graph> WhyPaths<'graph> {
    fn iter(&self) -> impl Iterator<Item = &[&'graph str]> + '_ {
        let mut start = 0;
        self.ends.iter().map(move |&end| {
            let path = &self.nodes[start..end];
            start = end;
            path
        })
    }

    fn shown(&self) -> u64 {
        self.ends.len() as u64
    }

    /// How many paths the count includes that aren't collected.
    fn hidden(&self) -> u64 {
        self.count.saturating_sub(self.shown())
    }

    /// Whether some path to the package isn't collected, or may not be.
    fn truncated(&self) -> bool {
        self.hidden() > 0 || !self.count_exact
    }
}

/// A graph's nodes by position, in key order, with their edges.
struct GraphIndex<'graph> {
    keys: Vec<&'graph str>,
    children: Vec<Vec<usize>>,
    parents: Vec<Vec<usize>>,
}

impl<'graph> GraphIndex<'graph> {
    fn new(graph: &'graph DepGraph) -> Self {
        let mut keys: Vec<&str> = graph.nodes.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let positions: HashMap<&str, usize> = keys
            .iter()
            .enumerate()
            .map(|(position, key)| (*key, position))
            .collect();
        let mut children = Vec::with_capacity(keys.len());
        let mut parents = vec![Vec::new(); keys.len()];
        for (parent, key) in keys.iter().enumerate() {
            let node_children: Vec<usize> = graph.nodes[*key]
                .dependencies
                .iter()
                .filter_map(|dependency| positions.get(dependency.as_str()).copied())
                .collect();
            for &child in &node_children {
                parents[child].push(parent);
            }
            children.push(node_children);
        }
        Self {
            keys,
            children,
            parents,
        }
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.keys.binary_search(&key).ok()
    }
}

/// What the search knows about the paths to one target node.
struct TargetPaths {
    node: usize,
    /// The nodes on some path from a root to the target.
    relevant: Vec<bool>,
    /// The number of paths, counted without trying them, when the relevant
    /// nodes form no cycle.
    exact_count: Option<u64>,
    /// The count passed `u64::MAX`.
    saturated: bool,
    /// Paths the search found.
    found: u64,
    /// The search tried every path from every root.
    complete: bool,
}

impl TargetPaths {
    fn new(index: &GraphIndex<'_>, roots: &[usize], node: usize) -> Self {
        let len = index.keys.len();
        let mut reaches_target = vec![false; len];
        reaches_target[node] = true;
        let mut queue = VecDeque::from([node]);
        while let Some(current) = queue.pop_front() {
            for &parent in &index.parents[current] {
                if !reaches_target[parent] {
                    reaches_target[parent] = true;
                    queue.push_back(parent);
                }
            }
        }

        let mut relevant = vec![false; len];
        let mut relevant_nodes = Vec::new();
        for &root in roots {
            if reaches_target[root] && !relevant[root] {
                relevant[root] = true;
                relevant_nodes.push(root);
                queue.push_back(root);
            }
        }
        while let Some(current) = queue.pop_front() {
            for &child in &index.children[current] {
                if reaches_target[child] && !relevant[child] {
                    relevant[child] = true;
                    relevant_nodes.push(child);
                    queue.push_back(child);
                }
            }
        }

        let (exact_count, saturated) = if relevant[node] {
            count_acyclic_paths(index, roots, &relevant, &relevant_nodes, node)
                .map_or((None, false), |(count, saturated)| (Some(count), saturated))
        } else {
            (Some(0), false)
        };
        Self {
            node,
            relevant,
            exact_count,
            saturated,
            found: 0,
            complete: true,
        }
    }

    fn reachable(&self) -> bool {
        self.relevant[self.node]
    }

    /// A shortest path from a root to the target, which is always a path a
    /// search could find.
    fn shortest_path(&self, index: &GraphIndex<'_>, roots: &[usize]) -> Vec<usize> {
        let mut previous = vec![usize::MAX; index.keys.len()];
        let mut seen = vec![false; index.keys.len()];
        let mut queue = VecDeque::new();
        for &root in roots {
            if self.relevant[root] && !seen[root] {
                seen[root] = true;
                queue.push_back(root);
            }
        }
        while let Some(current) = queue.pop_front() {
            if current == self.node {
                break;
            }
            for &child in &index.children[current] {
                if self.relevant[child] && !seen[child] {
                    seen[child] = true;
                    previous[child] = current;
                    queue.push_back(child);
                }
            }
        }
        let mut path = vec![self.node];
        while let Some(&node) = path.last()
            && previous[node] != usize::MAX
        {
            path.push(previous[node]);
        }
        path.reverse();
        path
    }
}

/// The number of paths from `roots` to `target` through `relevant` nodes,
/// and whether it passed `u64::MAX`, or `None` when those nodes form a
/// cycle. Counts in topological order, so each node's count is final
/// before it is passed on.
fn count_acyclic_paths(
    index: &GraphIndex<'_>,
    roots: &[usize],
    relevant: &[bool],
    relevant_nodes: &[usize],
    target: usize,
) -> Option<(u64, bool)> {
    let mut parents_left = vec![0_usize; index.keys.len()];
    for &node in relevant_nodes {
        for &child in &index.children[node] {
            if relevant[child] {
                parents_left[child] += 1;
            }
        }
    }
    let mut counts = vec![0_u64; index.keys.len()];
    for &root in roots {
        if relevant[root] {
            counts[root] = 1;
        }
    }
    let mut ready: Vec<usize> = relevant_nodes
        .iter()
        .copied()
        .filter(|&node| parents_left[node] == 0)
        .collect();
    let mut counted = 0;
    let mut saturated = false;
    while let Some(node) = ready.pop() {
        counted += 1;
        let count = counts[node];
        for &child in &index.children[node] {
            if !relevant[child] {
                continue;
            }
            counts[child] = counts[child].checked_add(count).unwrap_or_else(|| {
                saturated = true;
                u64::MAX
            });
            parents_left[child] -= 1;
            if parents_left[child] == 0 {
                ready.push(child);
            }
        }
    }
    (counted == relevant_nodes.len()).then_some((counts[target], saturated))
}

enum SearchOutcome {
    Finished,
    /// The visitor asked to stop.
    Stopped,
    /// The search used its budget.
    OutOfBudget,
}

/// A depth-first search for the simple paths from one root to one target,
/// kept on the heap so a deep graph can't exhaust the stack.
struct PathSearch {
    on_path: Vec<bool>,
    /// Each node on the path, with the next of its dependencies to follow.
    stack: Vec<(usize, usize)>,
    path: Vec<usize>,
    #[cfg(test)]
    expanded_edges: u64,
}

impl PathSearch {
    fn new(len: usize) -> Self {
        Self {
            on_path: vec![false; len],
            stack: Vec::new(),
            path: Vec::new(),
            #[cfg(test)]
            expanded_edges: 0,
        }
    }

    /// Visits each simple path from `root` to `target` through `relevant`
    /// nodes. With a `budget`, each edge followed spends one, and the search
    /// ends once it is spent.
    fn run(
        &mut self,
        index: &GraphIndex<'_>,
        relevant: &[bool],
        root: usize,
        target: usize,
        mut budget: Option<&mut u64>,
        mut visit: impl FnMut(&[usize]) -> std::ops::ControlFlow<()>,
    ) -> SearchOutcome {
        #[cfg(test)]
        {
            self.expanded_edges = 0;
        }
        self.path.clear();
        self.path.push(root);
        if root == target {
            return match visit(&self.path) {
                std::ops::ControlFlow::Continue(()) => SearchOutcome::Finished,
                std::ops::ControlFlow::Break(()) => SearchOutcome::Stopped,
            };
        }
        self.stack.clear();
        self.stack.push((root, 0));
        self.on_path[root] = true;
        let outcome = loop {
            let Some((node, next)) = self.stack.last_mut() else {
                break SearchOutcome::Finished;
            };
            let Some(&child) = index.children[*node].get(*next) else {
                self.on_path[*node] = false;
                self.stack.pop();
                self.path.pop();
                continue;
            };
            *next += 1;
            #[cfg(test)]
            {
                self.expanded_edges += 1;
            }
            if let Some(budget) = budget.as_deref_mut() {
                if *budget == 0 {
                    break SearchOutcome::OutOfBudget;
                }
                *budget -= 1;
            }
            if !relevant[child] || self.on_path[child] {
                continue;
            }
            self.path.push(child);
            if child == target {
                let flow = visit(&self.path);
                self.path.pop();
                if flow.is_break() {
                    break SearchOutcome::Stopped;
                }
                continue;
            }
            self.on_path[child] = true;
            self.stack.push((child, 0));
        };
        for &(node, _) in &self.stack {
            self.on_path[node] = false;
        }
        outcome
    }
}

// ── Tree Renderer ──────────────────────────────────────────────────

#[cfg(test)]
pub fn render_tree(graph: &DepGraph, use_color: bool) -> String {
    let mut output = Vec::new();
    write_tree(&mut output, graph, use_color).expect("write graph tree");
    String::from_utf8(output).expect("graph tree must be UTF-8")
}

/// Writes the graph as a tree, expanding each node's dependencies the first
/// time it appears and marking it `(shared)` after that, or `(circular)`
/// when it is one of its own ancestors.
///
/// The walk keeps its place on the heap and shares one prefix buffer among
/// all levels, so memory grows with the graph's depth rather than with its
/// square, and a deep graph can't exhaust the stack.
pub fn write_tree<W: Write>(writer: W, graph: &DepGraph, use_color: bool) -> io::Result<()> {
    let mut walk = TreeWalk {
        writer,
        graph,
        use_color,
        expanded: HashSet::with_capacity(graph.nodes.len()),
        visiting: HashSet::with_capacity(graph.stats.max_depth.max(1)),
        prefix: String::new(),
        stack: Vec::with_capacity(graph.stats.max_depth.max(1)),
    };

    let mut sorted_roots: Vec<&str> = graph.roots.iter().map(String::as_str).collect();
    sorted_roots.sort_unstable();
    for (index, root_key) in sorted_roots.iter().enumerate() {
        walk.write_node(root_key, index + 1 == sorted_roots.len())?;
        while let Some(top) = walk.stack.last_mut() {
            if let Some(dependency) = top.dependencies.get(top.next) {
                top.next += 1;
                let is_last = top.next == top.dependencies.len();
                walk.write_node(dependency, is_last)?;
            } else {
                walk.prefix.truncate(top.prefix_len);
                let key = top.key;
                walk.stack.pop();
                walk.visiting.remove(key);
            }
        }
    }

    let writer = &mut walk.writer;
    writer.write_all(b"\n")?;
    write!(
        writer,
        "{} packages, max depth {}",
        graph.stats.total_packages, graph.stats.max_depth
    )?;
    if !graph.stats.duplicates.is_empty() {
        write!(writer, ", {} duplicates (", graph.stats.duplicates.len())?;
        for (index, (name, _)) in graph.stats.duplicates.iter().enumerate() {
            if index > 0 {
                writer.write_all(b", ")?;
            }
            writer.write_all(sanitize_terminal_inline(name).as_bytes())?;
        }
        writer.write_all(b")")?;
    }
    writer.write_all(b"\n")
}

struct TreeWalk<'graph, W> {
    writer: W,
    graph: &'graph DepGraph,
    use_color: bool,
    expanded: HashSet<&'graph str>,
    /// The nodes whose children are being written: the current node's
    /// ancestors.
    visiting: HashSet<&'graph str>,
    prefix: String,
    stack: Vec<ExpandingNode<'graph>>,
}

struct ExpandingNode<'graph> {
    key: &'graph str,
    dependencies: &'graph [String],
    next: usize,
    /// The prefix's length before this node's children extended it.
    prefix_len: usize,
}

impl<'graph, W: Write> TreeWalk<'graph, W> {
    /// Writes `key`'s line, and starts expanding it unless it was expanded
    /// before or is one of its own ancestors.
    fn write_node(&mut self, key: &str, is_last: bool) -> io::Result<()> {
        let Some((key, node)) = self.graph.nodes.get_key_value(key) else {
            return Ok(());
        };
        let top_level = self.stack.is_empty();
        let connector = if top_level {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };
        let circular = self.visiting.contains(key.as_str());
        let shared = !circular && self.expanded.contains(key.as_str());
        write_tree_meta(&mut self.writer, &self.prefix, self.use_color)?;
        write_tree_meta(&mut self.writer, connector, self.use_color)?;
        self.writer
            .write_all(render_tree_label(node, self.use_color).as_bytes())?;
        if circular {
            write_tree_meta(&mut self.writer, " (circular)", self.use_color)?;
        } else if shared {
            write_tree_meta(&mut self.writer, " (shared)", self.use_color)?;
        }
        self.writer.write_all(b"\n")?;
        if circular || shared {
            return Ok(());
        }
        self.visiting.insert(key);
        self.expanded.insert(key);
        let prefix_len = self.prefix.len();
        if !top_level {
            self.prefix.push_str(if is_last { "    " } else { "│   " });
        }
        self.stack.push(ExpandingNode {
            key,
            dependencies: &node.dependencies,
            next: 0,
            prefix_len,
        });
        Ok(())
    }
}

fn write_tree_meta<W: Write>(writer: &mut W, text: &str, use_color: bool) -> io::Result<()> {
    if use_color && !text.is_empty() {
        write!(writer, "\x1b[2m{text}\x1b[22m")
    } else {
        writer.write_all(text.as_bytes())
    }
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
/// contains `filter`. Keeps the synthetic project root and all ancestors
/// and descendants of matching dependency nodes. Removes dangling edges.
pub fn filter_graph(graph: &mut DepGraph, filter: &str) {
    let keep: HashSet<String> = {
        let mut reachable = HashSet::with_capacity(graph.nodes.len());
        let mut parents: HashMap<&str, Vec<&str>> = HashMap::with_capacity(graph.nodes.len());
        let mut pending: Vec<&str> = graph.roots.iter().map(String::as_str).collect();
        let mut matches = Vec::new();
        while let Some(key) = pending.pop() {
            let Some(node) = graph.nodes.get(key) else {
                continue;
            };
            if !reachable.insert(key) {
                continue;
            }
            if !node.is_project_root && node.name.contains(filter) {
                matches.push(key);
            }
            for dep in &node.dependencies {
                parents.entry(dep.as_str()).or_default().push(key);
                pending.push(dep);
            }
        }

        let mut keep = HashSet::with_capacity(reachable.len());
        pending.extend(matches.iter().copied());
        while let Some(key) = pending.pop() {
            if keep.insert(key)
                && let Some(ancestors) = parents.get(key)
            {
                pending.extend(ancestors.iter().copied());
            }
        }

        // Ancestors are already retained, but matching nodes still need expansion.
        let mut descendants = HashSet::with_capacity(reachable.len());
        pending.extend(matches);
        while let Some(key) = pending.pop() {
            if descendants.insert(key)
                && let Some(node) = graph.nodes.get(key)
            {
                keep.insert(key);
                pending.extend(node.dependencies.iter().map(String::as_str));
            }
        }
        keep.extend(graph.roots.iter().filter_map(|key| {
            graph.nodes.get(key).filter(|node| node.is_project_root)?;
            Some(key.as_str())
        }));
        keep.into_iter().map(str::to_owned).collect()
    };

    graph.nodes.retain(|key, _| keep.contains(key));
    graph.roots.retain(|key| keep.contains(key));
    for node in graph.nodes.values_mut() {
        node.dependencies.retain(|dep_key| keep.contains(dep_key));
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

fn recompute_depths(nodes: &mut HashMap<String, DepNode>, roots: &[String]) {
    for node in nodes.values_mut() {
        node.depth = usize::MAX;
    }
    let mut queue = VecDeque::from_iter(roots.iter().map(|key| (key.clone(), 0)));
    while let Some((key, depth)) = queue.pop_front() {
        let Some(node) = nodes.get_mut(&key) else {
            continue;
        };
        if node.depth != usize::MAX {
            continue;
        }
        node.depth = depth;
        queue.extend(
            node.dependencies
                .iter()
                .map(|target| (target.clone(), depth + 1)),
        );
    }
    for node in nodes.values_mut() {
        if node.depth == usize::MAX {
            node.depth = 0;
        }
    }
}

/// Recompute graph stats after a mutation (filter, depth-prune,
/// subtree restriction, unreachable prune). Counts exclude synthetic
/// root nodes so `total_packages` is the user-meaningful count.
pub fn recompute_stats(graph: &mut DepGraph) {
    recompute_depths(&mut graph.nodes, &graph.roots);
    let lpm_count = graph
        .nodes
        .values()
        .filter(|n| !n.is_project_root && n.registry == Registry::Lpm)
        .count();
    let npm_count = graph
        .nodes
        .values()
        .filter(|n| !n.is_project_root && n.registry == Registry::Npm)
        .count();
    // 1-based to match the `--depth N` flag contract (root = 1).
    let max_depth = level_from_node_depths(graph.nodes.values().map(|n| &n.depth));

    let duplicates = recompute_duplicate_state(&mut graph.nodes);

    let root_count = graph.nodes.values().filter(|n| n.is_project_root).count();

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
    let mut sorted_keys: Vec<&String> = graph.nodes.keys().collect();
    sorted_keys.sort_unstable();
    let node_ids: HashMap<&str, usize> = sorted_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.as_str(), index))
        .collect();

    for (index, key) in sorted_keys.iter().enumerate() {
        output.push_str(&format!("  n{index}[\"{}\"]\n", mermaid_escape(key)));
    }
    output.push('\n');

    for (index, key) in sorted_keys.iter().enumerate() {
        let node = &graph.nodes[*key];
        for dep_key in &node.dependencies {
            if let Some(target) = node_ids.get(dep_key.as_str()) {
                output.push_str(&format!("  n{index} --> n{target}\n"));
            }
        }
    }

    for (index, key) in sorted_keys.iter().enumerate() {
        let node = &graph.nodes[*key];
        if node.registry == Registry::Lpm {
            output.push_str(&format!("  style n{index} fill:#10b981,color:#fff\n"));
        } else if node.is_duplicate {
            output.push_str(&format!("  style n{index} fill:#f59e0b,color:#fff\n"));
        }
    }
    output
}

// ── JSON Renderer ──────────────────────────────────────────────────

#[cfg(test)]
pub fn render_json(graph: &DepGraph) -> Result<String, serde_json::Error> {
    let mut output = Vec::new();
    write_json(&mut output, graph)?;
    Ok(String::from_utf8(output).expect("graph JSON must be UTF-8"))
}

pub fn write_json<W: Write>(mut writer: W, graph: &DepGraph) -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(&mut writer, &GraphJson { graph })?;
    writer.write_all(b"\n").map_err(serde_json::Error::io)
}

struct GraphJson<'graph> {
    graph: &'graph DepGraph,
}

impl Serialize for GraphJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let graph = self.graph;
        let root_name = graph
            .roots
            .first()
            .and_then(|key| graph.nodes.get(key))
            .map(|node| format!("{}@{}", node.name, node.version))
            .unwrap_or_default();
        let mut output = serializer.serialize_struct("GraphJson", 9)?;
        output.serialize_field("success", &true)?;
        output.serialize_field("root", &root_name)?;
        output.serialize_field("packages", &graph.stats.total_packages)?;
        output.serialize_field("lpm_packages", &graph.stats.lpm_packages)?;
        output.serialize_field("npm_packages", &graph.stats.npm_packages)?;
        output.serialize_field("max_depth", &graph.stats.max_depth)?;
        output.serialize_field("duplicates", &GraphJsonDuplicates { graph })?;
        output.serialize_field("nodes", &GraphJsonNodes { graph })?;
        output.serialize_field("edges", &GraphJsonEdges { graph })?;
        output.end()
    }
}

struct GraphJsonDuplicates<'graph> {
    graph: &'graph DepGraph,
}

impl Serialize for GraphJsonDuplicates<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut duplicates = serializer.serialize_seq(Some(self.graph.stats.duplicates.len()))?;
        for (name, versions) in &self.graph.stats.duplicates {
            duplicates.serialize_element(&GraphJsonDuplicate { name, versions })?;
        }
        duplicates.end()
    }
}

#[derive(Serialize)]
struct GraphJsonDuplicate<'value> {
    name: &'value str,
    versions: &'value [String],
}

struct GraphJsonNodes<'graph> {
    graph: &'graph DepGraph,
}

impl Serialize for GraphJsonNodes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sorted_keys: Vec<&String> = self.graph.nodes.keys().collect();
        sorted_keys.sort_unstable();
        let mut nodes = serializer.serialize_seq(Some(sorted_keys.len()))?;
        for key in sorted_keys {
            let node = &self.graph.nodes[key];
            nodes.serialize_element(&GraphJsonNode { key, node })?;
        }
        nodes.end()
    }
}

struct GraphJsonNode<'value> {
    key: &'value str,
    node: &'value DepNode,
}

impl Serialize for GraphJsonNode<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut node = serializer.serialize_struct("GraphJsonNode", 10)?;
        node.serialize_field("key", self.key)?;
        node.serialize_field("name", &self.node.name)?;
        node.serialize_field("version", &self.node.version)?;
        let registry = match self.node.registry {
            Registry::Lpm => "lpm",
            Registry::Npm => "npm",
            Registry::Unknown => "unknown",
        };
        node.serialize_field("registry", registry)?;
        node.serialize_field("depth", &self.node.depth)?;
        node.serialize_field("is_direct", &self.node.is_direct)?;
        node.serialize_field("is_duplicate", &self.node.is_duplicate)?;
        node.serialize_field("is_root", &self.node.is_root)?;
        node.serialize_field("dependency_count", &self.node.dependencies.len())?;
        node.serialize_field("deps", &self.node.dependencies)?;
        node.end()
    }
}

struct GraphJsonEdges<'graph> {
    graph: &'graph DepGraph,
}

impl Serialize for GraphJsonEdges<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let edge_count = self
            .graph
            .nodes
            .values()
            .map(|node| node.dependencies.len())
            .sum();
        let mut sorted_keys: Vec<&String> = self.graph.nodes.keys().collect();
        sorted_keys.sort_unstable();
        let mut edges = serializer.serialize_seq(Some(edge_count))?;
        for from in sorted_keys {
            let node = &self.graph.nodes[from];
            for to in &node.dependencies {
                edges.serialize_element(&GraphJsonEdge { from, to })?;
            }
        }
        edges.end()
    }
}

#[derive(Serialize)]
struct GraphJsonEdge<'value> {
    from: &'value str,
    to: &'value str,
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

/// Writes why `target_name` is in the graph: its paths from the roots, at
/// most `path_limit` of them (all when `None`), and how many there are.
pub fn write_why<W: Write>(
    mut writer: W,
    graph: &DepGraph,
    target_name: &str,
    path_limit: Option<usize>,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> io::Result<()> {
    let target_display = sanitize_terminal_inline(target_name);
    let is_direct = graph
        .nodes
        .values()
        .any(|n| n.name == target_name && n.is_direct);
    let paths = graph.why_paths(target_name, path_limit);

    if paths.count == 0 {
        writeln!(writer, "{target_display} is not in your dependency tree.")?;
        return Ok(());
    }

    if is_direct {
        writeln!(writer, "{target_display} is a direct dependency.\n")?;
    }

    let at_least = if paths.count_exact { "" } else { "at least " };
    writeln!(
        writer,
        "{target_display} is required by {at_least}{} path(s):\n",
        paths.count
    )?;

    for path in paths.iter() {
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
        writeln!(writer)?;
    }

    if paths.truncated() && !paths.search_stopped {
        match paths.hidden() {
            0 => write!(writer, "\n… and possibly more path(s).")?,
            hidden => write!(writer, "\n… and {at_least}{hidden} more path(s).")?,
        }
        if paths.limit_reached {
            write!(writer, " Use --limit <N> or --all-paths to show more.")?;
        }
        writeln!(writer)?;
    }
    if paths.search_stopped {
        writeln!(
            writer,
            "\nThe search stopped after following {CYCLIC_PATH_SEARCH_BUDGET} dependency edges through a cycle, so more paths may exist."
        )?;
    }

    if paths.version_count > 1 {
        writeln!(
            writer,
            "\n{} versions installed (duplicate)",
            paths.version_count
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
                let from_version =
                    sanitize_terminal_inline(hit.from_version.as_deref().unwrap_or("unresolved"));
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
        Some(DEFAULT_WHY_PATH_LIMIT),
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

/// Writes [`write_why`]'s report as JSON. `paths` and `path_keys` hold the
/// same collected paths, by display name and by graph key.
pub fn write_why_json<W: Write>(
    mut writer: W,
    graph: &DepGraph,
    target_name: &str,
    path_limit: Option<usize>,
    overrides_state: Option<&crate::overrides_state::OverridesState>,
    patch_state: Option<&crate::patch_state::PatchState>,
) -> Result<(), serde_json::Error> {
    let output = WhyJson {
        graph,
        target_name,
        paths: graph.why_paths(target_name, path_limit),
        overrides_state,
        patch_state,
    };
    serde_json::to_writer_pretty(&mut writer, &output)?;
    writer.write_all(b"\n").map_err(serde_json::Error::io)
}

struct WhyJson<'graph, 'value> {
    graph: &'graph DepGraph,
    target_name: &'value str,
    paths: WhyPaths<'graph>,
    overrides_state: Option<&'value crate::overrides_state::OverridesState>,
    patch_state: Option<&'value crate::patch_state::PatchState>,
}

// The explicit serializer keeps the JSON field names and their order stable.
impl Serialize for WhyJson<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut output = serializer.serialize_struct("WhyJson", 10)?;
        output.serialize_field("success", &true)?;
        output.serialize_field("target", self.target_name)?;
        output.serialize_field("found", &(self.paths.count > 0))?;
        output.serialize_field("path_count", &self.paths.count)?;
        output.serialize_field("path_count_exact", &self.paths.count_exact)?;
        output.serialize_field(
            "paths",
            &WhyJsonPaths {
                graph: self.graph,
                paths: &self.paths,
                keys: false,
            },
        )?;
        output.serialize_field(
            "path_keys",
            &WhyJsonPaths {
                graph: self.graph,
                paths: &self.paths,
                keys: true,
            },
        )?;
        output.serialize_field("paths_truncated", &self.paths.truncated())?;
        output.serialize_field(
            "applied_overrides",
            &WhyJsonOverrideHits {
                target_name: self.target_name,
                state: self.overrides_state,
            },
        )?;
        output.serialize_field(
            "applied_patches",
            &WhyJsonPatchHits {
                target_name: self.target_name,
                state: self.patch_state,
            },
        )?;
        output.end()
    }
}

struct WhyJsonOverrideHits<'value> {
    target_name: &'value str,
    state: Option<&'value crate::overrides_state::OverridesState>,
}

impl Serialize for WhyJsonOverrideHits<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let matching_count = self.state.map_or(0, |state| {
            state
                .applied
                .iter()
                .filter(|hit| hit.package == self.target_name)
                .count()
        });
        let mut hits = serializer.serialize_seq(Some(matching_count))?;
        if let Some(state) = self.state {
            for hit in state
                .applied
                .iter()
                .filter(|hit| hit.package == self.target_name)
            {
                hits.serialize_element(hit)?;
            }
        }
        hits.end()
    }
}

struct WhyJsonPatchHits<'value> {
    target_name: &'value str,
    state: Option<&'value crate::patch_state::PatchState>,
}

impl Serialize for WhyJsonPatchHits<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let matching_count = self.state.map_or(0, |state| {
            state
                .applied
                .iter()
                .filter(|hit| hit.name == self.target_name)
                .count()
        });
        let mut hits = serializer.serialize_seq(Some(matching_count))?;
        if let Some(state) = self.state {
            for hit in state
                .applied
                .iter()
                .filter(|hit| hit.name == self.target_name)
            {
                hits.serialize_element(hit)?;
            }
        }
        hits.end()
    }
}

struct WhyJsonPaths<'graph, 'paths> {
    graph: &'graph DepGraph,
    paths: &'paths WhyPaths<'graph>,
    /// Write each path's graph keys rather than its display names.
    keys: bool,
}

impl Serialize for WhyJsonPaths<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut paths = serializer.serialize_seq(Some(self.paths.ends.len()))?;
        for path in self.paths.iter() {
            if self.keys {
                paths.serialize_element(path)?;
            } else {
                paths.serialize_element(&WhyJsonPath {
                    graph: self.graph,
                    path,
                })?;
            }
        }
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
        Some(DEFAULT_WHY_PATH_LIMIT),
        overrides_state,
        patch_state,
    )?;
    Ok(String::from_utf8(output).expect("graph why JSON must be UTF-8"))
}

// ── HTML Renderer ──────────────────────────────────────────────────

#[cfg(test)]
pub fn render_html(graph: &DepGraph) -> Result<String, serde_json::Error> {
    let mut output = Vec::new();
    write_html(&mut output, graph)?;
    Ok(String::from_utf8(output).expect("graph HTML must be UTF-8"))
}

pub fn write_html<W: Write>(mut writer: W, graph: &DepGraph) -> Result<(), serde_json::Error> {
    let template = include_str!("templates/graph.html");
    let (before_stats, after_stats) = template
        .split_once("__STATS__")
        .expect("graph template must contain the stats placeholder");
    let (before_graph, after_graph) = after_stats
        .split_once("__GRAPH_DATA__")
        .expect("graph template must contain the graph placeholder");
    let stats = render_stats(graph).replace('\n', " | ");
    let stats = stats.trim_end_matches(" | ");
    let safe_stats = html_escape(stats);

    writer
        .write_all(before_stats.as_bytes())
        .map_err(serde_json::Error::io)?;
    writer
        .write_all(safe_stats.as_bytes())
        .map_err(serde_json::Error::io)?;
    writer
        .write_all(before_graph.as_bytes())
        .map_err(serde_json::Error::io)?;
    {
        let mut script_safe_writer = ScriptSafeJsonWriter::new(&mut writer);
        write_json(&mut script_safe_writer, graph)?;
    }
    writer
        .write_all(after_graph.as_bytes())
        .map_err(serde_json::Error::io)
}

struct ScriptSafeJsonWriter<'writer, W> {
    writer: &'writer mut W,
}

impl<'writer, W: Write> ScriptSafeJsonWriter<'writer, W> {
    fn new(writer: &'writer mut W) -> Self {
        Self { writer }
    }
}

impl<W: Write> Write for ScriptSafeJsonWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (index, byte) in buffer.iter().enumerate() {
            if *byte != b'<' {
                continue;
            }
            self.writer.write_all(&buffer[start..index])?;
            self.writer.write_all(br"\u003c")?;
            start = index + 1;
        }
        self.writer.write_all(&buffer[start..])?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "express".into(),
                version: "4.22.1".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "accepts".into(),
                version: "1.3.8".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "debug".into(),
                version: "2.6.9".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "ms".into(),
                version: "2.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
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
                name: "ms".into(),
                version: "2.1.3".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
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
                name: "mime-types".into(),
                version: "2.1.35".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
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
                name: "@lpm.dev/neo.highlight".into(),
                version: "1.1.1".into(),
                source: Some("registry+https://lpm.dev".into()),
                integrity: None,
                unpacked_size: None,
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

    fn direct_deps() -> HashSet<String> {
        ["express", "@lpm.dev/neo.highlight"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn package(name: &str, dependencies: &[&str]) -> LockedPackage {
        LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: name.into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
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
            peer_edges: Vec::new(),
            tarball: None,
        }
    }

    #[test]
    fn exact_graph_keeps_contextual_instances_and_their_distinct_targets() {
        let source = "registry+https://registry.npmjs.org";
        let left_parent_id = lpm_common::PackageInstanceId::derive(
            "left-parent",
            "1.0.0",
            source,
            "root/left-parent",
        );
        let right_parent_id = lpm_common::PackageInstanceId::derive(
            "right-parent",
            "1.0.0",
            source,
            "root/right-parent",
        );
        let left_plugin_id = lpm_common::PackageInstanceId::derive(
            "plugin",
            "1.0.0",
            source,
            "root/left-parent/plugin",
        );
        let right_plugin_id = lpm_common::PackageInstanceId::derive(
            "plugin",
            "1.0.0",
            source,
            "root/right-parent/plugin",
        );
        let left_leaf_id = lpm_common::PackageInstanceId::derive(
            "left-leaf",
            "1.0.0",
            source,
            "root/left-parent/plugin/left-leaf",
        );
        let right_leaf_id = lpm_common::PackageInstanceId::derive(
            "right-leaf",
            "1.0.0",
            source,
            "root/right-parent/plugin/right-leaf",
        );
        let packages = vec![
            LockedPackage {
                instance_id: Some(left_parent_id),
                name: "left-parent".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["plugin@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([(
                    "plugin".into(),
                    left_plugin_id,
                )]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(right_parent_id),
                name: "right-parent".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["plugin@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([(
                    "plugin".into(),
                    right_plugin_id,
                )]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(left_plugin_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["left-leaf@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([(
                    "left-leaf".into(),
                    left_leaf_id,
                )]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(right_plugin_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["right-leaf@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([(
                    "right-leaf".into(),
                    right_leaf_id,
                )]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(left_leaf_id),
                name: "left-leaf".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(right_leaf_id),
                name: "right-leaf".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
        ];
        let direct = HashSet::from(["left-parent".to_string(), "right-parent".to_string()]);

        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        assert_eq!(graph.stats.total_packages, 6);
        assert_eq!(
            graph
                .nodes
                .values()
                .filter(|node| node.name == "plugin")
                .count(),
            2
        );
        assert!(graph.nodes.values().any(|node| {
            node.name == "plugin"
                && node.dependencies.iter().any(|dependency| {
                    graph
                        .nodes
                        .get(dependency)
                        .is_some_and(|target| target.name == "left-leaf")
                })
        }));
        assert!(graph.nodes.values().any(|node| {
            node.name == "plugin"
                && node.dependencies.iter().any(|dependency| {
                    graph
                        .nodes
                        .get(dependency)
                        .is_some_and(|target| target.name == "right-leaf")
                })
        }));
    }

    #[test]
    fn exact_graph_includes_peer_target_reachable_only_through_peer_edge() {
        let source = "registry+https://registry.npmjs.org";
        let consumer_id =
            lpm_common::PackageInstanceId::derive("consumer", "1.0.0", source, "root/consumer");
        let provider_id = lpm_common::PackageInstanceId::derive(
            "provider",
            "2.0.0",
            source,
            "root/consumer/provider",
        );
        let packages = vec![
            LockedPackage {
                instance_id: Some(consumer_id),
                name: "consumer".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                peers: vec!["provider@2.0.0".into()],
                peer_targets: std::collections::BTreeMap::from([("provider".into(), provider_id)]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(provider_id),
                name: "provider".into(),
                version: "2.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
        ];
        let graph = DepGraph::from_lockfile(
            &packages,
            &HashSet::from(["consumer".to_string()]),
            "app@1.0.0",
        );

        assert_eq!(
            graph.nodes["consumer@1.0.0"].dependencies,
            vec!["provider@2.0.0".to_string()]
        );
    }

    #[test]
    fn project_root_key_does_not_overwrite_matching_dependency_coordinate() {
        let packages = vec![LockedPackage {
            name: "app".into(),
            version: "1.0.0".into(),
            ..Default::default()
        }];

        let graph =
            DepGraph::from_lockfile(&packages, &HashSet::from(["app".to_string()]), "app@1.0.0");

        assert_eq!(graph.nodes.len(), 2);
        assert!(!graph.nodes["app@1.0.0"].is_root);
        assert_eq!(graph.nodes[&graph.roots[0]].dependencies, ["app@1.0.0"]);
    }

    #[test]
    fn scoped_project_root_preserves_name_and_version() {
        let graph = DepGraph::from_lockfile(&[], &HashSet::new(), "@scope/app@1.2.3");
        let root = &graph.nodes[&graph.roots[0]];

        assert_eq!((&*root.name, &*root.version), ("@scope/app", "1.2.3"));
    }

    #[test]
    fn project_root_is_excluded_from_duplicate_state() {
        let packages = vec![
            LockedPackage {
                name: "app".into(),
                version: "2.0.0".into(),
                ..Default::default()
            },
            LockedPackage {
                name: "app".into(),
                version: "3.0.0".into(),
                ..Default::default()
            },
        ];
        let graph = DepGraph::from_lockfile(&packages, &HashSet::new(), "app@1.0.0");

        assert_eq!(
            graph.stats.duplicates,
            [(
                "app".to_string(),
                vec!["2.0.0".to_string(), "3.0.0".to_string()]
            )]
        );
        assert!(!graph.nodes[&graph.roots[0]].is_duplicate);
    }

    #[test]
    fn exact_graph_root_uses_only_the_selected_contextual_instance() {
        let source = "registry+https://registry.npmjs.org";
        let root_plugin_id =
            lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/plugin");
        let parent_id =
            lpm_common::PackageInstanceId::derive("parent", "1.0.0", source, "root/parent");
        let nested_plugin_id =
            lpm_common::PackageInstanceId::derive("plugin", "1.0.0", source, "root/parent/plugin");
        let packages = vec![
            LockedPackage {
                instance_id: Some(root_plugin_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(parent_id),
                name: "parent".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                dependencies: vec!["plugin@1.0.0".into()],
                dependency_targets: std::collections::BTreeMap::from([(
                    "plugin".into(),
                    nested_plugin_id,
                )]),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(nested_plugin_id),
                name: "plugin".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
        ];
        let direct = HashSet::from(["parent".to_string(), "plugin".to_string()]);
        let root_resolutions = lpm_lockfile::RootResolutions::from([
            (
                "parent".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(parent_id),
                    package: "parent".to_string(),
                    version: "1.0.0".to_string(),
                    source: Some(source.to_string()),
                },
            ),
            (
                "plugin".to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(root_plugin_id),
                    package: "plugin".to_string(),
                    version: "1.0.0".to_string(),
                    source: Some(source.to_string()),
                },
            ),
        ]);

        let graph = DepGraph::from_lockfile_with_root_resolutions(
            &packages,
            &direct,
            &root_resolutions,
            "app@1.0.0",
        );

        assert_eq!(
            graph.nodes["app@1.0.0"].dependencies,
            vec![
                "parent@1.0.0".to_string(),
                format!("plugin@1.0.0#{root_plugin_id}"),
            ]
        );
    }

    #[test]
    fn exact_graph_marks_every_contextual_version_as_duplicate() {
        let source = "registry+https://registry.npmjs.org";
        let first_id = lpm_common::PackageInstanceId::derive("dep", "1.0.0", source, "root/first");
        let first_sibling_id =
            lpm_common::PackageInstanceId::derive("dep", "1.0.0", source, "root/first-sibling");
        let second_id =
            lpm_common::PackageInstanceId::derive("dep", "2.0.0", source, "root/second");
        let packages = vec![
            LockedPackage {
                instance_id: Some(first_id),
                name: "dep".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(first_sibling_id),
                name: "dep".into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
            LockedPackage {
                instance_id: Some(second_id),
                name: "dep".into(),
                version: "2.0.0".into(),
                source: Some(source.into()),
                ..Default::default()
            },
        ];
        let direct = HashSet::from(["dep".to_string()]);

        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        assert!(
            graph
                .nodes
                .values()
                .filter(|node| node.name == "dep")
                .all(|node| node.is_duplicate)
        );
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
    fn recompute_stats_clears_duplicate_flags_when_one_version_is_filtered_out() {
        let packages = vec![
            package("parent-a", &["dup@1.0.0"]),
            package("parent-b", &["dup@2.0.0"]),
            LockedPackage {
                name: "dup".into(),
                version: "1.0.0".into(),
                ..Default::default()
            },
            LockedPackage {
                name: "dup".into(),
                version: "2.0.0".into(),
                ..Default::default()
            },
        ];
        let mut graph = DepGraph::from_lockfile(
            &packages,
            &HashSet::from(["parent-a".to_string(), "parent-b".to_string()]),
            "app@1.0.0",
        );

        filter_graph(&mut graph, "parent-a");
        recompute_stats(&mut graph);

        assert!(!graph.nodes["dup@1.0.0"].is_duplicate);
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
    fn json_output_orders_nodes_and_edges_by_key() {
        let graph = DepGraph::from_lockfile(&mock_packages(), &direct_deps(), "test-app@1.0.0");
        let parsed: serde_json::Value =
            serde_json::from_str(&render_json(&graph).expect("render graph JSON"))
                .expect("parse graph JSON");
        let node_keys: Vec<&str> = parsed["nodes"]
            .as_array()
            .expect("nodes array")
            .iter()
            .map(|node| node["key"].as_str().expect("node key"))
            .collect();
        let mut sorted_node_keys = node_keys.clone();
        sorted_node_keys.sort_unstable();
        assert_eq!(node_keys, sorted_node_keys);

        let edges: Vec<(&str, &str)> = parsed["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .map(|edge| {
                (
                    edge["from"].as_str().expect("edge source"),
                    edge["to"].as_str().expect("edge target"),
                )
            })
            .collect();
        let mut sorted_edges = edges.clone();
        sorted_edges.sort_unstable();
        assert_eq!(edges, sorted_edges);
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "<img src=x onerror=alert(1)>".into(),
                version: "1.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
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
                name: "<img src=x onerror=alert(1)>".into(),
                version: "2.0.0".into(),
                source: Some("registry+https://registry.npmjs.org".into()),
                integrity: None,
                unpacked_size: None,
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

    // ── Why paths ────────────────────────────────────────

    /// A chain of `depth` levels in which every level has two packages that
    /// both depend on the next level's shared package, ending at `target`:
    /// 2^`depth` paths from the root to `target`.
    fn dense_chain(depth: usize) -> Vec<LockedPackage> {
        let mut packages = Vec::with_capacity(depth * 3 + 1);
        for level in 0..depth {
            let shared = format!("shared-{level}@1.0.0");
            packages.push(package(&format!("branch-{level}-a"), &[shared.as_str()]));
            packages.push(package(&format!("branch-{level}-b"), &[shared.as_str()]));
            let next = if level + 1 < depth {
                vec![
                    format!("branch-{}-a@1.0.0", level + 1),
                    format!("branch-{}-b@1.0.0", level + 1),
                ]
            } else {
                vec!["target@1.0.0".to_string()]
            };
            let next: Vec<&str> = next.iter().map(String::as_str).collect();
            packages.push(package(&format!("shared-{level}"), &next));
        }
        packages.push(package("target", &[]));
        packages
    }

    fn dense_chain_graph(depth: usize, extra_direct: &[&str]) -> DepGraph {
        let mut packages = dense_chain(depth);
        for name in extra_direct {
            packages.push(package(name, &[]));
        }
        let mut direct = HashSet::from(["branch-0-a".to_string(), "branch-0-b".to_string()]);
        direct.extend(extra_direct.iter().map(|name| (*name).to_string()));
        DepGraph::from_lockfile(&packages, &direct, "app@1.0.0")
    }

    fn collected(paths: &WhyPaths<'_>) -> Vec<Vec<String>> {
        paths
            .iter()
            .map(|path| path.iter().map(|key| (*key).to_string()).collect())
            .collect()
    }

    #[test]
    fn why_paths_collects_every_path_within_the_limit() {
        let graph = dense_chain_graph(7, &[]);

        let paths = graph.why_paths("target", Some(DEFAULT_WHY_PATH_LIMIT));

        assert_eq!((paths.count, paths.count_exact), (1 << 7, true));
        assert_eq!(paths.shown(), 1 << 7);
        assert!(paths.iter().all(|path| path.len() == 7 * 2 + 2));
        assert!(!paths.truncated());
    }

    #[test]
    fn why_paths_follow_only_edges_that_lead_to_the_target() {
        let graph = dense_chain_graph(64, &["lone"]);
        let edges: usize = graph
            .nodes
            .values()
            .map(|node| node.dependencies.len())
            .sum();

        let paths = graph.why_paths("lone", None);

        assert_eq!(
            collected(&paths),
            [["app@1.0.0".to_string(), "lone@1.0.0".to_string()]]
        );
        assert_eq!((paths.count, paths.count_exact), (1, true));
        assert!(
            paths.expanded_edges <= edges as u64,
            "followed {} of {edges} edges",
            paths.expanded_edges
        );
    }

    #[test]
    fn why_paths_count_a_dense_graph_exactly_but_collect_only_the_limit() {
        let graph = dense_chain_graph(40, &[]);

        let paths = graph.why_paths("target", Some(3));

        assert_eq!((paths.count, paths.count_exact), (1 << 40, true));
        assert_eq!(paths.shown(), 3);
        assert_eq!(paths.hidden(), (1 << 40) - 3);
        assert!(paths.limit_reached && paths.truncated());
        assert!(paths.expanded_edges < 1_000, "{}", paths.expanded_edges);
    }

    #[test]
    fn why_paths_say_a_count_past_u64_max_is_not_exact() {
        let graph = dense_chain_graph(64, &[]);

        let paths = graph.why_paths("target", Some(1));

        assert_eq!((paths.count, paths.count_exact), (u64::MAX, false));
        assert!(paths.truncated());
    }

    #[test]
    fn why_paths_end_cycles_without_losing_paths() {
        let packages = vec![
            package("a", &["target@1.0.0", "b@1.0.0"]),
            package("b", &["target@1.0.0", "a@1.0.0"]),
            package("target", &[]),
        ];
        let direct = HashSet::from(["a".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        let paths = graph.why_paths("target", None);

        assert_eq!((paths.count, paths.count_exact), (2, true));
        let json = render_why_json(&graph, "target", None, None).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(report["path_count"], 2);
        assert_eq!(report["path_count_exact"], true);
        assert_eq!(report["paths_truncated"], false);
        assert_eq!(report["path_keys"], report["paths"]);
    }

    #[test]
    fn why_paths_through_a_cycle_report_a_lower_bound_past_the_limit() {
        let mut packages = dense_chain(4);
        packages
            .iter_mut()
            .find(|package| package.name == "shared-3")
            .unwrap()
            .dependencies
            .push("branch-0-a@1.0.0".to_string());
        let direct = HashSet::from(["branch-0-a".to_string(), "branch-0-b".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        let limited = graph.why_paths("target", Some(5));
        let every = graph.why_paths("target", None);

        assert_eq!((limited.count, limited.count_exact), (6, false));
        assert_eq!(limited.shown(), 5);
        assert_eq!(limited.hidden(), 1);
        assert_eq!((every.count, every.count_exact), (16, true));
        assert_eq!(every.shown(), 16);
    }

    #[test]
    fn why_paths_through_a_cycle_stop_at_their_budget_and_still_show_a_path() {
        let packages = vec![
            package("a", &["b@1.0.0", "target@1.0.0"]),
            package("b", &["a@1.0.0", "c@1.0.0"]),
            package("c", &["b@1.0.0", "target@1.0.0"]),
            package("target", &[]),
        ];
        let direct = HashSet::from(["a".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        let paths = graph.why_paths_within("target", Some(10), 2);

        assert!(paths.search_stopped);
        assert!(!paths.count_exact);
        assert_eq!(paths.count, 1);
        assert_eq!(
            collected(&paths),
            [[
                "app@1.0.0".to_string(),
                "a@1.0.0".to_string(),
                "target@1.0.0".to_string()
            ]]
        );
    }

    #[test]
    fn why_paths_count_reachable_same_name_targets_independently() {
        let mut target_v1 = package("target", &["target@2.0.0"]);
        target_v1.version = "1.0.0".into();
        let mut target_v2 = package("target", &[]);
        target_v2.version = "2.0.0".into();
        let mut unreachable_target = package("target", &[]);
        unreachable_target.version = "3.0.0".into();
        let direct = HashSet::from(["entry".to_string()]);
        let graph = DepGraph::from_lockfile(
            &[
                package("entry", &["target@1.0.0"]),
                target_v1,
                target_v2,
                unreachable_target,
            ],
            &direct,
            "app@1.0.0",
        );

        let paths = graph.why_paths("target", None);

        assert_eq!((paths.count, paths.version_count), (2, 2));
    }

    #[test]
    fn why_paths_order_target_versions_and_edges_lexically() {
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

        let paths = graph.why_paths("target", None);

        assert_eq!(
            collected(&paths),
            [
                ["app@1.0.0", "alpha@1.0.0", "target@1.0.0"],
                ["app@1.0.0", "zeta@1.0.0", "target@1.0.0"],
                ["app@1.0.0", "alpha@1.0.0", "target@2.0.0"],
                ["app@1.0.0", "zeta@1.0.0", "target@2.0.0"],
            ]
            .map(|path| path.map(str::to_string))
        );
    }

    const DEEP_GRAPH_CHILD: &str = "LPM_TEST_GRAPH_DEEP_CHAIN_CHILD";

    #[test]
    fn graph_traversals_handle_a_deep_chain_without_stack_growth() {
        if std::env::var_os(DEEP_GRAPH_CHILD).is_some() {
            const DEPTH: usize = 100_000;
            let mut packages = Vec::with_capacity(DEPTH);
            for level in 0..DEPTH {
                let next = format!("link-{}@1.0.0", level + 1);
                let dependencies: &[&str] = if level + 1 < DEPTH { &[&next] } else { &[] };
                packages.push(package(&format!("link-{level}"), dependencies));
            }
            let direct = HashSet::from(["link-0".to_string()]);
            let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
            let last = format!("link-{}", DEPTH - 1);
            let walk = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let paths = graph.why_paths(&last, Some(1));
                    assert_eq!((paths.count, paths.shown()), (1, 1));
                    write_tree(io::sink(), &graph, false).unwrap();
                    write_why(io::sink(), &graph, &last, Some(1), None, None).unwrap();
                })
                .unwrap();
            walk.join().unwrap();
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "graph_render::tests::graph_traversals_handle_a_deep_chain_without_stack_growth",
                "--nocapture",
            ])
            .env(DEEP_GRAPH_CHILD, "1")
            .status()
            .expect("run the deep graph child process");
        assert!(status.success(), "a deep graph traversal aborted: {status}");
    }

    /// Accepts `capacity` bytes, then fails every write.
    struct FullWriter {
        capacity: usize,
        written: usize,
        attempts_after_full: usize,
    }

    impl Write for FullWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written >= self.capacity {
                self.attempts_after_full += 1;
                return Err(io::Error::new(io::ErrorKind::StorageFull, "full"));
            }
            let accepted = buf.len().min(self.capacity - self.written);
            self.written += accepted;
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tree_writer_stops_at_the_first_write_error() {
        let graph = dense_chain_graph(200, &[]);
        let mut writer = FullWriter {
            capacity: 512,
            written: 0,
            attempts_after_full: 0,
        };

        let error = write_tree(&mut writer, &graph, false).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert_eq!(writer.attempts_after_full, 1);
    }

    #[test]
    fn tree_writer_writes_what_the_tree_renderer_did() {
        let packages = vec![
            package("a", &["b@1.0.0", "c@1.0.0"]),
            package("b", &["c@1.0.0", "a@1.0.0"]),
            package("c", &[]),
            package("d", &["c@1.0.0"]),
        ];
        let direct = HashSet::from(["a".to_string(), "d".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");

        assert_eq!(
            render_tree(&graph, false),
            "app@1.0.0\n\
             ├── a@1.0.0\n\
             │   ├── b@1.0.0\n\
             │   │   ├── a@1.0.0 (circular)\n\
             │   │   └── c@1.0.0\n\
             │   └── c@1.0.0 (shared)\n\
             └── d@1.0.0\n\
             \x20   └── c@1.0.0 (shared)\n\
             \n\
             4 packages, max depth 3\n"
        );
        assert_eq!(
            render_tree(&graph, true),
            "app\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\n\
             \x1b[2m├── \x1b[22ma\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\n\
             \x1b[2m│   \x1b[22m\x1b[2m├── \x1b[22mb\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\n\
             \x1b[2m│   │   \x1b[22m\x1b[2m├── \x1b[22ma\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\x1b[2m (circular)\x1b[22m\n\
             \x1b[2m│   │   \x1b[22m\x1b[2m└── \x1b[22mc\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\n\
             \x1b[2m│   \x1b[22m\x1b[2m└── \x1b[22mc\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\x1b[2m (shared)\x1b[22m\n\
             \x1b[2m└── \x1b[22md\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\n\
             \x1b[2m    \x1b[22m\x1b[2m└── \x1b[22mc\x1b[2m@\x1b[22m\x1b[33m1.0.0\x1b[39m\x1b[2m (shared)\x1b[22m\n\
             \n\
             4 packages, max depth 3\n"
        );
    }

    // ── DOT unescaped quotes in node names ───────────────

    #[test]
    fn dot_escapes_quotes_in_names() {
        let packages = vec![LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "foo\"bar\\baz".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
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
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "foo\"bar]baz".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
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
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "pkg</SCRIPT>test".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
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

    #[test]
    fn streamed_html_matches_buffered_html_and_escapes_less_than() {
        let packages = vec![LockedPackage {
            name: "pkg</script>test".into(),
            version: "1.0.0".into(),
            ..Default::default()
        }];
        let direct = HashSet::from(["pkg</script>test".to_string()]);
        let graph = DepGraph::from_lockfile(&packages, &direct, "app@1.0.0");
        let buffered = render_html(&graph).expect("render buffered HTML");
        let mut streamed = Vec::new();
        write_html(&mut streamed, &graph).expect("stream HTML");
        let streamed = String::from_utf8(streamed).expect("HTML is UTF-8");

        assert_eq!(streamed, buffered);
        assert!(streamed.contains(r"pkg\u003c/script>test"));
        assert!(!streamed.contains("pkg</script>test"));
    }

    // ── --filter misses diamond-pattern matches ───────────

    #[test]
    fn filter_finds_match_through_both_diamond_branches() {
        let packages = vec![
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "branch-a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "branch-b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "shared-target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                name: "c".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "foo(bar)".into(),
            version: "1.0.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
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
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "private-pkg".into(),
            version: "1.0.0".into(),
            source: Some("registry+https://custom.registry.com".into()),
            integrity: None,
            unpacked_size: None,
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "ms".into(),
                version: "2.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                name: "ms".into(),
                version: "2.1.3".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                from_version: Some(from.to_string()),
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
            captured_at: "T00:00:00Z".to_string(),
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
            captured_at: "T00:00:00Z".to_string(),
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
            captured_at: "T00:00:00Z".to_string(),
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
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
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "local-pkg".into(),
            version: "0.1.0".into(),
            source: None,
            integrity: None,
            unpacked_size: None,
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
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "parent".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
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
                peer_edges: Vec::new(),
                tarball: None,
            },
            LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "child-of-target".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
                name: "unrelated".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                unpacked_size: None,
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
