//! Generic directed acyclic graph utilities.
//!
//! Provides topological sort with parallel grouping, used by:
//! - Service graph (lpm dev orchestrator)
//! - Task graph (lpm run --parallel)
//! - Workspace graph (lpm run --all)

use std::collections::{HashMap, HashSet, VecDeque};

/// Topologically sort nodes into parallel execution groups.
///
/// Input: `nodes` maps each node name to its list of dependency names.
/// Returns `Vec<Vec<String>>` where each inner Vec is a group of nodes
/// that can execute in parallel (all dependencies are in earlier groups).
///
/// Errors on cycles or missing dependency references.
pub fn topological_levels(
    nodes: &HashMap<String, Vec<String>>,
) -> Result<Vec<Vec<String>>, String> {
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    validate_deps(nodes)?;

    // Build in-degree map and reverse adjacency (Kahn's algorithm)
    let mut in_degree: HashMap<&str, usize> = HashMap::with_capacity(nodes.len());
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::with_capacity(nodes.len());

    for name in nodes.keys() {
        in_degree.insert(name.as_str(), 0);
        dependents.entry(name.as_str()).or_default();
    }

    for (name, deps) in nodes {
        *in_degree.entry(name.as_str()).or_default() += deps.len();
        for dep in deps {
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(name.as_str());
        }
    }

    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    let mut processed = 0usize;

    // Seed with zero-indegree nodes
    for (&name, &degree) in &in_degree {
        if degree == 0 {
            queue.push_back(name);
        }
    }

    while !queue.is_empty() {
        // All items currently in the queue can run in parallel
        let mut group: Vec<String> = queue.drain(..).map(|s| s.to_string()).collect();
        group.sort_unstable(); // deterministic ordering within each level
        processed += group.len();

        // Decrease in-degree for dependents of this group
        for name in &group {
            if let Some(deps) = dependents.get(name.as_str()) {
                for &dep in deps {
                    let deg = in_degree.get_mut(dep).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }

        groups.push(group);
    }

    if processed != nodes.len() {
        // Cycle detected — collect the nodes that are stuck
        let mut remaining: Vec<&str> = in_degree
            .iter()
            .filter(|(_, d)| **d > 0)
            .map(|(n, _)| *n)
            .collect();
        remaining.sort_unstable();
        return Err(format!(
            "circular dependency detected among: {}",
            remaining.join(", ")
        ));
    }

    Ok(groups)
}

/// Validate all dependency references exist as nodes.
pub fn validate_deps(nodes: &HashMap<String, Vec<String>>) -> Result<(), String> {
    for (name, deps) in nodes {
        for dep in deps {
            if !nodes.contains_key(dep) {
                return Err(format!("'{name}' depends on '{dep}', which is not defined"));
            }
        }
    }
    Ok(())
}

/// Get all transitive dependencies of a node (including itself).
pub fn transitive_deps(name: &str, nodes: &HashMap<String, Vec<String>>) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(name.to_string());

    while let Some(current) = queue.pop_front() {
        if !result.insert(current.clone()) {
            continue;
        }
        if let Some(deps) = nodes.get(&current) {
            for dep in deps {
                if !result.contains(dep) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    result
}

/// Get all transitive dependents of a node (nodes that directly or indirectly depend on it).
///
/// This traverses reverse edges: if B depends on A, then B is a dependent of A.
/// Does NOT include the node itself.
pub fn transitive_dependents(name: &str, nodes: &HashMap<String, Vec<String>>) -> HashSet<String> {
    // Build reverse adjacency: for each dep, who depends on it?
    let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
    for (node, deps) in nodes {
        for dep in deps {
            reverse.entry(dep.as_str()).or_default().push(node.as_str());
        }
    }

    let mut result = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(name);

    while let Some(current) = queue.pop_front() {
        if let Some(deps_of) = reverse.get(current) {
            for &dep in deps_of {
                if result.insert(dep.to_string()) {
                    queue.push_back(dep);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a graph from `(node, &[deps])` pairs.
    fn graph(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(name, deps)| {
                (
                    name.to_string(),
                    deps.iter().map(|d| d.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn empty_graph() {
        let g = graph(&[]);
        let levels = topological_levels(&g).unwrap();
        assert!(levels.is_empty());
    }

    #[test]
    fn single_node_no_deps() {
        let g = graph(&[("a", &[])]);
        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels, vec![vec!["a"]]);
    }

    #[test]
    fn linear_chain() {
        // a depends on b, b depends on c → [c], [b], [a]
        let g = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["c"]);
        assert_eq!(levels[1], vec!["b"]);
        assert_eq!(levels[2], vec!["a"]);
    }

    #[test]
    fn diamond() {
        // a → [b, c], b → d, c → d
        let g = graph(&[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"]), ("d", &[])]);
        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["d"]);
        assert_eq!(levels[1], vec!["b", "c"]); // sorted alphabetically
        assert_eq!(levels[2], vec!["a"]);
    }

    #[test]
    fn parallel_independent() {
        let g = graph(&[("a", &[]), ("b", &[])]);
        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["a", "b"]);
    }

    #[test]
    fn cycle_detection() {
        let g = graph(&[("a", &["b"]), ("b", &["a"])]);
        let result = topological_levels(&g);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("circular dependency"), "got: {err}");
        assert!(err.contains('a'));
        assert!(err.contains('b'));
    }

    #[test]
    fn cycle_detection_three_nodes() {
        let g = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &["a"])]);
        let result = topological_levels(&g);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("circular dependency"));
    }

    #[test]
    fn missing_dependency() {
        let g = graph(&[("a", &["missing"])]);
        let result = topological_levels(&g);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
        assert!(err.contains("not defined"), "got: {err}");
    }

    #[test]
    fn large_graph() {
        // Build a 20-node chain: n0 → n1 → n2 → ... → n19
        let mut entries: Vec<(String, Vec<String>)> = Vec::new();
        for i in 0..20 {
            let name = format!("n{i}");
            let deps = if i < 19 {
                vec![format!("n{}", i + 1)]
            } else {
                vec![]
            };
            entries.push((name, deps));
        }
        let g: HashMap<String, Vec<String>> = entries.into_iter().collect();

        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels.len(), 20);
        assert_eq!(levels[0], vec!["n19"]);
        assert_eq!(levels[19], vec!["n0"]);
    }

    #[test]
    fn large_graph_wide() {
        // 20 independent nodes → one level
        let g: HashMap<String, Vec<String>> = (0..20).map(|i| (format!("n{i}"), vec![])).collect();
        let levels = topological_levels(&g).unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 20);
    }

    #[test]
    fn transitive_deps_linear() {
        let g = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        let deps = transitive_deps("a", &g);
        assert_eq!(deps, HashSet::from(["a".into(), "b".into(), "c".into()]));
    }

    #[test]
    fn transitive_deps_diamond() {
        let g = graph(&[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"]), ("d", &[])]);
        let deps = transitive_deps("a", &g);
        assert_eq!(deps.len(), 4);
        assert!(deps.contains("a"));
        assert!(deps.contains("b"));
        assert!(deps.contains("c"));
        assert!(deps.contains("d"));
    }

    #[test]
    fn transitive_deps_nonexistent_node() {
        let g = graph(&[("a", &[])]);
        let deps = transitive_deps("missing", &g);
        // Returns just the node itself even if it's not in the graph
        assert_eq!(deps, HashSet::from(["missing".into()]));
    }

    #[test]
    fn transitive_deps_single() {
        let g = graph(&[("a", &[])]);
        let deps = transitive_deps("a", &g);
        assert_eq!(deps, HashSet::from(["a".into()]));
    }

    #[test]
    fn validate_deps_ok() {
        let g = graph(&[("a", &["b"]), ("b", &[])]);
        assert!(validate_deps(&g).is_ok());
    }

    #[test]
    fn validate_deps_missing() {
        let g = graph(&[("a", &["nope"])]);
        let err = validate_deps(&g).unwrap_err();
        assert!(err.contains("nope"));
        assert!(err.contains("not defined"));
    }

    // ── transitive_dependents tests ──────────────────────────────────

    #[test]
    fn transitive_dependents_linear_chain() {
        // C depends on B, B depends on A. If A crashes, B and C should be dependents.
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let deps = transitive_dependents("a", &g);
        assert!(deps.contains("b"), "b directly depends on a");
        assert!(deps.contains("c"), "c transitively depends on a");
        assert!(!deps.contains("a"), "should not include self");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn transitive_dependents_diamond() {
        // d has no dependents, b and c depend on d, a depends on b and c
        let g = graph(&[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"]), ("d", &[])]);
        let deps = transitive_dependents("d", &g);
        assert_eq!(deps.len(), 3);
        assert!(deps.contains("a"));
        assert!(deps.contains("b"));
        assert!(deps.contains("c"));
    }

    #[test]
    fn transitive_dependents_leaf_has_none() {
        let g = graph(&[("a", &[]), ("b", &["a"])]);
        let deps = transitive_dependents("b", &g);
        assert!(deps.is_empty(), "leaf node should have no dependents");
    }

    #[test]
    fn transitive_dependents_nonexistent_node() {
        let g = graph(&[("a", &[])]);
        let deps = transitive_dependents("missing", &g);
        assert!(deps.is_empty());
    }
}
