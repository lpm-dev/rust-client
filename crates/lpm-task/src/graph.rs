//! Workspace dependency graph — DAG construction and topological sort.
//!
//! Builds a directed acyclic graph from workspace member dependencies,
//! enabling correct execution order for `--all` and `dependsOn: ["^task"]`.

use lpm_workspace::{Workspace, WorkspaceMember};
use std::collections::{HashMap, HashSet, VecDeque};

/// A workspace dependency graph.
#[derive(Debug)]
pub struct WorkspaceGraph {
	/// Workspace member names in order.
	pub members: Vec<GraphNode>,
	/// Adjacency list: edges[i] = indices of packages that package i depends on.
	pub edges: Vec<Vec<usize>>,
	/// Reverse adjacency: reverse_edges[i] = indices of packages that depend on package i.
	pub reverse_edges: Vec<Vec<usize>>,
	/// Name → index mapping.
	pub name_to_idx: HashMap<String, usize>,
}

/// A node in the workspace graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
	/// Package name from package.json.
	pub name: String,
	/// Path to the package directory.
	pub path: std::path::PathBuf,
}

impl WorkspaceGraph {
	/// Build a dependency graph from a discovered workspace.
	pub fn from_workspace(workspace: &Workspace) -> Self {
		let mut members = Vec::new();
		let mut name_to_idx = HashMap::new();

		// Collect all member names
		for (idx, member) in workspace.members.iter().enumerate() {
			let name = member
				.package
				.name
				.clone()
				.unwrap_or_else(|| format!("unnamed-{idx}"));
			name_to_idx.insert(name.clone(), idx);
			members.push(GraphNode {
				name,
				path: member.path.clone(),
			});
		}

		// Build edges: member i depends on member j if j's name appears in i's deps
		let mut edges = vec![vec![]; members.len()];
		let mut reverse_edges = vec![vec![]; members.len()];

		for (idx, member) in workspace.members.iter().enumerate() {
			let all_deps = member
				.package
				.dependencies
				.keys()
				.chain(member.package.dev_dependencies.keys());

			for dep_name in all_deps {
				if let Some(&dep_idx) = name_to_idx.get(dep_name) {
					edges[idx].push(dep_idx);
					reverse_edges[dep_idx].push(idx);
				}
			}
		}

		WorkspaceGraph {
			members,
			edges,
			reverse_edges,
			name_to_idx,
		}
	}

	/// Topological sort using Kahn's algorithm.
	///
	/// Returns member indices in dependency order (dependencies first).
	/// Returns `Err` if there's a cycle.
	pub fn topological_sort(&self) -> Result<Vec<usize>, GraphError> {
		let n = self.members.len();

		// unmet_deps[i] = number of dependencies of package i not yet processed.
		// Packages with 0 unmet deps can be emitted immediately.
		let mut unmet_deps: Vec<usize> = self.edges.iter().map(|deps| deps.len()).collect();

		let mut queue: VecDeque<usize> = VecDeque::new();
		for i in 0..n {
			if unmet_deps[i] == 0 {
				queue.push_back(i);
			}
		}

		let mut sorted = Vec::with_capacity(n);

		while let Some(node) = queue.pop_front() {
			sorted.push(node);

			// For each package that depends on this node, reduce their unmet deps
			for &dependent in &self.reverse_edges[node] {
				unmet_deps[dependent] -= 1;
				if unmet_deps[dependent] == 0 {
					queue.push_back(dependent);
				}
			}
		}

		if sorted.len() != n {
			// Find packages involved in the cycle for a useful error message
			let in_cycle: Vec<&str> = (0..n)
				.filter(|i| unmet_deps[*i] > 0)
				.map(|i| self.members[i].name.as_str())
				.collect();
			return Err(GraphError::Cycle(in_cycle.join(", ")));
		}

		Ok(sorted)
	}

	/// Get the index of a member by name.
	pub fn index_of(&self, name: &str) -> Option<usize> {
		self.name_to_idx.get(name).copied()
	}

	/// Get all transitive dependents of a package (packages that depend on it, recursively).
	pub fn transitive_dependents(&self, idx: usize) -> HashSet<usize> {
		let mut result = HashSet::new();
		let mut queue = VecDeque::new();
		queue.push_back(idx);

		while let Some(node) = queue.pop_front() {
			for &dep in &self.reverse_edges[node] {
				if result.insert(dep) {
					queue.push_back(dep);
				}
			}
		}

		result
	}

	/// Topological sort grouped by level — packages in the same level can run in parallel.
	///
	/// Returns `Vec<Vec<usize>>` where each inner Vec is a group of independent packages.
	/// Level 0 = packages with no workspace dependencies, Level 1 = depends only on level 0, etc.
	pub fn topological_levels(&self) -> Result<Vec<Vec<usize>>, GraphError> {
		let n = self.members.len();
		let mut unmet_deps: Vec<usize> = self.edges.iter().map(|deps| deps.len()).collect();
		let mut levels: Vec<Vec<usize>> = Vec::new();

		// Start with packages that have no dependencies
		let mut current_level: Vec<usize> = (0..n)
			.filter(|&i| unmet_deps[i] == 0)
			.collect();

		let mut processed = 0;

		while !current_level.is_empty() {
			processed += current_level.len();
			let mut next_level = Vec::new();

			for &node in &current_level {
				for &dependent in &self.reverse_edges[node] {
					unmet_deps[dependent] -= 1;
					if unmet_deps[dependent] == 0 {
						next_level.push(dependent);
					}
				}
			}

			levels.push(current_level);
			current_level = next_level;
		}

		if processed != n {
			let in_cycle: Vec<&str> = (0..n)
				.filter(|i| unmet_deps[*i] > 0)
				.map(|i| self.members[i].name.as_str())
				.collect();
			return Err(GraphError::Cycle(in_cycle.join(", ")));
		}

		Ok(levels)
	}

	/// Number of members.
	pub fn len(&self) -> usize {
		self.members.len()
	}

	pub fn is_empty(&self) -> bool {
		self.members.is_empty()
	}
}

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
	#[error("dependency cycle detected in workspace: {0}")]
	Cycle(String),
}

#[cfg(test)]
mod tests {
	use super::*;
	use lpm_workspace::{PackageJson, Workspace, WorkspaceMember};
	use std::collections::HashMap;
	use std::path::PathBuf;

	fn make_member(name: &str, deps: &[&str]) -> WorkspaceMember {
		let mut dependencies = HashMap::new();
		for d in deps {
			dependencies.insert(d.to_string(), "*".to_string());
		}
		WorkspaceMember {
			path: PathBuf::from(format!("packages/{name}")),
			package: PackageJson {
				name: Some(name.to_string()),
				dependencies,
				..Default::default()
			},
		}
	}

	fn make_workspace(members: Vec<WorkspaceMember>) -> Workspace {
		Workspace {
			root: PathBuf::from("/"),
			root_package: PackageJson::default(),
			members,
		}
	}

	#[test]
	fn empty_workspace() {
		let ws = make_workspace(vec![]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		assert!(graph.is_empty());
		let sorted: Vec<usize> = graph.topological_sort().unwrap();
		assert!(sorted.is_empty());
	}

	#[test]
	fn no_dependencies() {
		let ws = make_workspace(vec![
			make_member("a", &[]),
			make_member("b", &[]),
			make_member("c", &[]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		let sorted = graph.topological_sort().unwrap();
		assert_eq!(sorted.len(), 3);
	}

	#[test]
	fn linear_chain() {
		// c depends on b, b depends on a
		let ws = make_workspace(vec![
			make_member("a", &[]),
			make_member("b", &["a"]),
			make_member("c", &["b"]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		let sorted = graph.topological_sort().unwrap();

		// a must come before b, b must come before c
		let pos_a = sorted.iter().position(|&x| x == 0).unwrap();
		let pos_b = sorted.iter().position(|&x| x == 1).unwrap();
		let pos_c = sorted.iter().position(|&x| x == 2).unwrap();
		assert!(pos_a < pos_b);
		assert!(pos_b < pos_c);
	}

	#[test]
	fn diamond_dependency() {
		// d depends on b and c, both depend on a
		let ws = make_workspace(vec![
			make_member("a", &[]),
			make_member("b", &["a"]),
			make_member("c", &["a"]),
			make_member("d", &["b", "c"]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		let sorted = graph.topological_sort().unwrap();
		assert_eq!(sorted.len(), 4);

		let pos_a = sorted.iter().position(|&x| x == 0).unwrap();
		let pos_d = sorted.iter().position(|&x| x == 3).unwrap();
		assert!(pos_a < pos_d);
	}

	#[test]
	fn transitive_dependents_found() {
		// c → b → a
		let ws = make_workspace(vec![
			make_member("a", &[]),
			make_member("b", &["a"]),
			make_member("c", &["b"]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);

		let deps_of_a = graph.transitive_dependents(0);
		assert!(deps_of_a.contains(&1)); // b depends on a
		assert!(deps_of_a.contains(&2)); // c transitively depends on a
	}

	#[test]
	fn cycle_detected_with_details() {
		// a depends on b, b depends on a
		let ws = make_workspace(vec![
			make_member("a", &["b"]),
			make_member("b", &["a"]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		let result = graph.topological_sort();
		assert!(result.is_err());
		let err = result.unwrap_err().to_string();
		assert!(err.contains("a"), "error should mention package 'a'");
		assert!(err.contains("b"), "error should mention package 'b'");
	}

	#[test]
	fn external_deps_ignored() {
		// "react" is an external dep, not a workspace member
		let ws = make_workspace(vec![
			make_member("ui", &["react"]),
			make_member("app", &["ui"]),
		]);
		let graph = WorkspaceGraph::from_workspace(&ws);
		let sorted = graph.topological_sort().unwrap();
		assert_eq!(sorted.len(), 2);

		// ui has no workspace deps (react is external), app depends on ui
		let pos_ui = sorted.iter().position(|&x| x == 0).unwrap();
		let pos_app = sorted.iter().position(|&x| x == 1).unwrap();
		assert!(pos_ui < pos_app);
	}
}
