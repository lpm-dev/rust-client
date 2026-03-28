//! Service dependency graph and topological sort.
//!
//! Builds a DAG from service `dependsOn` declarations and produces
//! an execution order (groups of services that can start in parallel).

use crate::lpm_json::ServiceConfig;
use std::collections::{HashMap, HashSet, VecDeque};

/// Topologically sort services into parallel execution groups.
///
/// Returns `Vec<Vec<String>>` where each inner Vec is a group of services
/// that can start simultaneously (all their dependencies are in earlier groups).
///
/// Example:
///   web(no deps), api(depends on db), db(no deps), worker(depends on api)
///   → [["db", "web"], ["api"], ["worker"]]
pub fn topological_sort(
	services: &HashMap<String, ServiceConfig>,
) -> Result<Vec<Vec<String>>, String> {
	if services.is_empty() {
		return Ok(vec![]);
	}

	// Validate all dependsOn references exist
	for (name, config) in services {
		for dep in &config.depends_on {
			if !services.contains_key(dep) {
				return Err(format!(
					"service '{name}' depends on '{dep}', which is not defined in services"
				));
			}
		}
	}

	// Build in-degree map (Kahn's algorithm)
	let mut in_degree: HashMap<&str, usize> = HashMap::new();
	let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

	for name in services.keys() {
		in_degree.insert(name.as_str(), 0);
		dependents.entry(name.as_str()).or_default();
	}

	for (name, config) in services {
		for dep in &config.depends_on {
			*in_degree.entry(name.as_str()).or_default() += 1;
			dependents.entry(dep.as_str()).or_default().push(name.as_str());
		}
	}

	let mut groups: Vec<Vec<String>> = Vec::new();
	let mut queue: VecDeque<&str> = VecDeque::new();
	let mut processed = 0;

	// Start with all services that have no dependencies
	for (&name, &degree) in &in_degree {
		if degree == 0 {
			queue.push_back(name);
		}
	}

	while !queue.is_empty() {
		// All items currently in the queue can run in parallel
		let group: Vec<String> = queue.drain(..).map(|s| s.to_string()).collect();
		processed += group.len();

		// Decrease in-degree for dependents
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

	if processed != services.len() {
		// Cycle detected — find the cycle for a helpful error message
		let remaining: Vec<&str> = in_degree
			.iter()
			.filter(|(_, d)| **d > 0)
			.map(|(n, _)| *n)
			.collect();
		return Err(format!(
			"circular dependency detected among services: {}",
			remaining.join(" → ")
		));
	}

	Ok(groups)
}

/// Get all transitive dependencies of a service (including itself).
pub fn transitive_deps(
	name: &str,
	services: &HashMap<String, ServiceConfig>,
) -> HashSet<String> {
	let mut result = HashSet::new();
	let mut queue = VecDeque::new();
	queue.push_back(name.to_string());

	while let Some(current) = queue.pop_front() {
		if result.contains(&current) {
			continue;
		}
		result.insert(current.clone());

		if let Some(config) = services.get(&current) {
			for dep in &config.depends_on {
				if !result.contains(dep) {
					queue.push_back(dep.clone());
				}
			}
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;

	fn svc(command: &str, deps: &[&str]) -> ServiceConfig {
		ServiceConfig {
			command: command.to_string(),
			depends_on: deps.iter().map(|s| s.to_string()).collect(),
			..Default::default()
		}
	}

	#[test]
	fn empty_services() {
		let services = HashMap::new();
		let groups = topological_sort(&services).unwrap();
		assert!(groups.is_empty());
	}

	#[test]
	fn no_dependencies() {
		let mut services = HashMap::new();
		services.insert("web".into(), svc("next dev", &[]));
		services.insert("api".into(), svc("node server.js", &[]));

		let groups = topological_sort(&services).unwrap();
		assert_eq!(groups.len(), 1);
		assert_eq!(groups[0].len(), 2);
	}

	#[test]
	fn linear_dependencies() {
		let mut services = HashMap::new();
		services.insert("db".into(), svc("docker compose up", &[]));
		services.insert("api".into(), svc("node server.js", &["db"]));
		services.insert("worker".into(), svc("node worker.js", &["api"]));

		let groups = topological_sort(&services).unwrap();
		assert_eq!(groups.len(), 3);
		assert_eq!(groups[0], vec!["db"]);
		assert_eq!(groups[1], vec!["api"]);
		assert_eq!(groups[2], vec!["worker"]);
	}

	#[test]
	fn diamond_dependencies() {
		let mut services = HashMap::new();
		services.insert("db".into(), svc("postgres", &[]));
		services.insert("cache".into(), svc("redis", &[]));
		services.insert("api".into(), svc("node api.js", &["db", "cache"]));
		services.insert("web".into(), svc("next dev", &["api"]));

		let groups = topological_sort(&services).unwrap();
		assert_eq!(groups.len(), 3);
		// First group: db + cache (parallel)
		assert_eq!(groups[0].len(), 2);
		// Second: api
		assert_eq!(groups[1], vec!["api"]);
		// Third: web
		assert_eq!(groups[2], vec!["web"]);
	}

	#[test]
	fn cycle_detection() {
		let mut services = HashMap::new();
		services.insert("a".into(), svc("a", &["b"]));
		services.insert("b".into(), svc("b", &["a"]));

		let result = topological_sort(&services);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("circular dependency"));
	}

	#[test]
	fn missing_dependency() {
		let mut services = HashMap::new();
		services.insert("api".into(), svc("node server.js", &["db"]));

		let result = topological_sort(&services);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("not defined"));
	}

	#[test]
	fn transitive_deps_collects_all() {
		let mut services = HashMap::new();
		services.insert("db".into(), svc("postgres", &[]));
		services.insert("api".into(), svc("node api.js", &["db"]));
		services.insert("web".into(), svc("next dev", &["api"]));

		let deps = transitive_deps("web", &services);
		assert!(deps.contains("web"));
		assert!(deps.contains("api"));
		assert!(deps.contains("db"));
		assert_eq!(deps.len(), 3);
	}
}
