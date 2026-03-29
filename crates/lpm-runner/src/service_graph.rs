//! Service dependency graph and topological sort.
//!
//! Builds a DAG from service `dependsOn` declarations and produces
//! an execution order (groups of services that can start in parallel).
//!
//! Delegates to [`crate::dag`] for the generic topological sort algorithm.

use crate::lpm_json::ServiceConfig;
use std::collections::{HashMap, HashSet};

/// Convert services to a generic node → deps map for the DAG solver.
fn to_dag(services: &HashMap<String, ServiceConfig>) -> HashMap<String, Vec<String>> {
	services
		.iter()
		.map(|(name, config)| (name.clone(), config.depends_on.clone()))
		.collect()
}

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
	crate::dag::topological_levels(&to_dag(services)).map_err(|e| {
		// Preserve the original error format for services
		e.replace("among:", "among services:")
			.replace("which is not defined", "which is not defined in services")
	})
}

/// Get all transitive dependents of a service (services that directly or indirectly depend on it).
/// Does NOT include the service itself.
pub fn transitive_dependents(
	name: &str,
	services: &HashMap<String, ServiceConfig>,
) -> HashSet<String> {
	crate::dag::transitive_dependents(name, &to_dag(services))
}

/// Get all transitive dependencies of a service (including itself).
pub fn transitive_deps(
	name: &str,
	services: &HashMap<String, ServiceConfig>,
) -> HashSet<String> {
	crate::dag::transitive_deps(name, &to_dag(services))
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
