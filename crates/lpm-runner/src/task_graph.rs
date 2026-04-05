//! Build a task dependency graph from lpm.json and package.json.
//!
//! Converts task `dependsOn` config into a DAG for execution ordering.

use crate::dag;
use crate::lpm_json::TaskConfig;
use std::collections::{HashMap, HashSet};

/// Build a task dependency graph for the requested scripts.
///
/// Resolves transitive local dependencies (same-package tasks).
/// Upstream dependencies (`^build`) are excluded — they're handled at workspace level.
///
/// Returns a map of task_name → dependencies, ready for `dag::topological_levels()`.
pub fn build_task_graph(
    scripts: &HashMap<String, String>,
    tasks: &HashMap<String, TaskConfig>,
    requested: &[String],
) -> Result<HashMap<String, Vec<String>>, String> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut to_process: Vec<String> = requested.to_vec();
    let mut seen: HashSet<String> = HashSet::new();

    while let Some(task_name) = to_process.pop() {
        if !seen.insert(task_name.clone()) {
            continue;
        }

        // Get local dependencies from lpm.json task config (skip upstream `^` deps)
        let local_deps: Vec<String> = tasks
            .get(&task_name)
            .map(|tc| {
                tc.depends_on
                    .iter()
                    .filter(|d| !d.starts_with('^'))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Validate each dep exists as a script, a task with a command, or a
        // meta-task (task with dependsOn but no command — acts as a dependency
        // group that succeeds once its own deps complete).
        for dep in &local_deps {
            let is_script = scripts.contains_key(dep);
            let is_task_with_command = tasks.get(dep).and_then(|t| t.command.as_ref()).is_some();
            let is_meta_task = tasks
                .get(dep)
                .map(|t| !t.depends_on.is_empty())
                .unwrap_or(false);

            if !is_script && !is_task_with_command && !is_meta_task {
                return Err(format!(
                    "task '{task_name}' depends on '{dep}', but '{dep}' is not a script in package.json, a task with a command, or a meta-task with dependsOn in lpm.json"
                ));
            }
            to_process.push(dep.clone());
        }

        graph.insert(task_name, local_deps);
    }

    // Validate no cycles (validate_deps checks references, topological_levels checks cycles)
    dag::validate_deps(&graph)?;
    // Also run the sort to detect cycles (validate_deps only checks existence)
    dag::topological_levels(&graph)?;

    Ok(graph)
}

/// Get execution levels for a set of tasks.
///
/// Combines task graph building with topological sort.
pub fn task_levels(
    scripts: &HashMap<String, String>,
    tasks: &HashMap<String, TaskConfig>,
    requested: &[String],
) -> Result<Vec<Vec<String>>, String> {
    let graph = build_task_graph(scripts, tasks, requested)?;
    dag::topological_levels(&graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a scripts map from `(name, command)` pairs.
    fn scripts(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Helper: build a tasks map from `(name, depends_on)` pairs.
    fn tasks(entries: &[(&str, &[&str])]) -> HashMap<String, TaskConfig> {
        entries
            .iter()
            .map(|(name, deps)| {
                (
                    name.to_string(),
                    TaskConfig {
                        depends_on: deps.iter().map(|d| d.to_string()).collect(),
                        ..Default::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn no_tasks_config_all_independent() {
        let s = scripts(&[
            ("lint", "eslint ."),
            ("test", "vitest"),
            ("build", "vite build"),
        ]);
        let t = HashMap::new();
        let requested = vec!["lint".into(), "test".into(), "build".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 3);
    }

    #[test]
    fn simple_depends_on() {
        // test depends on check → [check], [test]
        let s = scripts(&[("test", "vitest"), ("check", "tsc --noEmit")]);
        let t = tasks(&[("test", &["check"])]);
        let requested = vec!["test".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec!["check"]);
        assert_eq!(levels[1], vec!["test"]);
    }

    #[test]
    fn transitive_deps() {
        // ci → [lint, test], test → check → [check], [lint, test], [ci]
        let s = scripts(&[
            ("ci", "echo ci"),
            ("lint", "eslint ."),
            ("test", "vitest"),
            ("check", "tsc --noEmit"),
        ]);
        let t = tasks(&[("ci", &["lint", "test"]), ("test", &["check"])]);
        let requested = vec!["ci".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 3);
        // check and lint both have no deps → parallel in first level
        assert_eq!(levels[0], vec!["check", "lint"]);
        assert_eq!(levels[1], vec!["test"]);
        assert_eq!(levels[2], vec!["ci"]);
    }

    #[test]
    fn upstream_deps_excluded() {
        // build has ^build (upstream) — should be ignored, only local deps matter
        let s = scripts(&[("build", "vite build"), ("codegen", "graphql-codegen")]);
        let t = tasks(&[("build", &["^build", "codegen"])]);
        let requested = vec!["build".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec!["codegen"]);
        assert_eq!(levels[1], vec!["build"]);
    }

    #[test]
    fn unknown_dep_error() {
        let s = scripts(&[("test", "vitest")]);
        let t = tasks(&[("test", &["nonexistent"])]);
        let requested = vec!["test".into()];

        let result = task_levels(&s, &t, &requested);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("nonexistent"), "got: {err}");
        assert!(err.contains("not a script"), "got: {err}");
    }

    #[test]
    fn circular_dep_error() {
        let s = scripts(&[("a", "echo a"), ("b", "echo b")]);
        let t = tasks(&[("a", &["b"]), ("b", &["a"])]);
        let requested = vec!["a".into()];

        let result = task_levels(&s, &t, &requested);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("circular dependency"));
    }

    #[test]
    fn task_with_command_but_no_script() {
        // "codegen" is not in package.json scripts but has a command in lpm.json
        let s = scripts(&[("build", "vite build")]);
        let mut t = tasks(&[("build", &["codegen"])]);
        t.insert(
            "codegen".into(),
            TaskConfig {
                command: Some("graphql-codegen".into()),
                ..Default::default()
            },
        );
        let requested = vec!["build".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec!["codegen"]);
        assert_eq!(levels[1], vec!["build"]);
    }

    #[test]
    fn meta_task_as_dependency_target() {
        // "release" depends on "ci", "ci" is a meta-task (dependsOn only, no command)
        let s = scripts(&[("lint", "eslint ."), ("test", "vitest")]);
        let t = tasks(&[
            ("ci", &["lint", "test"]),
            ("release", &["ci"]),
        ]);
        let requested = vec!["release".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        // Should be: [lint, test], [ci], [release]
        assert_eq!(levels.len(), 3, "expected 3 levels, got {levels:?}");
        assert!(levels[0].contains(&"lint".to_string()));
        assert!(levels[0].contains(&"test".to_string()));
        assert_eq!(levels[1], vec!["ci"]);
        assert_eq!(levels[2], vec!["release"]);
    }

    #[test]
    fn single_requested_no_deps() {
        let s = scripts(&[("lint", "eslint .")]);
        let t = HashMap::new();
        let requested = vec!["lint".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels, vec![vec!["lint"]]);
    }

    #[test]
    fn diamond_task_deps() {
        // deploy → [build, test], build → codegen, test → codegen
        let s = scripts(&[
            ("deploy", "echo deploy"),
            ("build", "vite build"),
            ("test", "vitest"),
            ("codegen", "graphql-codegen"),
        ]);
        let t = tasks(&[
            ("deploy", &["build", "test"]),
            ("build", &["codegen"]),
            ("test", &["codegen"]),
        ]);
        let requested = vec!["deploy".into()];

        let levels = task_levels(&s, &t, &requested).unwrap();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["codegen"]);
        assert_eq!(levels[1], vec!["build", "test"]);
        assert_eq!(levels[2], vec!["deploy"]);
    }
}
