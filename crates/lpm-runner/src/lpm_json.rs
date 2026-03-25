//! `lpm.json` configuration reader.
//!
//! `lpm.json` sits alongside `package.json` and provides LPM-specific config:
//! - `runtime` — pinned runtime versions (e.g., `{"node": ">=22.0.0"}`)
//! - `env` — env file mapping per script (e.g., `{"dev": ".env.development"}`)
//! - `tasks` — task configuration with caching, dependencies, outputs
//!
//! This file is optional. Falls back to `package.json` fields when absent.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Configuration from `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LpmJsonConfig {
	/// Pinned runtime versions.
	/// e.g., `{"node": ">=22.0.0", "deno": ">=2.0.0"}`
	#[serde(default)]
	pub runtime: HashMap<String, String>,

	/// Env file mapping per script name.
	/// e.g., `{"dev": ".env.development", "staging": ".env.staging"}`
	#[serde(default)]
	pub env: HashMap<String, String>,

	/// Task configuration for caching, dependency ordering, and outputs.
	#[serde(default)]
	pub tasks: HashMap<String, TaskConfig>,

	/// Pinned tool plugin versions.
	/// e.g., `{"oxlint": "1.57.0", "biome": "2.4.8"}`
	#[serde(default)]
	pub tools: HashMap<String, String>,
}

/// Configuration for a single task in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TaskConfig {
	/// Command to run (overrides package.json scripts).
	#[serde(default)]
	pub command: Option<String>,

	/// Task dependencies. `"build"` = same package, `"^build"` = upstream workspace deps.
	#[serde(default, rename = "dependsOn")]
	pub depends_on: Vec<String>,

	/// Enable local task caching for this task.
	#[serde(default)]
	pub cache: bool,

	/// Output file globs to cache (e.g., `["dist/**"]`). Required for caching.
	#[serde(default)]
	pub outputs: Vec<String>,

	/// Input file globs that invalidate cache (default: `["src/**", "package.json"]`).
	#[serde(default)]
	pub inputs: Vec<String>,

	/// Env mode for this task (e.g., `"development"` → loads `.env.development`).
	#[serde(default)]
	pub env: Option<String>,
}

impl TaskConfig {
	/// Get the effective inputs globs (defaults to common source dirs if empty).
	pub fn effective_inputs(&self) -> Vec<String> {
		if self.inputs.is_empty() {
			vec![
				"src/**".into(),
				"lib/**".into(),
				"app/**".into(),
				"pages/**".into(),
				"components/**".into(),
				"package.json".into(),
			]
		} else {
			self.inputs.clone()
		}
	}

	/// Whether this task has upstream dependencies (`^` prefix).
	pub fn has_upstream_deps(&self) -> bool {
		self.depends_on.iter().any(|d| d.starts_with('^'))
	}

	/// Get upstream task names (strips `^` prefix).
	pub fn upstream_tasks(&self) -> Vec<&str> {
		self.depends_on
			.iter()
			.filter_map(|d| d.strip_prefix('^'))
			.collect()
	}

	/// Get same-package task dependencies (no `^` prefix).
	pub fn local_deps(&self) -> Vec<&str> {
		self.depends_on
			.iter()
			.filter(|d| !d.starts_with('^'))
			.map(|d| d.as_str())
			.collect()
	}
}

/// Read `lpm.json` from a project directory.
///
/// Returns `None` if the file doesn't exist (not an error).
/// Returns `Err` if the file exists but is malformed.
pub fn read_lpm_json(project_dir: &Path) -> Result<Option<LpmJsonConfig>, String> {
	let path = project_dir.join("lpm.json");
	if !path.exists() {
		return Ok(None);
	}

	let content = std::fs::read_to_string(&path)
		.map_err(|e| format!("failed to read lpm.json: {e}"))?;

	let config: LpmJsonConfig = serde_json::from_str(&content)
		.map_err(|e| format!("failed to parse lpm.json: {e}"))?;

	Ok(Some(config))
}

/// Resolve the `.env` file path for a given script name.
///
/// Checks `lpm.json` `env` mapping first. Returns the mapped file name
/// (e.g., `"dev"` → `".env.development"`) or `None` if no mapping exists.
pub fn resolve_env_mode(config: &LpmJsonConfig, script_name: &str) -> Option<String> {
	config.env.get(script_name).cloned()
}

/// Extract the env mode from a `.env.{mode}` filename.
///
/// e.g., `.env.development` → `Some("development")`
/// e.g., `.env` → `None`
pub fn extract_mode_from_env_path(env_path: &str) -> Option<&str> {
	env_path.strip_prefix(".env.")
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn read_missing_lpm_json() {
		let dir = tempfile::tempdir().unwrap();
		let result = read_lpm_json(dir.path()).unwrap();
		assert!(result.is_none());
	}

	#[test]
	fn read_minimal_lpm_json() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("lpm.json"), "{}").unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert!(config.runtime.is_empty());
		assert!(config.env.is_empty());
	}

	#[test]
	fn read_full_lpm_json() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{
				"runtime": { "node": ">=22.0.0" },
				"env": {
					"dev": ".env.development",
					"staging": ".env.staging",
					"prod": ".env.production"
				}
			}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert_eq!(config.runtime.get("node").unwrap(), ">=22.0.0");
		assert_eq!(config.env.get("dev").unwrap(), ".env.development");
		assert_eq!(config.env.len(), 3);
	}

	#[test]
	fn resolve_env_mode_found() {
		let config = LpmJsonConfig {
			runtime: HashMap::new(),
			env: [("dev".into(), ".env.development".into())].into(),
			tasks: HashMap::new(),
			tools: HashMap::new(),
		};
		assert_eq!(
			resolve_env_mode(&config, "dev"),
			Some(".env.development".into())
		);
	}

	#[test]
	fn resolve_env_mode_not_found() {
		let config = LpmJsonConfig::default();
		assert_eq!(resolve_env_mode(&config, "dev"), None);
	}

	#[test]
	fn extract_mode_from_path() {
		assert_eq!(extract_mode_from_env_path(".env.development"), Some("development"));
		assert_eq!(extract_mode_from_env_path(".env.staging"), Some("staging"));
		assert_eq!(extract_mode_from_env_path(".env"), None);
	}

	#[test]
	fn read_lpm_json_with_tasks() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{
				"tasks": {
					"build": {
						"dependsOn": ["^build"],
						"cache": true,
						"outputs": ["dist/**"],
						"inputs": ["src/**", "package.json"]
					},
					"dev": {
						"command": "vite dev",
						"env": "development"
					},
					"test": {
						"cache": true
					}
				}
			}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert_eq!(config.tasks.len(), 3);

		let build = &config.tasks["build"];
		assert!(build.cache);
		assert_eq!(build.outputs, vec!["dist/**"]);
		assert_eq!(build.depends_on, vec!["^build"]);
		assert!(build.has_upstream_deps());
		assert_eq!(build.upstream_tasks(), vec!["build"]);

		let dev = &config.tasks["dev"];
		assert_eq!(dev.command.as_deref(), Some("vite dev"));
		assert_eq!(dev.env.as_deref(), Some("development"));
		assert!(!dev.cache);
	}

	#[test]
	fn task_config_effective_inputs_default() {
		let t = TaskConfig::default();
		let inputs = t.effective_inputs();
		assert!(inputs.contains(&"src/**".to_string()));
		assert!(inputs.contains(&"package.json".to_string()));
	}

	#[test]
	fn task_config_effective_inputs_custom() {
		let t = TaskConfig {
			inputs: vec!["custom/**".into()],
			..Default::default()
		};
		let inputs = t.effective_inputs();
		assert_eq!(inputs, vec!["custom/**"]);
	}

	#[test]
	fn task_config_dep_parsing() {
		let t = TaskConfig {
			depends_on: vec!["^build".into(), "lint".into(), "^test".into()],
			..Default::default()
		};
		assert!(t.has_upstream_deps());
		assert_eq!(t.upstream_tasks(), vec!["build", "test"]);
		assert_eq!(t.local_deps(), vec!["lint"]);
	}
}
