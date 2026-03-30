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

	/// Dev services for multi-process orchestration.
	/// e.g., `{"web": {"command": "next dev", "port": 3000}}`
	#[serde(default)]
	pub services: HashMap<String, ServiceConfig>,

	/// Tunnel configuration for `lpm dev --tunnel`.
	/// e.g., `{"domain": "acme-api.lpm.llc"}`
	#[serde(default)]
	pub tunnel: Option<TunnelConfig>,

	/// Publish configuration for multi-registry publishing.
	/// e.g., `{"registries": ["lpm", "npm"], "npm": {"name": "@scope/pkg"}}`
	#[serde(default)]
	pub publish: Option<PublishConfig>,
}

/// Tunnel configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TunnelConfig {
	/// Full tunnel domain (e.g., "acme-api.lpm.llc").
	/// Pro/Org only — free users get ephemeral random domains.
	#[serde(default)]
	pub domain: Option<String>,
}

/// Publish configuration in `lpm.json`.
///
/// Controls which registries `lpm publish` targets and per-registry settings.
/// CLI flags (`--npm`, `--lpm`) override these values.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PublishConfig {
	/// Target registries. e.g., `["lpm", "npm"]`.
	/// If absent, defaults to `["lpm"]` (backward compatible).
	#[serde(default)]
	pub registries: Vec<String>,

	/// LPM registry publish settings.
	#[serde(default)]
	pub lpm: Option<LpmPublishConfig>,

	/// npm-specific publish settings.
	#[serde(default)]
	pub npm: Option<NpmPublishConfig>,

	/// GitHub Packages publish settings.
	#[serde(default)]
	pub github: Option<GithubPublishConfig>,

	/// GitLab Packages publish settings.
	#[serde(default)]
	pub gitlab: Option<GitlabPublishConfig>,
}

/// LPM registry publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LpmPublishConfig {
	/// Override package name for LPM (must be `@lpm.dev/owner.pkg` format).
	#[serde(default)]
	pub name: Option<String>,
}

/// npm-specific publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NpmPublishConfig {
	/// Override package name for npm (e.g., `"@scope/pkg"`).
	/// Required if the package.json name starts with `@lpm.dev/`.
	#[serde(default)]
	pub name: Option<String>,

	/// Access level: `"public"` or `"restricted"`.
	/// Scoped packages default to `"restricted"`, unscoped to `"public"`.
	#[serde(default)]
	pub access: Option<String>,

	/// dist-tag for the published version (default: `"latest"`).
	#[serde(default)]
	pub tag: Option<String>,

	/// Custom npm registry URL (default: `https://registry.npmjs.org`).
	#[serde(default)]
	pub registry: Option<String>,

	/// Prompt for OTP before the first publish attempt (saves a round-trip).
	#[serde(default)]
	pub otp_required: Option<bool>,
}

/// GitHub Packages publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubPublishConfig {
	/// Override package name for GitHub Packages (must be scoped: `@owner/pkg`).
	#[serde(default)]
	pub name: Option<String>,

	/// Access level: `"public"` or `"restricted"`.
	#[serde(default)]
	pub access: Option<String>,
}

/// GitLab Packages publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitlabPublishConfig {
	/// Override package name for GitLab Packages.
	#[serde(default)]
	pub name: Option<String>,

	/// Access level: `"public"` or `"restricted"`.
	#[serde(default)]
	pub access: Option<String>,

	/// GitLab project ID (required for GitLab npm registry URL).
	pub project_id: Option<String>,

	/// GitLab instance URL (default: `https://gitlab.com`).
	#[serde(default)]
	pub registry: Option<String>,
}

/// Configuration for a dev service in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceConfig {
	/// Shell command to run.
	pub command: String,

	/// Port this service listens on (used for env injection, display, and readiness).
	#[serde(default)]
	pub port: Option<u16>,

	/// Services that must be ready before this one starts.
	#[serde(default, rename = "dependsOn")]
	pub depends_on: Vec<String>,

	/// TCP port to check for readiness (defaults to `port` if set).
	#[serde(default, rename = "readyPort")]
	pub ready_port: Option<u16>,

	/// HTTP URL to poll for readiness (2xx = ready).
	#[serde(default, rename = "readyUrl")]
	pub ready_url: Option<String>,

	/// Seconds to wait for readiness (default: 30).
	#[serde(default = "default_ready_timeout", rename = "readyTimeout")]
	pub ready_timeout: u64,

	/// Extra environment variables for this service.
	#[serde(default)]
	pub env: HashMap<String, String>,

	/// Auto-restart on crash with exponential backoff.
	#[serde(default)]
	pub restart: bool,

	/// This is the primary service (receives --https/--tunnel/--network).
	#[serde(default)]
	pub primary: bool,

	/// Working directory relative to project root.
	#[serde(default)]
	pub cwd: Option<String>,
}

fn default_ready_timeout() -> u64 {
	30
}

impl ServiceConfig {
	/// Get the port to use for readiness checking.
	/// Priority: readyPort > port > None
	pub fn effective_ready_port(&self) -> Option<u16> {
		self.ready_port.or(self.port)
	}
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
	/// Get the effective inputs globs (defaults to common source dirs + config files if empty).
	pub fn effective_inputs(&self) -> Vec<String> {
		if self.inputs.is_empty() {
			vec![
				"src/**".into(),
				"lib/**".into(),
				"app/**".into(),
				"pages/**".into(),
				"components/**".into(),
				"package.json".into(),
				"tsconfig.json".into(),
				"tsconfig.*.json".into(),
				"*.config.js".into(),
				"*.config.ts".into(),
				"*.config.mjs".into(),
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
	///
	/// Filters out malformed entries: bare `"^"` (empty after strip) and
	/// double-prefixed `"^^build"` (still starts with `^` after strip).
	pub fn upstream_tasks(&self) -> Vec<&str> {
		self.depends_on
			.iter()
			.filter_map(|d| d.strip_prefix('^'))
			.filter(|d| !d.is_empty() && !d.starts_with('^'))
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
			services: HashMap::new(),
			tunnel: None,
			publish: None,
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
	fn read_lpm_json_with_services() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{
				"services": {
					"web": {
						"command": "next dev",
						"port": 3000
					},
					"api": {
						"command": "node server.js",
						"port": 4000,
						"dependsOn": ["db"],
						"env": { "DATABASE_URL": "postgres://localhost:5432/myapp" }
					},
					"db": {
						"command": "docker compose up postgres",
						"readyPort": 5432,
						"readyTimeout": 60
					}
				}
			}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert_eq!(config.services.len(), 3);

		let web = &config.services["web"];
		assert_eq!(web.command, "next dev");
		assert_eq!(web.port, Some(3000));
		assert!(web.depends_on.is_empty());

		let api = &config.services["api"];
		assert_eq!(api.command, "node server.js");
		assert_eq!(api.depends_on, vec!["db"]);
		assert_eq!(api.env.get("DATABASE_URL").unwrap(), "postgres://localhost:5432/myapp");

		let db = &config.services["db"];
		assert_eq!(db.ready_port, Some(5432));
		assert_eq!(db.ready_timeout, 60);
		assert_eq!(db.effective_ready_port(), Some(5432));
	}

	#[test]
	fn service_config_defaults() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{"services": {"web": {"command": "npm run dev"}}}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		let web = &config.services["web"];
		assert_eq!(web.port, None);
		assert!(web.depends_on.is_empty());
		assert!(!web.restart);
		assert!(!web.primary);
		assert_eq!(web.ready_timeout, 30);
		assert_eq!(web.effective_ready_port(), None);
	}

	#[test]
	fn read_lpm_json_with_tunnel() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{"tunnel": {"domain": "acme-api.lpm.llc"}}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		let tunnel = config.tunnel.unwrap();
		assert_eq!(tunnel.domain.as_deref(), Some("acme-api.lpm.llc"));
	}

	#[test]
	fn read_lpm_json_no_tunnel() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("lpm.json"), r#"{"runtime":{"node":"22"}}"#).unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert!(config.tunnel.is_none());
	}

	#[test]
	fn read_lpm_json_invalid_json_returns_err() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("lpm.json"), "{ invalid json !!!").unwrap();

		let result = read_lpm_json(dir.path());
		assert!(result.is_err(), "malformed lpm.json should return Err, not be silently swallowed");
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

	// Finding #17: bare "^" and double-prefix "^^build" edge cases
	#[test]
	fn upstream_tasks_filters_bare_caret_and_double_prefix() {
		let t = TaskConfig {
			depends_on: vec![
				"^build".into(),
				"^".into(),        // bare caret → should be filtered out
				"^^test".into(),   // double prefix → should be filtered out
				"lint".into(),     // local dep → not in upstream
			],
			..Default::default()
		};
		assert_eq!(t.upstream_tasks(), vec!["build"]);
	}

	#[test]
	fn read_lpm_json_with_publish_config() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{
				"publish": {
					"registries": ["lpm", "npm"],
					"npm": {
						"name": "@tolga/highlight",
						"access": "public",
						"tag": "latest",
						"registry": "https://registry.npmjs.org",
						"otpRequired": true
					}
				}
			}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		let publish = config.publish.unwrap();
		assert_eq!(publish.registries, vec!["lpm", "npm"]);

		let npm = publish.npm.unwrap();
		assert_eq!(npm.name.as_deref(), Some("@tolga/highlight"));
		assert_eq!(npm.access.as_deref(), Some("public"));
		assert_eq!(npm.tag.as_deref(), Some("latest"));
		assert_eq!(npm.registry.as_deref(), Some("https://registry.npmjs.org"));
		assert_eq!(npm.otp_required, Some(true));
	}

	#[test]
	fn read_lpm_json_publish_config_defaults() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{"publish": {"registries": ["npm"]}}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		let publish = config.publish.unwrap();
		assert_eq!(publish.registries, vec!["npm"]);
		assert!(publish.npm.is_none());
	}

	#[test]
	fn cli_flags_override_lpm_json_config() {
		// Simulates the merge logic: CLI flags take precedence over lpm.json
		let dir = tempfile::tempdir().unwrap();
		fs::write(
			dir.path().join("lpm.json"),
			r#"{"publish": {"registries": ["lpm"]}}"#,
		)
		.unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		let config_registries = config.publish.as_ref().map(|p| &p.registries);

		// CLI --npm flag overrides config
		let cli_npm = true;
		let cli_lpm = false;

		let targets: Vec<&str> = if cli_npm || cli_lpm {
			// CLI flags present — use them, ignore config
			let mut t = Vec::new();
			if cli_lpm {
				t.push("lpm");
			}
			if cli_npm {
				t.push("npm");
			}
			t
		} else if let Some(regs) = config_registries {
			regs.iter().map(|s| s.as_str()).collect()
		} else {
			vec!["lpm"]
		};

		assert_eq!(targets, vec!["npm"], "CLI --npm should override config");
	}

	#[test]
	fn default_to_lpm_when_no_config() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("lpm.json"), r#"{}"#).unwrap();

		let config = read_lpm_json(dir.path()).unwrap().unwrap();
		assert!(config.publish.is_none());
	}

	#[test]
	fn local_deps_filters_bare_caret_and_double_prefix() {
		let t = TaskConfig {
			depends_on: vec![
				"^build".into(),
				"^".into(),        // bare caret → should be filtered out
				"^^test".into(),   // double prefix → should be filtered out
				"lint".into(),
			],
			..Default::default()
		};
		// "^" and "^^test" start with '^' so they are NOT local deps,
		// but they should not appear as valid upstream either.
		// local_deps should only return "lint"
		assert_eq!(t.local_deps(), vec!["lint"]);
	}

	// Finding #18: effective_inputs() should include config files
	#[test]
	fn effective_inputs_includes_config_files() {
		let t = TaskConfig::default();
		let inputs = t.effective_inputs();
		assert!(inputs.contains(&"tsconfig.json".to_string()), "missing tsconfig.json");
		assert!(inputs.contains(&"tsconfig.*.json".to_string()), "missing tsconfig.*.json");
		assert!(inputs.contains(&"*.config.js".to_string()), "missing *.config.js");
		assert!(inputs.contains(&"*.config.ts".to_string()), "missing *.config.ts");
		assert!(inputs.contains(&"*.config.mjs".to_string()), "missing *.config.mjs");
	}
}
