//! Monorepo/workspace discovery and filtering for LPM.
//!
//! Detects workspace configurations from:
//! - `package.json` `"workspaces"` field (npm/yarn)
//! - `pnpm-workspace.yaml`
//!
//! Discovers member packages and reads their package.json for dependencies.
//!
//! Remaining: `workspace:*` protocol, catalogs. See phase-17-todo.md and phase-20-todo.md.
//! `--filter` and workspace-aware `run` already implemented (Phase 13).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A discovered workspace root with its member packages.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// Path to the workspace root (where the root package.json lives).
    pub root: PathBuf,
    /// Root package.json data.
    pub root_package: PackageJson,
    /// Discovered member packages.
    pub members: Vec<WorkspaceMember>,
}

/// A single workspace member package.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Path to the member's directory.
    pub path: PathBuf,
    /// Parsed package.json.
    pub package: PackageJson,
}

/// Minimal package.json fields needed for dependency resolution.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageJson {
    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// npm overrides / yarn resolutions — force specific versions for transitive deps.
    #[serde(default)]
    pub overrides: HashMap<String, String>,

    /// Yarn-style resolutions (same purpose as overrides).
    #[serde(default)]
    pub resolutions: HashMap<String, String>,

    #[serde(default)]
    pub workspaces: Option<WorkspacesConfig>,

    /// LPM-specific config section (decided: config goes in package.json "lpm" key).
    #[serde(default)]
    pub lpm: Option<LpmConfig>,

    /// Engine version constraints (e.g., `{"node": ">=22.0.0"}`).
    #[serde(default)]
    pub engines: HashMap<String, String>,

    /// Scripts defined in package.json (e.g., "build": "tsup", "dev": "vite dev").
    #[serde(default)]
    pub scripts: HashMap<String, String>,

    /// Binary executables exposed by this package.
    #[serde(default)]
    pub bin: Option<BinConfig>,

    /// Centralized version catalogs for monorepos.
    /// Root defines versions, members use `"catalog:"` or `"catalog:{name}"`.
    ///
    /// Example:
    /// ```json
    /// {
    ///   "catalogs": {
    ///     "default": { "react": "^18.2.0", "react-dom": "^18.2.0" },
    ///     "testing": { "jest": "^29.0.0", "vitest": "^1.0.0" }
    ///   }
    /// }
    /// ```
    #[serde(default)]
    pub catalogs: HashMap<String, HashMap<String, String>>,
}

/// The `"bin"` field in package.json can be a string or an object.
///
/// - String form: `"bin": "./cli.js"` — name defaults to package name
/// - Object form: `"bin": { "my-cmd": "./cli.js", "other": "./other.js" }`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BinConfig {
    /// Single binary: `"bin": "./cli.js"` — command name = package name.
    Single(String),
    /// Multiple binaries: `"bin": { "cmd": "./path.js" }`.
    Map(HashMap<String, String>),
}

impl BinConfig {
    /// Resolve bin entries into (command_name, script_path) pairs.
    /// For the `Single` variant, `package_name` is used as the command name.
    pub fn entries(&self, package_name: &str) -> Vec<(String, String)> {
        match self {
            BinConfig::Single(path) => {
                if path.is_empty() {
                    return Vec::new();
                }
                // Strip scope from package name for bin command name
                // e.g., "@scope/foo" → "foo"
                let cmd_name = package_name
                    .rsplit('/')
                    .next()
                    .unwrap_or(package_name);
                vec![(cmd_name.to_string(), path.clone())]
            }
            BinConfig::Map(map) => {
                map.iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }
        }
    }
}

/// Workspaces field can be an array of globs or an object with "packages" field.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum WorkspacesConfig {
    /// Simple array of glob patterns: `["packages/*", "apps/*"]`
    Globs(Vec<String>),
    /// Object form: `{ "packages": ["packages/*"] }`
    Object { packages: Vec<String> },
}

/// LPM-specific config in package.json `"lpm"` key.
#[derive(Debug, Clone, Deserialize)]
pub struct LpmConfig {
    /// Dependency isolation strictness: "strict", "warn", or "loose".
    #[serde(default, rename = "strictDeps")]
    pub strict_deps: Option<String>,

    /// node_modules linker mode: "symlink" or "hoisted".
    #[serde(default)]
    pub linker: Option<String>,

    /// Packages trusted to run lifecycle scripts (postinstall, etc).
    #[serde(default, rename = "trustedDependencies")]
    pub trusted_dependencies: Vec<String>,

    /// Minimum release age in seconds before install is allowed (default: 86400 = 24h).
    #[serde(default, rename = "minimumReleaseAge")]
    pub minimum_release_age: Option<u64>,
}

/// Discover the workspace from a starting directory.
///
/// Walks up from `start_dir` looking for a root package.json with workspaces,
/// or a pnpm-workspace.yaml.
///
/// Returns `None` if no workspace root is found (single-package project).
pub fn discover_workspace(start_dir: &Path) -> Result<Option<Workspace>, WorkspaceError> {
    let mut current = start_dir.to_path_buf();

    loop {
        let pkg_json_path = current.join("package.json");
        if pkg_json_path.exists() {
            let root_package = read_package_json(&pkg_json_path)?;

            // Check for workspace globs in package.json
            let workspace_globs = match &root_package.workspaces {
                Some(WorkspacesConfig::Globs(globs)) => Some(globs.clone()),
                Some(WorkspacesConfig::Object { packages }) => Some(packages.clone()),
                None => None,
            };

            // Also check for pnpm-workspace.yaml
            let pnpm_workspace_path = current.join("pnpm-workspace.yaml");
            let pnpm_globs = if pnpm_workspace_path.exists() {
                read_pnpm_workspace(&pnpm_workspace_path)?
            } else {
                None
            };

            let globs = workspace_globs.or(pnpm_globs);

            if let Some(globs) = globs {
                let members = discover_members(&current, &globs)?;
                return Ok(Some(Workspace {
                    root: current,
                    root_package,
                    members,
                }));
            }

            // Found a package.json but no workspaces — this is the project root
            // (single-package, no workspace)
            return Ok(None);
        }

        // Walk up to parent
        if !current.pop() {
            break;
        }
    }

    Ok(None)
}

/// Read and parse a package.json file.
pub fn read_package_json(path: &Path) -> Result<PackageJson, WorkspaceError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| WorkspaceError::Io(format!("failed to read {}: {e}", path.display())))?;

    serde_json::from_str(&content)
        .map_err(|e| WorkspaceError::Parse(format!("failed to parse {}: {e}", path.display())))
}

/// Read pnpm-workspace.yaml and extract package globs.
fn read_pnpm_workspace(path: &Path) -> Result<Option<Vec<String>>, WorkspaceError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| WorkspaceError::Io(format!("failed to read {}: {e}", path.display())))?;

    // pnpm-workspace.yaml is simple enough to parse with basic string matching
    // rather than pulling in a full YAML parser.
    // Format: packages:\n  - "glob1"\n  - "glob2"
    let mut packages = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if in_packages {
            if let Some(rest) = trimmed.strip_prefix("- ") {
                let glob = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !glob.is_empty() {
                    packages.push(glob);
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                // New top-level key, stop parsing packages
                break;
            }
        }
    }

    if packages.is_empty() {
        Ok(None)
    } else {
        Ok(Some(packages))
    }
}

/// Discover workspace member packages matching the given glob patterns.
fn discover_members(
    root: &Path,
    globs: &[String],
) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let mut members = Vec::new();

    for pattern in globs {
        // Resolve glob pattern relative to workspace root
        let full_pattern = root.join(pattern).join("package.json");
        let pattern_str = full_pattern.to_string_lossy().to_string();

        let paths = glob::glob(&pattern_str)
            .map_err(|e| WorkspaceError::Parse(format!("invalid glob pattern '{pattern}': {e}")))?;

        for entry in paths {
            let pkg_json_path = entry.map_err(|e| {
                WorkspaceError::Io(format!("glob error: {e}"))
            })?;

            let member_dir = pkg_json_path.parent().unwrap().to_path_buf();
            let package = read_package_json(&pkg_json_path)?;

            members.push(WorkspaceMember {
                path: member_dir,
                package,
            });
        }
    }

    // Sort by path for deterministic ordering
    members.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(members)
}

/// Collect all production dependencies across the workspace.
///
/// Merges root + member dependencies. For overlapping deps, the root's
/// version range takes precedence.
pub fn collect_all_dependencies(workspace: &Workspace) -> HashMap<String, String> {
    let mut all_deps: HashMap<String, String> = HashMap::new();

    // Members first (root overrides)
    for member in &workspace.members {
        for (name, range) in &member.package.dependencies {
            all_deps.insert(name.clone(), range.clone());
        }
    }

    // Root overrides members
    for (name, range) in &workspace.root_package.dependencies {
        all_deps.insert(name.clone(), range.clone());
    }

    all_deps
}

/// Resolve `workspace:*`, `workspace:^`, `workspace:~` protocol in dependencies.
///
/// Replaces workspace protocol references with actual versions from workspace members.
/// Must be called before passing dependencies to the resolver.
///
/// # Examples
/// - `"workspace:*"` → `"1.2.3"` (exact version of the workspace member)
/// - `"workspace:^"` → `"^1.2.3"` (caret range)
/// - `"workspace:~"` → `"~1.2.3"` (tilde range)
///
/// Returns a list of (package_name, original_protocol, resolved_version) for logging.
pub fn resolve_workspace_protocol(
	deps: &mut HashMap<String, String>,
	workspace: &Workspace,
) -> Vec<(String, String, String)> {
	let mut resolved = Vec::new();

	// Build member name → version mapping
	let member_versions: HashMap<&str, &str> = workspace
		.members
		.iter()
		.filter_map(|m| {
			let name = m.package.name.as_deref()?;
			let version = m.package.version.as_deref().unwrap_or("0.0.0");
			Some((name, version))
		})
		.collect();

	for (name, range) in deps.iter_mut() {
		if !range.starts_with("workspace:") {
			continue;
		}

		let protocol = &range["workspace:".len()..];

		if let Some(&member_version) = member_versions.get(name.as_str()) {
			let original = range.clone();
			*range = match protocol {
				"*" | "" => member_version.to_string(),
				"^" => format!("^{member_version}"),
				"~" => format!("~{member_version}"),
				exact => {
					// workspace:1.2.3 → treat as exact version
					exact.to_string()
				}
			};
			resolved.push((name.clone(), original, range.clone()));
		}
		// If member not found, leave as-is — resolver will error on unknown range
	}

	resolved
}

/// Resolve `catalog:` and `catalog:{name}` protocol references in dependencies.
///
/// - `"catalog:"` resolves from `catalogs["default"]`
/// - `"catalog:testing"` resolves from `catalogs["testing"]`
///
/// Must be called before passing dependencies to the resolver.
///
/// Returns a list of `(package_name, original_protocol, resolved_version)` for logging.
pub fn resolve_catalog_protocol(
	deps: &mut HashMap<String, String>,
	catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<Vec<(String, String, String)>, String> {
	let mut resolved = Vec::new();

	for (name, range) in deps.iter_mut() {
		if !range.starts_with("catalog:") {
			continue;
		}

		let catalog_ref = &range["catalog:".len()..];
		let catalog_name = if catalog_ref.is_empty() {
			"default"
		} else {
			catalog_ref
		};

		let catalog = catalogs.get(catalog_name).ok_or_else(|| {
			let available = if catalogs.is_empty() {
				"(none)".to_string()
			} else {
				let mut keys: Vec<&str> = catalogs.keys().map(|s| s.as_str()).collect();
				keys.sort();
				keys.join(", ")
			};
			format!(
				"catalog '{}' not found for dependency '{}'. Available catalogs: {}",
				catalog_name, name, available
			)
		})?;

		let version = catalog.get(name.as_str()).ok_or_else(|| {
			let available = if catalog.is_empty() {
				"(none)".to_string()
			} else {
				let mut keys: Vec<&str> = catalog.keys().map(|s| s.as_str()).collect();
				keys.sort();
				keys.join(", ")
			};
			format!(
				"dependency '{}' not found in catalog '{}'. Available: {}",
				name, catalog_name, available
			)
		})?;

		let original = range.clone();
		*range = version.clone();
		resolved.push((name.clone(), original, range.clone()));
	}

	Ok(resolved)
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn read_simple_package_json() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "@lpm.dev/neo.highlight": "^1.0.0",
                    "react": "^19.0.0"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        assert_eq!(pkg.name.as_deref(), Some("my-app"));
        assert_eq!(pkg.dependencies.len(), 2);
        assert_eq!(pkg.dependencies.get("react").unwrap(), "^19.0.0");
    }

    #[test]
    fn read_package_json_with_lpm_config() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "lpm": {
                    "strictDeps": "strict",
                    "linker": "symlink"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.strict_deps.as_deref(), Some("strict"));
        assert_eq!(lpm.linker.as_deref(), Some("symlink"));
    }

    #[test]
    fn discover_no_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name": "single-package", "dependencies": {}}"#,
        );

        let result = discover_workspace(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn discover_npm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        // Create a member package
        let member_dir = dir.path().join("packages/my-lib");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "@lpm.dev/test.my-lib", "dependencies": {"react": "^19.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(
            ws.members[0].package.name.as_deref(),
            Some("@lpm.dev/test.my-lib")
        );
    }

    #[test]
    fn discover_workspace_object_form() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": { "packages": ["apps/*"] }
            }"#,
        );

        let app_dir = dir.path().join("apps/web");
        fs::create_dir_all(&app_dir).unwrap();
        create_package_json(&app_dir, r#"{"name": "web"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn discover_pnpm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name": "monorepo"}"#);

        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n",
        )
        .unwrap();

        let member_dir = dir.path().join("packages/utils");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "utils"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn collect_all_deps_merges() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "dependencies": {"shared": "^2.0.0"}
            }"#,
        );

        let member_dir = dir.path().join("packages/a");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "a", "dependencies": {"shared": "^1.0.0", "only-a": "^1.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        let all = collect_all_dependencies(&ws);

        // Root's version wins for "shared"
        assert_eq!(all.get("shared").unwrap(), "^2.0.0");
        // Member-only dep is included
        assert!(all.contains_key("only-a"));
    }
}

#[cfg(test)]
mod workspace_protocol_tests {
    use super::*;

    fn make_workspace(members: Vec<(&str, &str)>) -> Workspace {
        let root = std::path::PathBuf::from("/test");
        let root_package = PackageJson {
            name: Some("root".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let members = members
            .into_iter()
            .map(|(name, version)| WorkspaceMember {
                path: root.join(format!("packages/{name}")),
                package: PackageJson {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    ..Default::default()
                },
            })
            .collect();
        Workspace {
            root,
            root_package,
            members,
        }
    }

    #[test]
    fn workspace_star_resolves_to_exact() {
        let ws = make_workspace(vec![("@scope/ui", "2.3.1")]);
        let mut deps = HashMap::from([("@scope/ui".to_string(), "workspace:*".to_string())]);
        let resolved = resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["@scope/ui"], "2.3.1");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn workspace_caret() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:^".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["utils"], "^1.0.0");
    }

    #[test]
    fn workspace_tilde() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:~".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["utils"], "~1.0.0");
    }

    #[test]
    fn workspace_missing_member_unchanged() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("missing".to_string(), "workspace:*".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["missing"], "workspace:*"); // unchanged
    }

    #[test]
    fn non_workspace_deps_unchanged() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("utils".to_string(), "workspace:*".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["utils"], "1.0.0"); // resolved
    }

    #[test]
    fn multiple_members() {
        let ws = make_workspace(vec![("@scope/ui", "2.0.0"), ("@scope/utils", "1.5.0")]);
        let mut deps = HashMap::from([
            ("@scope/ui".to_string(), "workspace:^".to_string()),
            ("@scope/utils".to_string(), "workspace:~".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["@scope/ui"], "^2.0.0");
        assert_eq!(deps["@scope/utils"], "~1.5.0");
    }

    #[test]
    fn workspace_empty_protocol_resolves_to_exact() {
        let ws = make_workspace(vec![("utils", "3.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["utils"], "3.0.0");
    }

    #[test]
    fn workspace_explicit_version() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:1.2.3".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["utils"], "1.2.3"); // exact passthrough
    }

    #[test]
    fn member_without_version_defaults_to_0_0_0() {
        let root = std::path::PathBuf::from("/test");
        let ws = Workspace {
            root: root.clone(),
            root_package: PackageJson {
                name: Some("root".to_string()),
                ..Default::default()
            },
            members: vec![WorkspaceMember {
                path: root.join("packages/no-ver"),
                package: PackageJson {
                    name: Some("no-ver".to_string()),
                    version: None,
                    ..Default::default()
                },
            }],
        };
        let mut deps = HashMap::from([("no-ver".to_string(), "workspace:*".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws);
        assert_eq!(deps["no-ver"], "0.0.0");
    }
}

#[cfg(test)]
mod catalog_protocol_tests {
    use super::*;

    #[test]
    fn catalog_default_resolves() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
    }

    #[test]
    fn catalog_named_resolves() {
        let mut deps = HashMap::from([("jest".to_string(), "catalog:testing".to_string())]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["jest"], "^29.0.0");
    }

    #[test]
    fn catalog_missing_catalog_errors() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:nonexistent".to_string())]);
        let catalogs = HashMap::new();
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("catalog 'nonexistent' not found"));
    }

    #[test]
    fn catalog_missing_entry_errors() {
        let mut deps = HashMap::from([("vue".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("dependency 'vue' not found in catalog"));
    }

    #[test]
    fn non_catalog_deps_unchanged() {
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["jest"], "^29.0.0"); // resolved
    }

    #[test]
    fn catalog_returns_resolved_log() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([
            (
                "default".to_string(),
                HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
            ),
            (
                "testing".to_string(),
                HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
            ),
        ]);
        let resolved = resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn catalog_multiple_entries_in_default() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("react-dom".to_string(), "catalog:".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([
                ("react".to_string(), "^18.2.0".to_string()),
                ("react-dom".to_string(), "^18.2.0".to_string()),
            ]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
        assert_eq!(deps["react-dom"], "^18.2.0");
    }
}

#[cfg(test)]
mod bin_config_tests {
    use super::*;

    #[test]
    fn test_bin_config_single() {
        let json = r#"{"bin": "./cli.js"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let bin = pkg.bin.unwrap();
        assert!(matches!(bin, BinConfig::Single(ref p) if p == "./cli.js"));
        let entries = bin.entries("mypackage");
        assert_eq!(entries, vec![("mypackage".to_string(), "./cli.js".to_string())]);
    }

    #[test]
    fn test_bin_config_map() {
        let json = r#"{"bin": {"cmd1": "./a.js", "cmd2": "./b.js"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let bin = pkg.bin.unwrap();
        assert!(matches!(bin, BinConfig::Map(_)));
        let mut entries = bin.entries("ignored");
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("cmd1".to_string(), "./a.js".to_string()));
        assert_eq!(entries[1], ("cmd2".to_string(), "./b.js".to_string()));
    }

    #[test]
    fn test_bin_config_scoped_package() {
        let bin = BinConfig::Single("./cli.js".to_string());
        let entries = bin.entries("@scope/pkg");
        assert_eq!(entries, vec![("pkg".to_string(), "./cli.js".to_string())]);
    }

    #[test]
    fn test_bin_config_missing() {
        let json = r#"{"name": "no-bin"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert!(pkg.bin.is_none());
    }

    #[test]
    fn test_bin_config_single_empty_path_filtered() {
        let bin = BinConfig::Single("".to_string());
        let entries = bin.entries("pkg");
        assert!(entries.is_empty(), "empty path should be filtered out, got: {:?}", entries);
    }

    #[test]
    fn test_bin_config_map_empty_path_filtered() {
        let bin = BinConfig::Map(HashMap::from([
            ("valid".to_string(), "./ok.js".to_string()),
            ("empty".to_string(), "".to_string()),
        ]));
        let entries = bin.entries("pkg");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ("valid".to_string(), "./ok.js".to_string()));
    }
}

#[cfg(test)]
mod package_json_field_tests {
    use super::*;

    #[test]
    fn test_scripts_deserialization() {
        let json = r#"{"scripts": {"build": "tsc", "test": "vitest"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.scripts.len(), 2);
        assert_eq!(pkg.scripts.get("build").unwrap(), "tsc");
        assert_eq!(pkg.scripts.get("test").unwrap(), "vitest");
    }

    #[test]
    fn test_trusted_dependencies() {
        let json = r#"{"lpm": {"trustedDependencies": ["pkg-a"]}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.trusted_dependencies, vec!["pkg-a".to_string()]);
    }

    #[test]
    fn test_minimum_release_age() {
        let json = r#"{"lpm": {"minimumReleaseAge": 86400}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.minimum_release_age, Some(86400u64));
    }
}
