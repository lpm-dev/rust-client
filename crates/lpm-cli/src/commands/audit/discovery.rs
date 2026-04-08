//! Universal package discovery for audit.
//!
//! Discovers packages from any supported lockfile format or by walking
//! `node_modules/` as a fallback. Reuses parsers from `lpm-migrate`.
//!
//! Priority: `lpm.lock` → `package-lock.json` → `pnpm-lock.yaml`
//!           → `yarn.lock` → `node_modules/` walk (degraded mode).

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// How a discovered package can be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Source is present on disk, can be behaviorally analyzed.
    FullLocal,
    /// Package can be queried in OSV but source is unavailable (e.g., Yarn PnP).
    OsvOnly,
    /// @lpm.dev package with registry metadata, source in LPM store.
    RegistryAndStore,
    /// Lockfile says it exists, but source is not present on disk.
    LocalMissing,
}

/// A package discovered during the inventory phase.
#[derive(Debug, Clone)]
#[allow(dead_code)] // is_dev and is_optional used by Phase 31 --fail-on policy
pub struct DiscoveredPackage {
    /// Package name (e.g., "react", "@scope/name", "@lpm.dev/owner.pkg").
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Path relative to project root (e.g., "node_modules/react").
    /// For LPM store packages this is the lockfile key.
    pub path: String,
    /// SRI integrity hash from the lockfile (e.g., "sha512-...").
    pub integrity: Option<String>,
    /// Tarball resolved URL. Used for private registry detection.
    pub resolved_url: Option<String>,
    /// How this package can be scanned.
    pub scan_mode: ScanMode,
    /// Whether this is a dev dependency.
    pub is_dev: bool,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
    /// Direct dependencies: (name, exact_version).
    /// Extracted from lockfile dependency edges. Used by the query engine
    /// for `>` combinator traversal (e.g., `lpm query :eval > :network`).
    pub dependencies: Vec<(String, String)>,
}

/// Which package manager produced the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerKind {
    Lpm,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    /// No lockfile — walked `node_modules/` directly.
    FallbackNodeModules,
}

impl std::fmt::Display for ManagerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerKind::Lpm => write!(f, "lpm"),
            ManagerKind::Npm => write!(f, "npm"),
            ManagerKind::Pnpm => write!(f, "pnpm"),
            ManagerKind::Yarn => write!(f, "yarn"),
            ManagerKind::Bun => write!(f, "bun"),
            ManagerKind::FallbackNodeModules => write!(f, "node_modules"),
        }
    }
}

/// Result of package discovery.
pub struct DiscoveryResult {
    /// Which package manager was detected.
    pub manager: ManagerKind,
    /// Path to the lockfile (if any).
    pub lockfile_path: Option<PathBuf>,
    /// The project root where the lockfile / node_modules was found.
    pub project_root: PathBuf,
    /// Whether this is degraded mode (no lockfile, weaker identity).
    pub is_degraded: bool,
    /// Whether Yarn PnP was detected (packages are OsvOnly).
    pub is_yarn_pnp: bool,
    /// All discovered packages.
    pub packages: Vec<DiscoveredPackage>,
}

/// Discover all packages in a project.
///
/// Walks up from `start_dir` to find the closest lockfile, then parses it.
/// Falls back to walking `node_modules/` if no lockfile is found.
///
/// Priority:
/// 1. `lpm.lock` always wins (LPM-managed project)
/// 2. For foreign lockfiles, uses `lpm-migrate`'s mtime-based detection
///    (most recently modified lockfile wins when multiple exist)
/// 3. Falls back to walking `node_modules/` (degraded mode)
pub fn discover_packages(start_dir: &Path) -> Result<DiscoveryResult, LpmError> {
    // Walk up to find a lockfile
    let mut current = start_dir.to_path_buf();
    loop {
        // 1. lpm.lock — always highest priority (LPM-managed project)
        if current.join("lpm.lock").exists() {
            return discover_from_lpm_lock(&current);
        }

        // 2. Foreign lockfiles — use lpm-migrate's mtime-based detection.
        // This correctly handles projects with multiple lockfiles by
        // picking the most recently modified one.
        if let Ok(source) = lpm_migrate::detect::detect_source(&current) {
            return match source.kind {
                lpm_migrate::SourceKind::Npm => discover_from_npm_lockfile(&current),
                lpm_migrate::SourceKind::Pnpm => discover_from_pnpm_lockfile(&current),
                lpm_migrate::SourceKind::Yarn => discover_from_yarn_lockfile(&current),
                lpm_migrate::SourceKind::Bun => discover_from_bun_lockfile(&current),
            };
        }

        // Walk up
        if !current.pop() {
            break;
        }
    }

    // No lockfile found — try node_modules/ fallback from start_dir
    let nm_dir = start_dir.join("node_modules");
    if nm_dir.is_dir() {
        return discover_from_node_modules(start_dir);
    }

    Err(LpmError::NotFound(
        "No lockfile or node_modules found. Nothing to audit.".into(),
    ))
}

// ─── LPM lockfile ───────────────────────────────────────────────────────────

fn discover_from_lpm_lock(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let lockfile_path = project_root.join("lpm.lock");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?;

    let packages = lockfile
        .packages
        .iter()
        .map(|p| {
            // All packages in lpm.lock (both @lpm.dev and npm) are in the
            // LPM store at ~/.lpm/store/v1/<name>@<version>/. The store-backed
            // scan uses store.package_dir(name, version), not the path field.

            // Parse dependencies from "name@version" format
            let dependencies = p
                .dependencies
                .iter()
                .filter_map(|dep_ref| {
                    dep_ref
                        .rfind('@')
                        .map(|at| (dep_ref[..at].to_string(), dep_ref[at + 1..].to_string()))
                })
                .collect();

            DiscoveredPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                path: format!("node_modules/{}", p.name),
                integrity: p.integrity.clone(),
                resolved_url: None,
                scan_mode: ScanMode::RegistryAndStore,
                is_dev: false,
                is_optional: false,
                dependencies,
            }
        })
        .collect();

    Ok(DiscoveryResult {
        manager: ManagerKind::Lpm,
        lockfile_path: Some(lockfile_path),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
    })
}

// ─── npm (package-lock.json) ────────────────────────────────────────────────

fn discover_from_npm_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let lockfile_path = project_root.join("package-lock.json");
    let source = lpm_migrate::DetectedSource {
        kind: lpm_migrate::SourceKind::Npm,
        path: lockfile_path.clone(),
        version: detect_npm_lockfile_version(&lockfile_path)?,
    };

    let migrated = lpm_migrate::npm::parse(&source.path, source.version)?;
    let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

    Ok(DiscoveryResult {
        manager: ManagerKind::Npm,
        lockfile_path: Some(lockfile_path),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
    })
}

/// Read `lockfileVersion` from package-lock.json.
fn detect_npm_lockfile_version(path: &Path) -> Result<u32, LpmError> {
    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Registry(format!("invalid package-lock.json: {e}")))?;
    Ok(json
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32)
}

// ─── pnpm (pnpm-lock.yaml) ─────────────────────────────────────────────────

fn discover_from_pnpm_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let lockfile_path = project_root.join("pnpm-lock.yaml");

    // Detect lockfile version
    let version = detect_pnpm_lockfile_version(&lockfile_path);
    let migrated = lpm_migrate::pnpm::parse(&lockfile_path, version)?;
    let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

    Ok(DiscoveryResult {
        manager: ManagerKind::Pnpm,
        lockfile_path: Some(lockfile_path),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
    })
}

fn detect_pnpm_lockfile_version(path: &Path) -> u32 {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines().take(5) {
            if let Some(rest) = line.strip_prefix("lockfileVersion:") {
                let rest = rest.trim().trim_matches('\'').trim_matches('"');
                if let Ok(v) = rest.parse::<f64>() {
                    return v as u32;
                }
            }
        }
    }
    6 // default to latest
}

// ─── yarn (yarn.lock) ───────────────────────────────────────────────────────

fn discover_from_yarn_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let lockfile_path = project_root.join("yarn.lock");

    // Check for Yarn PnP
    let is_yarn_pnp =
        project_root.join(".pnp.cjs").exists() || project_root.join(".pnp.js").exists();

    let migrated = lpm_migrate::yarn::parse(&lockfile_path, project_root)?;

    let packages: Vec<DiscoveredPackage> = if is_yarn_pnp {
        // PnP mode — packages are in zip archives, can't scan source
        migrated
            .iter()
            .map(|p| DiscoveredPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                path: format!("node_modules/{}", p.name),
                integrity: p.integrity.clone(),
                resolved_url: p.resolved.clone(),
                scan_mode: ScanMode::OsvOnly,
                is_dev: p.is_dev,
                is_optional: p.is_optional,
                dependencies: p.dependencies.clone(),
            })
            .collect()
    } else {
        migrated_to_discovered(project_root, &migrated, &lockfile_path)
    };

    Ok(DiscoveryResult {
        manager: ManagerKind::Yarn,
        lockfile_path: Some(lockfile_path),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp,
        packages,
    })
}

// ─── bun (bun.lockb / bun.lock) ────────────────────────────────────────────

fn discover_from_bun_lockfile(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    // bun.lock (text) is parseable; bun.lockb (binary) is not.
    let lockfile_path = if project_root.join("bun.lock").exists() {
        project_root.join("bun.lock")
    } else {
        // bun.lockb is binary — we can't parse it directly.
        // Fall back to node_modules walk if available.
        let nm_dir = project_root.join("node_modules");
        if nm_dir.is_dir() {
            return discover_from_node_modules(project_root);
        }
        return Err(LpmError::NotFound(
            "bun.lockb is a binary lockfile. Run `bun install` to generate \
			 node_modules, then retry lpm audit."
                .into(),
        ));
    };

    let migrated = lpm_migrate::bun::parse(&lockfile_path)?;
    let packages = migrated_to_discovered(project_root, &migrated, &lockfile_path);

    Ok(DiscoveryResult {
        manager: ManagerKind::Bun,
        lockfile_path: Some(lockfile_path),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
    })
}

// ─── node_modules fallback (degraded mode) ──────────────────────────────────

fn discover_from_node_modules(project_root: &Path) -> Result<DiscoveryResult, LpmError> {
    let nm_dir = project_root.join("node_modules");

    // Pass 1: Read all packages and collect unresolved dependency names
    let mut entries: Vec<(DiscoveredPackage, Vec<String>)> = Vec::new();

    if let Ok(dir_entries) = std::fs::read_dir(&nm_dir) {
        for entry in dir_entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden dirs, .package-lock.json, .lpm, etc.
            if name.starts_with('.') {
                continue;
            }

            if name.starts_with('@') {
                // Scoped package — descend one level
                let scope_dir = entry.path();
                if let Ok(scoped_entries) = std::fs::read_dir(&scope_dir) {
                    for scoped_entry in scoped_entries.flatten() {
                        let scoped_name = scoped_entry.file_name().to_string_lossy().to_string();
                        let full_name = format!("{name}/{scoped_name}");
                        if let Some(result) = read_package_from_node_modules(
                            project_root,
                            &scoped_entry.path(),
                            &full_name,
                        ) {
                            entries.push(result);
                        }
                    }
                }
            } else if let Some(result) =
                read_package_from_node_modules(project_root, &entry.path(), &name)
            {
                entries.push(result);
            }
        }
    }

    // Pass 2: Build name → version lookup, then resolve dependency edges
    let version_lookup: std::collections::HashMap<String, String> = entries
        .iter()
        .map(|(pkg, _)| (pkg.name.clone(), pkg.version.clone()))
        .collect();

    let packages = entries
        .into_iter()
        .map(|(mut pkg, dep_names)| {
            pkg.dependencies = dep_names
                .into_iter()
                .filter_map(|dep_name| {
                    version_lookup
                        .get(&dep_name)
                        .map(|ver| (dep_name, ver.clone()))
                })
                .collect();
            pkg
        })
        .collect();

    Ok(DiscoveryResult {
        manager: ManagerKind::FallbackNodeModules,
        lockfile_path: None,
        project_root: project_root.to_path_buf(),
        is_degraded: true,
        is_yarn_pnp: false,
        packages,
    })
}

/// Read a single package's info from its `node_modules/<name>/package.json`.
///
/// Returns the discovered package and its dependency names (unresolved).
/// Dependency versions are resolved in a second pass after all packages
/// have been discovered, using a `name → version` lookup.
fn read_package_from_node_modules(
    project_root: &Path,
    pkg_dir: &Path,
    name: &str,
) -> Option<(DiscoveredPackage, Vec<String>)> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let version = json.get("version")?.as_str()?.to_string();

    let rel_path = pkg_dir.strip_prefix(project_root).ok()?;
    let path = rel_path.to_string_lossy().to_string();

    // Extract dependency names from package.json (versions resolved in second pass)
    let mut dep_names = Vec::new();
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for dep_name in deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }
    if let Some(opt_deps) = json.get("optionalDependencies").and_then(|d| d.as_object()) {
        for dep_name in opt_deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }

    Some((
        DiscoveredPackage {
            name: name.to_string(),
            version,
            path,
            integrity: None,
            resolved_url: None,
            scan_mode: ScanMode::FullLocal,
            is_dev: false,            // Can't determine without lockfile
            is_optional: false,       // Can't determine without lockfile
            dependencies: Vec::new(), // Resolved in second pass
        },
        dep_names,
    ))
}

// ─── Shared conversion ─────────────────────────────────────────────────────

/// Convert `MigratedPackage` entries from lpm-migrate into `DiscoveredPackage`.
///
/// For each package, checks whether the source exists on disk to set ScanMode.
/// Uses lockfile key as the path when available (npm v2/v3), otherwise
/// constructs `node_modules/<name>`.
fn migrated_to_discovered(
    project_root: &Path,
    migrated: &[lpm_migrate::MigratedPackage],
    lockfile_path: &Path,
) -> Vec<DiscoveredPackage> {
    // For npm v2/v3, we need the raw lockfile to get the `packages` keys
    // (which include nested paths like `node_modules/express/node_modules/qs`).
    // The MigratedPackage doesn't carry this, so we parse the raw keys.
    //
    // The multimap handles duplicate (name, version) at different paths:
    // e.g., qs@1.0.0 at both `node_modules/qs` and `node_modules/a/node_modules/qs`.
    // We pop from the front of each vec so each MigratedPackage gets a unique path
    // (both vecs are in lockfile iteration order; stable sort preserves that order).
    let mut raw_paths = parse_npm_package_paths(lockfile_path);

    let mut packages = Vec::with_capacity(migrated.len());

    for mp in migrated {
        // Try to find the exact path from the raw lockfile keys.
        // Pop from front so each instance gets a distinct path.
        let path = raw_paths
            .as_mut()
            .and_then(|paths| {
                let key = format!("{}@{}", mp.name, mp.version);
                let vec = paths.get_mut(&key)?;
                if vec.is_empty() {
                    None
                } else {
                    Some(vec.remove(0))
                }
            })
            .unwrap_or_else(|| format!("node_modules/{}", mp.name));

        let abs_path = project_root.join(&path);
        let scan_mode = if abs_path.is_dir() {
            ScanMode::FullLocal
        } else if mp.is_optional {
            ScanMode::LocalMissing
        } else {
            // Not optional but missing — still mark as missing, don't error
            ScanMode::LocalMissing
        };

        packages.push(DiscoveredPackage {
            name: mp.name.clone(),
            version: mp.version.clone(),
            path,
            integrity: mp.integrity.clone(),
            resolved_url: mp.resolved.clone(),
            scan_mode,
            is_dev: mp.is_dev,
            is_optional: mp.is_optional,
            dependencies: mp.dependencies.clone(),
        });
    }

    packages
}

/// Parse the raw `packages` keys from `package-lock.json` to build
/// a `"name@version" → [paths...]` multimap.
///
/// This gives us the exact nested path for each package instance.
/// Multiple instances of the same `name@version` at different paths
/// (e.g., `node_modules/qs` and `node_modules/a/node_modules/qs`)
/// are all preserved. Paths are in lockfile iteration order.
///
/// Returns None for non-npm lockfiles or parse failures.
fn parse_npm_package_paths(
    lockfile_path: &Path,
) -> Option<std::collections::HashMap<String, Vec<String>>> {
    if !lockfile_path
        .file_name()?
        .to_str()?
        .contains("package-lock")
    {
        return None;
    }

    let content = std::fs::read_to_string(lockfile_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let packages = json.get("packages")?.as_object()?;

    let mut map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::with_capacity(packages.len());

    for (key, value) in packages {
        if key.is_empty() {
            continue;
        }
        // Skip workspace links (symlinks in node_modules/)
        if value.get("link").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }

        // Skip entries without a version (workspace member definitions
        // like "packages/app" are local projects, not installed packages)
        let Some(version) = value.get("version").and_then(|v| v.as_str()) else {
            continue;
        };

        // Extract name from the last `node_modules/` segment in the key.
        // Skip entries without `node_modules/` — these are workspace member
        // paths like "packages/app" that define local projects.
        let prefix = "node_modules/";
        let Some(last_nm) = key.rfind(prefix) else {
            continue;
        };
        let name = &key[last_nm + prefix.len()..];

        map.entry(format!("{name}@{version}"))
            .or_default()
            .push(key.clone());
    }

    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn npm_lockfile_preserves_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "4.22.1"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"express": "4.22.1"}},
					"node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
						"integrity": "sha512-abc",
						"dependencies": {"accepts": "1.3.8", "qs": "6.14.0"}
					},
					"node_modules/accepts": {
						"version": "1.3.8",
						"resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
						"integrity": "sha512-def"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz",
						"integrity": "sha512-ghi"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs so ScanMode is FullLocal
        fs::create_dir_all(dir.path().join("node_modules/express")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/accepts")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Npm);
        assert_eq!(result.packages.len(), 3);

        // Express should have dependency edges to accepts and qs
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );

        // Leaf packages should have no dependencies
        let accepts = result
            .packages
            .iter()
            .find(|p| p.name == "accepts")
            .expect("accepts not found");
        assert!(accepts.dependencies.is_empty());
    }

    #[test]
    fn npm_nested_deps_get_correct_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "6.14.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "6.14.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "6.5.3"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "6.5.3",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.5.3.tgz"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Package "a" should depend on qs@6.5.3 (nested), not qs@6.14.0 (hoisted)
        let a = result
            .packages
            .iter()
            .find(|p| p.name == "a")
            .expect("package a not found");
        assert_eq!(a.dependencies.len(), 1);
        assert_eq!(a.dependencies[0], ("qs".to_string(), "6.5.3".to_string()));
    }

    #[test]
    fn node_modules_fallback_builds_edges() {
        let dir = tempfile::tempdir().unwrap();

        // Create packages in node_modules (no lockfile)
        let express_dir = dir.path().join("node_modules/express");
        fs::create_dir_all(&express_dir).unwrap();
        fs::write(
            express_dir.join("package.json"),
            r#"{"name": "express", "version": "4.22.1", "dependencies": {"qs": "6.14.0"}}"#,
        )
        .unwrap();

        let qs_dir = dir.path().join("node_modules/qs");
        fs::create_dir_all(&qs_dir).unwrap();
        fs::write(
            qs_dir.join("package.json"),
            r#"{"name": "qs", "version": "6.14.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::FallbackNodeModules);
        assert!(result.is_degraded);
        assert_eq!(result.packages.len(), 2);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        // Should resolve edge to qs@6.14.0 from installed version
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("qs".to_string(), "6.14.0".to_string())
        );
    }

    #[test]
    fn lpm_lock_extracts_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.lock"),
            r#"
[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "express"
version = "4.22.1"
dependencies = ["accepts@1.3.8", "qs@6.14.0"]

[[packages]]
name = "accepts"
version = "1.3.8"

[[packages]]
name = "qs"
version = "6.14.0"
"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Lpm);
        assert_eq!(result.packages.len(), 3);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );
    }

    #[test]
    fn node_modules_fallback_unresolved_deps_filtered() {
        let dir = tempfile::tempdir().unwrap();

        // Package depends on "missing-pkg" which isn't installed
        let pkg_dir = dir.path().join("node_modules/my-pkg");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "my-pkg", "version": "1.0.0", "dependencies": {"missing-pkg": "^1.0.0"}}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        let pkg = result
            .packages
            .iter()
            .find(|p| p.name == "my-pkg")
            .expect("my-pkg not found");
        // missing-pkg is not in node_modules, so it should be filtered out
        assert!(pkg.dependencies.is_empty());
    }

    #[test]
    fn cache_stores_and_retrieves_dependencies() {
        let dir = tempfile::tempdir().unwrap();

        let mut cache = super::super::cache::ProjectAuditCache::new("npm");
        let analysis = lpm_security::behavioral::PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "2026-04-08T00:00:00Z".to_string(),
            source: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            meta: Default::default(),
        };
        let deps = vec![
            ("accepts".to_string(), "1.3.8".to_string()),
            ("qs".to_string(), "6.14.0".to_string()),
        ];

        cache.insert(
            "node_modules/express".to_string(),
            "express".to_string(),
            "4.22.1".to_string(),
            Some("sha512-abc".to_string()),
            analysis,
            deps.clone(),
        );

        // Write and read back
        cache.write(dir.path()).unwrap();
        let loaded =
            super::super::cache::ProjectAuditCache::read(dir.path()).expect("cache should load");

        let entry = loaded
            .entries
            .get("node_modules/express")
            .expect("entry should exist");
        assert_eq!(entry.dependencies, deps);
    }

    #[test]
    fn npm_duplicate_name_version_at_different_paths_preserved() {
        // Bug: parse_npm_package_paths keys by name@version, so two instances
        // of qs@1.0.0 at different paths collapse onto one. The second insert
        // overwrites the first, losing a package instance.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "1.0.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "1.0.0"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/a")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Must have 3 packages: a, qs (hoisted), qs (nested under a)
        assert_eq!(
            result.packages.len(),
            3,
            "expected 3 packages, got {}",
            result.packages.len()
        );

        // Both qs instances must have DIFFERENT paths
        let qs_packages: Vec<&DiscoveredPackage> =
            result.packages.iter().filter(|p| p.name == "qs").collect();
        assert_eq!(qs_packages.len(), 2, "expected 2 qs instances");

        let mut paths: Vec<&str> = qs_packages.iter().map(|p| p.path.as_str()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["node_modules/a/node_modules/qs", "node_modules/qs"],
            "qs instances must have distinct paths"
        );
    }

    #[test]
    fn npm_workspace_entries_dont_abort_path_recovery() {
        // Bug: workspace entries like "packages/app" in package-lock.json
        // caused parse_npm_package_paths to return None via ? propagation,
        // losing ALL path recovery for the entire lockfile.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/lodash": {
						"version": "4.17.21",
						"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
					},
					"node_modules/web": {
						"resolved": "packages/web",
						"link": true
					},
					"packages/web": {
						"name": "web",
						"version": "1.0.0",
						"dependencies": {"lodash": "^4.17.0"}
					},
					"packages/web/node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/lodash")).unwrap();
        fs::create_dir_all(dir.path().join("packages/web/node_modules/express")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Should discover qs, lodash, AND express (under workspace member)
        assert!(
            result.packages.len() >= 3,
            "expected at least 3 packages, got {}",
            result.packages.len()
        );

        // Express should have the workspace-nested path
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(
            express.path, "packages/web/node_modules/express",
            "express should have workspace-nested path"
        );
    }
}
