//! npm `package-lock.json` parser.
//!
//! Supports lockfile versions 1, 2, and 3:
//! - v3 (npm 7+): uses `packages` map with `node_modules/` prefixed keys
//! - v2 (npm 6→7 bridge): has both `packages` and `dependencies` — prefers `packages`
//! - v1 (npm 5–6): uses nested `dependencies` tree
//!
//! Two-pass approach:
//! 1. Collect all packages into a lookup map (`name → version`) for dependency resolution
//! 2. Build `MigratedPackage` entries with exact resolved dependency versions

use crate::MigratedPackage;
use lpm_common::LpmError;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

/// Parse an npm `package-lock.json` file from disk.
pub fn parse(path: &Path, lockfile_version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    let content = std::fs::read_to_string(path)?;
    parse_str(&content, lockfile_version)
}

/// Parse npm `package-lock.json` content from a string.
pub fn parse_str(content: &str, lockfile_version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    let json: Value = serde_json::from_str(content)?;

    // v2 and v3 both have "packages" — prefer it over "dependencies"
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        return parse_packages_block(packages);
    }

    // v1 fallback: use "dependencies" block
    if lockfile_version <= 1 {
        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            return parse_dependencies_block(deps);
        }
    }

    Err(LpmError::Script(
        "package-lock.json has no 'packages' or 'dependencies' block".to_string(),
    ))
}

/// Intermediate entry collected during first pass.
struct RawEntry {
    name: String,
    version: String,
    resolved: Option<String>,
    integrity: Option<String>,
    is_optional: bool,
    is_dev: bool,
    /// Dependency names declared by this package (semver ranges, not exact versions).
    dep_names: Vec<String>,
    /// The full key in the packages map (for nested resolution).
    key: String,
}

/// Extract the package name from a `node_modules/...` key.
///
/// Handles:
/// - `"node_modules/express"` → `"express"`
/// - `"node_modules/@scope/pkg"` → `"@scope/pkg"`
/// - `"node_modules/a/node_modules/b"` → `"b"`
/// - `"node_modules/a/node_modules/@scope/pkg"` → `"@scope/pkg"`
fn extract_name_from_key(key: &str) -> Option<String> {
    // Find the last occurrence of "node_modules/"
    let prefix = "node_modules/";
    let last_nm = key.rfind(prefix)?;
    let after = &key[last_nm + prefix.len()..];

    if after.is_empty() {
        return None;
    }

    // If scoped package (@scope/name), include both segments
    if after.starts_with('@') {
        // The name is everything after the last node_modules/
        // e.g., "@scope/pkg" or "@scope/pkg/node_modules/..." (but we already took the last one)
        Some(after.to_string())
    } else {
        // Unscoped: take just the first segment (there shouldn't be more after last node_modules/)
        Some(after.to_string())
    }
}

/// Parse the v2/v3 `packages` block.
fn parse_packages_block(
    packages: &serde_json::Map<String, Value>,
) -> Result<Vec<MigratedPackage>, LpmError> {
    // First pass: collect all entries and build name → version lookup
    let mut entries = Vec::with_capacity(packages.len());
    // name → version (shallowest nesting level preferred)
    let mut version_lookup: HashMap<String, String> = HashMap::with_capacity(packages.len());
    // name → nesting depth (for determining shallowest)
    let mut version_depth: HashMap<String, usize> = HashMap::with_capacity(packages.len());

    for (key, value) in packages {
        // Skip root entry
        if key.is_empty() {
            continue;
        }

        // Skip workspace links
        if value.get("link").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }

        let name = match extract_name_from_key(key) {
            Some(n) => n,
            None => {
                warn!(key, "skipping package-lock entry with unparseable key");
                continue;
            }
        };

        let version = match value.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => {
                warn!(key, "skipping package-lock entry without version");
                continue;
            }
        };

        let resolved = value.get("resolved").and_then(|v| v.as_str()).map(String::from);

        // Skip entries without resolved URL (file: deps, workspace links, etc.)
        if resolved.is_none() {
            continue;
        }

        let integrity = value.get("integrity").and_then(|v| v.as_str()).map(String::from);
        let is_optional = value.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

        // Collect dependency names (from both dependencies and optionalDependencies)
        let mut dep_names = Vec::new();
        if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
            for dep_name in deps.keys() {
                dep_names.push(dep_name.clone());
            }
        }
        if let Some(opt_deps) = value.get("optionalDependencies").and_then(|d| d.as_object()) {
            for dep_name in opt_deps.keys() {
                dep_names.push(dep_name.clone());
            }
        }

        // Build version lookup: prefer shallowest nesting level (root = depth 1)
        let depth = key.matches("node_modules/").count();
        let existing_depth = version_depth.get(&name).copied().unwrap_or(usize::MAX);
        if depth < existing_depth {
            version_lookup.insert(name.clone(), version.clone());
            version_depth.insert(name.clone(), depth);
        }

        entries.push(RawEntry {
            name,
            version,
            resolved,
            integrity,
            is_optional,
            is_dev,
            dep_names,
            key: key.clone(),
        });
    }

    // Second pass: resolve dependency names to exact versions
    let mut result = Vec::with_capacity(entries.len());

    for entry in &entries {
        let mut dependencies = Vec::with_capacity(entry.dep_names.len());

        for dep_name in &entry.dep_names {
            // For nested packages, check the nested path first, then fall back to root
            let dep_version = resolve_dependency_version(
                dep_name,
                &entry.key,
                packages,
                &version_lookup,
            );

            if let Some(ver) = dep_version {
                dependencies.push((dep_name.clone(), ver));
            } else {
                warn!(
                    package = entry.name,
                    dependency = dep_name.as_str(),
                    "could not resolve dependency version"
                );
            }
        }

        // Sort dependencies by name for deterministic output
        dependencies.sort_by(|a, b| a.0.cmp(&b.0));

        result.push(MigratedPackage {
            name: entry.name.clone(),
            version: entry.version.clone(),
            resolved: entry.resolved.clone(),
            integrity: entry.integrity.clone(),
            dependencies,
            is_optional: entry.is_optional,
            is_dev: entry.is_dev,
        });
    }

    // Sort by name then version for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    Ok(result)
}

/// Resolve a dependency's exact version using npm's node_modules resolution algorithm.
///
/// npm uses a "walk up the tree" resolution: for a package at
/// `node_modules/a/node_modules/b`, to resolve dep `c`, check:
/// 1. `node_modules/a/node_modules/b/node_modules/c`
/// 2. `node_modules/a/node_modules/c`
/// 3. `node_modules/c`
///
/// We replicate this by checking progressively shorter paths in the packages map.
fn resolve_dependency_version(
    dep_name: &str,
    parent_key: &str,
    packages: &serde_json::Map<String, Value>,
    version_lookup: &HashMap<String, String>,
) -> Option<String> {
    // Walk up from the parent's location
    let mut search_base = parent_key.to_string();

    loop {
        let candidate = format!("{}/node_modules/{}", search_base, dep_name);
        if let Some(entry) = packages.get(&candidate) {
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                return Some(version.to_string());
            }
        }

        // Move up one node_modules level
        match search_base.rfind("/node_modules/") {
            Some(pos) => {
                search_base.truncate(pos);
            }
            None => break,
        }
    }

    // Final check: root-level node_modules
    let root_candidate = format!("node_modules/{}", dep_name);
    if let Some(entry) = packages.get(&root_candidate) {
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            return Some(version.to_string());
        }
    }

    // Fallback to the flat lookup
    version_lookup.get(dep_name).cloned()
}

/// Parse the v1 `dependencies` block (nested tree format).
fn parse_dependencies_block(
    deps: &serde_json::Map<String, Value>,
) -> Result<Vec<MigratedPackage>, LpmError> {
    let mut result = Vec::new();
    // First pass: collect all packages for version lookup
    let mut version_lookup: HashMap<String, String> = HashMap::new();
    collect_v1_versions(deps, &mut version_lookup);

    // Second pass: build migrated packages
    parse_v1_deps_recursive(deps, &version_lookup, &mut result);

    // Sort by name then version for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    Ok(result)
}

/// Maximum nesting depth for v1 recursive parsing.
/// Prevents stack overflow from maliciously deep lockfiles.
const MAX_V1_DEPTH: usize = 256;

/// Recursively collect name → version for all packages in a v1 dependencies tree.
fn collect_v1_versions(
    deps: &serde_json::Map<String, Value>,
    lookup: &mut HashMap<String, String>,
) {
    collect_v1_versions_inner(deps, lookup, 0);
}

fn collect_v1_versions_inner(
    deps: &serde_json::Map<String, Value>,
    lookup: &mut HashMap<String, String>,
    depth: usize,
) {
    if depth > MAX_V1_DEPTH {
        warn!("npm v1 lockfile exceeds max nesting depth ({MAX_V1_DEPTH}), truncating");
        return;
    }
    for (name, value) in deps {
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            // Root-level wins; don't overwrite
            lookup.entry(name.clone()).or_insert_with(|| version.to_string());
        }
        // Recurse into nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            collect_v1_versions_inner(nested, lookup, depth + 1);
        }
    }
}

/// Recursively parse v1 dependencies tree into flat `MigratedPackage` list.
fn parse_v1_deps_recursive(
    deps: &serde_json::Map<String, Value>,
    version_lookup: &HashMap<String, String>,
    result: &mut Vec<MigratedPackage>,
) {
    parse_v1_deps_recursive_inner(deps, version_lookup, result, 0);
}

fn parse_v1_deps_recursive_inner(
    deps: &serde_json::Map<String, Value>,
    version_lookup: &HashMap<String, String>,
    result: &mut Vec<MigratedPackage>,
    depth: usize,
) {
    if depth > MAX_V1_DEPTH {
        warn!("npm v1 lockfile exceeds max nesting depth ({MAX_V1_DEPTH}), truncating");
        return;
    }
    for (name, value) in deps {
        let version = match value.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };

        let resolved = value.get("resolved").and_then(|v| v.as_str()).map(String::from);

        // Skip entries without resolved URL
        if resolved.is_none() {
            continue;
        }

        let integrity = value.get("integrity").and_then(|v| v.as_str()).map(String::from);
        let is_optional = value.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

        // v1 dependencies have a "requires" object with semver ranges
        let mut dependencies = Vec::new();
        if let Some(requires) = value.get("requires").and_then(|r| r.as_object()) {
            for (dep_name, _range) in requires {
                if let Some(dep_version) = version_lookup.get(dep_name) {
                    dependencies.push((dep_name.clone(), dep_version.clone()));
                }
            }
        }

        dependencies.sort_by(|a, b| a.0.cmp(&b.0));

        result.push(MigratedPackage {
            name: name.clone(),
            version,
            resolved,
            integrity,
            dependencies,
            is_optional,
            is_dev,
        });

        // Recurse into nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            parse_v1_deps_recursive_inner(nested, version_lookup, result, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_v3() {
        let json = r#"{
            "name": "test-project",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "test-project",
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-abc123"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "express");
        assert_eq!(result[0].version, "4.22.1");
        assert_eq!(
            result[0].resolved.as_deref(),
            Some("https://registry.npmjs.org/express/-/express-4.22.1.tgz")
        );
        assert_eq!(result[0].integrity.as_deref(), Some("sha512-abc123"));
    }

    #[test]
    fn parse_with_dependencies() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-aaa",
                    "dependencies": {
                        "accepts": "~1.3.8",
                        "body-parser": "1.20.3"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.8",
                    "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                    "integrity": "sha512-bbb"
                },
                "node_modules/body-parser": {
                    "version": "1.20.3",
                    "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.3.tgz",
                    "integrity": "sha512-ccc"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 3);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 2);
        // Dependencies are sorted by name
        assert_eq!(express.dependencies[0], ("accepts".to_string(), "1.3.8".to_string()));
        assert_eq!(express.dependencies[1], ("body-parser".to_string(), "1.20.3".to_string()));
    }

    #[test]
    fn parse_scoped_packages() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/@babel/core": {
                    "version": "7.24.0",
                    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
                    "integrity": "sha512-babel"
                },
                "node_modules/@types/node": {
                    "version": "20.11.0",
                    "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz",
                    "integrity": "sha512-types"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "@babel/core");
        assert_eq!(result[0].version, "7.24.0");
        assert_eq!(result[1].name, "@types/node");
        assert_eq!(result[1].version, "20.11.0");
    }

    #[test]
    fn parse_nested_multi_version() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/debug": {
                    "version": "4.3.4",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
                    "integrity": "sha512-root"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-expr",
                    "dependencies": {
                        "debug": "2.6.9"
                    }
                },
                "node_modules/express/node_modules/debug": {
                    "version": "2.6.9",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                    "integrity": "sha512-nested"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // Should have 3 entries: debug@4.3.4, debug@2.6.9, express
        assert_eq!(result.len(), 3);

        let debugs: Vec<_> = result.iter().filter(|p| p.name == "debug").collect();
        assert_eq!(debugs.len(), 2);
        let versions: Vec<&str> = debugs.iter().map(|d| d.version.as_str()).collect();
        assert!(versions.contains(&"4.3.4"));
        assert!(versions.contains(&"2.6.9"));

        // Express should resolve debug to 2.6.9 (nested version, not root)
        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(express.dependencies[0], ("debug".to_string(), "2.6.9".to_string()));
    }

    #[test]
    fn parse_skips_root_entry() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0",
                    "dependencies": { "lodash": "^4.17.21" }
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
        // Root project "my-app" should NOT appear
        assert!(result.iter().all(|p| p.name != "my-app"));
    }

    #[test]
    fn parse_skips_link_entries() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "monorepo", "version": "1.0.0" },
                "node_modules/my-lib": {
                    "resolved": "packages/my-lib",
                    "link": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                },
                "packages/my-lib": {
                    "name": "my-lib",
                    "version": "1.0.0"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // Only lodash should be included; my-lib is a workspace link
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
    }

    #[test]
    fn parse_preserves_integrity() {
        let integrity = "sha512-aGVz0Rb+QLGxaNJUqL/xCRJJhoyPbLOfMQjRQmo5A2VjMbCT7BPH02LcQRbOBLXCEPE9LaXIjIvemG0TwjWbQ==";
        let json = format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "": {{ "name": "proj", "version": "1.0.0" }},
                    "node_modules/accepts": {{
                        "version": "1.3.8",
                        "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                        "integrity": "{integrity}"
                    }}
                }}
            }}"#
        );

        let result = parse_str(&json, 3).unwrap();
        assert_eq!(result[0].integrity.as_deref(), Some(integrity));
    }

    #[test]
    fn parse_handles_optional() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/fsevents": {
                    "version": "2.3.3",
                    "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                    "integrity": "sha512-fse",
                    "optional": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lod"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let fsevents = result.iter().find(|p| p.name == "fsevents").unwrap();
        assert!(fsevents.is_optional);

        let lodash = result.iter().find(|p| p.name == "lodash").unwrap();
        assert!(!lodash.is_optional);
    }

    #[test]
    fn parse_handles_dev() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/vitest": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/vitest/-/vitest-1.0.0.tgz",
                    "integrity": "sha512-vit",
                    "dev": true
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-exp"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let vitest = result.iter().find(|p| p.name == "vitest").unwrap();
        assert!(vitest.is_dev);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert!(!express.is_dev);
    }

    #[test]
    fn parse_handles_missing_resolved() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/local-pkg": {
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lod"
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        // local-pkg without resolved URL should be skipped
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
    }

    #[test]
    fn parse_v2_uses_packages_block() {
        let json = r#"{
            "name": "proj",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv2"
                }
            },
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv1-compat"
                }
            }
        }"#;

        let result = parse_str(json, 2).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "lodash");
        // Should use packages block, not the v1 dependencies block
        assert_eq!(result[0].integrity.as_deref(), Some("sha512-lodv2"));
    }

    #[test]
    fn parse_empty_packages() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "empty-proj", "version": "1.0.0" }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_real_world_small() {
        let json = r#"{
            "name": "my-api",
            "version": "2.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-api",
                    "version": "2.0.0",
                    "dependencies": {
                        "express": "^4.22.0",
                        "cors": "^2.8.5"
                    },
                    "devDependencies": {
                        "vitest": "^1.0.0"
                    }
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-ePqK5MnFG2so8cWsFDfg3wEgrBqMFuPsHCMqb3vjBVQ+kDH7rMKBUB6PE/aGHkivOpFMw2naYNyGFhmi8eiDg==",
                    "dependencies": {
                        "accepts": "~1.3.8",
                        "debug": "2.6.9"
                    }
                },
                "node_modules/cors": {
                    "version": "2.8.5",
                    "resolved": "https://registry.npmjs.org/cors/-/cors-2.8.5.tgz",
                    "integrity": "sha512-KIHbLJqu73RGr/hnbrO9uBeixNGuvSQjul/jdFvS05CbVHts80oPh0BmFUf09+os9NQ7jJKbN+JQwrAJR3drNA==",
                    "dependencies": {
                        "object-assign": "^4",
                        "vary": "^1"
                    }
                },
                "node_modules/accepts": {
                    "version": "1.3.8",
                    "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                    "integrity": "sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw=="
                },
                "node_modules/debug": {
                    "version": "4.3.4",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
                    "integrity": "sha512-debug434"
                },
                "node_modules/express/node_modules/debug": {
                    "version": "2.6.9",
                    "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                    "integrity": "sha512-debug269"
                },
                "node_modules/object-assign": {
                    "version": "4.1.1",
                    "resolved": "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz",
                    "integrity": "sha512-objassign"
                },
                "node_modules/vary": {
                    "version": "1.1.2",
                    "resolved": "https://registry.npmjs.org/vary/-/vary-1.1.2.tgz",
                    "integrity": "sha512-vary112"
                },
                "node_modules/vitest": {
                    "version": "1.2.0",
                    "resolved": "https://registry.npmjs.org/vitest/-/vitest-1.2.0.tgz",
                    "integrity": "sha512-vitest120",
                    "dev": true
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();

        // 8 packages (everything except root)
        assert_eq!(result.len(), 8);

        // Check express resolves debug to 2.6.9 (nested), not 4.3.4 (root)
        let express = result.iter().find(|p| p.name == "express").unwrap();
        let debug_dep = express.dependencies.iter().find(|d| d.0 == "debug").unwrap();
        assert_eq!(debug_dep.1, "2.6.9");

        // Check cors resolves its deps to root-level versions
        let cors = result.iter().find(|p| p.name == "cors").unwrap();
        assert_eq!(cors.dependencies.len(), 2);
        let oa_dep = cors.dependencies.iter().find(|d| d.0 == "object-assign").unwrap();
        assert_eq!(oa_dep.1, "4.1.1");
        let vary_dep = cors.dependencies.iter().find(|d| d.0 == "vary").unwrap();
        assert_eq!(vary_dep.1, "1.1.2");

        // Check vitest is dev
        let vitest = result.iter().find(|p| p.name == "vitest").unwrap();
        assert!(vitest.is_dev);

        // Two debug packages exist
        let debugs: Vec<_> = result.iter().filter(|p| p.name == "debug").collect();
        assert_eq!(debugs.len(), 2);

        // All packages have integrity
        assert!(result.iter().all(|p| p.integrity.is_some()));
    }

    #[test]
    fn extract_name_basic() {
        assert_eq!(
            extract_name_from_key("node_modules/express"),
            Some("express".to_string())
        );
    }

    #[test]
    fn extract_name_scoped() {
        assert_eq!(
            extract_name_from_key("node_modules/@babel/core"),
            Some("@babel/core".to_string())
        );
    }

    #[test]
    fn extract_name_nested() {
        assert_eq!(
            extract_name_from_key("node_modules/express/node_modules/debug"),
            Some("debug".to_string())
        );
    }

    #[test]
    fn extract_name_nested_scoped() {
        assert_eq!(
            extract_name_from_key("node_modules/a/node_modules/@scope/pkg"),
            Some("@scope/pkg".to_string())
        );
    }

    #[test]
    fn parse_v1_fallback() {
        let json = r#"{
            "name": "old-project",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodv1"
                },
                "express": {
                    "version": "4.17.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                    "integrity": "sha512-exv1",
                    "requires": {
                        "debug": "2.6.9"
                    },
                    "dependencies": {
                        "debug": {
                            "version": "2.6.9",
                            "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                            "integrity": "sha512-dbgv1"
                        }
                    }
                }
            }
        }"#;

        let result = parse_str(json, 1).unwrap();
        assert_eq!(result.len(), 3);

        let express = result.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(express.dependencies[0], ("debug".to_string(), "2.6.9".to_string()));

        // Nested debug should also be present
        let debugs: Vec<_> = result.iter().filter(|p| p.name == "debug").collect();
        assert_eq!(debugs.len(), 1); // Only the nested one (it's the only one with `resolved`)
        assert_eq!(debugs[0].version, "2.6.9");
    }

    #[test]
    fn version_lookup_prefers_root_level_deterministic() {
        // Finding #5: root-level entry should always win over nested
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "proj", "version": "1.0.0" },
                "node_modules/some-pkg/node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "integrity": "sha512-nested"
                },
                "node_modules/express": {
                    "version": "4.22.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
                    "integrity": "sha512-root"
                },
                "node_modules/consumer": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/consumer/-/consumer-1.0.0.tgz",
                    "integrity": "sha512-cons",
                    "dependencies": {
                        "express": "^4.0.0"
                    }
                }
            }
        }"#;

        let result = parse_str(json, 3).unwrap();
        let consumer = result.iter().find(|p| p.name == "consumer").unwrap();
        // consumer is at root level, so its dep on express should resolve to root express (4.22.1)
        assert_eq!(consumer.dependencies[0], ("express".to_string(), "4.22.1".to_string()));
    }

    #[test]
    fn parse_no_blocks_returns_error() {
        let json = r#"{ "lockfileVersion": 3 }"#;
        let result = parse_str(json, 3);
        assert!(result.is_err());
    }
}
