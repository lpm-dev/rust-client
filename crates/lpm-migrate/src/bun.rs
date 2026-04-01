//! Parser for Bun lockfiles (`bun.lock` JSON and `bun.lockb` binary).

use crate::MigratedPackage;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a bun lockfile (either `bun.lock` JSON or `bun.lockb` binary).
pub fn parse(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "lock" => parse_json_lockfile(path),
        "lockb" => parse_binary_lockfile(path),
        _ => Err(LpmError::Script(format!(
            "unknown bun lockfile format: {}",
            path.display()
        ))),
    }
}

/// Parse a `bun.lock` (JSON format, Bun v1.2+).
fn parse_json_lockfile(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    let content = std::fs::read_to_string(path).map_err(LpmError::Io)?;
    parse_json_str(&content)
}

/// Parse bun lockfile JSON from a string (for testing).
pub fn parse_json_str(content: &str) -> Result<Vec<MigratedPackage>, LpmError> {
    let json: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| LpmError::Script(format!("failed to parse bun.lock: {e}")))?;

    let packages = json
        .get("packages")
        .and_then(|p| p.as_object())
        .ok_or_else(|| LpmError::Script("bun.lock has no 'packages' block".to_string()))?;

    // Build name → resolved_version lookup from all packages.
    // Each package entry's arr[0] is "name@version" with the exact resolved version.
    let mut version_lookup: HashMap<String, String> = HashMap::with_capacity(packages.len());
    for (_key, value) in packages.iter() {
        if let Some(arr) = value.as_array()
            && let Some(nv) = arr.first().and_then(|v| v.as_str())
        {
            let (n, v) = split_name_version(nv);
            if !n.is_empty() && !v.is_empty() {
                version_lookup.insert(n, v);
            }
        }
    }

    let mut result = Vec::with_capacity(packages.len());

    for (key, value) in packages {
        let arr = match value.as_array() {
            Some(a) => a,
            None => {
                tracing::debug!("skipping non-array package entry: {key}");
                continue;
            }
        };

        if arr.is_empty() {
            continue;
        }

        // arr[0] = "name@version"
        // arr[1] = tarball URL (or empty string)
        // arr[2] = integrity hash (or empty string)
        // arr[3] = metadata object (dependencies, optionalDependencies, etc.)
        let name_version = arr[0].as_str().unwrap_or("");
        let (name, version) = split_name_version(name_version);
        if name.is_empty() {
            tracing::debug!("skipping unparseable bun package key: {key}");
            continue;
        }

        let resolved = arr
            .get(1)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let integrity = arr
            .get(2)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let metadata = arr.get(3);

        // Parse dependencies from metadata, resolving ranges to exact versions
        let mut dependencies =
            extract_deps_from_metadata(metadata, "dependencies", &version_lookup);
        let optional_deps =
            extract_deps_from_metadata(metadata, "optionalDependencies", &version_lookup);

        let is_optional = metadata
            .and_then(|m| m.get("optional"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let is_dev = metadata
            .and_then(|m| m.get("dev"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        dependencies.extend(optional_deps);

        result.push(MigratedPackage {
            name,
            version,
            resolved,
            integrity,
            dependencies,
            is_optional,
            is_dev,
        });
    }

    // Sort for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    Ok(result)
}

/// Handle `bun.lockb` (binary format).
///
/// Strategy:
/// 1. Look for `bun.lock` (JSON) alongside it — if found, parse that instead.
/// 2. Try running `bun bun.lockb` to get a text representation.
/// 3. Fail with a clear error message.
fn parse_binary_lockfile(path: &Path) -> Result<Vec<MigratedPackage>, LpmError> {
    // Try bun.lock (JSON) alongside bun.lockb
    let json_path = path.with_extension("lock");
    if json_path.exists() {
        tracing::info!(
            "found bun.lock alongside bun.lockb, using JSON format: {}",
            json_path.display()
        );
        return parse_json_lockfile(&json_path);
    }

    // Try running bun to convert
    match std::process::Command::new("bun")
        .arg(path.as_os_str())
        .output()
    {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            parse_json_str(&text)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(LpmError::Script(format!(
                "bun failed to convert lockfile (exit {}): {stderr}",
                output.status
            )))
        }
        Err(_) => Err(LpmError::Script(
            "cannot parse bun.lockb: 'bun' binary not found.\n\
             Install bun (https://bun.sh) or generate bun.lock with: bun install --save-text-lockfile"
                .to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Split `"name@version"` into `(name, version)`.
///
/// Handles scoped packages: `"@scope/name@1.0.0"` -> `("@scope/name", "1.0.0")`.
/// Finds the last `@` that is not at position 0.
fn split_name_version(s: &str) -> (String, String) {
    let at_pos = s
        .char_indices()
        .rev()
        .find(|&(i, c)| c == '@' && i > 0)
        .map(|(i, _)| i);

    match at_pos {
        Some(pos) => (s[..pos].to_string(), s[pos + 1..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// Extract dependency pairs from a metadata object's named field.
///
/// Bun stores dependency ranges (e.g., `"~1.3.8"`) in metadata, not exact versions.
/// The `version_lookup` resolves each dep name to its exact installed version.
fn extract_deps_from_metadata(
    metadata: Option<&serde_json::Value>,
    field: &str,
    version_lookup: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let deps = metadata
        .and_then(|m| m.get(field))
        .and_then(|d| d.as_object());

    match deps {
        Some(obj) => {
            let mut out: Vec<(String, String)> = obj
                .keys()
                .filter_map(|dep_name| {
                    version_lookup
                        .get(dep_name.as_str())
                        .map(|exact_ver| (dep_name.clone(), exact_ver.clone()))
                })
                .collect();
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        }
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "my-project",
      "dependencies": {
        "express": "^4.22.0"
      }
    }
  },
  "packages": {
    "express": ["express@4.22.1", "https://registry.npmjs.org/express/-/express-4.22.1.tgz", "sha512-abc123", { "dependencies": { "accepts": "~1.3.8" } }],
    "accepts": ["accepts@1.3.8", "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz", "sha512-xyz789", { "dependencies": { "mime-types": "~2.1.34" } }],
    "mime-types": ["mime-types@2.1.35", "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz", "sha512-mime", {}]
  }
}"#
    }

    #[test]
    fn parse_json_simple() {
        let packages = parse_json_str(sample_json()).unwrap();
        assert_eq!(packages.len(), 3);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.22.1");
    }

    #[test]
    fn parse_json_with_deps() {
        let packages = parse_json_str(sample_json()).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("accepts".to_string(), "1.3.8".to_string())
        );

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.dependencies.len(), 1);
        assert_eq!(
            accepts.dependencies[0],
            ("mime-types".to_string(), "2.1.35".to_string())
        );
    }

    #[test]
    fn parse_json_scoped() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "@babel/core": ["@babel/core@7.24.0", "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz", "sha512-babel", {}],
    "@types/node": ["@types/node@20.11.0", "", "sha512-types", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        assert_eq!(packages.len(), 2);

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");
        assert_eq!(
            babel.resolved.as_deref(),
            Some("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz")
        );

        let types = packages.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types.version, "20.11.0");
        // Empty string resolved should become None
        assert!(types.resolved.is_none());
    }

    #[test]
    fn parse_preserves_integrity() {
        let packages = parse_json_str(sample_json()).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.integrity.as_deref(), Some("sha512-abc123"));

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.integrity.as_deref(), Some("sha512-xyz789"));
    }

    #[test]
    fn parse_empty_packages() {
        let json = r#"{"lockfileVersion": 0, "packages": {}}"#;
        let packages = parse_json_str(json).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_optional_and_dev() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "fsevents": ["fsevents@2.3.3", "", "sha512-fs", { "optional": true }],
    "eslint": ["eslint@8.57.0", "", "sha512-lint", { "dev": true }]
  }
}"#;
        let packages = parse_json_str(json).unwrap();

        let fse = packages.iter().find(|p| p.name == "fsevents").unwrap();
        assert!(fse.is_optional);
        assert!(!fse.is_dev);

        let eslint = packages.iter().find(|p| p.name == "eslint").unwrap();
        assert!(eslint.is_dev);
        assert!(!eslint.is_optional);
    }

    #[test]
    fn split_name_version_regular() {
        let (name, ver) = split_name_version("express@4.22.1");
        assert_eq!(name, "express");
        assert_eq!(ver, "4.22.1");
    }

    #[test]
    fn split_name_version_scoped() {
        let (name, ver) = split_name_version("@babel/core@7.24.0");
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn split_name_version_no_version() {
        let (name, ver) = split_name_version("express");
        assert_eq!(name, "express");
        assert_eq!(ver, "");
    }

    #[test]
    fn binary_fallback_to_json() {
        // Create a temp directory with both bun.lockb and bun.lock
        let dir = tempfile::tempdir().unwrap();
        let lockb_path = dir.path().join("bun.lockb");
        let lock_path = dir.path().join("bun.lock");

        // Write dummy binary file
        std::fs::write(&lockb_path, b"\x00\x01\x02").unwrap();

        // Write valid JSON lockfile
        std::fs::write(
            &lock_path,
            r#"{
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "sha512-lodash", {}]
  }
}"#,
        )
        .unwrap();

        let packages = parse(&lockb_path).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.21");
    }

    #[test]
    fn binary_missing_bun_errors() {
        // Create a temp directory with only bun.lockb (no bun.lock, no bun binary)
        let dir = tempfile::tempdir().unwrap();
        let lockb_path = dir.path().join("bun.lockb");
        std::fs::write(&lockb_path, b"\x00\x01\x02").unwrap();

        let result = parse(&lockb_path);
        // This will either fail because bun isn't installed or succeed if it is.
        // On most CI/dev machines without bun, it should error.
        // We just verify it doesn't panic.
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                msg.contains("bun") || msg.contains("parse"),
                "error should mention bun: {msg}"
            );
        }
    }

    #[test]
    fn parse_missing_packages_errors() {
        let json = r#"{"lockfileVersion": 0}"#;
        let result = parse_json_str(json);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("packages"));
    }

    #[test]
    fn deps_resolve_to_exact_versions_not_ranges() {
        // Finding #1: deps should have exact versions, not semver ranges
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "express": ["express@4.22.1", "https://registry.npmjs.org/express/-/express-4.22.1.tgz", "sha512-abc", { "dependencies": { "accepts": "~1.3.8" } }],
    "accepts": ["accepts@1.3.8", "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz", "sha512-xyz", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("accepts".to_string(), "1.3.8".to_string()),
            "dependency version should be exact (1.3.8), not a range (~1.3.8)"
        );
    }

    #[test]
    fn parse_with_optional_deps_in_metadata() {
        let json = r#"{
  "lockfileVersion": 0,
  "packages": {
    "sharp": ["sharp@0.33.0", "", "sha512-sharp", {
      "dependencies": { "color": "^4.0.0" },
      "optionalDependencies": { "@img/sharp-darwin-arm64": "0.33.0" }
    }],
    "color": ["color@4.2.3", "", "sha512-color", {}],
    "@img/sharp-darwin-arm64": ["@img/sharp-darwin-arm64@0.33.0", "", "sha512-img", {}]
  }
}"#;
        let packages = parse_json_str(json).unwrap();
        let sharp = packages.iter().find(|p| p.name == "sharp").unwrap();
        assert_eq!(sharp.dependencies.len(), 2);
        assert!(
            sharp
                .dependencies
                .iter()
                .any(|(n, v)| n == "@img/sharp-darwin-arm64" && v == "0.33.0")
        );
        assert!(
            sharp
                .dependencies
                .iter()
                .any(|(n, v)| n == "color" && v == "4.2.3")
        );
    }
}
