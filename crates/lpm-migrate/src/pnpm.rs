//! Parser for pnpm-lock.yaml (v5, v6, and v9 formats).

use crate::MigratedPackage;
use lpm_common::LpmError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PnpmLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: serde_yaml::Value,
    #[serde(default)]
    packages: HashMap<String, PnpmPackage>,
}

#[derive(Deserialize)]
struct PnpmPackage {
    #[serde(default)]
    resolution: Option<PnpmResolution>,
    #[serde(default)]
    dependencies: HashMap<String, serde_yaml::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, serde_yaml::Value>,
    #[serde(default)]
    dev: Option<bool>,
    #[serde(default)]
    optional: Option<bool>,
}

#[derive(Deserialize)]
struct PnpmResolution {
    integrity: Option<String>,
    tarball: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a pnpm-lock.yaml file.
///
/// `version` is the lockfile major version detected by `detect`
/// (5, 6, or 9 are the significant ones).
pub fn parse(path: &Path, _version: u32) -> Result<Vec<MigratedPackage>, LpmError> {
    let content = std::fs::read_to_string(path).map_err(LpmError::Io)?;
    parse_str(&content)
}

/// Parse pnpm lockfile contents from a string (for testing).
pub fn parse_str(content: &str) -> Result<Vec<MigratedPackage>, LpmError> {
    let lockfile: PnpmLockfile = serde_yaml::from_str(content)
        .map_err(|e| LpmError::Script(format!("failed to parse pnpm-lock.yaml: {e}")))?;

    let format = detect_format(&lockfile.lockfile_version);

    let mut result = Vec::with_capacity(lockfile.packages.len());

    for (key, pkg) in &lockfile.packages {
        // Skip workspace links and file references
        if let Some(ref res) = pkg.resolution
            && let Some(ref tarball) = res.tarball
            && (tarball.starts_with("link:") || tarball.starts_with("file:"))
        {
            continue;
        }

        let (name, version) = match format {
            PnpmFormat::V9 => parse_v9_key(key),
            PnpmFormat::V5V6 => parse_v5_key(key),
        };

        if name.is_empty() || version.is_empty() {
            tracing::debug!("skipping unparseable pnpm key: {key}");
            continue;
        }

        // Skip entries that look like local links (no version semver)
        if version.starts_with("link:") || version.starts_with("file:") {
            continue;
        }

        let resolved = pkg.resolution.as_ref().and_then(|r| r.tarball.clone());
        let integrity = pkg.resolution.as_ref().and_then(|r| r.integrity.clone());

        let mut dependencies = extract_deps(&pkg.dependencies);
        let optional_deps = extract_deps(&pkg.optional_dependencies);

        // Mark optional deps separately but include them in the dependency list
        // since pnpm resolves them into the lockfile when they apply
        dependencies.extend(optional_deps);

        let is_dev = pkg.dev.unwrap_or(false);
        let is_optional = pkg.optional.unwrap_or(false);

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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum PnpmFormat {
    V9,
    V5V6,
}

/// Determine lockfile format from the lockfileVersion value.
///
/// v9 uses `'9.0'` (string); v5/v6 use a number like `5.4` or `'5.4'`.
/// v9 also uses `name@version` keys; older uses `/name/version`.
fn detect_format(version_value: &serde_yaml::Value) -> PnpmFormat {
    let version_str = match version_value {
        serde_yaml::Value::Number(n) => n.as_f64().map(|f| f.to_string()),
        serde_yaml::Value::String(s) => Some(s.clone()),
        _ => None,
    };

    match version_str {
        Some(s) if s.starts_with('9') || s.starts_with("9.") => PnpmFormat::V9,
        _ => PnpmFormat::V5V6,
    }
}

/// Parse v9 key: `name@version` or `@scope/name@version`.
///
/// Split at the last `@` that is not at position 0.
fn parse_v9_key(key: &str) -> (String, String) {
    split_at_last_at(clean_pnpm_key(key))
}

/// Parse v5/v6 key: `/name/version` or `/@scope/name/version`.
///
/// Strip leading `/`, then split at the last `/`.
fn parse_v5_key(key: &str) -> (String, String) {
    let stripped = key.strip_prefix('/').unwrap_or(key);

    // For scoped: `@scope/name/version` -> split at last `/`
    // For unscoped: `name/version` -> split at last `/`
    match stripped.rfind('/') {
        Some(pos) => {
            let name = &stripped[..pos];
            let version_part = &stripped[pos + 1..];
            // Version part may have extra qualifiers like `_peer@version`
            // or `peer+dep@version` — take only the semver prefix
            let version = version_part
                .find('_')
                .map(|i| &version_part[..i])
                .unwrap_or(version_part);
            (name.to_string(), version.to_string())
        }
        None => (stripped.to_string(), String::new()),
    }
}

/// Strip parenthesized peer dependency suffix from pnpm v9 keys.
///
/// `"pkg@1.0.0(@scope/peer@2.0.0)"` → `"pkg@1.0.0"`
/// `"pkg@1.0.0"` → `"pkg@1.0.0"` (no-op)
fn clean_pnpm_key(key: &str) -> &str {
    key.split('(').next().unwrap_or(key)
}

/// Split `"name@version"` at the last `@` that is not at position 0.
fn split_at_last_at(s: &str) -> (String, String) {
    // rfind '@' but skip position 0 (scoped package prefix)
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

/// Extract dependency pairs from a pnpm dependency map.
///
/// Values can be bare version strings (`"1.3.8"`) or objects
/// (`{version: "1.3.8", ...}`). Numbers are also coerced to strings
/// since YAML may parse `1.0` as a float.
fn extract_deps(deps: &HashMap<String, serde_yaml::Value>) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(deps.len());
    for (name, val) in deps {
        let version = match val {
            serde_yaml::Value::String(s) => s.clone(),
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::Mapping(m) => {
                // Object form: extract "version" field
                m.get(serde_yaml::Value::String("version".to_string()))
                    .and_then(|v| match v {
                        serde_yaml::Value::String(s) => Some(s.clone()),
                        serde_yaml::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .unwrap_or_default()
            }
            _ => continue,
        };
        if !version.is_empty() {
            out.push((name.clone(), version));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v9_simple() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  express@4.22.1:
    resolution: {integrity: sha512-abc123}
    engines: {node: '>= 0.10.0'}
  accepts@1.3.8:
    resolution: {integrity: sha512-xyz789}
    engines: {node: '>= 0.6'}
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 2);

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.version, "1.3.8");

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.version, "4.22.1");
    }

    #[test]
    fn parse_v6_format() {
        let yaml = r#"
lockfileVersion: 5.4

packages:
  /accepts/1.3.8:
    resolution: {integrity: sha512-abc}
    dev: false
  /express/4.22.1:
    resolution: {integrity: sha512-def}
    dev: false
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 2);

        let accepts = packages.iter().find(|p| p.name == "accepts").unwrap();
        assert_eq!(accepts.version, "1.3.8");
        assert_eq!(accepts.integrity.as_deref(), Some("sha512-abc"));
    }

    #[test]
    fn parse_scoped_packages() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  '@babel/core@7.24.0':
    resolution: {integrity: sha512-scoped}
  '@types/node@20.11.0':
    resolution: {integrity: sha512-types}
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 2);

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");

        let types = packages.iter().find(|p| p.name == "@types/node").unwrap();
        assert_eq!(types.version, "20.11.0");
    }

    #[test]
    fn parse_scoped_packages_v5() {
        let yaml = r#"
lockfileVersion: 5.4

packages:
  /@babel/core/7.24.0:
    resolution: {integrity: sha512-scoped-v5}
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 1);

        let babel = packages.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "7.24.0");
        assert_eq!(babel.integrity.as_deref(), Some("sha512-scoped-v5"));
    }

    #[test]
    fn parse_with_dependencies() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  express@4.22.1:
    resolution: {integrity: sha512-expr}
    dependencies:
      accepts: 1.3.8
      body-parser: 1.20.3
  accepts@1.3.8:
    resolution: {integrity: sha512-acc}
    dependencies:
      mime-types: 2.1.35
"#;
        let packages = parse_str(yaml).unwrap();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
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
                .any(|(n, v)| n == "body-parser" && v == "1.20.3")
        );
    }

    #[test]
    fn parse_optional_deps() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  fsevents@2.3.3:
    resolution: {integrity: sha512-fs}
    optional: true
    optionalDependencies:
      node-gyp: 10.0.0
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 1);
        let fse = &packages[0];
        assert_eq!(fse.name, "fsevents");
        assert!(fse.is_optional);
        assert_eq!(fse.dependencies.len(), 1);
        assert_eq!(
            fse.dependencies[0],
            ("node-gyp".to_string(), "10.0.0".to_string())
        );
    }

    #[test]
    fn parse_preserves_integrity() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  lodash@4.17.21:
    resolution:
      integrity: sha512-WfBlB7LvfL52ngazidRbNuGGJMJQR/8dGX+MNwfn8TCoFGNEk3DYPfoGlbMXSCeGeKOPmiJHGCfReHMy6KDGQ==
      tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
"#;
        let packages = parse_str(yaml).unwrap();
        let lodash = &packages[0];
        assert!(lodash.integrity.as_ref().unwrap().starts_with("sha512-"));
        assert_eq!(
            lodash.resolved.as_deref(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        );
    }

    #[test]
    fn parse_dev_flag() {
        let yaml = r#"
lockfileVersion: 5.4

packages:
  /eslint/8.57.0:
    resolution: {integrity: sha512-lint}
    dev: true
  /express/4.22.1:
    resolution: {integrity: sha512-expr}
    dev: false
"#;
        let packages = parse_str(yaml).unwrap();
        let eslint = packages.iter().find(|p| p.name == "eslint").unwrap();
        assert!(eslint.is_dev);

        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert!(!express.is_dev);
    }

    #[test]
    fn parse_empty_packages() {
        let yaml = r#"
lockfileVersion: '9.0'

packages: {}
"#;
        let packages = parse_str(yaml).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_no_packages_section() {
        let yaml = r#"
lockfileVersion: '9.0'
"#;
        let packages = parse_str(yaml).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_real_world_small() {
        let yaml = r#"
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      express:
        specifier: ^4.22.0
        version: 4.22.1
    devDependencies:
      typescript:
        specifier: ^5.0.0
        version: 5.4.2

packages:
  accepts@1.3.8:
    resolution: {integrity: sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==}
    engines: {node: '>= 0.6'}

  body-parser@1.20.3:
    resolution: {integrity: sha512-body}
    dependencies:
      bytes: 3.1.2

  bytes@3.1.2:
    resolution: {integrity: sha512-bytes}

  express@4.22.1:
    resolution: {integrity: sha512-express}
    dependencies:
      accepts: 1.3.8
      body-parser: 1.20.3
    engines: {node: '>= 0.10.0'}

  mime-types@2.1.35:
    resolution: {integrity: sha512-mime}

  typescript@5.4.2:
    resolution: {integrity: sha512-ts}
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 6);

        // Verify dependency chain
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert_eq!(express.dependencies.len(), 2);

        let body = packages.iter().find(|p| p.name == "body-parser").unwrap();
        assert_eq!(body.dependencies.len(), 1);
        assert_eq!(body.dependencies[0].0, "bytes");
    }

    #[test]
    fn parse_v5_key_with_peer_suffix() {
        // v5/v6 sometimes appends peer info after underscore
        let (name, version) = parse_v5_key("/postcss/8.4.38_postcss@8.4.38");
        assert_eq!(name, "postcss");
        assert_eq!(version, "8.4.38");
    }

    #[test]
    fn split_at_last_at_regular() {
        let (name, ver) = split_at_last_at("express@4.22.1");
        assert_eq!(name, "express");
        assert_eq!(ver, "4.22.1");
    }

    #[test]
    fn split_at_last_at_scoped() {
        let (name, ver) = split_at_last_at("@babel/core@7.24.0");
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.24.0");
    }

    #[test]
    fn detect_format_v9() {
        assert_eq!(
            detect_format(&serde_yaml::Value::String("9.0".to_string())),
            PnpmFormat::V9
        );
    }

    #[test]
    fn detect_format_v5() {
        let val: serde_yaml::Value = serde_yaml::from_str("5.4").unwrap();
        assert_eq!(detect_format(&val), PnpmFormat::V5V6);
    }

    #[test]
    fn extract_deps_number_coercion() {
        // YAML parses bare `1.0` as a float
        let mut map = HashMap::new();
        map.insert(
            "some-dep".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(1)),
        );
        let deps = extract_deps(&map);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "some-dep");
        assert_eq!(deps[0].1, "1");
    }

    #[test]
    fn clean_pnpm_key_strips_peer_dep_parentheses() {
        // Finding #12: peer dep qualifiers in v9 keys
        assert_eq!(
            clean_pnpm_key("express@4.22.1(supports-color@9.4.0)"),
            "express@4.22.1"
        );
        assert_eq!(
            clean_pnpm_key("@scope/pkg@1.0.0(@scope/peer@2.0.0)"),
            "@scope/pkg@1.0.0"
        );
        assert_eq!(clean_pnpm_key("express@4.22.1"), "express@4.22.1");
    }

    #[test]
    fn parse_v9_with_peer_dep_in_key() {
        let yaml = r#"
lockfileVersion: '9.0'

packages:
  express@4.22.1(supports-color@9.4.0):
    resolution: {integrity: sha512-expr}
"#;
        let packages = parse_str(yaml).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "express");
        assert_eq!(packages[0].version, "4.22.1");
    }

    #[test]
    fn extract_deps_object_form() {
        let yaml_str = r#"
some-dep:
  version: "2.1.0"
  optional: true
"#;
        let map: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(yaml_str).unwrap();
        let deps = extract_deps(&map);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], ("some-dep".to_string(), "2.1.0".to_string()));
    }
}
