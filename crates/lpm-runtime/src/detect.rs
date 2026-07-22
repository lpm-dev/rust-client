//! Auto-detect managed runtime version requirements from project configuration.
//!
//! Node resolution order (first match wins):
//! 1. `lpm.json` -> `runtime.node`
//! 2. `package.json` -> `engines.node`
//! 3. `.nvmrc` file
//! 4. `.node-version` file
//! 5. None (use system Node)
//!
//! Bun is currently detected only from `lpm.json` -> `runtime.bun`.

use std::collections::HashMap;
use std::path::Path;

use lpm_common::{BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, read_text_file_capped};

/// Result of reading local runtime-version configuration.
pub type DetectionResult<T> = Result<T, BoundedReadError>;

/// Managed runtime kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    Node,
    Bun,
}

impl RuntimeKind {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }

    #[inline]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Node => "Node",
            Self::Bun => "Bun",
        }
    }

    #[inline]
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

impl std::fmt::Display for RuntimeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RuntimeKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "node" => Ok(Self::Node),
            "bun" => Ok(Self::Bun),
            _ => Err(()),
        }
    }
}

/// Detected managed runtime version requirement.
#[derive(Debug, Clone)]
pub struct DetectedRuntimeVersion {
    /// Runtime provider.
    pub runtime: RuntimeKind,
    /// The version spec (e.g., ">=22.0.0", "22", "22.5.0")
    pub spec: String,
    /// Where it was found
    pub source: VersionSource,
}

/// Backward-compatible alias for Node-only callers.
pub type DetectedNodeVersion = DetectedRuntimeVersion;

/// Where a version requirement was detected from.
#[derive(Debug, Clone)]
pub enum VersionSource {
    LpmJson,
    PackageJsonEngines,
    Nvmrc,
    NodeVersion,
}

impl std::fmt::Display for VersionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionSource::LpmJson => write!(f, "lpm.json"),
            VersionSource::PackageJsonEngines => write!(f, "package.json engines"),
            VersionSource::Nvmrc => write!(f, ".nvmrc"),
            VersionSource::NodeVersion => write!(f, ".node-version"),
        }
    }
}

/// Detect the required Node.js version for a project.
///
/// Walks through config sources in priority order and returns the first match.
/// Missing files are skipped; any other read failure stops detection.
pub fn detect_node_version(project_dir: &Path) -> DetectionResult<Option<DetectedNodeVersion>> {
    detect_node_version_inner(project_dir, None)
}

/// Detect the required Bun version for a project.
///
/// Bun is intentionally scoped to `lpm.json > runtime.bun`; `engines.bun`
/// remains a compatibility warning, not an enforced runtime contract.
pub fn detect_bun_version(project_dir: &Path) -> DetectionResult<Option<DetectedRuntimeVersion>> {
    detect_from_lpm_json_runtime(project_dir, RuntimeKind::Bun)
}

/// Detect every managed runtime requirement in deterministic PATH order.
/// Missing files are skipped; any other read failure stops detection.
pub fn detect_runtime_versions(project_dir: &Path) -> DetectionResult<Vec<DetectedRuntimeVersion>> {
    let mut detected = Vec::with_capacity(2);
    if let Some(node) = detect_node_version(project_dir)? {
        detected.push(node);
    }
    if let Some(bun) = detect_bun_version(project_dir)? {
        detected.push(bun);
    }
    Ok(detected)
}

/// Variant for callers that have already parsed `package.json`'s
/// `engines` block. Avoids a second disk read when the install
/// pipeline (or another command) already loaded the manifest.
///
/// Pass the `engines` HashMap from `lpm_workspace::PackageJson::engines`.
/// Other sources (`lpm.json`, `.nvmrc`, `.node-version`) are read
/// from disk as before — they live in separate files.
pub fn detect_node_version_with_engines(
    project_dir: &Path,
    engines: &HashMap<String, String>,
) -> DetectionResult<Option<DetectedNodeVersion>> {
    detect_node_version_inner(project_dir, Some(engines))
}

fn detect_node_version_inner(
    project_dir: &Path,
    engines: Option<&HashMap<String, String>>,
) -> DetectionResult<Option<DetectedNodeVersion>> {
    // 1. lpm.json -> runtime.node
    if let Some(v) = detect_from_lpm_json_runtime(project_dir, RuntimeKind::Node)? {
        return Ok(Some(v));
    }

    // 2. package.json -> engines.node — prefer the pre-parsed map
    //    when the caller supplied it; otherwise read the file.
    let engines_hit = match engines {
        Some(map) => detect_from_engines_map(map),
        None => detect_from_engines(project_dir)?,
    };
    if let Some(v) = engines_hit {
        return Ok(Some(v));
    }

    // 3. .nvmrc
    if let Some(v) = detect_from_file(project_dir, ".nvmrc", VersionSource::Nvmrc)? {
        return Ok(Some(v));
    }

    // 4. .node-version
    if let Some(v) = detect_from_file(project_dir, ".node-version", VersionSource::NodeVersion)? {
        return Ok(Some(v));
    }

    Ok(None)
}

fn detect_from_lpm_json_runtime(
    project_dir: &Path,
    runtime: RuntimeKind,
) -> DetectionResult<Option<DetectedRuntimeVersion>> {
    let path = project_dir.join("lpm.json");
    let Some(content) = read_optional_runtime_config(&path)? else {
        return Ok(None);
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Ok(None);
    };
    let Some(spec) = doc
        .get("runtime")
        .and_then(|config| config.get(runtime.as_str()))
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };

    Ok(Some(DetectedRuntimeVersion {
        runtime,
        spec: spec.to_string(),
        source: VersionSource::LpmJson,
    }))
}

fn detect_from_engines(project_dir: &Path) -> DetectionResult<Option<DetectedNodeVersion>> {
    let path = project_dir.join("package.json");
    let Some(content) = read_optional_runtime_config(&path)? else {
        return Ok(None);
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Ok(None);
    };
    let Some(spec) = doc
        .get("engines")
        .and_then(|engines| engines.get("node"))
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };

    Ok(Some(DetectedRuntimeVersion {
        runtime: RuntimeKind::Node,
        spec: spec.to_string(),
        source: VersionSource::PackageJsonEngines,
    }))
}

/// Pure variant: read `node` from a pre-parsed `engines` HashMap.
fn detect_from_engines_map(engines: &HashMap<String, String>) -> Option<DetectedNodeVersion> {
    let spec = engines.get("node")?;
    if spec.is_empty() {
        return None;
    }
    Some(DetectedRuntimeVersion {
        runtime: RuntimeKind::Node,
        spec: spec.clone(),
        source: VersionSource::PackageJsonEngines,
    })
}

/// Parse an .nvmrc or .node-version file content into a version spec.
///
/// Handles:
/// - Comments (lines starting with `#`)
/// - Empty lines
/// - `v` prefix stripping
/// - `lts/*` and `lts/codename` -> `"lts"`
/// - Whitespace trimming
///
/// Only the first non-empty, non-comment line is used.
fn parse_version_file(content: &str) -> Option<String> {
    content
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.strip_prefix('v').unwrap_or(l))
        .map(|l| {
            if l.starts_with("lts/") || l == "lts/*" {
                "lts"
            } else {
                l
            }
        })
        .map(|l| l.to_string())
}

fn detect_from_file(
    project_dir: &Path,
    filename: &str,
    source: VersionSource,
) -> DetectionResult<Option<DetectedNodeVersion>> {
    let path = project_dir.join(filename);
    let Some(content) = read_optional_runtime_config(&path)? else {
        return Ok(None);
    };
    let Some(spec) = parse_version_file(&content) else {
        return Ok(None);
    };

    if spec.is_empty() {
        return Ok(None);
    }

    Ok(Some(DetectedRuntimeVersion {
        runtime: RuntimeKind::Node,
        spec,
        source,
    }))
}

fn read_optional_runtime_config(path: &Path) -> DetectionResult<Option<String>> {
    match read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => Ok(Some(content)),
        Err(BoundedReadError::NotFound { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_from_lpm_json_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": ">=22.0.0"}}"#,
        )
        .unwrap();

        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.runtime, RuntimeKind::Node);
        assert_eq!(v.spec, ">=22.0.0");
        assert!(matches!(v.source, VersionSource::LpmJson));
    }

    #[test]
    fn detect_bun_from_lpm_json_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"bun": "1.3.14"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"bun": ">=1"}}"#,
        )
        .unwrap();

        let v = detect_bun_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.runtime, RuntimeKind::Bun);
        assert_eq!(v.spec, "1.3.14");
        assert!(matches!(v.source, VersionSource::LpmJson));
    }

    #[test]
    fn engines_bun_is_not_a_managed_runtime_pin() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"bun": ">=1"}}"#,
        )
        .unwrap();

        assert!(detect_bun_version(dir.path()).unwrap().is_none());
    }

    #[test]
    fn detect_runtime_versions_returns_node_before_bun() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"bun": "1.3.14", "node": "22"}}"#,
        )
        .unwrap();

        let versions = detect_runtime_versions(dir.path()).unwrap();
        let kinds: Vec<RuntimeKind> = versions.iter().map(|v| v.runtime).collect();
        assert_eq!(kinds, vec![RuntimeKind::Node, RuntimeKind::Bun]);
    }

    #[test]
    fn detect_from_package_json_engines() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": ">=20.0.0"}}"#,
        )
        .unwrap();

        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, ">=20.0.0");
        assert!(matches!(v.source, VersionSource::PackageJsonEngines));
    }

    #[test]
    fn detect_from_nvmrc() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "v22.5.0\n").unwrap();

        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "22.5.0"); // v prefix stripped
        assert!(matches!(v.source, VersionSource::Nvmrc));
    }

    #[test]
    fn detect_from_node_version_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".node-version"), "20.18.0\n").unwrap();

        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "20.18.0");
        assert!(matches!(v.source, VersionSource::NodeVersion));
    }

    #[test]
    fn lpm_json_has_priority() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": "22"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": "20"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join(".nvmrc"), "18").unwrap();

        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "22"); // lpm.json wins
    }

    #[test]
    fn no_version_detected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_node_version(dir.path()).unwrap().is_none());
    }

    #[test]
    fn oversized_lpm_json_does_not_fall_back_to_package_json_engines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.json");
        fs::File::create(&path)
            .unwrap()
            .set_len(CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": "20"}}"#,
        )
        .unwrap();

        assert!(matches!(
            detect_node_version(dir.path()),
            Err(BoundedReadError::TooLarge { path: error_path, .. }) if error_path == path
        ));
    }

    #[test]
    fn oversized_package_json_does_not_fall_back_to_nvmrc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        fs::File::create(&path)
            .unwrap()
            .set_len(CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();
        fs::write(dir.path().join(".nvmrc"), "20").unwrap();

        assert!(matches!(
            detect_node_version(dir.path()),
            Err(BoundedReadError::TooLarge { path: error_path, .. }) if error_path == path
        ));
    }

    #[test]
    fn oversized_nvmrc_does_not_fall_back_to_node_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".nvmrc");
        fs::File::create(&path)
            .unwrap()
            .set_len(CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();
        fs::write(dir.path().join(".node-version"), "20").unwrap();

        assert!(matches!(
            detect_node_version(dir.path()),
            Err(BoundedReadError::TooLarge { path: error_path, .. }) if error_path == path
        ));
    }

    #[test]
    fn oversized_node_version_is_not_treated_as_no_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".node-version");
        fs::File::create(&path)
            .unwrap()
            .set_len(CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();

        assert!(matches!(
            detect_node_version(dir.path()),
            Err(BoundedReadError::TooLarge { path: error_path, .. }) if error_path == path
        ));
    }

    #[test]
    fn invalid_utf8_nvmrc_does_not_fall_back_to_node_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".nvmrc");
        fs::write(&path, b"20\xff").unwrap();
        fs::write(dir.path().join(".node-version"), "20").unwrap();

        assert!(matches!(
            detect_node_version(dir.path()),
            Err(BoundedReadError::InvalidUtf8 { path: error_path, .. }) if error_path == path
        ));
    }

    // .nvmrc parsing -- comments, v prefix, lts/*
    #[test]
    fn parse_version_file_with_comments() {
        assert_eq!(parse_version_file("# comment\n22"), Some("22".into()));
    }

    #[test]
    fn parse_version_file_lts_star() {
        assert_eq!(parse_version_file("lts/*"), Some("lts".into()));
    }

    #[test]
    fn parse_version_file_lts_codename() {
        assert_eq!(parse_version_file("lts/iron"), Some("lts".into()));
    }

    #[test]
    fn parse_version_file_v_prefix() {
        assert_eq!(parse_version_file("v20.5.0"), Some("20.5.0".into()));
    }

    #[test]
    fn parse_version_file_whitespace() {
        assert_eq!(parse_version_file("  22.1.0  "), Some("22.1.0".into()));
    }

    #[test]
    fn parse_version_file_multiline_with_comments() {
        assert_eq!(
            parse_version_file("# Use Node 22\n\n22.5.0\n# end"),
            Some("22.5.0".into())
        );
    }

    #[test]
    fn nvmrc_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "# comment\n22").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "22");
    }

    #[test]
    fn nvmrc_lts_star() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "lts/*").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "lts");
    }

    #[test]
    fn nvmrc_lts_codename() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "lts/iron").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "lts");
    }

    #[test]
    fn nvmrc_v_prefix() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "v20.5.0").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "20.5.0");
    }

    #[test]
    fn nvmrc_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "  22.1.0  ").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "22.1.0");
    }

    #[test]
    fn nvmrc_multiline_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "# Use Node 22\n\n22.5.0\n# end").unwrap();
        let v = detect_node_version(dir.path()).unwrap().unwrap();
        assert_eq!(v.spec, "22.5.0");
    }
}
