//! Auto-detect required Node.js version from project configuration.
//!
//! Resolution order (first match wins):
//! 1. `lpm.json` -> `runtime.node`
//! 2. `package.json` -> `engines.node`
//! 3. `.nvmrc` file
//! 4. `.node-version` file
//! 5. None (use system Node)

use std::path::Path;

/// Detected Node.js version requirement.
#[derive(Debug, Clone)]
pub struct DetectedNodeVersion {
    /// The version spec (e.g., ">=22.0.0", "22", "22.5.0")
    pub spec: String,
    /// Where it was found
    pub source: VersionSource,
}

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
pub fn detect_node_version(project_dir: &Path) -> Option<DetectedNodeVersion> {
    // 1. lpm.json -> runtime.node
    if let Some(v) = detect_from_lpm_json(project_dir) {
        return Some(v);
    }

    // 2. package.json -> engines.node
    if let Some(v) = detect_from_engines(project_dir) {
        return Some(v);
    }

    // 3. .nvmrc
    if let Some(v) = detect_from_file(project_dir, ".nvmrc", VersionSource::Nvmrc) {
        return Some(v);
    }

    // 4. .node-version
    if let Some(v) = detect_from_file(project_dir, ".node-version", VersionSource::NodeVersion) {
        return Some(v);
    }

    None
}

fn detect_from_lpm_json(project_dir: &Path) -> Option<DetectedNodeVersion> {
    let path = project_dir.join("lpm.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&content).ok()?;
    let spec = doc.get("runtime")?.get("node")?.as_str()?;

    Some(DetectedNodeVersion {
        spec: spec.to_string(),
        source: VersionSource::LpmJson,
    })
}

fn detect_from_engines(project_dir: &Path) -> Option<DetectedNodeVersion> {
    let path = project_dir.join("package.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&content).ok()?;
    let spec = doc.get("engines")?.get("node")?.as_str()?;

    Some(DetectedNodeVersion {
        spec: spec.to_string(),
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
) -> Option<DetectedNodeVersion> {
    let path = project_dir.join(filename);
    let content = std::fs::read_to_string(&path).ok()?;
    let spec = parse_version_file(&content)?;

    if spec.is_empty() {
        return None;
    }

    Some(DetectedNodeVersion { spec, source })
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

        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, ">=22.0.0");
        assert!(matches!(v.source, VersionSource::LpmJson));
    }

    #[test]
    fn detect_from_package_json_engines() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": ">=20.0.0"}}"#,
        )
        .unwrap();

        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, ">=20.0.0");
        assert!(matches!(v.source, VersionSource::PackageJsonEngines));
    }

    #[test]
    fn detect_from_nvmrc() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "v22.5.0\n").unwrap();

        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "22.5.0"); // v prefix stripped
        assert!(matches!(v.source, VersionSource::Nvmrc));
    }

    #[test]
    fn detect_from_node_version_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".node-version"), "20.18.0\n").unwrap();

        let v = detect_node_version(dir.path()).unwrap();
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

        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "22"); // lpm.json wins
    }

    #[test]
    fn no_version_detected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_node_version(dir.path()).is_none());
    }

    // Finding #11: .nvmrc parsing -- comments, v prefix, lts/*
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
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "22");
    }

    #[test]
    fn nvmrc_lts_star() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "lts/*").unwrap();
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "lts");
    }

    #[test]
    fn nvmrc_lts_codename() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "lts/iron").unwrap();
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "lts");
    }

    #[test]
    fn nvmrc_v_prefix() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "v20.5.0").unwrap();
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "20.5.0");
    }

    #[test]
    fn nvmrc_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "  22.1.0  ").unwrap();
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "22.1.0");
    }

    #[test]
    fn nvmrc_multiline_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "# Use Node 22\n\n22.5.0\n# end").unwrap();
        let v = detect_node_version(dir.path()).unwrap();
        assert_eq!(v.spec, "22.5.0");
    }
}
