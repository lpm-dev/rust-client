//! Lockfile migration from npm/yarn/pnpm/bun to LPM.
//!
//! Parses foreign lockfiles into a common intermediate (`MigratedPackage`),
//! then converts to `lpm_lockfile::Lockfile` for writing.
//!
//! The converted lockfile is used by `lpm install`'s lockfile fast path
//! (skips PubGrub resolution entirely, goes straight to download + link).

pub mod backup;
pub mod bun;
pub mod ci;
pub mod detect;
pub mod normalize;
pub mod npm;
pub mod pnpm;
pub mod validate;
pub mod yarn;

use lpm_common::LpmError;
use std::path::Path;

/// Maximum number of packages allowed in a lockfile.
/// Protects against malicious/corrupt lockfiles causing unbounded memory usage.
const MAX_PACKAGES: usize = 200_000;

/// Common intermediate for all foreign lockfile formats.
/// Every parser normalizes its format into this structure.
#[derive(Debug, Clone, PartialEq)]
pub struct MigratedPackage {
    /// Package name (e.g., "express", "@scope/name").
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Tarball download URL (if available).
    pub resolved: Option<String>,
    /// SRI integrity hash (e.g., "sha512-...").
    pub integrity: Option<String>,
    /// Direct dependencies: (name, exact_version).
    pub dependencies: Vec<(String, String)>,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
    /// Whether this is a dev dependency.
    pub is_dev: bool,
}

/// Detected source package manager.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedSource {
    /// Which package manager.
    pub kind: SourceKind,
    /// Path to the lockfile.
    pub path: std::path::PathBuf,
    /// Lockfile format version (e.g., 2, 3 for npm; 1 for yarn v1).
    pub version: u32,
}

/// Package manager type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceKind::Npm => write!(f, "npm"),
            SourceKind::Yarn => write!(f, "yarn"),
            SourceKind::Pnpm => write!(f, "pnpm"),
            SourceKind::Bun => write!(f, "bun"),
        }
    }
}

/// Result of a migration.
#[derive(Debug)]
pub struct MigrateResult {
    /// The converted lockfile.
    pub lockfile: lpm_lockfile::Lockfile,
    /// Detected source.
    pub source: DetectedSource,
    /// Total packages migrated.
    pub package_count: usize,
    /// Packages with integrity hashes preserved.
    pub integrity_count: usize,
    /// Warnings generated during migration.
    pub warnings: Vec<String>,
    /// Packages skipped (workspace links, git deps, etc.).
    pub skipped: Vec<SkippedPackage>,
    /// Number of workspace members detected (0 = not a monorepo).
    pub workspace_members: usize,
}

/// A package that was skipped during migration.
#[derive(Debug, Clone)]
pub struct SkippedPackage {
    pub name: String,
    pub reason: String,
}

/// Run the full migration pipeline: detect → parse → normalize → validate.
///
/// Does NOT write files — caller decides what to do with the result.
pub fn migrate(project_dir: &Path) -> Result<MigrateResult, LpmError> {
    // Detect source
    let source = detect::detect_source(project_dir)?;

    // Parse foreign lockfile into common intermediate
    let mut packages = match source.kind {
        SourceKind::Npm => npm::parse(&source.path, source.version)?,
        SourceKind::Yarn => yarn::parse(&source.path, project_dir)?,
        SourceKind::Pnpm => pnpm::parse(&source.path, source.version)?,
        SourceKind::Bun => bun::parse(&source.path)?,
    };

    // Guard against corrupt/malicious lockfiles with excessive entries
    if packages.len() > MAX_PACKAGES {
        return Err(LpmError::Script(format!(
            "lockfile contains {} packages (max: {}). This may indicate a corrupt lockfile.",
            packages.len(),
            MAX_PACKAGES
        )));
    }

    // For yarn v1: mark dev/optional from package.json (yarn doesn't encode this per-entry)
    if source.kind == SourceKind::Yarn
        && let Some((dev_deps, optional_deps)) = read_dep_sets(project_dir)
    {
        normalize::mark_dev_optional(&mut packages, &dev_deps, &optional_deps);
    }

    // Detect workspace members
    let workspace_members = detect_workspace_members(project_dir);

    // Normalize to LPM lockfile
    let (lockfile, skipped) = normalize::to_lockfile(packages);

    // Validate
    let warnings = validate::validate(&lockfile, project_dir);

    let integrity_count = lockfile
        .packages
        .iter()
        .filter(|p| p.integrity.is_some())
        .count();

    Ok(MigrateResult {
        package_count: lockfile.packages.len(),
        integrity_count,
        lockfile,
        source,
        warnings,
        skipped,
        workspace_members,
    })
}

/// Read devDependencies and optionalDependencies from package.json.
fn read_dep_sets(
    project_dir: &Path,
) -> Option<(std::collections::HashSet<String>, std::collections::HashSet<String>)> {
    let content = std::fs::read_to_string(project_dir.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let dev_deps = json
        .get("devDependencies")
        .and_then(|d| d.as_object())
        .map(|d| d.keys().cloned().collect())
        .unwrap_or_default();

    let optional_deps = json
        .get("optionalDependencies")
        .and_then(|d| d.as_object())
        .map(|d| d.keys().cloned().collect())
        .unwrap_or_default();

    Some((dev_deps, optional_deps))
}

/// Detect how many workspace members exist in the project.
fn detect_workspace_members(project_dir: &Path) -> usize {
    // Check package.json "workspaces" field (npm/yarn/bun)
    if let Ok(content) = std::fs::read_to_string(project_dir.join("package.json"))
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(workspaces) = json.get("workspaces")
    {
        // "workspaces": ["packages/*", "apps/*"]
        if let Some(arr) = workspaces.as_array() {
            return count_workspace_globs(project_dir, arr);
        }
        // "workspaces": { "packages": ["packages/*"] }
        if let Some(obj) = workspaces.as_object()
            && let Some(arr) = obj.get("packages").and_then(|p| p.as_array())
        {
            return count_workspace_globs(project_dir, arr);
        }
    }

    // Check pnpm-workspace.yaml
    if let Ok(content) = std::fs::read_to_string(project_dir.join("pnpm-workspace.yaml"))
        && let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(&content)
        && let Some(arr) = yaml.get("packages").and_then(|p| p.as_array())
    {
        return count_workspace_globs(project_dir, arr);
    }

    0
}

/// Count workspace members by expanding glob patterns.
fn count_workspace_globs(project_dir: &Path, patterns: &[serde_json::Value]) -> usize {
    let mut count = 0;
    for pattern in patterns {
        if let Some(glob_str) = pattern.as_str() {
            let full_pattern = project_dir.join(glob_str).join("package.json");
            if let Ok(paths) = glob::glob(full_pattern.to_str().unwrap_or("")) {
                count += paths.filter_map(|p| p.ok()).count();
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn workspace_detection_npm_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        // Create workspace structure
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"]}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/a")).unwrap();
        fs::write(
            dir.path().join("packages/a/package.json"),
            r#"{"name": "a"}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("packages/b")).unwrap();
        fs::write(
            dir.path().join("packages/b/package.json"),
            r#"{"name": "b"}"#,
        )
        .unwrap();

        assert_eq!(detect_workspace_members(dir.path()), 2);
    }

    #[test]
    fn workspace_detection_pnpm_workspace_yaml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root"}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        fs::write(
            dir.path().join("apps/web/package.json"),
            r#"{"name": "web"}"#,
        )
        .unwrap();

        assert_eq!(detect_workspace_members(dir.path()), 1);
    }

    #[test]
    fn workspace_detection_no_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "single-package"}"#,
        )
        .unwrap();

        assert_eq!(detect_workspace_members(dir.path()), 0);
    }

    #[test]
    fn workspace_detection_yarn_object_form() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": {"packages": ["libs/*"]}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("libs/utils")).unwrap();
        fs::write(
            dir.path().join("libs/utils/package.json"),
            r#"{"name": "utils"}"#,
        )
        .unwrap();

        assert_eq!(detect_workspace_members(dir.path()), 1);
    }

    #[test]
    fn migrate_result_includes_workspace_members() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"ms": "2.1.3"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"ms": "2.1.3"}},
                    "node_modules/ms": {
                        "version": "2.1.3",
                        "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
                        "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsFVVw6Qy6/M+cSyZDJhGAVoS1CNDaMhVTDcLP06bIXw=="
                    }
                }
            }"#,
        )
        .unwrap();

        let result = migrate(dir.path()).unwrap();
        assert_eq!(result.workspace_members, 0);
        assert_eq!(result.package_count, 1);
    }
}
