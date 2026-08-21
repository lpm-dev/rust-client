//! Lockfile migration from npm/yarn/pnpm/bun to LPM.
//!
//! Parses foreign lockfiles into a common intermediate (`MigratedPackage`),
//! then converts to `lpm_lockfile::Lockfile` for writing.
//!
//! The converted lockfile uses the newest schema that does not require
//! LPM-specific package-instance identities. A mutable `lpm install`
//! resolves those identities and writes the current lockfile schema.

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
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::Path;

/// Maximum accepted size of a foreign lockfile snapshot.
pub const FOREIGN_LOCKFILE_SIZE_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum number of packages accepted from a foreign lockfile.
pub const MAX_PACKAGES: usize = 200_000;

trait MapStorage: Sized {
    type Key;
    type Value;

    fn with_capacity(capacity: usize) -> Self;
    fn insert(&mut self, key: Self::Key, value: Self::Value);
}

impl<K, V> MapStorage for HashMap<K, V>
where
    K: Eq + Hash,
{
    type Key = K;
    type Value = V;

    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    fn insert(&mut self, key: K, value: V) {
        HashMap::insert(self, key, value);
    }
}

impl MapStorage for serde_json::Map<String, serde_json::Value> {
    type Key = String;
    type Value = serde_json::Value;

    fn with_capacity(capacity: usize) -> Self {
        serde_json::Map::with_capacity(capacity)
    }

    fn insert(&mut self, key: String, value: serde_json::Value) {
        serde_json::Map::insert(self, key, value);
    }
}

impl MapStorage for serde_yaml::Mapping {
    type Key = serde_yaml::Value;
    type Value = serde_yaml::Value;

    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        serde_yaml::Mapping::insert(self, key, value);
    }
}

pub(crate) struct BoundedMap<M, const LIMIT: usize>(M);

impl<M, const LIMIT: usize> Default for BoundedMap<M, LIMIT>
where
    M: MapStorage,
{
    fn default() -> Self {
        Self(M::with_capacity(0))
    }
}

impl<M, const LIMIT: usize> Deref for BoundedMap<M, LIMIT> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de, M, const LIMIT: usize> Deserialize<'de> for BoundedMap<M, LIMIT>
where
    M: MapStorage,
    M::Key: Deserialize<'de>,
    M::Value: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedMapVisitor<M, const LIMIT: usize>(PhantomData<M>);

        impl<'de, M, const LIMIT: usize> Visitor<'de> for BoundedMapVisitor<M, LIMIT>
        where
            M: MapStorage,
            M::Key: Deserialize<'de>,
            M::Value: Deserialize<'de>,
        {
            type Value = BoundedMap<M, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a package map with at most {LIMIT} entries")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let capacity = access.size_hint().unwrap_or(0).min(LIMIT);
                let mut map = M::with_capacity(capacity);
                let mut entry_count = 0usize;
                while let Some(key) = access.next_key()? {
                    if entry_count == LIMIT {
                        return Err(<A::Error as serde::de::Error>::custom(format!(
                            "package map exceeds the {LIMIT}-entry limit"
                        )));
                    }
                    let value = access.next_value()?;
                    map.insert(key, value);
                    entry_count += 1;
                }
                Ok(BoundedMap(map))
            }
        }

        deserializer.deserialize_map(BoundedMapVisitor::<M, LIMIT>(PhantomData))
    }
}

/// Common intermediate for all foreign lockfile formats.
/// Every parser normalizes its format into this structure.
#[derive(Debug, Clone, PartialEq)]
pub struct MigratedPackage {
    /// Exact package-manager instance key when the source format distinguishes
    /// multiple installed instances with the same name and version.
    pub lockfile_key: Option<String>,
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

/// A selected foreign lockfile before its format version is decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedLockfile {
    pub kind: SourceKind,
    pub path: std::path::PathBuf,
}

/// Package manager type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

/// Read one bounded, immutable foreign-lockfile snapshot.
pub fn read_lockfile_snapshot(path: &Path) -> Result<String, LpmError> {
    lpm_common::read_text_file_capped(path, FOREIGN_LOCKFILE_SIZE_CAP_BYTES).map_err(|error| {
        LpmError::Script(format!(
            "failed to read foreign lockfile {}: {error}",
            path.display()
        ))
    })
}

/// Reject a foreign lockfile before a parser or converter consumes it.
pub fn ensure_lockfile_size(path: &Path) -> Result<(), LpmError> {
    let metadata = std::fs::metadata(path).map_err(LpmError::Io)?;
    if metadata.len() > FOREIGN_LOCKFILE_SIZE_CAP_BYTES {
        return Err(LpmError::Script(format!(
            "foreign lockfile {} is {} bytes, exceeding the {} byte limit",
            path.display(),
            metadata.len(),
            FOREIGN_LOCKFILE_SIZE_CAP_BYTES
        )));
    }
    Ok(())
}

pub(crate) fn enforce_package_limit(package_count: usize) -> Result<(), LpmError> {
    if package_count > MAX_PACKAGES {
        return Err(LpmError::Script(format!(
            "lockfile contains {package_count} packages (max: {MAX_PACKAGES}). This may indicate a corrupt lockfile."
        )));
    }
    Ok(())
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
    enforce_package_limit(packages.len())?;

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
) -> Option<(
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
)> {
    let content = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
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
    if let Ok(content) = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
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
    if let Ok(content) = lpm_common::read_text_file_capped(
        &project_dir.join("pnpm-workspace.yaml"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) && let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(&content)
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
        fs::write(dir.path().join("package.json"), r#"{"name": "root"}"#).unwrap();
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

    #[test]
    fn foreign_lockfile_snapshot_rejects_file_over_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(FOREIGN_LOCKFILE_SIZE_CAP_BYTES + 1).unwrap();

        let error = read_lockfile_snapshot(&path).unwrap_err();

        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn binary_foreign_lockfile_rejects_file_over_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bun.lockb");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(FOREIGN_LOCKFILE_SIZE_CAP_BYTES + 1).unwrap();

        let error = ensure_lockfile_size(&path).unwrap_err();

        assert!(error.to_string().contains("exceeding"));
    }
}
