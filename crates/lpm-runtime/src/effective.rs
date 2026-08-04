//! Resolve the "effective" Node.js version for a project — the version
//! that LPM will actually invoke when scripts run.
//!
//! Used by the engine-strict gate (`crates/lpm-cli/src/engine_check.rs`)
//! to validate `engines.node` against the version that will be picked
//! up at script-execution time, rather than blindly trusting whatever
//! happens to be on `PATH`.
//!
//! Resolution order:
//!
//! 1. If the project selects a Node version (`lpm.json > runtime.node`,
//!    `.nvmrc`, `.node-version`) and a managed runtime under
//!    `~/.lpm/runtimes/node/` satisfies that selector, use the managed version.
//! 2. Else, fall back to the system `node --version` from `PATH`.
//! 3. Else, return [`Effective::Unknown`].
//!
//! The pin-but-not-yet-installed case intentionally falls through to
//! the system Node: that mirrors npm's behavior (compare engines.node
//! against the running Node), and it gives the user a clear escape
//! hatch — `lpm use node@<v>` first, then re-run install.

use crate::detect;
use crate::node;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What Node version LPM resolved as "effective" for this project.
#[derive(Debug, Clone)]
pub enum Effective {
    /// A managed runtime at `~/.lpm/runtimes/node/<version>/` matched
    /// the project's pin. This version will be on `PATH` when scripts
    /// run.
    Managed { version: String, source: String },
    /// No managed runtime matched (or no pin exists). `node --version`
    /// from `PATH` will be invoked.
    System { version: String },
    /// No managed runtime matched and `node` is not on `PATH`.
    Unknown,
}

/// Effective Node selection paired with a stable executable fingerprint.
///
/// The fingerprint is derived without executing Node and is absent when
/// LPM cannot identify a concrete executable. Callers may persist it to
/// decide whether a later version probe can be reused safely.
#[derive(Debug, Clone)]
pub struct EffectiveNodeResolution {
    effective: Effective,
    runtime_fingerprint: Option<String>,
}

impl EffectiveNodeResolution {
    /// Resolved Node version and source.
    pub fn effective(&self) -> &Effective {
        &self.effective
    }

    /// Fingerprint of the selected executable, when one can be identified.
    pub fn runtime_fingerprint(&self) -> Option<&str> {
        self.runtime_fingerprint.as_deref()
    }
}

impl Effective {
    /// The resolved version string, if any.
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Managed { version, .. } | Self::System { version } => Some(version),
            Self::Unknown => None,
        }
    }

    /// Where the version came from, for user-facing error messages.
    pub fn source_label(&self) -> &str {
        match self {
            Self::Managed { source, .. } => source,
            Self::System { .. } => "system PATH",
            Self::Unknown => "unknown",
        }
    }
}

/// Resolve the effective Node version LPM would invoke for `project_dir`.
///
/// Pure helper: no network, no filesystem mutation. Reads the project's
/// pin sources and `~/.lpm/runtimes/node/`, and shells out to `node
/// --version` once at the system-fallback step.
pub fn resolve_effective_node_version(project_dir: &Path) -> detect::DetectionResult<Effective> {
    Ok(resolve_inner(detect::detect_node_version(project_dir)?))
}

/// Compatibility shim for callers that already parsed `package.json`.
///
/// The `engines` map is intentionally ignored because `engines.node` can only
/// validate the effective runtime; it cannot select one.
#[deprecated(note = "use resolve_effective_node_version; engines.node does not select a runtime")]
pub fn resolve_effective_node_version_with_engines(
    project_dir: &Path,
    _engines: &HashMap<String, String>,
) -> detect::DetectionResult<Effective> {
    resolve_effective_node_version(project_dir)
}

/// Resolve effective Node and fingerprint the selected executable.
///
/// System Node is executed once to obtain its version. The fingerprint uses
/// only the selected executable's path and filesystem metadata, so subsequent
/// freshness checks can probe it without spawning Node.
pub fn resolve_effective_node_with_fingerprint(
    project_dir: &Path,
) -> detect::DetectionResult<EffectiveNodeResolution> {
    Ok(resolve_detected_node_with_fingerprint(
        detect::detect_node_version(project_dir)?,
    ))
}

/// Compatibility shim that ignores `engines` during runtime selection.
#[deprecated(
    note = "use resolve_effective_node_with_fingerprint; engines.node does not select a runtime"
)]
pub fn resolve_effective_node_with_fingerprint_with_engines(
    project_dir: &Path,
    _engines: &HashMap<String, String>,
) -> detect::DetectionResult<EffectiveNodeResolution> {
    resolve_effective_node_with_fingerprint(project_dir)
}

/// Resolve and fingerprint an already-detected Node requirement.
pub fn resolve_detected_node_with_fingerprint(
    detected: Option<detect::DetectedNodeVersion>,
) -> EffectiveNodeResolution {
    resolve_inner_with_fingerprint(detected)
}

/// Fingerprint the Node executable LPM would select without executing it.
///
/// Returns `None` when no concrete executable can be identified. Managed
/// runtime selection still follows project selectors and installed runtime state.
pub fn probe_effective_node_fingerprint(
    project_dir: &Path,
) -> detect::DetectionResult<Option<String>> {
    Ok(probe_detected_node_fingerprint(
        detect::detect_node_version(project_dir)?,
    ))
}

/// Compatibility shim that ignores `engines` during runtime selection.
#[deprecated(note = "use probe_effective_node_fingerprint; engines.node does not select a runtime")]
pub fn probe_effective_node_fingerprint_with_engines(
    project_dir: &Path,
    _engines: &HashMap<String, String>,
) -> detect::DetectionResult<Option<String>> {
    probe_effective_node_fingerprint(project_dir)
}

/// Fingerprint the executable selected for an already-detected Node requirement.
pub fn probe_detected_node_fingerprint(
    detected: Option<detect::DetectedNodeVersion>,
) -> Option<String> {
    selected_node(detected).runtime_fingerprint()
}

enum SelectedNode {
    Managed {
        version: String,
        source: String,
        executable: PathBuf,
    },
    System {
        executable: Option<PathBuf>,
    },
}

impl SelectedNode {
    fn runtime_fingerprint(&self) -> Option<String> {
        match self {
            Self::Managed { executable, .. } => executable_fingerprint(b"managed\0", executable),
            Self::System {
                executable: Some(executable),
            } => executable_fingerprint(b"system\0", executable),
            Self::System { executable: None } => None,
        }
    }
}

fn selected_node(detected: Option<detect::DetectedNodeVersion>) -> SelectedNode {
    if let Some(detected) = detected.filter(detect::DetectedRuntimeVersion::is_runtime_selector) {
        let installed = node::list_installed().unwrap_or_default();
        if let Some(version) = node::find_matching_installed(&detected.spec, &installed)
            && let Ok(executable) = node::node_binary_path(&version)
        {
            return SelectedNode::Managed {
                version,
                source: detected.source_label(),
                executable,
            };
        }
    }

    SelectedNode::System {
        executable: system_node_executable(),
    }
}

fn resolve_inner_with_fingerprint(
    detected: Option<detect::DetectedNodeVersion>,
) -> EffectiveNodeResolution {
    let selected = selected_node(detected);
    let runtime_fingerprint_before = selected.runtime_fingerprint();
    let effective = resolve_selected(&selected);
    let runtime_fingerprint = selected
        .runtime_fingerprint()
        .filter(|after| runtime_fingerprint_before.as_ref() == Some(after));
    EffectiveNodeResolution {
        effective,
        runtime_fingerprint,
    }
}

fn resolve_inner(detected: Option<detect::DetectedNodeVersion>) -> Effective {
    resolve_selected(&selected_node(detected))
}

fn resolve_selected(selected: &SelectedNode) -> Effective {
    match selected {
        SelectedNode::Managed {
            version, source, ..
        } => Effective::Managed {
            version: version.clone(),
            source: source.clone(),
        },
        SelectedNode::System { executable } => {
            let version = match executable {
                Some(executable) => system_node_version_at(executable),
                None => system_node_version(),
            };
            version.map_or(Effective::Unknown, |version| Effective::System { version })
        }
    }
}

/// Run `node --version` and return the bare version string (no `v`
/// prefix). Returns `None` when `node` is not on `PATH` or the output
/// is unparseable.
fn system_node_version() -> Option<String> {
    parse_system_node_version(Command::new("node").arg("--version").output().ok()?)
}

fn system_node_version_at(executable: &Path) -> Option<String> {
    parse_system_node_version(Command::new(executable).arg("--version").output().ok()?)
}

fn parse_system_node_version(output: std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

fn system_node_executable() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    system_node_executable_in_path(&path)
}

fn system_node_executable_in_path(path: &OsStr) -> Option<PathBuf> {
    for dir in std::env::split_paths(path) {
        #[cfg(windows)]
        let candidate = dir.join("node.exe");
        #[cfg(not(windows))]
        let candidate = dir.join("node");

        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_file(path: &Path) -> bool {
    path.is_file()
}

fn executable_fingerprint(kind: &[u8], executable: &Path) -> Option<String> {
    let canonical = executable.canonicalize().ok()?;
    let metadata = canonical.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"lpm-node-runtime-fingerprint-v1\0");
    hasher.update(kind);
    hash_os_string(&mut hasher, canonical.as_os_str());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        hasher.update(metadata.size().to_le_bytes());
        hasher.update(metadata.mtime().to_le_bytes());
        hasher.update(metadata.mtime_nsec().to_le_bytes());
        hasher.update(metadata.mode().to_le_bytes());
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        hasher.update(metadata.file_size().to_le_bytes());
        hasher.update(metadata.creation_time().to_le_bytes());
        hasher.update(metadata.last_write_time().to_le_bytes());
        hasher.update(metadata.file_attributes().to_le_bytes());
    }

    #[cfg(not(any(unix, windows)))]
    {
        hasher.update(metadata.len().to_le_bytes());
        if let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = modified.duration_since(std::time::UNIX_EPOCH)
        {
            hasher.update(elapsed.as_nanos().to_le_bytes());
        }
    }

    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn hash_os_string(hasher: &mut Sha256, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;

    hasher.update(value.as_bytes());
}

#[cfg(windows)]
fn hash_os_string(hasher: &mut Sha256, value: &OsStr) {
    use std::os::windows::ffi::OsStrExt;

    for unit in value.encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_os_string(hasher: &mut Sha256, value: &OsStr) {
    hasher.update(value.to_string_lossy().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_node_path(dir: &Path) -> PathBuf {
        #[cfg(windows)]
        let name = "node.exe";
        #[cfg(not(windows))]
        let name = "node";
        dir.join(name)
    }

    fn write_test_executable(path: &Path, content: &[u8]) {
        fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn no_pin_no_node_returns_managed_or_system_or_unknown() {
        // We can't reliably control PATH in a unit test, so the only
        // assertion that holds across CI environments is "doesn't panic
        // and returns one of the three variants."
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_effective_node_version(dir.path()).unwrap();
        match result {
            Effective::Managed { .. } | Effective::System { .. } | Effective::Unknown => {}
        }
    }

    #[test]
    fn unknown_has_no_version() {
        let e = Effective::Unknown;
        assert!(e.version().is_none());
        assert_eq!(e.source_label(), "unknown");
    }

    #[test]
    fn managed_exposes_source_label() {
        let e = Effective::Managed {
            version: "22.5.0".into(),
            source: "lpm.json".into(),
        };
        assert_eq!(e.version(), Some("22.5.0"));
        assert_eq!(e.source_label(), "lpm.json");
    }

    #[test]
    fn system_exposes_path_source_label() {
        let e = Effective::System {
            version: "20.18.0".into(),
        };
        assert_eq!(e.version(), Some("20.18.0"));
        assert_eq!(e.source_label(), "system PATH");
    }

    #[test]
    fn selector_without_managed_runtime_falls_through_to_system() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": "99.0.0"}}"#,
        )
        .unwrap();
        let result = resolve_effective_node_version(dir.path()).unwrap();
        assert!(!matches!(
            result,
            Effective::Managed { ref version, .. } if version == "99.0.0"
        ));
    }

    #[test]
    fn package_json_engine_constraint_cannot_select_managed_node() {
        let detected = detect::DetectedRuntimeVersion {
            runtime: detect::RuntimeKind::Node,
            spec: ">=18".to_string(),
            source: detect::VersionSource::PackageJsonEngines,
        };

        assert!(matches!(
            selected_node(Some(detected)),
            SelectedNode::System { .. }
        ));
    }

    #[test]
    fn unchanged_executable_has_stable_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let executable = test_node_path(dir.path());
        write_test_executable(&executable, b"node-runtime");

        let first = executable_fingerprint(b"system\0", &executable).unwrap();
        let second = executable_fingerprint(b"system\0", &executable).unwrap();

        assert_eq!(second, first);
    }

    #[test]
    fn replaced_executable_changes_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let executable = test_node_path(dir.path());
        let replacement = dir.path().join("replacement-node");
        write_test_executable(&executable, b"first-runtime");
        let first = executable_fingerprint(b"system\0", &executable).unwrap();

        write_test_executable(&replacement, b"second-runtime-with-different-size");
        #[cfg(windows)]
        fs::remove_file(&executable).unwrap();
        fs::rename(&replacement, &executable).unwrap();
        let second = executable_fingerprint(b"system\0", &executable).unwrap();

        assert_ne!(second, first);
    }

    #[test]
    fn path_selection_uses_first_executable() {
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let first = test_node_path(first_dir.path());
        let second = test_node_path(second_dir.path());
        write_test_executable(&first, b"first");
        write_test_executable(&second, b"second");
        let path = std::env::join_paths([first_dir.path(), second_dir.path()]).unwrap();

        assert_eq!(system_node_executable_in_path(&path), Some(first));
    }

    #[test]
    fn missing_executable_has_no_reusable_fingerprint() {
        let dir = tempfile::tempdir().unwrap();

        assert!(system_node_executable_in_path(dir.path().as_os_str()).is_none());
    }

    #[test]
    fn managed_and_system_selections_have_distinct_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let executable = test_node_path(dir.path());
        write_test_executable(&executable, b"node-runtime");

        let managed = executable_fingerprint(b"managed\0", &executable).unwrap();
        let system = executable_fingerprint(b"system\0", &executable).unwrap();

        assert_ne!(managed, system);
    }
}
