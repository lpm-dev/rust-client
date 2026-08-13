//! Resolve Node.js versions from managed-runtime selectors or an explicit
//! script `PATH`.
//!
//! Used by the engine-strict gate (`crates/lpm-cli/src/engine_check.rs`)
//! to validate `engines.node` against the first Node on the final script
//! `PATH`, including project-local `node_modules/.bin` entries.
//!
//! Selector-based resolution order:
//!
//! 1. If the project selects a Node version (`lpm.json > runtime.node`,
//!    `.nvmrc`, `.node-version`) and a managed runtime under
//!    `~/.lpm/runtimes/node/` satisfies that selector, use the managed version.
//! 2. Else, fall back to `node --version` from the inherited `PATH`.
//! 3. Else, return [`Effective::Unknown`].
//!
//! The pin-but-not-yet-installed case intentionally falls through to
//! the inherited Node: that mirrors npm's behavior (compare engines.node
//! against the running Node), and it gives the user a clear escape
//! hatch — `lpm use node@<v>` first, then re-run install.

use crate::detect;
use crate::node;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Node version resolved from managed-runtime selectors and inherited `PATH`.
#[derive(Debug, Clone)]
pub enum Effective {
    /// A managed runtime at `~/.lpm/runtimes/node/<version>/` matched
    /// the project's pin.
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

/// Node version and executable fingerprint resolved from an explicit `PATH`.
#[derive(Debug, Clone)]
pub struct PathNodeResolution {
    version: Option<String>,
    runtime_fingerprint: Option<String>,
    executable: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PathNodeIdentity {
    canonical_executable: PathBuf,
    runtime_fingerprint: String,
    context: PathNodeCacheContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PathNodeCacheContext {
    WorkingDirectory(PathBuf),
    LpmManaged,
}

/// Reuses Node version probes within the same script execution context.
///
/// Executables in LPM's managed Node store are context-independent and may be
/// reused across working directories. Other executables are cached per cwd so
/// version-manager shims can select different runtimes for different projects.
#[derive(Debug, Default)]
pub struct PathNodeVersionCache {
    resolutions: HashMap<PathNodeIdentity, PathNodeResolution>,
    managed_node_root: Option<PathBuf>,
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

impl PathNodeResolution {
    /// Bare Node version without the leading `v`, when `node` is executable.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Fingerprint of the executable selected by `PATH`, when identifiable.
    pub fn runtime_fingerprint(&self) -> Option<&str> {
        self.runtime_fingerprint.as_deref()
    }

    /// Executable selected by the script `PATH`, when identifiable.
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

impl PathNodeVersionCache {
    /// Resolve Node from `path` as observed by a script running in `cwd`.
    ///
    /// Relative `PATH` entries are anchored to `cwd`. Version probes are reused
    /// only when the canonical executable, metadata fingerprint, and execution
    /// context match.
    pub fn resolve(&mut self, cwd: &Path, path: &OsStr) -> PathNodeResolution {
        if self.managed_node_root.is_none() {
            self.managed_node_root = managed_node_root();
        }
        let managed_node_root = self.managed_node_root.as_deref();
        let executable_before = node_executable_in_path(cwd, path);
        let identity_before = executable_before
            .as_deref()
            .and_then(|executable| path_node_identity(executable, cwd, managed_node_root));
        if let Some(cached) = identity_before
            .as_ref()
            .and_then(|identity| self.resolutions.get(identity))
        {
            return cached.clone();
        }

        let version = node_version_on_path(cwd, path, executable_before.as_deref());
        let identity_after = node_executable_in_path(cwd, path)
            .as_deref()
            .and_then(|executable| path_node_identity(executable, cwd, managed_node_root));
        let stable_identity =
            identity_before.filter(|before| Some(before) == identity_after.as_ref());
        let resolution = PathNodeResolution {
            version,
            runtime_fingerprint: stable_identity
                .as_ref()
                .map(|identity| identity.runtime_fingerprint.clone()),
            executable: executable_before,
        };
        if let Some(identity) = stable_identity {
            self.resolutions.insert(identity, resolution.clone());
        }
        resolution
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

/// Resolve and fingerprint the Node executable selected by a script's cwd and `PATH`.
///
/// The version probe uses the same command lookup rules as script execution.
/// The fingerprint is retained only when the selected executable is unchanged
/// across that probe.
pub fn resolve_node_on_path_with_fingerprint(cwd: &Path, path: &OsStr) -> PathNodeResolution {
    PathNodeVersionCache::default().resolve(cwd, path)
}

/// Fingerprint the Node executable selected by a script's cwd and `PATH`.
pub fn probe_node_fingerprint_on_path(cwd: &Path, path: &OsStr) -> Option<String> {
    let executable = runtime_executable_in_path(cwd, path, detect::RuntimeKind::Node)?;
    executable_fingerprint(b"script-path\0", &executable)
}

/// Fingerprint a Node or Bun executable selected by a script's cwd and `PATH`.
pub fn probe_runtime_fingerprint_on_path(
    cwd: &Path,
    path: &OsStr,
    runtime: detect::RuntimeKind,
) -> Option<String> {
    let executable = runtime_executable_in_path(cwd, path, runtime)?;
    executable_fingerprint(runtime.as_str().as_bytes(), &executable)
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

#[cfg(not(windows))]
fn node_version_on_path(cwd: &Path, _path: &OsStr, executable: Option<&Path>) -> Option<String> {
    parse_system_node_version(
        Command::new(executable?)
            .arg("--version")
            .current_dir(cwd)
            .output()
            .ok()?,
    )
}

#[cfg(windows)]
fn node_version_on_path(cwd: &Path, path: &OsStr, _executable: Option<&Path>) -> Option<String> {
    parse_system_node_version(
        Command::new("cmd")
            .args(["/D", "/S", "/C", "node --version"])
            .current_dir(cwd)
            .env("PATH", path)
            .output()
            .ok()?,
    )
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
    node_executable_in_path(&std::env::current_dir().ok()?, &path)
}

fn node_executable_in_path(cwd: &Path, path: &OsStr) -> Option<PathBuf> {
    runtime_executable_in_path(cwd, path, detect::RuntimeKind::Node)
}

fn runtime_executable_in_path(
    cwd: &Path,
    path: &OsStr,
    runtime: detect::RuntimeKind,
) -> Option<PathBuf> {
    #[cfg(windows)]
    let executable_names = windows_runtime_executable_names(runtime);

    #[cfg(windows)]
    for executable_name in &executable_names {
        let candidate = cwd.join(executable_name);
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }

    for dir in std::env::split_paths(path) {
        let dir = if dir.is_absolute() {
            dir
        } else {
            cwd.join(dir)
        };
        #[cfg(windows)]
        for executable_name in &executable_names {
            let candidate = dir.join(executable_name);
            if executable_file(&candidate) {
                return Some(candidate);
            }
        }
        #[cfg(not(windows))]
        let candidate = dir.join(runtime.binary_name());

        #[cfg(not(windows))]
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn windows_runtime_executable_names(runtime: detect::RuntimeKind) -> Vec<std::ffi::OsString> {
    let path_extensions =
        std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut names = Vec::with_capacity(4);
    names.extend(
        path_extensions
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| {
                std::ffi::OsString::from(format!("{}{extension}", runtime.binary_name()))
            }),
    );
    names
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
    executable_fingerprint_from_canonical(kind, &canonical)
}

fn path_node_identity(
    executable: &Path,
    cwd: &Path,
    managed_node_root: Option<&Path>,
) -> Option<PathNodeIdentity> {
    let canonical_executable = executable.canonicalize().ok()?;
    let runtime_fingerprint =
        executable_fingerprint_from_canonical(b"script-path\0", &canonical_executable)?;
    let context = if managed_node_root.is_some_and(|root| canonical_executable.starts_with(root)) {
        PathNodeCacheContext::LpmManaged
    } else {
        PathNodeCacheContext::WorkingDirectory(cwd.canonicalize().ok()?)
    };
    Some(PathNodeIdentity {
        canonical_executable,
        runtime_fingerprint,
        context,
    })
}

fn managed_node_root() -> Option<PathBuf> {
    crate::node::runtimes_dir()
        .ok()?
        .join("node")
        .canonicalize()
        .ok()
}

fn executable_fingerprint_from_canonical(kind: &[u8], canonical: &Path) -> Option<String> {
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

        assert_eq!(
            node_executable_in_path(first_dir.path(), &path),
            Some(first)
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_path_resolution_versions_and_fingerprints_first_node() {
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let first = test_node_path(first_dir.path());
        let second = test_node_path(second_dir.path());
        write_test_executable(&first, b"#!/bin/sh\necho v16.0.0\n");
        write_test_executable(&second, b"#!/bin/sh\necho v22.0.0\n");
        let path = std::env::join_paths([first_dir.path(), second_dir.path()]).unwrap();

        let resolution = resolve_node_on_path_with_fingerprint(first_dir.path(), &path);

        assert_eq!(resolution.version(), Some("16.0.0"));
        assert_eq!(
            resolution.runtime_fingerprint(),
            probe_node_fingerprint_on_path(first_dir.path(), &path).as_deref()
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_path_entries_resolve_from_script_working_directory() {
        let script_dir = tempfile::tempdir().unwrap();
        let fallback_dir = tempfile::tempdir().unwrap();
        let local = test_node_path(script_dir.path());
        let fallback = test_node_path(fallback_dir.path());
        write_test_executable(&local, b"#!/bin/sh\necho v18.0.0\n");
        write_test_executable(&fallback, b"#!/bin/sh\necho v22.0.0\n");
        let path = std::env::join_paths([Path::new("."), fallback_dir.path()]).unwrap();

        let resolution = resolve_node_on_path_with_fingerprint(script_dir.path(), &path);

        assert_eq!(resolution.version(), Some("18.0.0"));
    }

    #[test]
    fn missing_executable_has_no_reusable_fingerprint() {
        let dir = tempfile::tempdir().unwrap();

        assert!(node_executable_in_path(dir.path(), dir.path().as_os_str()).is_none());
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
