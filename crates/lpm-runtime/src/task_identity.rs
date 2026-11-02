//! The runtimes a task-cache key covers, identified so that machines can share
//! the key.

use crate::binary_target::{binary_target, host_libc};
use crate::detect::RuntimeKind;
use crate::effective::{
    RecordedNodeVersions, node_version_output, parse_system_node_version,
    runtime_executable_in_path,
};
use crate::node_identity::{
    RuntimeExecutable, ScriptNodeIdentity, SelectorEnvironment, classify_identified,
    script_runtime_identities, shim_selection_key, workspace_selector_digest,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

const RUNTIMES: [RuntimeKind; 2] = [RuntimeKind::Node, RuntimeKind::Bun];
const BINARY_FINGERPRINT_DOMAIN: &[u8] = b"lpm-task-runtime-binary-v1\0";

/// Versions of the runtimes that task-cache keys name, shared by every task of
/// a command. Each distinct runtime is probed at most once, and tasks that
/// need different runtimes probe concurrently.
#[derive(Debug, Default)]
pub struct TaskRuntimeVersions {
    recorded: Option<RecordedNodeVersions>,
    probes: Mutex<HashMap<String, Arc<OnceLock<Option<String>>>>>,
}

impl TaskRuntimeVersions {
    /// Reuse and record runtime binaries' versions in `recorded`.
    pub fn new(recorded: Option<RecordedNodeVersions>) -> Self {
        Self {
            recorded,
            probes: Mutex::default(),
        }
    }

    fn probe(&self, key: &str) -> Arc<OnceLock<Option<String>>> {
        let mut probes = self.probes.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(probe) = probes.get(key) {
            return Arc::clone(probe);
        }
        Arc::clone(probes.entry(key.to_owned()).or_default())
    }

    /// The version a runtime binary reports. It depends on the file alone, so
    /// one probe serves every project, and later commands reuse the record.
    fn binary_version(&self, runtime: RuntimeKind, canonical: &Path) -> Option<String> {
        let fingerprint = binary_fingerprint(runtime, canonical)?;
        let mut probed = None;
        let version = self
            .probe(&fingerprint)
            .get_or_init(|| {
                if let Some(version) = self
                    .recorded
                    .as_ref()
                    .and_then(|recorded| recorded.version(&fingerprint))
                {
                    return Some(version);
                }
                let mut command = Command::new(canonical);
                command.arg("--version");
                let version = parse_system_node_version(node_version_output(&mut command)?)?;
                // A binary replaced while it ran may have reported the old one.
                if binary_fingerprint(runtime, canonical).as_deref() != Some(&fingerprint) {
                    return None;
                }
                probed = Some(version.clone());
                Some(version)
            })
            .clone();
        // Written after the version is published, so tasks waiting on this
        // probe don't also wait for the write.
        if let (Some(recorded), Some(version)) = (&self.recorded, probed) {
            recorded.record_now(&fingerprint, &version);
        }
        version
    }

    /// The version a version manager's shim selects for a script in `cwd`
    /// with `path` and the manager `variables` the script sees, and whether
    /// this call ran the shim for it. Never recorded: a manager can resolve a
    /// range to a newly installed release without any file the key covers
    /// changing.
    fn shim_version(
        &self,
        selection: &str,
        runtime: RuntimeKind,
        executable: &Path,
        cwd: &Path,
        path: &OsStr,
        variables: &[(OsString, OsString)],
    ) -> (Option<String>, bool) {
        let mut ran = false;
        let version = self
            .probe(selection)
            .get_or_init(|| {
                ran = true;
                let mut command = if cfg!(windows) {
                    let mut command = Command::new("cmd");
                    command
                        .args(["/D", "/S", "/C"])
                        .arg(format!("{} --version", runtime.binary_name()));
                    command
                } else {
                    let mut command = Command::new(executable);
                    command.arg("--version");
                    command
                };
                command.current_dir(cwd).env("PATH", path);
                lpm_common::child_env::strip_inherited_env_hooks(&mut command);
                command.envs(variables.iter().map(|(name, value)| (name, value)));
                let output = lpm_common::process_output::output_capped(
                    &mut command,
                    std::time::Duration::from_secs(2),
                    4096,
                )
                .ok()?;
                parse_system_node_version(output)
            })
            .clone();
        (version, ran)
    }

    /// Drop a version whose selection changed while it was probed.
    fn forget(&self, key: &str) {
        self.probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }
}

/// A runtime binary's identity: its path and the metadata that changes when
/// it is replaced or rewritten. Version files don't affect what a binary
/// reports, so they are left out.
fn binary_fingerprint(runtime: RuntimeKind, canonical: &Path) -> Option<String> {
    let metadata = canonical.metadata().ok()?;
    let mut hasher = Sha256::new();
    hasher.update(BINARY_FINGERPRINT_DOMAIN);
    hasher.update(runtime.as_str().as_bytes());
    hasher.update(b"\0");
    crate::effective::hash_os_string(&mut hasher, canonical.as_os_str());
    crate::effective::update_with_file_metadata(&mut hasher, &metadata);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // An edit that restores the old size and mtime still moves ctime.
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// What a task's environment adds to runtime selection: the workspace root
/// that portable names are measured from, and the version-manager variables
/// that the project environment sets.
#[derive(Debug, Clone, Copy)]
pub struct TaskRuntimeScope<'a> {
    pub workspace_root: &'a Path,
    pub project_variables: &'a [(OsString, OsString)],
}

/// The Node and Bun that a task's `PATH` selects, by version and platform.
///
/// A runtime binary is identified by its version and the architecture and C
/// library its header names. A version manager's shim is identified by the
/// version it selects and by the version files in the workspace, which some
/// managers also read environment settings from. Any other launcher is
/// identified by its local fingerprint, which covers its location, the script
/// `PATH`, and the working directory.
///
/// Each selected executable's local fingerprint is kept too: it changes when
/// the executable or its version selectors do, so a key can be rechecked
/// before a restore or an upload without probing versions again.
#[derive(Debug, Clone)]
pub struct TaskRuntimeIdentity {
    identities: Vec<(String, String)>,
    cwd: PathBuf,
    environment: SelectorEnvironment,
    local: [Option<String>; 2],
}

impl TaskRuntimeIdentity {
    /// Identify the runtimes `path` selects for a task in `cwd`. `None` when
    /// a selected executable can't be identified, or changes while its version
    /// is probed.
    pub fn capture(
        cwd: &Path,
        path: &OsStr,
        scope: TaskRuntimeScope<'_>,
        versions: &TaskRuntimeVersions,
    ) -> Option<Self> {
        Self::capture_with(cwd, path, scope, versions, classify_identified)
    }

    fn capture_with(
        cwd: &Path,
        path: &OsStr,
        scope: TaskRuntimeScope<'_>,
        versions: &TaskRuntimeVersions,
        classify: impl Fn(&ScriptNodeIdentity, &Path, &Path, &SelectorEnvironment) -> RuntimeExecutable,
    ) -> Option<Self> {
        let environment =
            SelectorEnvironment::with_script_variables(scope.project_variables.iter().cloned());
        let executables = RUNTIMES.map(|runtime| runtime_executable_in_path(cwd, path, runtime));
        let selected = identify(cwd, path, &executables, &environment);
        let mut identities = Vec::with_capacity(RUNTIMES.len() + 1);
        identities.push(("task-platform".to_string(), host_platform().to_string()));
        let mut probed_shims = Vec::new();
        for ((runtime, executable), selected) in
            RUNTIMES.into_iter().zip(&executables).zip(&selected)
        {
            let identity = match (executable, selected) {
                (None, None) => "missing".to_string(),
                (Some(_), None) | (None, Some(_)) => return None,
                (Some(executable), Some(selected)) => {
                    match classify(selected, executable, cwd, &environment) {
                        RuntimeExecutable::Launcher => format!("local:{}", selected.fingerprint),
                        RuntimeExecutable::Binary => {
                            binary_identity(versions, runtime, &selected.canonical_executable)
                                .unwrap_or_else(|| format!("local:{}", selected.fingerprint))
                        }
                        RuntimeExecutable::VersionManagerShim => {
                            let selection = shim_selection_key(
                                executable,
                                &selected.canonical_executable,
                                cwd,
                                &environment,
                                runtime,
                            )?;
                            let (version, ran) = versions.shim_version(
                                &selection,
                                runtime,
                                executable,
                                cwd,
                                path,
                                environment.variables(),
                            );
                            if ran {
                                probed_shims.push(selection);
                            }
                            let config =
                                workspace_selector_digest(cwd, scope.workspace_root, &environment);
                            match (version, config) {
                                (Some(version), Some(config)) => {
                                    format!("version:{version} shim-config:{config}")
                                }
                                _ => format!("local:{}", selected.fingerprint),
                            }
                        }
                    }
                }
            };
            identities.push((format!("{}-runtime", runtime.as_str()), identity));
        }
        let identity = Self {
            identities,
            cwd: cwd.to_path_buf(),
            local: selected.map(|identity| identity.map(|identity| identity.fingerprint)),
            environment,
        };
        // A shim this call ran must still be selected as it was. A version
        // reused from another task was checked by the task that ran it.
        if !probed_shims.is_empty() && !identity.is_unchanged_on_path(path) {
            for selection in &probed_shims {
                versions.forget(selection);
            }
            return None;
        }
        Some(identity)
    }

    /// The cache-key inputs, as `(name, value)` pairs.
    pub fn identities(&self) -> &[(String, String)] {
        &self.identities
    }

    /// The directory the runtimes were identified for.
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Whether `path` still selects the executables this identity captured,
    /// unchanged. Reads metadata and selector files only; runs nothing.
    pub fn is_unchanged_on_path(&self, path: &OsStr) -> bool {
        let executables =
            RUNTIMES.map(|runtime| runtime_executable_in_path(&self.cwd, path, runtime));
        identify(&self.cwd, path, &executables, &self.environment)
            .map(|identity| identity.map(|identity| identity.fingerprint))
            == self.local
    }
}

fn identify(
    cwd: &Path,
    path: &OsStr,
    executables: &[Option<PathBuf>; 2],
    environment: &SelectorEnvironment,
) -> [Option<ScriptNodeIdentity>; 2] {
    let roots = RUNTIMES.map(managed_runtime_root);
    script_runtime_identities(
        executables,
        cwd,
        path,
        [roots[0].as_deref(), roots[1].as_deref()],
        environment,
    )
}

/// A runtime binary by version, and by the architecture and C library its
/// header names. A binary under Rosetta or a foreign-libc container differs
/// from the host.
fn binary_identity(
    versions: &TaskRuntimeVersions,
    runtime: RuntimeKind,
    canonical: &Path,
) -> Option<String> {
    let version = versions.binary_version(runtime, canonical)?;
    let target = binary_target(canonical);
    let arch = target.map_or(std::env::consts::ARCH, |target| target.arch);
    let libc = target
        .and_then(|target| target.libc)
        .or_else(host_libc)
        .unwrap_or("-");
    Some(format!("version:{version} {arch}/{libc}"))
}

/// Whether a project environment variable named `name` can select the runtime
/// that a version manager's shim runs.
pub fn is_version_manager_variable(name: &str) -> bool {
    crate::node_identity::is_manager_variable(OsStr::new(name))
}

fn managed_runtime_root(runtime: RuntimeKind) -> Option<PathBuf> {
    crate::node::runtimes_dir()
        .ok()?
        .join(runtime.as_str())
        .canonicalize()
        .ok()
}

/// The host's operating system, CPU architecture, and C library, which every
/// key names: a task can build native code without Node or Bun. A run that
/// Rosetta translates builds a mix of x86_64 and arm64 code, so it gets an
/// architecture of its own.
fn host_platform() -> &'static str {
    static HOST_PLATFORM: OnceLock<String> = OnceLock::new();
    HOST_PLATFORM.get_or_init(|| {
        let arch = if lpm_common::platform::translated_by_rosetta() {
            "x86_64-rosetta"
        } else {
            std::env::consts::ARCH
        };
        format!(
            "{}/{arch}/{}",
            std::env::consts::OS,
            host_libc().unwrap_or("-")
        )
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_script(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A launcher named `node` in `bin` that reports `version` and appends a
    /// line to `bin/probes` each time it runs.
    fn write_launcher(bin: &Path, version: &str) -> PathBuf {
        let launcher = bin.join("node");
        write_script(
            &launcher,
            &format!(
                "echo probe >> '{}'\necho v{version}\n",
                bin.join("probes").display()
            ),
        );
        launcher
    }

    fn probes(bin: &Path) -> usize {
        std::fs::read_to_string(bin.join("probes")).map_or(0, |probes| probes.lines().count())
    }

    fn scope(root: &Path) -> TaskRuntimeScope<'_> {
        TaskRuntimeScope {
            workspace_root: root,
            project_variables: &[],
        }
    }

    fn capture_as(
        cwd: &Path,
        root: &Path,
        bin: &Path,
        kind: RuntimeExecutable,
        versions: &TaskRuntimeVersions,
    ) -> TaskRuntimeIdentity {
        TaskRuntimeIdentity::capture_with(
            cwd,
            bin.as_os_str(),
            scope(root),
            versions,
            |_, _, _, _| kind,
        )
        .unwrap()
    }

    /// Capture with `bin`'s launchers taken for version-manager shims.
    fn capture(cwd: &Path, bin: &Path) -> TaskRuntimeIdentity {
        capture_as(
            cwd,
            cwd,
            bin,
            RuntimeExecutable::VersionManagerShim,
            &TaskRuntimeVersions::default(),
        )
    }

    fn runtime(identity: &TaskRuntimeIdentity, name: &str) -> String {
        identity
            .identities()
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap()
    }

    #[test]
    fn same_version_at_other_paths_gives_the_same_identity() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_launcher(&first.path().join("bin"), "22.11.0");
        write_launcher(&second.path().join("tools/bin"), "22.11.0");

        let a = capture(first.path(), &first.path().join("bin"));
        let b = capture(second.path(), &second.path().join("tools/bin"));
        assert_eq!(a.identities(), b.identities());
        assert!(runtime(&a, "node-runtime").starts_with("version:22.11.0 shim-config:"));
        assert_eq!(runtime(&a, "bun-runtime"), "missing");
    }

    #[test]
    fn another_version_gives_another_identity() {
        let dir = tempfile::tempdir().unwrap();
        write_launcher(&dir.path().join("a"), "22.11.0");
        write_launcher(&dir.path().join("b"), "22.12.0");
        assert_ne!(
            capture(dir.path(), &dir.path().join("a")).identities(),
            capture(dir.path(), &dir.path().join("b")).identities()
        );
    }

    #[test]
    fn a_workspace_version_file_change_changes_a_shim_identity() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        write_launcher(&bin, "22.11.0");
        std::fs::write(
            dir.path().join("mise.toml"),
            "[env]\nNODE_ENV = 'production'\n",
        )
        .unwrap();
        let before = capture(dir.path(), &bin);
        std::fs::write(
            dir.path().join("mise.toml"),
            "[env]\nNODE_ENV = 'development'\n",
        )
        .unwrap();
        assert_ne!(before.identities(), capture(dir.path(), &bin).identities());
    }

    #[test]
    fn other_launchers_are_never_probed_and_keep_their_location() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let versions = TaskRuntimeVersions::default();
        for dir in [first.path(), second.path()] {
            write_launcher(&dir.join("bin"), "22.11.0");
        }
        let launcher = |dir: &Path| {
            capture_as(
                dir,
                dir,
                &dir.join("bin"),
                RuntimeExecutable::Launcher,
                &versions,
            )
        };
        let a = launcher(first.path());
        let b = launcher(second.path());
        assert_eq!(
            probes(&first.path().join("bin")),
            0,
            "a launcher must not run"
        );
        assert!(runtime(&a, "node-runtime").starts_with("local:"));
        assert_ne!(a.identities(), b.identities());
    }

    #[test]
    fn workspace_members_with_the_same_version_files_share_one_shim_probe() {
        let workspace = tempfile::tempdir().unwrap();
        let bin = workspace.path().join("bin");
        write_launcher(&bin, "22.11.0");
        let versions = TaskRuntimeVersions::default();
        for member in ["packages/a", "packages/b", "apps/web/c"] {
            let member = workspace.path().join(member);
            std::fs::create_dir_all(&member).unwrap();
            capture_as(
                &member,
                workspace.path(),
                &bin,
                RuntimeExecutable::VersionManagerShim,
                &versions,
            );
        }
        assert_eq!(probes(&bin), 1);
    }

    #[test]
    fn a_shim_whose_selection_changes_while_it_runs_gives_no_identity_and_is_probed_again() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let marker = dir.path().join("probed-once");
        // The first probe edits a version file, as an auto-install might.
        write_script(
            &bin.join("node"),
            &format!(
                "echo probe >> '{probes}'\nif [ ! -e '{marker}' ]; then touch '{marker}'; echo 20 > '{nvmrc}'; fi\necho v22.11.0\n",
                probes = bin.join("probes").display(),
                marker = marker.display(),
                nvmrc = dir.path().join(".nvmrc").display(),
            ),
        );
        let versions = TaskRuntimeVersions::default();
        let capture = || {
            TaskRuntimeIdentity::capture_with(
                dir.path(),
                bin.as_os_str(),
                scope(dir.path()),
                &versions,
                |_, _, _, _| RuntimeExecutable::VersionManagerShim,
            )
        };
        assert!(capture().is_none());
        assert!(capture().is_some());
        assert_eq!(probes(&bin), 2);
    }

    #[test]
    fn a_project_manager_variable_reaches_the_shim_probe() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        write_script(
            &bin.join("node"),
            "if [ -n \"$NODENV_VERSION\" ]; then echo \"v$NODENV_VERSION.0.0\"; else echo v99.0.0; fi\n",
        );
        let variables = [("NODENV_VERSION".into(), "18".into())];
        let identity = TaskRuntimeIdentity::capture_with(
            dir.path(),
            bin.as_os_str(),
            TaskRuntimeScope {
                workspace_root: dir.path(),
                project_variables: &variables,
            },
            &TaskRuntimeVersions::default(),
            |_, _, _, _| RuntimeExecutable::VersionManagerShim,
        )
        .unwrap();
        assert!(runtime(&identity, "node-runtime").starts_with("version:18.0.0 "));
    }

    #[test]
    fn identity_names_the_platform() {
        let dir = tempfile::tempdir().unwrap();
        let identity = capture(dir.path(), &dir.path().join("empty"));
        let platform = runtime(&identity, "task-platform");
        assert!(platform.starts_with(&format!("{}/", std::env::consts::OS)));
        if !lpm_common::platform::translated_by_rosetta() {
            assert!(platform.contains(&format!("/{}/", std::env::consts::ARCH)));
        }
        assert_eq!(runtime(&identity, "node-runtime"), "missing");
    }

    #[test]
    fn a_runtime_without_a_version_is_identified_by_this_executable_only() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        write_script(&bin.join("node"), "exit 1\n");
        assert!(runtime(&capture(dir.path(), &bin), "node-runtime").starts_with("local:"));
    }

    #[test]
    fn a_runtime_binary_is_probed_once_and_its_record_serves_later_commands() {
        let Ok(node) = std::process::Command::new("node")
            .args(["-p", "process.execPath"])
            .output()
        else {
            return;
        };
        let node = PathBuf::from(String::from_utf8(node.stdout).unwrap().trim());
        let records = tempfile::tempdir().unwrap();
        let versions = TaskRuntimeVersions::new(Some(RecordedNodeVersions::at(records.path())));
        let first = versions.binary_version(RuntimeKind::Node, &node).unwrap();
        assert_eq!(std::fs::read_dir(records.path()).unwrap().count(), 1);

        let later = TaskRuntimeVersions::new(Some(RecordedNodeVersions::at(records.path())));
        assert_eq!(later.binary_version(RuntimeKind::Node, &node), Some(first));
    }

    #[test]
    fn a_changed_or_newly_selected_runtime_is_detected_without_probing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let launcher = write_launcher(&bin, "22.11.0");
        let identity = capture(dir.path(), &bin);
        let probed = probes(&bin);
        assert!(identity.is_unchanged_on_path(bin.as_os_str()));

        std::fs::write(dir.path().join(".nvmrc"), "20\n").unwrap();
        assert!(
            !identity.is_unchanged_on_path(bin.as_os_str()),
            "a version selector change must invalidate a launcher's identity"
        );
        std::fs::remove_file(dir.path().join(".nvmrc")).unwrap();
        assert!(identity.is_unchanged_on_path(bin.as_os_str()));

        let earlier = dir.path().join("earlier");
        write_launcher(&earlier, "22.11.0");
        let path = std::env::join_paths([&earlier, &bin]).unwrap();
        assert!(
            !identity.is_unchanged_on_path(&path),
            "another selected executable must invalidate the identity"
        );
        assert_eq!(probes(&bin), probed, "a recheck must not run the runtime");

        std::fs::remove_file(launcher).unwrap();
        assert!(!identity.is_unchanged_on_path(bin.as_os_str()));
    }
}
