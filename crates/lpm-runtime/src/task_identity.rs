//! The runtimes a task-cache key covers, identified so that machines can share
//! the key.

use crate::detect::RuntimeKind;
use crate::effective::{
    PathNodeVersionCache, PathRuntime, identify_path_runtimes, probe_script_runtime_fingerprints,
    runtime_executable_in_path,
};
use crate::node_identity::RuntimeExecutable;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

const RUNTIMES: [RuntimeKind; 2] = [RuntimeKind::Node, RuntimeKind::Bun];

/// The Node and Bun that a task's `PATH` selects, by version and platform.
///
/// A runtime binary or a version manager's shim is identified by the release
/// it runs, so the same release on the same platform gives the same identity
/// wherever it is installed. Any other launcher is identified by its local
/// fingerprint, which covers its location, the script `PATH`, and the working
/// directory.
///
/// Each selected executable's local fingerprint is kept too: it changes when
/// the executable or its version selectors do, so a key can be rechecked
/// before a restore or an upload without probing versions again.
#[derive(Debug, Clone)]
pub struct TaskRuntimeIdentity {
    identities: Vec<(String, String)>,
    cwd: PathBuf,
    local: [Option<String>; 2],
}

impl TaskRuntimeIdentity {
    /// Identify the runtimes `path` selects for a task in `cwd`. `None` when
    /// a selected executable can't be identified, or changes while its version
    /// is probed.
    ///
    /// `versions` is locked only to reuse or probe a version, so tasks that
    /// share it identify their runtimes concurrently.
    pub fn capture(
        cwd: &Path,
        path: &OsStr,
        versions: &Mutex<PathNodeVersionCache>,
    ) -> Option<Self> {
        Self::capture_with(cwd, path, versions, PathRuntime::kind)
    }

    fn capture_with(
        cwd: &Path,
        path: &OsStr,
        versions: &Mutex<PathNodeVersionCache>,
        classify: impl Fn(&PathRuntime) -> RuntimeExecutable,
    ) -> Option<Self> {
        let selected = identify_path_runtimes(cwd, path);
        let mut identities = Vec::with_capacity(RUNTIMES.len() + 1);
        identities.push(("task-platform".to_string(), platform_identity()));
        let mut local = [None, None];
        for ((runtime, selected), local) in RUNTIMES.into_iter().zip(&selected).zip(&mut local) {
            let identity = match selected {
                None if runtime_executable_in_path(cwd, path, runtime).is_some() => return None,
                None => "missing".to_string(),
                Some(selected) => {
                    let fingerprint = selected.fingerprint();
                    *local = Some(fingerprint.to_string());
                    match classify(selected) {
                        RuntimeExecutable::Launcher => format!("local:{fingerprint}"),
                        RuntimeExecutable::Binary | RuntimeExecutable::VersionManagerShim => {
                            let mut versions =
                                versions.lock().unwrap_or_else(PoisonError::into_inner);
                            let resolution = versions.resolve_identified(cwd, path, selected);
                            versions.finish_recordings();
                            drop(versions);
                            if resolution.runtime_fingerprint() != Some(fingerprint) {
                                return None;
                            }
                            match resolution.version() {
                                Some(version) => format!("version:{version}"),
                                // Without a version, only this executable can
                                // vouch for the result.
                                None => format!("local:{fingerprint}"),
                            }
                        }
                    }
                }
            };
            identities.push((format!("{}-runtime", runtime.as_str()), identity));
        }
        Some(Self {
            identities,
            cwd: cwd.to_path_buf(),
            local,
        })
    }

    /// The cache-key inputs, as `(name, value)` pairs.
    pub fn identities(&self) -> &[(String, String)] {
        &self.identities
    }

    /// Whether `path` still selects the executables this identity captured,
    /// unchanged. Reads metadata and selector files only; runs nothing.
    pub fn is_unchanged_on_path(&self, path: &OsStr) -> bool {
        probe_script_runtime_fingerprints(&self.cwd, path) == self.local
    }
}

fn platform_identity() -> String {
    format!(
        "{}/{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        lpm_common::platform::detect_libc().unwrap_or("-")
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A launcher named `node` that reports `version`.
    fn write_launcher(bin: &Path, version: &str) -> PathBuf {
        std::fs::create_dir_all(bin).unwrap();
        let launcher = bin.join("node");
        std::fs::write(&launcher, format!("#!/bin/sh\necho v{version}\n")).unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        launcher
    }

    fn capture_as(cwd: &Path, bin: &Path, kind: RuntimeExecutable) -> TaskRuntimeIdentity {
        TaskRuntimeIdentity::capture_with(cwd, bin.as_os_str(), &Mutex::default(), |_| kind)
            .unwrap()
    }

    /// Capture with `bin`'s launchers taken for version-manager shims.
    fn capture(cwd: &Path, bin: &Path) -> TaskRuntimeIdentity {
        capture_as(cwd, bin, RuntimeExecutable::VersionManagerShim)
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
        assert_eq!(runtime(&a, "node-runtime"), "version:22.11.0");
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
    fn other_launchers_keep_their_location_and_skip_the_version_probe() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        // A probe of this launcher would fail the test: it never reports a version.
        for dir in [first.path(), second.path()] {
            let bin = dir.join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::write(bin.join("node"), "#!/bin/sh\nexit 1\n").unwrap();
            std::fs::set_permissions(bin.join("node"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let a = capture_as(
            first.path(),
            &first.path().join("bin"),
            RuntimeExecutable::Launcher,
        );
        let b = capture_as(
            second.path(),
            &second.path().join("bin"),
            RuntimeExecutable::Launcher,
        );
        assert!(runtime(&a, "node-runtime").starts_with("local:"));
        assert_ne!(a.identities(), b.identities());
    }

    #[test]
    fn identity_names_the_platform() {
        let dir = tempfile::tempdir().unwrap();
        let identity = capture(dir.path(), &dir.path().join("empty"));
        let platform = runtime(&identity, "task-platform");
        assert!(platform.starts_with(&format!(
            "{}/{}/",
            std::env::consts::OS,
            std::env::consts::ARCH
        )));
        assert_eq!(runtime(&identity, "node-runtime"), "missing");
    }

    #[test]
    fn a_runtime_without_a_version_is_identified_by_this_executable_only() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let launcher = bin.join("node");
        std::fs::write(&launcher, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(runtime(&capture(dir.path(), &bin), "node-runtime").starts_with("local:"));
    }

    #[test]
    fn a_changed_or_newly_selected_runtime_is_detected_without_probing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let launcher = write_launcher(&bin, "22.11.0");
        let identity = capture(dir.path(), &bin);
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

        std::fs::remove_file(launcher).unwrap();
        assert!(!identity.is_unchanged_on_path(bin.as_os_str()));
    }
}
