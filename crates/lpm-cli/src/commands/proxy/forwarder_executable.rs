//! Root-owned copy of the lpm executable that the privileged forwarder runs.
//!
//! The forwarder service starts as root, so it must never run an executable
//! the installing user can replace: that user, or anything running as them,
//! would get root the next time the service started. Installation copies the
//! running executable, or on macOS its whole signed app bundle, into a
//! directory only root can write, and the service runs that copy.

#![cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::proxy_platform::{run_checked_inherited, run_checked_output};
use lpm_common::LpmError;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// Where the privileged forwarder's executable is copied from and to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForwarderExecutable {
    /// What installation copies: a macOS app bundle or a plain executable.
    source: PathBuf,
    /// Root-owned directory that holds the copy.
    install_dir: PathBuf,
    /// Name of the copy inside `install_dir`.
    entry: OsString,
    /// Whether `source` is an app bundle that must be copied whole.
    app_bundle: bool,
    /// Path the forwarder service runs.
    installed_executable: PathBuf,
}

impl ForwarderExecutable {
    /// Plan a copy of the executable that is running now.
    pub(super) fn for_running_executable(install_dir: PathBuf) -> Result<Self, LpmError> {
        let executable = std::env::current_exe().map_err(LpmError::Io)?;
        let executable = std::fs::canonicalize(&executable).map_err(LpmError::Io)?;
        Ok(Self::plan(&executable, install_dir))
    }

    /// Plan a copy of `executable` into `install_dir`.
    ///
    /// An executable inside a macOS app bundle is copied with its bundle, since
    /// its code signature and provisioning profile live there.
    pub(super) fn plan(executable: &Path, install_dir: PathBuf) -> Self {
        if let Some(bundle) = enclosing_app_bundle(executable) {
            let entry = bundle
                .file_name()
                .expect("an app bundle path ends in its bundle name")
                .to_os_string();
            let inside_bundle = executable
                .strip_prefix(&bundle)
                .expect("the executable lies inside its enclosing bundle");
            let mut installed_executable = install_dir.join(&entry);
            installed_executable.push(inside_bundle);
            return Self {
                source: bundle,
                install_dir,
                entry,
                app_bundle: true,
                installed_executable,
            };
        }
        let entry = executable
            .file_name()
            .map_or_else(|| OsString::from("lpm"), |name| name.to_os_string());
        Self {
            source: executable.to_path_buf(),
            installed_executable: install_dir.join(&entry),
            install_dir,
            entry,
            app_bundle: false,
        }
    }

    pub(super) fn installed_executable(&self) -> &Path {
        &self.installed_executable
    }

    pub(super) fn install_dir(&self) -> &Path {
        &self.install_dir
    }
}

/// The `.app` bundle whose `Contents/MacOS` directory holds `executable`.
fn enclosing_app_bundle(executable: &Path) -> Option<PathBuf> {
    let macos_dir = executable.parent()?;
    let contents_dir = macos_dir.parent()?;
    let bundle = contents_dir.parent()?;
    (macos_dir.file_name()? == "MacOS"
        && contents_dir.file_name()? == "Contents"
        && bundle.extension()? == "app")
        .then(|| bundle.to_path_buf())
}

/// Refuse a path that someone other than root could change.
///
/// `path`, if it exists, and every directory on its canonical path must be
/// owned by root and not writable by group or others. Missing trailing
/// components are skipped: installation creates them as root.
#[cfg(unix)]
pub(super) fn require_root_controlled(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::MetadataExt;

    require_root_controlled_with(path, |path| {
        std::fs::metadata(path).map(|metadata| (metadata.uid(), metadata.mode()))
    })
}

#[cfg(unix)]
fn require_root_controlled_with(
    path: &Path,
    owner_and_mode: impl Fn(&Path) -> std::io::Result<(u32, u32)>,
) -> Result<(), LpmError> {
    let existing = path
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .unwrap_or_else(|| Path::new("/"));
    let existing = std::fs::canonicalize(existing).map_err(LpmError::Io)?;
    for component in existing.ancestors() {
        let (owner, mode) = owner_and_mode(component).map_err(|error| {
            LpmError::Script(format!("inspect {}: {error}", component.display()))
        })?;
        if owner != 0 || mode & 0o022 != 0 {
            return Err(LpmError::Script(format!(
                "{} must be owned by root and not writable by group or others (owner UID {owner}, mode {:o})",
                component.display(),
                mode & 0o7777
            )));
        }
    }
    Ok(())
}

/// The executable an installed privileged forwarder runs, when a non-root
/// user could replace it. Forwarders installed by earlier releases run the
/// installing user's own executable.
#[cfg(unix)]
pub(super) fn replaceable_forwarder_executable(config_path: &Path) -> Option<PathBuf> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InstalledForwarder {
        binary_path: PathBuf,
    }

    let bytes =
        lpm_common::read_file_capped(config_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES).ok()?;
    let installed: InstalledForwarder = serde_json::from_slice(&bytes).ok()?;
    require_root_controlled(&installed.binary_path)
        .is_err()
        .then_some(installed.binary_path)
}

/// Copy the planned executable into its root-owned directory, replacing any
/// earlier copy only after the new one is complete.
#[cfg(any(target_os = "linux", target_os = "macos"))]
///
/// `privileged` runs each step with root rights (`sudo` in production). The
/// copy is assembled in a root-only staging directory and handed to root
/// before it becomes visible at its final path.
pub(super) fn install_forwarder_executable(
    executable: &ForwarderExecutable,
    privileged: &Path,
) -> Result<(), LpmError> {
    let install_dir = &executable.install_dir;
    run_checked_inherited(
        Command::new(privileged)
            .arg("mkdir")
            .arg("-p")
            .arg(install_dir),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chown", "0:0"])
            .arg(install_dir),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "0755"])
            .arg(install_dir),
    )?;

    let staging_template = install_dir.join(".staging.XXXXXX");
    let staging = run_checked_output(
        Command::new(privileged)
            .args(["mktemp", "-d"])
            .arg(&staging_template),
    )?;
    let staging = PathBuf::from(String::from_utf8_lossy(&staging.stdout).trim());
    if staging.parent() != Some(install_dir.as_path()) {
        return Err(LpmError::Script(format!(
            "mktemp created {} outside {}",
            staging.display(),
            install_dir.display()
        )));
    }

    let installed = install_staged_copy(executable, privileged, &staging);
    let cleanup = run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&staging));
    installed.and(cleanup)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_staged_copy(
    executable: &ForwarderExecutable,
    privileged: &Path,
    staging: &Path,
) -> Result<(), LpmError> {
    let staged = staging.join(&executable.entry);
    if executable.app_bundle {
        // ditto keeps the bundle's code signature intact; extended attributes,
        // resource forks, and quarantine flags are not part of it.
        run_checked_inherited(
            Command::new(privileged)
                .args(["ditto", "--noextattr", "--norsrc", "--noqtn"])
                .arg(&executable.source)
                .arg(&staged),
        )?;
    } else {
        run_checked_inherited(
            Command::new(privileged)
                .args(["install", "-m", "0755"])
                .arg(&executable.source)
                .arg(&staged),
        )?;
    }
    run_checked_inherited(
        Command::new(privileged)
            .args(["chown", "-R", "0:0"])
            .arg(staging),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "-R", "go-w"])
            .arg(staging),
    )?;
    if executable.app_bundle {
        run_checked_inherited(
            Command::new(privileged)
                .args(["codesign", "--verify", "--strict"])
                .arg(&staged),
        )?;
    }

    let destination = executable.install_dir.join(&executable.entry);
    let mut previous_name = OsString::from(".previous.");
    previous_name.push(&executable.entry);
    let previous = executable.install_dir.join(previous_name);
    run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&previous))?;
    if std::fs::symlink_metadata(&destination).is_ok() {
        run_checked_inherited(
            Command::new(privileged)
                .arg("mv")
                .arg(&destination)
                .arg(&previous),
        )?;
    }
    run_checked_inherited(
        Command::new(privileged)
            .arg("mv")
            .arg(&staged)
            .arg(&destination),
    )?;
    run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&previous))
}

/// Remove the root-owned executable copy and its directory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn uninstall_forwarder_executable(
    install_dir: &Path,
    privileged: &Path,
) -> Result<(), LpmError> {
    run_checked_inherited(
        Command::new(privileged)
            .args(["rm", "-rf"])
            .arg(install_dir),
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn plan_copies_the_whole_macos_app_bundle_that_holds_the_executable() {
        let plan = ForwarderExecutable::plan(
            Path::new(
                "/Users/dev/lib/node_modules/@lpm-registry/cli-darwin-arm64/LPM CLI.app/Contents/MacOS/lpm-rs",
            ),
            PathBuf::from("/Library/Application Support/LPM/Forwarder"),
        );

        assert!(plan.app_bundle);
        assert_eq!(
            plan.source,
            Path::new("/Users/dev/lib/node_modules/@lpm-registry/cli-darwin-arm64/LPM CLI.app")
        );
        assert_eq!(plan.entry, "LPM CLI.app");
        assert_eq!(
            plan.installed_executable(),
            Path::new(
                "/Library/Application Support/LPM/Forwarder/LPM CLI.app/Contents/MacOS/lpm-rs"
            )
        );
    }

    #[test]
    fn plan_copies_a_plain_executable_under_its_own_name() {
        let plan = ForwarderExecutable::plan(
            Path::new("/home/dev/.lpm/bin/lpm"),
            PathBuf::from("/opt/lpm/proxy-forwarder"),
        );

        assert!(!plan.app_bundle);
        assert_eq!(plan.source, Path::new("/home/dev/.lpm/bin/lpm"));
        assert_eq!(
            plan.installed_executable(),
            Path::new("/opt/lpm/proxy-forwarder/lpm")
        );
    }

    #[test]
    fn plan_does_not_treat_a_lookalike_path_as_an_app_bundle() {
        for executable in [
            "/opt/tools/Contents/MacOS/lpm-rs",
            "/opt/LPM CLI.app/MacOS/lpm-rs",
            "/opt/LPM CLI.app/Contents/bin/lpm-rs",
        ] {
            let plan =
                ForwarderExecutable::plan(Path::new(executable), PathBuf::from("/opt/forwarder"));
            assert!(!plan.app_bundle, "{executable}");
        }
    }

    #[test]
    fn install_dir_check_rejects_directories_other_users_can_change() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("forwarder");
        let canonical_root = std::fs::canonicalize(dir.path()).unwrap();

        for (label, owner, mode) in [
            ("owned by a user", 501, 0o40755),
            ("group writable", 0, 0o40775),
            ("world writable", 0, 0o40757),
        ] {
            let error = require_root_controlled_with(&install_dir, |path| {
                Ok(if path == canonical_root {
                    (owner, mode)
                } else {
                    (0, 0o40755)
                })
            })
            .expect_err(label);
            assert!(
                error.to_string().contains("must be owned by root"),
                "{label}: {error}"
            );
        }

        require_root_controlled_with(&install_dir, |_| Ok((0, 0o40755)))
            .expect("a root-owned 0755 chain is accepted");
    }

    #[test]
    fn install_dir_check_rejects_the_installing_users_own_directories() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: `geteuid` only reads the process credentials.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let error = require_root_controlled(&dir.path().join("forwarder"))
            .expect_err("a user-owned temporary directory is not root-controlled");

        assert!(
            error.to_string().contains("must be owned by root"),
            "{error}"
        );
    }

    #[test]
    fn an_installed_forwarder_running_a_user_writable_executable_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: `geteuid` only reads the process credentials.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let config = dir.path().join("proxy-forwarder.json");
        let user_executable = dir.path().join("lpm");
        std::fs::write(&user_executable, "build").unwrap();

        std::fs::write(
            &config,
            serde_json::json!({"targetUid": 501, "binaryPath": user_executable}).to_string(),
        )
        .unwrap();
        assert_eq!(
            replaceable_forwarder_executable(&config),
            Some(user_executable)
        );

        std::fs::write(
            &config,
            serde_json::json!({"targetUid": 501, "binaryPath": "/bin/sh"}).to_string(),
        )
        .unwrap();
        assert_eq!(replaceable_forwarder_executable(&config), None);

        assert_eq!(
            replaceable_forwarder_executable(&dir.path().join("missing.json")),
            None
        );
    }

    /// Stands in for `sudo`: runs each step as the current user, and skips the
    /// steps that need root or a signed bundle.
    fn fake_privileged_runner(directory: &Path) -> PathBuf {
        let path = directory.join("privileged");
        std::fs::write(
            &path,
            "#!/bin/sh\ncase \"$1\" in chown|codesign) exit 0 ;; esac\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn install_replaces_an_earlier_copy_and_leaves_no_staging_behind() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path());
        let source = dir.path().join("lpm");
        let install_dir = dir.path().join("root/proxy-forwarder");
        let plan = ForwarderExecutable::plan(&source, install_dir.clone());

        std::fs::write(&source, "first build").unwrap();
        install_forwarder_executable(&plan, &privileged).unwrap();
        std::fs::write(&source, "second build").unwrap();
        install_forwarder_executable(&plan, &privileged).unwrap();

        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "second build"
        );
        let mode = std::fs::metadata(plan.installed_executable())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        let leftovers: Vec<_> = std::fs::read_dir(&install_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "lpm")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_failed_copy_keeps_the_earlier_copy_and_removes_its_staging() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path());
        let source = dir.path().join("lpm");
        let install_dir = dir.path().join("root/proxy-forwarder");
        let plan = ForwarderExecutable::plan(&source, install_dir.clone());
        std::fs::write(&source, "working build").unwrap();
        install_forwarder_executable(&plan, &privileged).unwrap();

        std::fs::remove_file(&source).unwrap();
        install_forwarder_executable(&plan, &privileged)
            .expect_err("copying a missing executable must fail");

        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "working build"
        );
        assert_eq!(std::fs::read_dir(&install_dir).unwrap().count(), 1);
    }

    #[test]
    fn uninstall_removes_the_copy_and_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path());
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan = ForwarderExecutable::plan(&source, dir.path().join("root/proxy-forwarder"));
        install_forwarder_executable(&plan, &privileged).unwrap();

        uninstall_forwarder_executable(plan.install_dir(), &privileged).unwrap();

        assert!(!plan.install_dir().exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_copies_the_whole_app_bundle_on_macos() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path());
        let bundle = dir.path().join("LPM CLI.app");
        std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        std::fs::create_dir_all(bundle.join("Contents/_CodeSignature")).unwrap();
        std::fs::write(bundle.join("Contents/MacOS/lpm-rs"), "binary").unwrap();
        std::fs::write(bundle.join("Contents/embedded.provisionprofile"), "profile").unwrap();
        std::fs::write(bundle.join("Contents/_CodeSignature/CodeResources"), "seal").unwrap();
        let plan = ForwarderExecutable::plan(
            &bundle.join("Contents/MacOS/lpm-rs"),
            dir.path().join("root/Forwarder"),
        );

        install_forwarder_executable(&plan, &privileged).unwrap();

        let copy = plan.install_dir().join("LPM CLI.app");
        for file in [
            "Contents/MacOS/lpm-rs",
            "Contents/embedded.provisionprofile",
            "Contents/_CodeSignature/CodeResources",
        ] {
            assert!(copy.join(file).is_file(), "{file}");
        }
        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "binary"
        );
    }
}
