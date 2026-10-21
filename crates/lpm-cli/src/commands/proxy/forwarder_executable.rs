//! Root-owned copy of the lpm executable that the privileged forwarder runs.
//!
//! The forwarder service starts as root, so it must never run an executable
//! the installing user can change: that user, or anything running as them,
//! would get root the next time the service started. Installation copies the
//! running executable, or on macOS its whole signed app bundle, into a
//! directory only root can write, strips every way the copy could stay
//! writable (ACLs, setuid and setgid bits, group and other write), verifies
//! the result, and only then lets the service run it.

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

    /// Describe an existing installation for removal. Only `install_dir` is
    /// meaningful, so this works even when the running executable is gone.
    pub(super) fn for_removal(install_dir: PathBuf) -> Self {
        Self {
            source: PathBuf::new(),
            installed_executable: install_dir.clone(),
            install_dir,
            entry: OsString::new(),
            app_bundle: false,
        }
    }

    /// Plan a copy of `executable` into `install_dir`.
    ///
    /// On macOS, an executable inside an app bundle is copied with its bundle,
    /// since its code signature and provisioning profile live there.
    pub(super) fn plan(executable: &Path, install_dir: PathBuf) -> Self {
        Self::plan_with(executable, install_dir, cfg!(target_os = "macos"))
    }

    fn plan_with(executable: &Path, install_dir: PathBuf, app_bundles: bool) -> Self {
        if let Some(bundle) = app_bundles
            .then(|| enclosing_app_bundle(executable))
            .flatten()
        {
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
/// `path`, if it exists, and every directory leading to it must be owned by
/// root and not writable by group or others, both along the path as written
/// and along its canonical form. A symlink on the way must itself be owned by
/// root. Missing trailing components are skipped: installation creates them.
#[cfg(unix)]
pub(super) fn require_root_controlled(path: &Path) -> Result<(), LpmError> {
    require_trusted_path(path, 0)
}

/// Like [`require_root_controlled`], also accepting `trusted_owner`, which is
/// root in production and the test user in tests.
#[cfg(unix)]
fn require_trusted_path(path: &Path, trusted_owner: u32) -> Result<(), LpmError> {
    use std::os::unix::fs::MetadataExt;

    let inspect = |component: &Path| -> Result<(), LpmError> {
        let metadata = std::fs::symlink_metadata(component).map_err(|error| {
            LpmError::Script(format!("inspect {}: {error}", component.display()))
        })?;
        let owner = metadata.uid();
        let mode = metadata.mode();
        let trusted = owner == 0 || owner == trusted_owner;
        if !trusted || (!metadata.file_type().is_symlink() && mode & 0o022 != 0) {
            return Err(LpmError::Script(format!(
                "{} must be owned by root and not writable by group or others (owner UID {owner}, mode {:o})",
                component.display(),
                mode & 0o7777
            )));
        }
        Ok(())
    };

    let literal = path
        .ancestors()
        .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())
        .unwrap_or_else(|| Path::new("/"));
    for component in literal
        .ancestors()
        .filter(|component| !component.as_os_str().is_empty())
    {
        inspect(component)?;
    }
    let canonical = std::fs::canonicalize(literal).map_err(LpmError::Io)?;
    for component in canonical.ancestors() {
        inspect(component)?;
    }
    Ok(())
}

/// What `lpm proxy status` should say about an installed privileged
/// forwarder: it starts as root from a path a non-root user can replace
/// (installs from earlier releases), or it runs an older lpm than this one.
#[cfg(unix)]
pub(super) fn installed_forwarder_notice(config_path: &Path) -> Option<String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InstalledForwarder {
        binary_path: PathBuf,
        #[serde(default)]
        lpm_version: Option<String>,
    }

    let bytes =
        lpm_common::read_file_capped(config_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES).ok()?;
    let installed: InstalledForwarder = serde_json::from_slice(&bytes).ok()?;
    if require_root_controlled(&installed.binary_path).is_err() {
        return Some(format!(
            "the privileged forwarder starts as root from {}, which a non-root user can replace; run `lpm proxy install --privileged-ports` to install a root-owned copy",
            installed.binary_path.display()
        ));
    }
    let current = env!("CARGO_PKG_VERSION");
    match installed.lpm_version {
        Some(version) if version != current => Some(format!(
            "the privileged forwarder runs lpm {version}; run `lpm proxy install --privileged-ports` to update it to {current}"
        )),
        _ => None,
    }
}

/// Copy the planned executable into its root-owned directory, replacing any
/// earlier copy only after the new one is complete and verified.
///
/// `privileged` runs each step with root rights (`sudo` in production). The
/// copy is assembled in a root-only staging directory, stripped of ACLs,
/// setuid and setgid bits, and group or other write access, verified, and
/// only then moved to its final path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn install_forwarder_executable(
    executable: &ForwarderExecutable,
    privileged: &Path,
) -> Result<(), LpmError> {
    install_forwarder_executable_trusting(executable, privileged, 0)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_forwarder_executable_trusting(
    executable: &ForwarderExecutable,
    privileged: &Path,
    trusted_owner: u32,
) -> Result<(), LpmError> {
    let install_dir = &executable.install_dir;
    create_root_owned_directory(install_dir, privileged)?;
    require_trusted_path(install_dir, trusted_owner)?;

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

    let installed = install_staged_copy(executable, privileged, &staging, trusted_owner);
    let cleanup = run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&staging));
    installed?;
    cleanup?;
    remove_stale_entries(executable, privileged)
}

/// Create each missing directory of `install_dir` as root with mode 0755, so
/// none inherits a permissive umask, and reset the final directory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_root_owned_directory(install_dir: &Path, privileged: &Path) -> Result<(), LpmError> {
    let missing: Vec<&Path> = install_dir
        .ancestors()
        .take_while(|ancestor| std::fs::symlink_metadata(ancestor).is_err())
        .collect();
    for directory in missing.into_iter().rev() {
        run_checked_inherited(
            Command::new(privileged)
                .args(["mkdir", "-m", "0755"])
                .arg(directory),
        )?;
        run_checked_inherited(
            Command::new(privileged)
                .args(["chown", "0:0"])
                .arg(directory),
        )?;
    }
    run_checked_inherited(
        Command::new(privileged)
            .args(["chown", "0:0"])
            .arg(install_dir),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "0755"])
            .arg(install_dir),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_staged_copy(
    executable: &ForwarderExecutable,
    privileged: &Path,
    staging: &Path,
    trusted_owner: u32,
) -> Result<(), LpmError> {
    let staged = staging.join(&executable.entry);
    if executable.app_bundle {
        // ditto keeps the bundle's code signature intact; extended attributes,
        // resource forks, and quarantine flags are not part of it.
        run_checked_inherited(
            Command::new(privileged)
                .args(["/usr/bin/ditto", "--noextattr", "--norsrc", "--noqtn"])
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
    // Copies keep the source's explicit ACLs on macOS, and those survive both
    // chown and chmod; a user-granted write ACL would leave the copy writable.
    #[cfg(target_os = "macos")]
    run_checked_inherited(Command::new(privileged).args(["chmod", "-RN"]).arg(staging))?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chown", "-R", "0:0"])
            .arg(staging),
    )?;
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "-R", "u-s,g-s,go-w"])
            .arg(staging),
    )?;
    // Let the installing user read, but not change, the staged copy to verify it.
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "0755"])
            .arg(staging),
    )?;
    verify_staged_copy(&staged, trusted_owner)?;
    #[cfg(target_os = "macos")]
    if executable.app_bundle {
        verify_macos_bundle_signature(&staged, privileged)?;
    }
    swap_into_place(executable, privileged, &staged)
}

/// Check every entry of the staged copy: directories and regular files only,
/// owned by root, no group or other write, no setuid or setgid, and on macOS
/// no ACL.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_staged_copy(staged: &Path, trusted_owner: u32) -> Result<(), LpmError> {
    use std::os::unix::fs::MetadataExt;

    let mut pending = vec![staged.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            LpmError::Script(format!("inspect staged {}: {error}", path.display()))
        })?;
        let owner = metadata.uid();
        let mode = metadata.mode();
        let kind_allowed = metadata.is_dir() || metadata.is_file();
        if !kind_allowed
            || (owner != 0 && owner != trusted_owner)
            || mode & 0o6022 != 0
            || has_extended_acl(&path)?
        {
            return Err(LpmError::Script(format!(
                "the staged forwarder executable {} is not safe for root to run (owner UID {owner}, mode {:o})",
                path.display(),
                mode & 0o7777
            )));
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).map_err(LpmError::Io)? {
                pending.push(entry.map_err(LpmError::Io)?.path());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn has_extended_acl(path: &Path) -> Result<bool, LpmError> {
    use std::os::unix::ffi::OsStrExt;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    unsafe extern "C" {
        fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| LpmError::Script(format!("path contains a NUL byte: {}", path.display())))?;
    // SAFETY: `path_c` is a valid NUL-terminated path for the duration of the call.
    let acl = unsafe { acl_get_link_np(path_c.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(LpmError::Script(format!(
                "read the ACL of {}: {error}",
                path.display()
            ))),
        };
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is a live ACL returned above and `entry` is valid storage.
    let has_entry = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
    // SAFETY: `acl` came from `acl_get_link_np` and is freed exactly once.
    unsafe { acl_free(acl) };
    Ok(has_entry)
}

/// `install -m` copies neither ACLs nor extended attributes on Linux.
#[cfg(target_os = "linux")]
fn has_extended_acl(_path: &Path) -> Result<bool, LpmError> {
    Ok(false)
}

/// Require the staged bundle to carry LPM's own Developer ID signature, not
/// merely any valid one.
#[cfg(target_os = "macos")]
fn verify_macos_bundle_signature(staged: &Path, privileged: &Path) -> Result<(), LpmError> {
    let requirement = format!(
        r#"=anchor apple generic and identifier "{}" and certificate leaf[subject.OU] = "{}""#,
        crate::commands::self_update::MACOS_EXPECTED_BUNDLE_ID,
        crate::commands::self_update::MACOS_EXPECTED_TEAM_ID,
    );
    run_checked_inherited(
        Command::new(privileged)
            .args(["/usr/bin/codesign", "--verify", "--strict"])
            .arg(format!("--test-requirement={requirement}"))
            .arg(staged),
    )
}

/// Move the verified copy to its final path. A plain executable replaces the
/// earlier one in a single rename; a bundle directory moves the earlier copy
/// aside first and restores it if the move fails.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn swap_into_place(
    executable: &ForwarderExecutable,
    privileged: &Path,
    staged: &Path,
) -> Result<(), LpmError> {
    let destination = executable.install_dir.join(&executable.entry);
    if !executable.app_bundle {
        return run_checked_inherited(
            Command::new(privileged)
                .args(["mv", "-f"])
                .arg(staged)
                .arg(&destination),
        );
    }
    let mut previous_name = OsString::from(".previous.");
    previous_name.push(&executable.entry);
    let previous = executable.install_dir.join(previous_name);
    run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&previous))?;
    let had_previous = std::fs::symlink_metadata(&destination).is_ok();
    if had_previous {
        run_checked_inherited(
            Command::new(privileged)
                .arg("mv")
                .arg(&destination)
                .arg(&previous),
        )?;
    }
    if let Err(error) = run_checked_inherited(
        Command::new(privileged)
            .arg("mv")
            .arg(staged)
            .arg(&destination),
    ) {
        if had_previous {
            let _ = run_checked_inherited(
                Command::new(privileged)
                    .arg("mv")
                    .arg(&previous)
                    .arg(&destination),
            );
        }
        return Err(error);
    }
    run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&previous))
}

/// Remove anything in the install directory besides the current copy: copies
/// under an earlier name and staging left by an interrupted install.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_stale_entries(
    executable: &ForwarderExecutable,
    privileged: &Path,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(&executable.install_dir).map_err(LpmError::Io)? {
        let entry = entry.map_err(LpmError::Io)?;
        if entry.file_name() != executable.entry {
            run_checked_inherited(
                Command::new(privileged)
                    .args(["rm", "-rf"])
                    .arg(entry.path()),
            )?;
        }
    }
    Ok(())
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

    fn current_uid() -> u32 {
        // SAFETY: `geteuid` only reads the process credentials.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn plan_copies_the_whole_macos_app_bundle_that_holds_the_executable() {
        let plan = ForwarderExecutable::plan_with(
            Path::new(
                "/Users/dev/lib/node_modules/@lpm-registry/cli-darwin-arm64/LPM CLI.app/Contents/MacOS/lpm-rs",
            ),
            PathBuf::from("/Library/Application Support/LPM/Forwarder"),
            true,
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
    fn plan_treats_a_bundle_layout_as_a_plain_executable_where_bundles_do_not_apply() {
        let plan = ForwarderExecutable::plan_with(
            Path::new("/opt/tools/LPM CLI.app/Contents/MacOS/lpm-rs"),
            PathBuf::from("/opt/lpm/proxy-forwarder"),
            false,
        );

        assert!(!plan.app_bundle);
        assert_eq!(
            plan.installed_executable(),
            Path::new("/opt/lpm/proxy-forwarder/lpm-rs")
        );
    }

    #[test]
    fn plan_copies_a_plain_executable_under_its_own_name() {
        let plan = ForwarderExecutable::plan_with(
            Path::new("/home/dev/.lpm/bin/lpm"),
            PathBuf::from("/opt/lpm/proxy-forwarder"),
            true,
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
            let plan = ForwarderExecutable::plan_with(
                Path::new(executable),
                PathBuf::from("/opt/forwarder"),
                true,
            );
            assert!(!plan.app_bundle, "{executable}");
        }
    }

    #[test]
    fn trusted_path_check_rejects_directories_others_can_write() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o775, 0o757] {
            let directory = dir.path().join(format!("mode-{mode:o}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();

            let error = require_trusted_path(&directory.join("forwarder"), current_uid())
                .expect_err("a group or world writable directory is not trusted");
            assert!(
                error.to_string().contains("must be owned by root"),
                "{error}"
            );
        }

        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        require_trusted_path(&private.join("forwarder"), current_uid())
            .expect("a 0755 directory of the trusted owner is accepted");
    }

    #[test]
    fn root_controlled_check_rejects_the_installing_users_own_directories() {
        if current_uid() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();

        let error = require_root_controlled(&dir.path().join("forwarder"))
            .expect_err("a user-owned temporary directory is not root-controlled");

        assert!(
            error.to_string().contains("must be owned by root"),
            "{error}"
        );
    }

    #[test]
    fn status_notice_flags_replaceable_and_outdated_forwarders() {
        if current_uid() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("proxy-forwarder.json");
        let user_executable = dir.path().join("lpm");
        std::fs::write(&user_executable, "build").unwrap();
        let write_config = |binary: &Path, version: Option<&str>| {
            let mut value = serde_json::json!({"targetUid": 501, "binaryPath": binary});
            if let Some(version) = version {
                value["lpmVersion"] = version.into();
            }
            std::fs::write(&config, value.to_string()).unwrap();
        };

        write_config(&user_executable, None);
        let notice = installed_forwarder_notice(&config).expect("a user-writable executable");
        assert!(notice.contains("a non-root user can replace"), "{notice}");

        write_config(Path::new("/bin/sh"), Some("0.1.0"));
        let notice = installed_forwarder_notice(&config).expect("an outdated forwarder");
        assert!(notice.contains("runs lpm 0.1.0"), "{notice}");

        write_config(Path::new("/bin/sh"), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(installed_forwarder_notice(&config), None);

        assert_eq!(
            installed_forwarder_notice(&dir.path().join("missing.json")),
            None
        );
    }

    /// Stands in for `sudo`: runs each step as the current user, skipping
    /// steps that need root or a signed bundle plus any listed in `skip`.
    fn fake_privileged_runner(directory: &Path, skip: &str) -> PathBuf {
        let path = directory.join("privileged");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in chown|/usr/bin/codesign{skip}) exit 0 ;; esac\n\
                 if [ \"$1\" = mv ] && [ -n \"$FAIL_MV_FROM_STAGING\" ]; then\n\
                   case \"$2\" in */.staging.*) exit 1 ;; esac\n\
                 fi\n\
                 exec \"$@\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn install(plan: &ForwarderExecutable, privileged: &Path) -> Result<(), LpmError> {
        install_forwarder_executable_trusting(plan, privileged, current_uid())
    }

    #[test]
    fn install_replaces_an_earlier_copy_and_clears_stale_entries() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        let install_dir = dir.path().join("root/proxy-forwarder");
        let plan = ForwarderExecutable::plan_with(&source, install_dir.clone(), false);

        std::fs::write(&source, "first build").unwrap();
        install(&plan, &privileged).unwrap();
        std::fs::write(install_dir.join("lpm-rs"), "copy under an earlier name").unwrap();
        std::fs::create_dir(install_dir.join(".staging.interrupted")).unwrap();
        std::fs::write(&source, "second build").unwrap();
        install(&plan, &privileged).unwrap();

        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "second build"
        );
        let entries: Vec<_> = std::fs::read_dir(&install_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from("lpm")]);
        let install_dir_mode = std::fs::metadata(&install_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(install_dir_mode & 0o777, 0o755);
    }

    #[test]
    fn install_strips_setuid_bits_and_acls_from_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o6775)).unwrap();
        #[cfg(target_os = "macos")]
        assert!(
            std::process::Command::new("chmod")
                .args(["+a", "everyone allow write"])
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/forwarder"), false);

        install(&plan, &privileged).unwrap();

        let mode = std::fs::metadata(plan.installed_executable())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755, "{mode:o}");
        assert!(!has_extended_acl(plan.installed_executable()).unwrap());
    }

    #[test]
    fn a_failed_copy_keeps_the_earlier_copy_and_removes_its_staging() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        let install_dir = dir.path().join("root/proxy-forwarder");
        let plan = ForwarderExecutable::plan_with(&source, install_dir.clone(), false);
        std::fs::write(&source, "working build").unwrap();
        install(&plan, &privileged).unwrap();

        std::fs::remove_file(&source).unwrap();
        install(&plan, &privileged).expect_err("copying a missing executable must fail");

        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "working build"
        );
        assert_eq!(std::fs::read_dir(&install_dir).unwrap().count(), 1);
    }

    #[test]
    fn uninstall_removes_the_copy_and_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/proxy-forwarder"), false);
        install(&plan, &privileged).unwrap();

        uninstall_forwarder_executable(plan.install_dir(), &privileged).unwrap();

        assert!(!plan.install_dir().exists());
    }

    #[cfg(target_os = "macos")]
    fn fake_bundle(directory: &Path, marker: &str) -> PathBuf {
        let bundle = directory.join(format!("{marker}/LPM CLI.app"));
        std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        std::fs::create_dir_all(bundle.join("Contents/_CodeSignature")).unwrap();
        std::fs::write(bundle.join("Contents/MacOS/lpm-rs"), marker).unwrap();
        std::fs::write(bundle.join("Contents/embedded.provisionprofile"), "profile").unwrap();
        std::fs::write(bundle.join("Contents/_CodeSignature/CodeResources"), "seal").unwrap();
        bundle.join("Contents/MacOS/lpm-rs")
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_copies_the_whole_app_bundle_on_macos() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let plan = ForwarderExecutable::plan_with(
            &fake_bundle(dir.path(), "first"),
            dir.path().join("root/Forwarder"),
            true,
        );

        install(&plan, &privileged).unwrap();

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
            "first"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_refuses_a_copy_that_was_not_hardened() {
        let dir = tempfile::tempdir().unwrap();
        // A runner whose chmod does nothing leaves the setuid and write bits that ditto keeps.
        let privileged = fake_privileged_runner(dir.path(), "|chmod");
        let executable = fake_bundle(dir.path(), "unhardened");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o4777)).unwrap();
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);

        let error = install(&plan, &privileged).expect_err("an unhardened copy must be refused");

        assert!(
            error.to_string().contains("not safe for root to run"),
            "{error}"
        );
        assert!(!plan.installed_executable().exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_bundle_that_cannot_move_into_place_restores_the_earlier_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let install_dir = dir.path().join("root/Forwarder");
        let first = ForwarderExecutable::plan_with(
            &fake_bundle(dir.path(), "first"),
            install_dir.clone(),
            true,
        );
        install(&first, &privileged).unwrap();
        let second =
            ForwarderExecutable::plan_with(&fake_bundle(dir.path(), "second"), install_dir, true);

        // SAFETY: nextest runs each test in its own process, so no other thread reads it.
        unsafe { std::env::set_var("FAIL_MV_FROM_STAGING", "1") };
        let result = install(&second, &privileged);
        // SAFETY: as above.
        unsafe { std::env::remove_var("FAIL_MV_FROM_STAGING") };

        result.expect_err("the failed move must be reported");
        assert_eq!(
            std::fs::read_to_string(first.installed_executable()).unwrap(),
            "first"
        );
    }
}
