//! Root-owned copy of the lpm executable that the privileged forwarder runs.
//!
//! The forwarder service starts as root, so it must never run an executable
//! the installing user can change: that user, or anything running as them,
//! would get root the next time the service started. Installation copies the
//! running executable, or on macOS its whole signed app bundle, into a
//! directory only root can change. Root makes each directory and file of the
//! copy itself, filled from handles the installing user opened, so the copy
//! is writable by no one else and holds nothing that user could not read.
//! It is then checked to be the code that is running before the service may
//! run it.

#![cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::proxy_platform::run_checked_inherited;
#[cfg(target_os = "macos")]
use super::proxy_platform::run_checked_output;
#[cfg(target_os = "macos")]
use super::root_fs::stream_as_root;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::root_fs::{
    changeable_by_others, create_missing_directories, open_for_copy, private_root_directory,
    rename_onto, tee_as_root,
};
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
    /// Where the installing user reads a plain executable's bytes from. For
    /// the running executable on Linux that is `/proc/self/exe`, the image
    /// that is running, whatever its path holds by now.
    read_from: PathBuf,
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
        let plan = Self::plan(&executable, install_dir);
        #[cfg(target_os = "linux")]
        let plan = Self {
            read_from: PathBuf::from("/proc/self/exe"),
            ..plan
        };
        Ok(plan)
    }

    /// Describe an existing installation for removal. Only `install_dir` is
    /// meaningful, so this works even when the running executable is gone.
    pub(super) fn for_removal(install_dir: PathBuf) -> Self {
        Self {
            source: PathBuf::new(),
            read_from: PathBuf::new(),
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
                read_from: bundle.clone(),
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
            read_from: executable.to_path_buf(),
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

/// Whether only root can change the executable at `path`: the file it
/// leads to and every directory on the way there. Only root could put a
/// missing one back.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_controlled_executable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    if changeable_by_others(path, 0).is_some() {
        return false;
    }
    let Ok(target) = std::fs::canonicalize(path) else {
        return true;
    };
    std::fs::symlink_metadata(&target).is_ok_and(|metadata| {
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
    }) && matches!(has_extended_acl(&target), Ok(false))
}

/// What `lpm proxy status` should say about an installed privileged
/// forwarder: it starts as root from a path a non-root user can replace
/// (installs from earlier releases), or it runs an older lpm than this one.
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    if !root_controlled_executable(&installed.binary_path) {
        return Some(format!(
            "the privileged forwarder starts as root from {}, which a non-root user can replace; run `lpm proxy install --privileged-ports` to install a root-owned copy",
            installed.binary_path.display()
        ));
    }
    let version = installed.lpm_version?;
    let running = env!("CARGO_PKG_VERSION");
    let older = match (
        lpm_semver::Version::parse(&version),
        lpm_semver::Version::parse(running),
    ) {
        (Ok(installed), Ok(running)) => installed < running,
        _ => true,
    };
    older.then(|| {
        format!(
            "the privileged forwarder runs lpm {version}; run `lpm proxy install --privileged-ports` to update it to {running}"
        )
    })
}

/// Copy the planned executable into its root-owned directory, replacing any
/// earlier copy only after the new one is complete and verified.
///
/// `privileged` runs each step with root rights (`sudo` in production). The
/// copy is assembled in a root-only staging directory, checked to be safe
/// for root to run and to be the code that is running, and only then moved
/// to its final path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn install_forwarder_executable(
    executable: &ForwarderExecutable,
    privileged: &Path,
) -> Result<(), LpmError> {
    let checks = InstallChecks {
        trusted_uid: 0,
        #[cfg(target_os = "macos")]
        code_requirement: running_code_requirement(executable.app_bundle)?,
        #[cfg(target_os = "macos")]
        bundle: BundlePolicy::lpm_release(),
    };
    install_checked(executable, privileged, &checks)
}

/// What installation trusts, and what it requires of the copy.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct InstallChecks {
    /// Owner trusted besides root: root itself in production, the test user
    /// in tests.
    trusted_uid: u32,
    /// What the copy's code signature must satisfy: the running executable's
    /// code directory hash, so the copy is exactly the code that is running,
    /// and for an app bundle LPM's release signature as well.
    #[cfg(target_os = "macos")]
    code_requirement: Option<String>,
    /// What an app bundle may hold.
    #[cfg(target_os = "macos")]
    bundle: BundlePolicy,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_checked(
    executable: &ForwarderExecutable,
    privileged: &Path,
    checks: &InstallChecks,
) -> Result<(), LpmError> {
    let install_dir = &executable.install_dir;
    let refuse = |reason: String| {
        LpmError::Script(format!(
            "cannot install the privileged forwarder under {}: {reason}",
            install_dir.display()
        ))
    };
    if let Some(reason) = changeable_by_others(install_dir, checks.trusted_uid) {
        return Err(refuse(reason));
    }
    create_root_owned_directory(install_dir, privileged)?;
    if let Some(reason) = changeable_by_others(install_dir, checks.trusted_uid) {
        return Err(refuse(reason));
    }

    let staging =
        private_root_directory(privileged, install_dir, std::ffi::OsStr::new(".staging"))?;
    let installed = install_staged_copy(executable, privileged, &staging, checks);
    let cleanup = run_checked_inherited(Command::new(privileged).args(["rm", "-rf"]).arg(&staging));
    installed?;
    cleanup?;
    remove_stale_entries(executable, privileged)
}

/// Create the missing directories of `install_dir`, then reset it, which
/// must be a directory itself and not a link to one: owned by root, mode
/// 0755, and on macOS without ACL entries for staging to inherit.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_root_owned_directory(install_dir: &Path, privileged: &Path) -> Result<(), LpmError> {
    create_missing_directories(privileged, install_dir)?;
    let is_directory = std::fs::symlink_metadata(install_dir)
        .map_err(LpmError::Io)?
        .is_dir();
    if !is_directory {
        return Err(LpmError::Script(format!(
            "{} must be a directory, not a link or a file",
            install_dir.display()
        )));
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
    )?;
    #[cfg(target_os = "macos")]
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "-N"])
            .arg(install_dir),
    )?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_staged_copy(
    executable: &ForwarderExecutable,
    privileged: &Path,
    staging: &Path,
    checks: &InstallChecks,
) -> Result<(), LpmError> {
    let staged = staging.join(&executable.entry);
    if executable.app_bundle {
        #[cfg(target_os = "macos")]
        copy_bundle_as_root(privileged, executable, &staged, &checks.bundle)?;
        #[cfg(not(target_os = "macos"))]
        return Err(LpmError::Script(format!(
            "{} is an app bundle, which only macOS installs",
            executable.source.display()
        )));
    } else {
        tee_as_root(privileged, open_for_copy(&executable.read_from)?, &staged)?;
        run_checked_inherited(
            Command::new(privileged)
                .args(["chmod", "0755"])
                .arg(&staged),
        )?;
    }
    // Let the installing user read, but not change, the staged copy to verify it.
    run_checked_inherited(
        Command::new(privileged)
            .args(["chmod", "0755"])
            .arg(staging),
    )?;
    verify_staged_copy(&staged, checks.trusted_uid)?;
    #[cfg(target_os = "macos")]
    if let Some(requirement) = &checks.code_requirement {
        verify_code_requirement(&staged, requirement)?;
    }
    swap_into_place(executable, privileged, &staged)
}

/// What an app bundle may hold to be copied: the directories and files
/// LPM's release bundle has, so nothing its code signature leaves unsealed,
/// such as a `.DS_Store`, reaches the root-owned copy, within limits on
/// their number and size.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct BundlePolicy {
    name: &'static str,
    /// Relative to the bundle, which is the empty path.
    directories: std::collections::HashSet<PathBuf>,
    required_files: std::collections::HashSet<PathBuf>,
    optional_files: std::collections::HashSet<PathBuf>,
    max_entries: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

#[cfg(target_os = "macos")]
impl BundlePolicy {
    /// The inventory and limits self-update holds release bundles to.
    fn lpm_release() -> Self {
        use crate::commands::self_update as release;

        let relative = |path: &'static str| {
            Path::new(path)
                .strip_prefix(release::MACOS_APP_NAME)
                .expect("release bundle paths start with its name")
                .to_path_buf()
        };
        Self {
            name: release::MACOS_APP_NAME,
            directories: release::MACOS_ALLOWED_BUNDLE_DIRECTORIES
                .into_iter()
                .map(relative)
                .collect(),
            required_files: release::MACOS_REQUIRED_BUNDLE_FILES
                .into_iter()
                .map(relative)
                .collect(),
            optional_files: release::MACOS_OPTIONAL_BUNDLE_FILES
                .into_iter()
                .map(relative)
                .collect(),
            max_entries: release::MACOS_BUNDLE_MAX_ENTRIES,
            max_file_bytes: release::MACOS_BUNDLE_MAX_ENTRY_BYTES,
            max_total_bytes: release::MACOS_BUNDLE_MAX_EXTRACTED_BYTES,
        }
    }
}

/// Recreate the planned app bundle as `staged`, as root: its directories
/// with mode 0755, and its files streamed to `tee` from handles the
/// installing user opens, executables with mode 0755 and the rest 0644.
/// Root reads nothing at a path the user controls, so whatever the bundle
/// path has become, the copy holds only what that user could read, and its
/// signature decides whether it is LPM. Anything `policy` does not allow is
/// refused before root writes a byte; a file that grows past its limit while
/// it is copied, during the copy.
#[cfg(target_os = "macos")]
fn copy_bundle_as_root(
    privileged: &Path,
    executable: &ForwarderExecutable,
    staged: &Path,
    policy: &BundlePolicy,
) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;

    let source = &executable.source;
    let not_lpm = |what: &dyn std::fmt::Display| {
        LpmError::Script(format!(
            "{what} is not part of LPM's app bundle, so it is not copied for the privileged forwarder"
        ))
    };
    if executable.entry != policy.name
        || !std::fs::symlink_metadata(source)
            .map_err(LpmError::Io)?
            .is_dir()
    {
        return Err(not_lpm(&source.display()));
    }
    let mut directories = vec![PathBuf::new()];
    let mut executables = Vec::new();
    let mut others = Vec::new();
    let mut entries = 0_usize;
    let mut pending = vec![PathBuf::new()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(source.join(&directory)).map_err(LpmError::Io)? {
            let entry = entry.map_err(LpmError::Io)?;
            entries += 1;
            if entries > policy.max_entries {
                return Err(LpmError::Script(format!(
                    "{} holds more than the {} entries LPM's app bundle may",
                    source.display(),
                    policy.max_entries
                )));
            }
            let relative = directory.join(entry.file_name());
            let metadata = entry.metadata().map_err(LpmError::Io)?;
            if metadata.is_dir() && policy.directories.contains(&relative) {
                directories.push(relative.clone());
                pending.push(relative);
            } else if metadata.is_file()
                && (policy.required_files.contains(&relative)
                    || policy.optional_files.contains(&relative))
            {
                if metadata.permissions().mode() & 0o111 != 0 {
                    executables.push(relative);
                } else {
                    others.push(relative);
                }
            } else {
                return Err(not_lpm(&source.join(relative).display()));
            }
        }
    }
    if let Some(missing) = policy
        .required_files
        .iter()
        .find(|required| !executables.contains(required) && !others.contains(required))
    {
        return Err(LpmError::Script(format!(
            "{} lacks {}, so it is not LPM's app bundle",
            source.display(),
            missing.display()
        )));
    }

    run_checked_inherited(
        Command::new(privileged)
            .args(["mkdir", "-m", "0755"])
            .args(directories.iter().map(|relative| staged.join(relative))),
    )?;
    let mut total = 0_u64;
    for relative in executables.iter().chain(&others) {
        let path = source.join(relative);
        let limit = policy.max_file_bytes.min(policy.max_total_bytes - total);
        let Some(copied) = stream_as_root(
            privileged,
            &mut open_for_copy(&path)?,
            &staged.join(relative),
            limit,
        )?
        else {
            return Err(LpmError::Script(format!(
                "{} is larger than LPM's app bundle may be",
                path.display()
            )));
        };
        total += copied;
    }
    for (mode, files) in [("0755", &executables), ("0644", &others)] {
        if !files.is_empty() {
            run_checked_inherited(
                Command::new(privileged)
                    .arg("chmod")
                    .arg(mode)
                    .args(files.iter().map(|relative| staged.join(relative))),
            )?;
        }
    }
    Ok(())
}

/// Check every entry of the staged copy: directories and regular files only,
/// owned by root, no group or other write, no setuid or setgid, and on macOS
/// no ACL.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_staged_copy(staged: &Path, trusted_uid: u32) -> Result<(), LpmError> {
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
            || (owner != 0 && owner != trusted_uid)
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
    lpm_common::macos_acl::has_extended_acl_at(path)
        .map_err(|error| LpmError::Script(format!("read the ACL of {}: {error}", path.display())))
}

/// A Linux ACL grants no more than the mode's group bits, which the checks
/// read already.
#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "keeps the signature of the fallible macOS check"
)]
fn has_extended_acl(_path: &Path) -> Result<bool, LpmError> {
    Ok(false)
}

/// The designated requirement of LPM's release bundles: LPM's bundle
/// identifier, signed with LPM's Developer ID Application certificate, whose
/// leaf and intermediate carry Apple's Developer ID extensions.
#[cfg(target_os = "macos")]
fn lpm_release_requirement() -> String {
    format!(
        r#"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "{}" and identifier "{}""#,
        crate::commands::self_update::MACOS_EXPECTED_TEAM_ID,
        crate::commands::self_update::MACOS_EXPECTED_BUNDLE_ID,
    )
}

/// What a copy must satisfy to be the code that is running: the running
/// executable's code directory hash, and for an app bundle LPM's release
/// signature too. None for an unsigned build, which only Intel Macs run.
#[cfg(target_os = "macos")]
fn running_code_requirement(app_bundle: bool) -> Result<Option<String>, LpmError> {
    match (running_cdhash(), app_bundle) {
        (Some(cdhash), true) => Ok(Some(format!(
            r#"={} and cdhash H"{cdhash}""#,
            lpm_release_requirement()
        ))),
        (Some(cdhash), false) => Ok(Some(format!(r#"=cdhash H"{cdhash}""#))),
        (None, true) => Err(LpmError::Script(
            "the running lpm app bundle has no code signature".into(),
        )),
        (None, false) => Ok(None),
    }
}

/// The code directory hash the kernel validated this process's executable
/// against when it started, which no later change to the file can alter.
#[cfg(target_os = "macos")]
fn running_cdhash() -> Option<String> {
    const CS_OPS_CDHASH: libc::c_uint = 5;
    unsafe extern "C" {
        fn csops(
            pid: libc::pid_t,
            ops: libc::c_uint,
            useraddr: *mut libc::c_void,
            usersize: libc::size_t,
        ) -> libc::c_int;
    }

    let mut cdhash = [0u8; 20];
    // SAFETY: csops writes at most `cdhash.len()` bytes into `cdhash`, which
    // outlives the call.
    let status = unsafe {
        csops(
            libc::getpid(),
            CS_OPS_CDHASH,
            cdhash.as_mut_ptr().cast(),
            cdhash.len(),
        )
    };
    (status == 0).then(|| hex::encode(cdhash))
}

/// Require the staged copy's code signature to satisfy `requirement`. This
/// runs as the installing user: checking reads the copy, it changes nothing.
#[cfg(target_os = "macos")]
fn verify_code_requirement(staged: &Path, requirement: &str) -> Result<(), LpmError> {
    run_checked_output(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(format!("--test-requirement={requirement}"))
            .arg(staged),
    )
    .map(drop)
    .map_err(|error| {
        LpmError::Script(format!(
            "the staged forwarder executable {} does not carry the code signature of the lpm that is running: {error}",
            staged.display()
        ))
    })
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
        return rename_onto(privileged, staged, &destination);
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
    use crate::commands::proxy::tests::fake_privileged_runner;
    use std::os::unix::fs::PermissionsExt;

    fn current_uid() -> u32 {
        lpm_common::current_uid()
    }

    fn checks() -> InstallChecks {
        InstallChecks {
            trusted_uid: current_uid(),
            #[cfg(target_os = "macos")]
            code_requirement: None,
            #[cfg(target_os = "macos")]
            bundle: BundlePolicy::lpm_release(),
        }
    }

    fn install(plan: &ForwarderExecutable, privileged: &Path) -> Result<(), LpmError> {
        install_checked(plan, privileged, &checks())
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
        assert_eq!(plan.read_from, Path::new("/home/dev/.lpm/bin/lpm"));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn the_running_executable_is_copied_from_its_running_image_on_linux() {
        let plan =
            ForwarderExecutable::for_running_executable(PathBuf::from("/opt/lpm/proxy-forwarder"))
                .unwrap();
        let running = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();

        assert_eq!(plan.read_from, Path::new("/proc/self/exe"));
        assert_eq!(plan.source, running);
        assert_eq!(
            plan.installed_executable(),
            Path::new("/opt/lpm/proxy-forwarder").join(running.file_name().unwrap())
        );
    }

    #[cfg(target_os = "macos")]
    fn add_acl(path: &Path, entry: &str) {
        assert!(
            std::process::Command::new("chmod")
                .args(["+a", entry])
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }

    fn write_forwarder_config(config: &Path, binary: &Path, version: Option<&str>) {
        let mut value = serde_json::json!({"targetUid": 501, "binaryPath": binary});
        if let Some(version) = version {
            value["lpmVersion"] = version.into();
        }
        std::fs::write(config, value.to_string()).unwrap();
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

        for replaceable in [user_executable, dir.path().join("deleted-lpm")] {
            write_forwarder_config(&config, &replaceable, None);
            let notice = installed_forwarder_notice(&config).expect("a user-writable executable");
            assert!(notice.contains("a non-root user can replace"), "{notice}");
        }

        write_forwarder_config(
            &config,
            Path::new("/bin/lpm-forwarder-that-is-gone"),
            Some(env!("CARGO_PKG_VERSION")),
        );
        assert_eq!(installed_forwarder_notice(&config), None);

        write_forwarder_config(&config, Path::new("/bin/sh"), Some("0.1.0"));
        let notice = installed_forwarder_notice(&config).expect("an outdated forwarder");
        assert!(notice.contains("runs lpm 0.1.0"), "{notice}");

        write_forwarder_config(&config, Path::new("/bin/sh"), Some("not a version"));
        let notice = installed_forwarder_notice(&config).expect("an unreadable version");
        assert!(notice.contains("runs lpm not a version"), "{notice}");

        write_forwarder_config(
            &config,
            Path::new("/bin/sh"),
            Some(env!("CARGO_PKG_VERSION")),
        );
        assert_eq!(installed_forwarder_notice(&config), None);

        assert_eq!(
            installed_forwarder_notice(&dir.path().join("missing.json")),
            None
        );
    }

    #[test]
    fn status_notice_does_not_recommend_downgrading_a_newer_forwarder() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("proxy-forwarder.json");
        write_forwarder_config(&config, Path::new("/bin/sh"), Some("999.0.0"));

        assert_eq!(installed_forwarder_notice(&config), None);
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
        for (path, expected) in [(&install_dir, 0o755), (&plan.installed_executable, 0o755)] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, expected, "{}", path.display());
        }
    }

    #[test]
    fn install_strips_setuid_bits_and_acls_from_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o6775)).unwrap();
        #[cfg(target_os = "macos")]
        add_acl(&source, "everyone allow write");
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
    fn install_copies_the_executable_it_opened_even_if_its_path_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("lpm");
        std::fs::write(&source, "the build that is running").unwrap();
        let replace_source = format!(
            "if [ \"$1\" = tee ]; then printf replaced > '{0}.new' && mv '{0}.new' '{0}'; fi\n",
            source.display()
        );
        let privileged = fake_privileged_runner(dir.path(), &replace_source);
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/forwarder"), false);

        install(&plan, &privileged).unwrap();

        assert_eq!(std::fs::read_to_string(&source).unwrap(), "replaced");
        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "the build that is running"
        );
    }

    #[test]
    fn install_refuses_an_install_directory_that_is_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("keep"), "unrelated").unwrap();
        let link = dir.path().join("forwarder");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan = ForwarderExecutable::plan_with(&source, link, false);

        let error =
            install(&plan, &privileged).expect_err("a symlinked install directory is refused");

        assert!(error.to_string().contains("must be a directory"), "{error}");
        assert!(elsewhere.join("keep").exists());
        assert!(!elsewhere.join("lpm").exists());
    }

    #[test]
    fn install_refuses_an_install_directory_under_one_others_can_change() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o757)).unwrap();
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan = ForwarderExecutable::plan_with(&source, shared.join("root/forwarder"), false);

        let error = install(&plan, &privileged).expect_err("an untrusted parent is refused");

        assert!(
            error
                .to_string()
                .contains("cannot install the privileged forwarder under"),
            "{error}"
        );
        assert!(!shared.join("root").exists());
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
    fn install_refuses_a_copy_root_left_writable() {
        let dir = tempfile::tempdir().unwrap();
        // Under umask 000 and with chmod doing nothing, tee leaves the copy writable by anyone.
        let privileged = fake_privileged_runner(
            dir.path(),
            "umask 000\nif [ \"$1\" = chmod ]; then exit 0; fi\n",
        );
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/forwarder"), false);

        let error = install(&plan, &privileged).expect_err("a writable copy must be refused");

        assert!(
            error.to_string().contains("not safe for root to run"),
            "{error}"
        );
        assert!(!plan.installed_executable().exists());
    }

    /// The privileged steps an install of `plan` runs, one command line each.
    fn privileged_steps_of_an_install(dir: &Path, plan: &ForwarderExecutable) -> Vec<String> {
        let log = dir.join("privileged.log");
        let privileged = fake_privileged_runner(
            &dir.join("logging"),
            &format!("printf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        );
        install(plan, &privileged).unwrap();
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn privileged_steps_never_name_a_path_inside_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let source_dir = dir.path().join("source");
        std::fs::create_dir(&source_dir).unwrap();
        let source = source_dir.join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/forwarder"), false);

        let steps = privileged_steps_of_an_install(dir.path(), &plan);

        assert!(
            steps.iter().any(|step| step.starts_with("tee ")),
            "{steps:?}"
        );
        let source_dir = source_dir.to_string_lossy();
        assert!(
            steps.iter().all(|step| !step.contains(source_dir.as_ref())),
            "{steps:?}"
        );
    }

    #[test]
    fn install_refuses_a_directory_where_the_copy_goes() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let install_dir = dir.path().join("root/forwarder");
        std::fs::create_dir_all(install_dir.join("lpm")).unwrap();
        let plan = ForwarderExecutable::plan_with(&source, install_dir, false);

        let error = install(&plan, &privileged).expect_err("a directory is not replaced");

        assert!(error.to_string().contains("is a directory"), "{error}");
        assert_eq!(
            std::fs::read_dir(plan.installed_executable())
                .unwrap()
                .count(),
            0
        );
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
        std::fs::write(
            bundle.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>lpm-rs</string><key>CFBundleIdentifier</key><string>dev.lpm.cli</string></dict></plist>
"#,
        )
        .unwrap();
        let executable = bundle.join("Contents/MacOS/lpm-rs");
        std::fs::write(&executable, format!("#!/bin/sh\necho {marker}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(bundle.join("Contents/embedded.provisionprofile"), "profile").unwrap();
        std::fs::write(bundle.join("Contents/CodeResources"), "legacy seal").unwrap();
        std::fs::write(bundle.join("Contents/_CodeSignature/CodeResources"), "seal").unwrap();
        executable
    }

    #[cfg(target_os = "macos")]
    fn bundle_checks(adjust: impl FnOnce(&mut BundlePolicy)) -> InstallChecks {
        let mut checks = checks();
        adjust(&mut checks.bundle);
        checks
    }

    /// Sign `bundle` ad hoc as `dev.lpm.cli` and return its code directory hash.
    #[cfg(target_os = "macos")]
    fn sign_ad_hoc(bundle: &Path) -> String {
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier", "dev.lpm.cli"])
            .arg(bundle)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let details = std::process::Command::new("/usr/bin/codesign")
            .args(["-d", "-vvv"])
            .arg(bundle)
            .output()
            .unwrap();
        String::from_utf8_lossy(&details.stderr)
            .lines()
            .find_map(|line| line.strip_prefix("CDHash="))
            .expect("a signed bundle has a code directory hash")
            .to_string()
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
            "#!/bin/sh\necho first\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn privileged_steps_never_name_a_path_inside_the_source_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let executable = fake_bundle(dir.path(), "source");
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);

        let steps = privileged_steps_of_an_install(dir.path(), &plan);

        assert!(
            steps.iter().any(|step| step.starts_with("tee ")),
            "{steps:?}"
        );
        let source = dir.path().join("source").to_string_lossy().into_owned();
        assert!(
            steps.iter().all(|step| !step.contains(&source)),
            "{steps:?}"
        );
        assert_eq!(
            std::fs::read_to_string(plan.installed_executable()).unwrap(),
            "#!/bin/sh\necho source\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_bundle_that_cannot_move_into_place_restores_the_earlier_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("root/Forwarder");
        let first = ForwarderExecutable::plan_with(
            &fake_bundle(dir.path(), "first"),
            install_dir.clone(),
            true,
        );
        install(&first, &fake_privileged_runner(dir.path(), "")).unwrap();
        let second =
            ForwarderExecutable::plan_with(&fake_bundle(dir.path(), "second"), install_dir, true);
        let failing_move = fake_privileged_runner(
            &dir.path().join("failing"),
            "if [ \"$1\" = mv ]; then case \"$2\" in */.staging.*) exit 1 ;; esac; fi\n",
        );

        install(&second, &failing_move).expect_err("the failed move must be reported");

        assert_eq!(
            std::fs::read_to_string(first.installed_executable()).unwrap(),
            "#!/bin/sh\necho first\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_refuses_a_bundle_that_holds_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "not part of lpm").unwrap();
        add_acl(&outside, "everyone deny read");
        let executable = fake_bundle(dir.path(), "linked");
        let bundle = enclosing_app_bundle(&executable).unwrap();
        std::os::unix::fs::symlink(&outside, bundle.join("Contents/outside")).unwrap();
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);

        let error = install(&plan, &privileged).expect_err("a bundle with a symlink is refused");

        assert!(
            error
                .to_string()
                .contains("is not part of LPM's app bundle"),
            "{error}"
        );
        assert!(has_extended_acl(&outside).unwrap());
        assert!(!plan.installed_executable().exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_copies_only_what_lpms_app_bundle_holds() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("privileged.log");
        let privileged = fake_privileged_runner(
            dir.path(),
            &format!("printf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        );
        let refused = |plan: &ForwarderExecutable| {
            let error = install(plan, &privileged).expect_err("the bundle must be refused");
            assert!(!plan.installed_executable().exists());
            assert!(
                !std::fs::read_to_string(&log)
                    .unwrap_or_default()
                    .lines()
                    .any(|step| step.starts_with("tee ")),
                "nothing is copied before the bundle is refused"
            );
            error.to_string()
        };

        let executable = fake_bundle(dir.path(), "finder-metadata");
        let bundle = enclosing_app_bundle(&executable).unwrap();
        std::fs::create_dir(bundle.join("Contents/Resources")).unwrap();
        std::fs::write(bundle.join("Contents/Resources/.DS_Store"), "unsealed").unwrap();
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);
        assert!(refused(&plan).contains("is not part of LPM's app bundle"));

        let executable = fake_bundle(dir.path(), "incomplete");
        let bundle = enclosing_app_bundle(&executable).unwrap();
        std::fs::remove_file(bundle.join("Contents/embedded.provisionprofile")).unwrap();
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);
        assert!(refused(&plan).contains("lacks Contents/embedded.provisionprofile"));

        let renamed = dir.path().join("renamed/Other.app/Contents/MacOS/lpm-rs");
        std::fs::create_dir_all(renamed.parent().unwrap()).unwrap();
        std::fs::write(&renamed, "build").unwrap();
        let plan =
            ForwarderExecutable::plan_with(&renamed, dir.path().join("root/Forwarder"), true);
        assert!(refused(&plan).contains("is not part of LPM's app bundle"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_refuses_a_bundle_larger_than_lpms_may_be() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let plan = ForwarderExecutable::plan_with(
            &fake_bundle(dir.path(), "large"),
            dir.path().join("root/Forwarder"),
            true,
        );

        for checks in [
            bundle_checks(|policy| policy.max_file_bytes = 8),
            bundle_checks(|policy| policy.max_total_bytes = 40),
            bundle_checks(|policy| policy.max_entries = 5),
        ] {
            let error = install_checked(&plan, &privileged, &checks)
                .expect_err("a bundle over its limits is refused");
            assert!(
                error.to_string().contains("LPM's app bundle may"),
                "{error}"
            );
            assert!(!plan.installed_executable().exists());
        }
        install_checked(&plan, &privileged, &checks()).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_strips_acls_that_new_directories_inherit() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        add_acl(
            &shared,
            "everyone deny delete,file_inherit,directory_inherit,only_inherit",
        );
        let source = dir.path().join("lpm");
        std::fs::write(&source, "build").unwrap();
        let plan = ForwarderExecutable::plan_with(&source, shared.join("root/forwarder"), false);

        install(&plan, &privileged).unwrap();

        for path in [
            shared.join("root"),
            shared.join("root/forwarder"),
            plan.installed_executable().to_path_buf(),
        ] {
            assert!(!has_extended_acl(&path).unwrap(), "{}", path.display());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_requires_lpms_release_signature_on_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let executable = fake_bundle(dir.path(), "ad-hoc");
        let cdhash = sign_ad_hoc(&enclosing_app_bundle(&executable).unwrap());
        let plan =
            ForwarderExecutable::plan_with(&executable, dir.path().join("root/Forwarder"), true);
        // A script's ad hoc signature lives in files a Mach-O keeps inside itself.
        let with_requirement = |requirement: String| InstallChecks {
            code_requirement: Some(requirement),
            ..bundle_checks(|policy| {
                policy.optional_files.extend(
                    ["CodeDirectory", "CodeRequirements", "CodeSignature"]
                        .map(|name| Path::new("Contents/_CodeSignature").join(name)),
                );
            })
        };

        let error = install_checked(
            &plan,
            &privileged,
            &with_requirement(format!("={}", lpm_release_requirement())),
        )
        .expect_err("an ad hoc signature is not LPM's release signature");
        assert!(error.to_string().contains("failed to satisfy"), "{error}");
        assert!(!plan.installed_executable().exists());

        if let Some(running) = running_cdhash() {
            let error = install_checked(
                &plan,
                &privileged,
                &with_requirement(format!(r#"=cdhash H"{running}""#)),
            )
            .expect_err("a validly signed bundle that is not the running code is refused");
            assert!(error.to_string().contains("failed to satisfy"), "{error}");
        }

        install_checked(
            &plan,
            &privileged,
            &with_requirement(format!(r#"=cdhash H"{cdhash}""#)),
        )
        .expect("the copy keeps the signature of the bundle it came from");
        assert!(plan.installed_executable().is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_refuses_a_validly_signed_copy_that_is_not_the_running_executable() {
        let Some(requirement) = running_code_requirement(false).unwrap() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let privileged = fake_privileged_runner(dir.path(), "");
        let source = dir.path().join("lpm-rs");
        std::fs::copy(std::env::current_exe().unwrap(), &source).unwrap();
        let resigned = std::process::Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                "dev.lpm.another-build",
            ])
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            resigned.status.success(),
            "{}",
            String::from_utf8_lossy(&resigned.stderr)
        );
        let plan =
            ForwarderExecutable::plan_with(&source, dir.path().join("root/forwarder"), false);
        let running = InstallChecks {
            code_requirement: Some(requirement),
            ..checks()
        };

        let error = install_checked(&plan, &privileged, &running)
            .expect_err("a different build is refused even with a valid signature");

        assert!(error.to_string().contains("failed to satisfy"), "{error}");
        assert!(!plan.installed_executable().exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_copy_of_the_running_executable_satisfies_its_code_requirement() {
        let Some(requirement) = running_code_requirement(false).unwrap() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("lpm-rs");
        std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();

        verify_code_requirement(&copy, &requirement).unwrap();
    }
}
