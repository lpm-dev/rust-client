//! Parent-side wiring for the Windows backend.
//!
//! This is the half that lives in the `lpm.exe` process — it builds
//! the helper argv from a [`SandboxedCommand`] and spawns
//! `lpm-sandbox-helper.exe`, which in turn does the AppContainer
//! dance (see [`crate::helper_appcontainer`] for the helper-side
//! mechanism). Lifecycle scripts on Windows run only this way: without
//! the helper, [`locate_sandbox_helper`] refuses with
//! [`SandboxError::HelperMissing`] rather than run them less contained.
//!
//! ## What this module DOES touch in the parent
//!
//! - Builds the argv block that the helper consumes (renders
//!   readable_allow_set + writable_allow_set into `--readable-dir` /
//!   `--writable-dir` flags).
//! - Captures the MSVC build environment once per process via
//!   `vcvarsall.bat` so AppContainer'd `node-gyp rebuild` keeps
//!   working without the COM-denied `vswhere` lookup.
//! - Probes for the helper binary location (env var override, then the
//!   directory of the running executable).
//!
//! All AppContainer-specific Win32 calls happen INSIDE the helper
//! — this module is plain `Command::spawn` against an argv vector.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{LazyLock, Mutex, OnceLock};

use crate::helper_appcontainer::ScriptJob;
use crate::helper_protocol::{APPCONTAINER_NAME, PROTOCOL_VERSION, StdioMode};
use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec, SandboxStdio,
    SandboxedCommand,
};

/// The AppContainer profile `package`'s lifecycle scripts run in, in
/// `project_dir`: one per project and package, named by a digest of the
/// two, within the 64 characters a profile name may have. Each run grants
/// it again and the helper revokes from it what its spec no longer
/// grants, so its access doesn't build up across runs, and no new
/// identity is left in every tree each run.
fn appcontainer_name_for(project_dir: &Path, package: &str) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let project = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(comparable_path(&project).as_bytes());
    hasher.update([0]);
    hasher.update(package.as_bytes());
    let mut name = format!("{APPCONTAINER_NAME}-");
    for byte in &hasher.finalize()[..16] {
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    name
}

/// `path` as Windows compares paths: case-insensitively, either
/// separator, without a verbatim prefix or a trailing separator.
fn comparable_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\").to_lowercase();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches('\\').to_owned()
}

/// Where the LPM home keeps each identity's records: the trees the helper
/// granted it, and the project and package it belongs to.
fn identity_records() -> Option<PathBuf> {
    lpm_common::LpmRoot::from_env()
        .ok()
        .map(|root| root.root().join("sandbox").join("appcontainers"))
}

/// The trees already swept of grants to profiles of earlier releases.
fn sweep_record() -> Option<PathBuf> {
    lpm_common::LpmRoot::from_env()
        .ok()
        .map(|root| root.root().join("sandbox").join("swept-trees.json"))
}

fn grant_record_path(records: &Path, name: &str) -> PathBuf {
    records.join(format!("{name}.grants.json"))
}

fn identity_record_path(records: &Path, name: &str) -> PathBuf {
    records.join(format!("{name}.identity.json"))
}

/// The project and package an identity belongs to, as the parent records
/// them for a later cleanup.
#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityRecord {
    version: u32,
    project: PathBuf,
    package: String,
    /// The package left the project and the identity couldn't be released
    /// then, so the next sweep tries again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    left_behind: bool,
}

const IDENTITY_RECORD_VERSION: u32 = 1;

impl IdentityRecord {
    fn read(path: &Path) -> Option<Self> {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok())
            .filter(|record| record.version == IDENTITY_RECORD_VERSION)
    }

    fn write(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).expect("an identity record serializes");
        lpm_common::write_file_atomic(path, bytes)
    }
}

/// Records which project and package `name` belongs to, unless that is
/// recorded already. A record that says the package left is of an
/// earlier stay: the package is back, and keeps the identity.
fn record_identity(records: &Path, name: &str, project: &Path, package: &str) {
    let path = identity_record_path(records, name);
    let recorded = path.exists();
    if recorded && !IdentityRecord::read(&path).is_some_and(|record| record.left_behind) {
        return;
    }
    let record = IdentityRecord {
        version: IDENTITY_RECORD_VERSION,
        project: project.to_path_buf(),
        package: package.to_owned(),
        left_behind: false,
    };
    let Err(error) = std::fs::create_dir_all(records).and_then(|()| record.write(&path)) else {
        return;
    };
    if recorded {
        tracing::warn!(
            "couldn't record that {package} is back in {}, so the next `lpm cache clean` \
             removes the sandbox access its scripts have there, and the run after that sets \
             it up again: {error}",
            project.display()
        );
    } else {
        tracing::warn!(
            "couldn't record the sandbox identity of {package} in {}, so removing the package \
             won't remove the access its scripts had: {error}",
            project.display()
        );
    }
}

pub(crate) fn release_package_identity(
    project_dir: &Path,
    package: &str,
) -> Result<bool, crate::IdentityLeftBehind> {
    let Some(records) = identity_records() else {
        return Ok(false);
    };
    release_package_identity_in(&records, locate_sandbox_helper, project_dir, package)
}

/// Releases the identity `package` has in `project_dir`, if `records`
/// holds one. One that can't be released is recorded as left behind, so
/// that [`release_identities_left_behind`] tries again.
fn release_package_identity_in(
    records: &Path,
    helper: impl FnOnce() -> Result<PathBuf, SandboxError>,
    project_dir: &Path,
    package: &str,
) -> Result<bool, crate::IdentityLeftBehind> {
    let name = appcontainer_name_for(project_dir, package);
    let path = identity_record_path(records, &name);
    if !path.exists() {
        return Ok(false);
    }
    helper()
        .and_then(|helper| {
            release_identity(
                records,
                &helper,
                &name,
                project_dir,
                package,
                Released::Forgotten,
            )
        })
        .map(|()| true)
        .map_err(|error| crate::IdentityLeftBehind {
            error,
            unrecorded: record_as_left_behind(&path, project_dir, package).err(),
        })
}

/// Says in the identity record `path` that `package` left `project`, or
/// why that couldn't be said. A record that can't be parsed is replaced:
/// what it should say is known here. One another release wrote isn't.
fn record_as_left_behind(path: &Path, project: &Path, package: &str) -> Result<(), String> {
    let parsed = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<IdentityRecord>(&bytes).ok());
    let record = match parsed {
        Some(record) if record.version != IDENTITY_RECORD_VERSION => {
            return Err(format!("another release of lpm wrote {}", path.display()));
        }
        Some(record) if record.left_behind => return Ok(()),
        Some(record) => IdentityRecord {
            left_behind: true,
            ..record
        },
        None => IdentityRecord {
            version: IDENTITY_RECORD_VERSION,
            project: project.to_path_buf(),
            package: package.to_owned(),
            left_behind: true,
        },
    };
    record
        .write(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

pub(crate) fn release_identities_left_behind() -> crate::ReleasedIdentities {
    let Some(records) = identity_records() else {
        return crate::ReleasedIdentities::default();
    };
    release_identities_left_behind_in(&records, locate_sandbox_helper)
}

fn release_identities_left_behind_in(
    records: &Path,
    helper: impl FnOnce() -> Result<PathBuf, SandboxError>,
) -> crate::ReleasedIdentities {
    let mut released = crate::ReleasedIdentities::default();
    let entries = match std::fs::read_dir(records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return released,
        Err(error) => {
            released.failed.push(SandboxError::IdentityCleanupFailed {
                project: records.to_path_buf(),
                package: String::new(),
                reason: error.to_string(),
            });
            return released;
        }
    };
    let left_behind: Vec<(String, IdentityRecord)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry
                .file_name()
                .to_str()?
                .strip_suffix(".identity.json")?
                .to_owned();
            let record = IdentityRecord::read(&entry.path())?;
            (record.left_behind || !record.project.exists()).then_some((name, record))
        })
        .collect();
    if left_behind.is_empty() {
        return released;
    }
    let helper = match helper() {
        Ok(helper) => helper,
        Err(error) => {
            released.failed.push(error);
            return released;
        }
    };
    for (name, record) in left_behind {
        let (then, count) = if record.project.exists() {
            (Released::Kept, &mut released.of_removed_packages)
        } else {
            (Released::Forgotten, &mut released.of_removed_projects)
        };
        // An identity that was released keeps its identity record while its
        // project is there, and has no grant record. Once the project is
        // gone that identity record goes too, with no access left to remove.
        let held_access = grant_record_path(records, &name).exists();
        match release_identity(
            records,
            &helper,
            &name,
            &record.project,
            &record.package,
            then,
        ) {
            Ok(()) if held_access => *count += 1,
            Ok(()) => {}
            Err(error) => released.failed.push(error),
        }
    }
    released
}

/// What becomes of an identity's record once the identity is released.
enum Released {
    Forgotten,
    /// The record stays and stops saying that the package left. In a
    /// project that is still there the package may be back, and a run of
    /// it records its identity before its helper holds it; removing the
    /// record here could remove that run's.
    Kept,
}

/// Has the helper revoke what `name` was granted and delete its profile,
/// then does to its identity record what `then` says.
fn release_identity(
    records: &Path,
    helper: &Path,
    name: &str,
    project: &Path,
    package: &str,
    then: Released,
) -> Result<(), SandboxError> {
    let failed = |reason: String| SandboxError::IdentityCleanupFailed {
        project: project.to_path_buf(),
        package: package.to_owned(),
        reason,
    };
    let output = Command::new(helper)
        .arg("--protocol-version")
        .arg(PROTOCOL_VERSION.to_string())
        .arg("--appcontainer-name")
        .arg(name)
        .arg("--grant-record")
        .arg(grant_record_path(records, name))
        .arg("--revoke-only")
        .arg("--delete-appcontainer-profile")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|error| failed(error.to_string()))?;
    let removing = format!(
        "removing the sandbox access {package}'s scripts had in {}",
        project.display()
    );
    if let Some(reason) = heard_from(output.status, &output.stderr, &removing) {
        return Err(failed(reason));
    }
    let path = identity_record_path(records, name);
    let recorded = match then {
        Released::Forgotten => std::fs::remove_file(&path),
        Released::Kept => IdentityRecord {
            version: IDENTITY_RECORD_VERSION,
            project: project.to_path_buf(),
            package: package.to_owned(),
            left_behind: false,
        }
        .write(&path),
    };
    match recorded {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(failed(error.to_string())),
    }
}

/// Passes on what a cleanup helper warned of on `stderr` while `doing`
/// its work, and returns what else it said.
fn pass_on_warnings(stderr: &[u8], doing: &str) -> String {
    let said = crate::helper_log::Said::on(stderr);
    for warning in &said.warnings {
        tracing::warn!("{warning} (while {doing})");
    }
    said.reason
}

/// [`pass_on_warnings`] for a cleanup helper that ended with `status`,
/// and why it failed, if it did.
fn heard_from(status: std::process::ExitStatus, stderr: &[u8], doing: &str) -> Option<String> {
    let reason = pass_on_warnings(stderr, doing);
    if status.success() {
        return None;
    }
    Some(if reason.is_empty() {
        format!("the sandbox helper ended with {status}")
    } else {
        reason
    })
}

// ── Runs the parent may have to end ──────────────────────────────────

/// A sandboxed run that is still going: its helper's process, and what a
/// cleanup after it needs.
struct TrackedRun {
    helper: std::os::windows::io::OwnedHandle,
    started: StartedRun,
}

/// The Job a run's script runs in, and what names the run's identity to
/// the helper that cleans up after it.
struct StartedRun {
    helper_path: PathBuf,
    name: String,
    record: PathBuf,
    job_name: String,
    job: ScriptJob,
}

/// Runs by their helper's PID. An entry holds the helper's process open,
/// so Windows gives its PID to no other process meanwhile.
static RUNS: LazyLock<Mutex<HashMap<u32, TrackedRun>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// How long ending the script an ended run left may take before the
/// process that ended the run stops waiting for it.
const CLEANUP_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// A name for a run's Job that no other run on the machine has. A later
/// run of the identity opens the Job by it from any session, as it takes
/// the identity's lock from any.
fn run_job_name() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let unguessed = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!(
        r"Global\LpmSandboxRun-{}-{}-{unguessed:016x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    )
}

/// Keeps `started` for the run of the helper `child`. A run that can't be
/// kept couldn't be ended at its time limit, so it is ended now instead.
fn track_run(child: &mut Child, started: StartedRun) -> Result<(), SandboxError> {
    use std::os::windows::io::AsHandle as _;

    match child.as_handle().try_clone_to_owned() {
        Ok(helper) => {
            RUNS.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(child.id(), TrackedRun { helper, started });
            Ok(())
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            clean_up_after(&started);
            Err(SandboxError::SpawnFailed {
                reason: format!("couldn't keep the sandbox helper's process open: {error}"),
            })
        }
    }
}

/// How long the take-back after an ended run may take. It waits for the
/// identity, and as long again for the identity's last process, and is
/// given the time to say how that went.
const TAKE_BACK_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

const TAKEN_BACK_LATER: &str = "the next run of the package or `lpm cache clean` takes it back";

/// Releases the run of the helper `pid`, which ended by itself. A helper
/// that ended as it should has ended its script and taken back what the
/// run set. One that was stopped from outside did neither: its script is
/// still in the Job, or its record still names the run, and the run is
/// cleaned up as one this process ended.
///
/// A record that can't be read names no run to clean up after. A helper
/// that stopped at it before it started a script has said so. One whose
/// script ran got past the record while it could be read, and can't have
/// taken the run out of it since, so that is said here.
pub(crate) fn finish_run(pid: u32) {
    let run = RUNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&pid);
    let Some(run) = run else {
        return;
    };
    match AfterRun::of(&run.started) {
        AfterRun::CleanUp => clean_up_after(&run.started),
        AfterRun::Unknown(error) => {
            tracing::warn!("couldn't tell whether a sandbox run took back what it set: {error}");
        }
        AfterRun::Nothing => {}
    }
}

/// What is left to do for a run whose helper ended by itself.
#[derive(Debug)]
enum AfterRun {
    CleanUp,
    /// The record can't be read, and the run got as far as its script.
    Unknown(crate::helper_appcontainer::AppContainerError),
    Nothing,
}

impl AfterRun {
    fn of(run: &StartedRun) -> Self {
        let script_is_left = !matches!(run.job.active_processes(), Ok(0));
        match crate::helper_appcontainer::record_names_the_run_in(&run.record, &run.job_name) {
            _ if script_is_left => Self::CleanUp,
            Ok(true) => Self::CleanUp,
            Ok(false) => Self::Nothing,
            Err(_) if matches!(run.job.processes_ever(), Ok(0)) => Self::Nothing,
            Err(error) => Self::Unknown(error),
        }
    }
}

/// Whether the helper `pid` is that of a run whose Job no process has
/// joined yet: the helper is still setting the sandbox up or waiting for
/// its identity.
pub(crate) fn script_is_yet_to_start(pid: u32) -> bool {
    RUNS.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&pid)
        .is_some_and(|run| matches!(run.started.job.processes_ever(), Ok(0)))
}

/// Ends the helper `pid`, then the script in the run's Job, then has a
/// helper take back what the run set until it ended: the read denials on
/// the project's secrets and its way through the folders above. An ended
/// helper can't do that itself.
pub(crate) fn end_run(pid: u32) {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{INFINITE, TerminateProcess, WaitForSingleObject};

    let run = RUNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&pid);
    let Some(run) = run else {
        return;
    };
    let helper = run.helper.as_raw_handle();
    // The helper holds its identity until it is gone, and the cleanup
    // leaves an identity that is held alone.
    // SAFETY: `run` owns the handle, which names the helper's process for
    // both calls. Ending a process that already ended fails and changes
    // nothing.
    let gone = unsafe {
        TerminateProcess(helper.cast(), 1);
        WaitForSingleObject(helper.cast(), INFINITE) == WAIT_OBJECT_0
    };
    if !gone {
        tracing::warn!(
            "couldn't wait for a stopped sandbox run's helper to end; {TAKEN_BACK_LATER}"
        );
        return;
    }
    clean_up_after(&run.started);
}

/// Ends what is left of `run`'s script, whose helper is gone, and has a
/// helper take back what the run set. The Job is held here, so the script
/// outlived the helper, and the Job says when its last process is gone.
/// The read denials come off only after that: the take-back finds the Job
/// in the run's record and asks it again. It is told the Job too, so that
/// it knows the run's part of a record another run has since added to.
fn clean_up_after(run: &StartedRun) {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let later = TAKEN_BACK_LATER;
    if let Err(error) = run.job.end_every_process(CLEANUP_WAIT) {
        tracing::warn!("couldn't end a stopped sandbox run's script; {later}: {error}");
        return;
    }
    // Neither a take-back nor the next run gets past a record that can't
    // be read, so nothing is promised of them.
    if let Err(error) =
        crate::helper_appcontainer::record_names_the_run_in(&run.record, &run.job_name)
    {
        tracing::warn!("couldn't take back what a stopped sandbox run set: {error}");
        return;
    }
    let cleanup = Command::new(&run.helper_path)
        .arg("--protocol-version")
        .arg(PROTOCOL_VERSION.to_string())
        .arg("--appcontainer-name")
        .arg(&run.name)
        .arg("--grant-record")
        .arg(&run.record)
        .arg("--job")
        .arg(&run.job_name)
        .arg("--take-back-run")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut cleanup = match cleanup {
        Ok(cleanup) => cleanup,
        Err(error) => {
            tracing::warn!("couldn't take back what a stopped sandbox run set; {later}: {error}");
            return;
        }
    };
    let doing = "taking back what a stopped sandbox run set";
    // A helper that has said more than its pipe holds waits for a reader,
    // so what it says is read while it runs.
    let said = cleanup.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr, &mut bytes);
            bytes
        })
    });
    let said = move || said.and_then(|said| said.join().ok()).unwrap_or_default();
    let wait_ms = u32::try_from(TAKE_BACK_WAIT.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `cleanup` owns its process handle for the call.
    let ended =
        unsafe { WaitForSingleObject(cleanup.as_raw_handle().cast(), wait_ms) } == WAIT_OBJECT_0;
    if !ended {
        let _ = cleanup.kill();
        let _ = cleanup.wait();
        pass_on_warnings(&said(), doing);
        tracing::warn!(
            "taking back what a stopped sandbox run set took too long and was given up; {later}"
        );
        return;
    }
    match cleanup.wait() {
        Ok(status) => {
            if let Some(reason) = heard_from(status, &said(), doing) {
                tracing::warn!(
                    "couldn't take back what a stopped sandbox run set; {later}: {reason}"
                );
            }
        }
        Err(error) => {
            tracing::warn!("couldn't take back what a stopped sandbox run set; {later}: {error}")
        }
    }
}

// ── Backend struct ───────────────────────────────────────────────────

/// AppContainer backend, the one Windows backend.
#[derive(Debug)]
pub(crate) struct AppContainerSandbox {
    spec: SandboxSpec,
    mode: SandboxMode,
    posture: BackendPosture,
    helper_path: PathBuf,
}

/// Internal posture tag for the AppContainer backend. Strict means
/// "no capabilities → full default-deny including outbound network";
/// Default means "InternetClient capability granted → outbound
/// network allowed". There is no `Degraded` variant — AppContainer
/// delivers full strict (filesystem + network) when requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendPosture {
    /// `deny_outbound_network = false`. Capability list contains
    /// `InternetClient`. Public posture: [`SandboxPosture::Default`].
    Default,
    /// `deny_outbound_network = true`. No network capability.
    /// Public posture: [`SandboxPosture::Strict`].
    Strict,
}

impl AppContainerSandbox {
    /// Construct the backend, which needs `lpm-sandbox-helper.exe`
    /// ([`locate_sandbox_helper`]).
    pub(crate) fn new(
        spec: SandboxSpec,
        mode: SandboxMode,
        options: SandboxOptions,
    ) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => Ok(Self {
                helper_path: locate_sandbox_helper()?,
                spec,
                mode,
                posture: decide_appcontainer_posture(options.deny_outbound_network),
            }),
            // No native AppContainer "audit-only" primitive, so LogOnly
            // surfaces with a clear pointer to --no-sandbox.
            SandboxMode::LogOnly => Err(SandboxError::ModeNotSupportedOnPlatform {
                platform: "windows".to_string(),
                mode: SandboxMode::LogOnly,
                remediation: "AppContainer has no native observe-only \
                              primitive. To debug a sandbox \
                              false-positive, re-run with --no-sandbox. \
                              `--sandbox-log` remains available on macOS."
                    .to_string(),
            }),
            // Disabled is short-circuited to NoopSandbox by the
            // factory before reaching here; defensive guard for
            // contract drift.
            SandboxMode::Disabled => Err(SandboxError::InvalidSpec {
                reason: "SandboxMode::Disabled reached AppContainerSandbox — should have been \
                         routed to NoopSandbox by the factory"
                    .to_string(),
            }),
        }
    }
}

/// Posture decision. Pure (inputs in, outcome out). Never refuses:
/// AppContainer delivers strict on every Windows host the helper runs on,
/// so `allow-degraded` has nothing to fall back to here.
pub(crate) fn decide_appcontainer_posture(deny_outbound_network: bool) -> BackendPosture {
    if deny_outbound_network {
        BackendPosture::Strict
    } else {
        BackendPosture::Default
    }
}

// ── Sandbox trait impl ───────────────────────────────────────────────

impl Sandbox for AppContainerSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<Child, SandboxError> {
        for (index, path) in self.spec.extra_write_dirs.iter().enumerate() {
            crate::config::revalidate_effective_write_dir(path, index)?;
        }
        let secret_read_denied_paths = if self.spec.read_project_full {
            Vec::new()
        } else {
            crate::linux_secret_overlay::enumerate_project_secrets(
                &self.spec.project_dir,
                &self.spec.secret_read_allow,
            )
            .map_err(|error| SandboxError::InvalidSpec {
                reason: format!("AppContainer secret-read policy preparation failed: {error}"),
            })?
        };

        let mut helper_cmd = Command::new(&self.helper_path);

        // Protocol version + container name come first — the helper
        // refuses argv with a mismatched version before doing any
        // AppContainer work.
        helper_cmd
            .arg("--protocol-version")
            .arg(PROTOCOL_VERSION.to_string());
        let name = appcontainer_name_for(&self.spec.project_dir, &self.spec.package_name);
        helper_cmd.arg("--appcontainer-name").arg(&name);
        let record = identity_records().map(|records| {
            record_identity(
                &records,
                &name,
                &self.spec.project_dir,
                &self.spec.package_name,
            );
            grant_record_path(&records, &name)
        });
        // A run that records what it sets gets a Job this process holds
        // too, so the script can be ended, and shown to be gone, after
        // its helper is.
        let started = match record {
            Some(record) => {
                let job_name = run_job_name();
                let job = ScriptJob::create(Some(&job_name)).map_err(|error| {
                    SandboxError::SpawnFailed {
                        reason: format!("couldn't make the Job for the script: {error}"),
                    }
                })?;
                helper_cmd.arg("--grant-record").arg(&record);
                helper_cmd.arg("--job").arg(&job_name);
                Some(StartedRun {
                    helper_path: self.helper_path.clone(),
                    name,
                    record,
                    job_name,
                    job,
                })
            }
            None => None,
        };
        if let Some(record) = sweep_record() {
            helper_cmd.arg("--sweep-record").arg(record);
        }

        // Broad-read grants (the cross-platform "reads broad"
        // contract). The helper applies DACL R+X ACEs on these.
        for dir in readable_allow_set(&self.spec) {
            helper_cmd.arg("--readable-dir").arg(dir);
        }
        // Tool-dir grants derived
        // from the lifecycle child's PATH, derived at spawn time.
        // `C:\Program Files\nodejs` (and similar third-party
        // installer dirs) ship with an `ALL_APPLICATION_PACKAGES`
        // ACE that AppContainer matches by default — empirically
        // that's wrong: the Node.js installer leaves the dir with
        // a `BUILTIN\Users:(I)(RX)` ACE only, which AppContainer
        // does NOT match. Without explicit grants the lifecycle
        // child's `cmd /c node install.js` fails with `'node' is
        // not recognized as an internal or external command`.
        //
        // Routed through `--readable-dir-best-effort` (NOT
        // `--readable-dir`) because PATH entries are frequently
        // SYSTEM-owned (`C:\Program Files\…`); unprivileged
        // `lpm.exe` can't modify their DACL and a strict grant
        // would fail the spawn entirely. The spec-derived
        // entries above (project_dir, ~/.nvm/versions,
        // writable_allow_set) stay on `--readable-dir` /
        // `--writable-dir` with the strict-root contract; only
        // these PATH-derived entries opt into the WARN-and-continue
        // semantics. See "Other (non-MSVC)
        // COM-dependent lifecycle scripts still break" row.
        for dir in tool_dirs_needing_explicit_grant(&cmd, &self.spec) {
            helper_cmd.arg("--readable-dir-best-effort").arg(dir);
        }
        // Narrow-write grants mirror the macOS/Linux writable set.
        // The helper applies these after reads so overlaps keep R+W+X.
        for dir in writable_allow_set(&self.spec) {
            helper_cmd.arg("--writable-dir").arg(dir);
        }
        for path in secret_read_denied_paths {
            helper_cmd.arg("--secret-read-deny").arg(path);
        }

        if let Some(dir) = &cmd.current_dir {
            helper_cmd.arg("--working-dir").arg(dir);
        }

        if cmd.env_clear {
            helper_cmd.arg("--env-clear");
        }

        // Lazily-cached MSVC
        // build environment from `vcvarsall.bat` (the parent has
        // full COM access; the AppContainer child does not, and
        // `node-gyp rebuild` relies on the discovery surface
        // `vswhere`/`ISetupConfiguration` provides). The captured
        // env is injected before caller env so caller settings win
        // on overlap.
        //
        // Failure here is non-fatal: packages without native deps
        // don't need it, and native rebuilds without it will fail
        // clearly at `cl.exe`-not-found rather than silently.
        //
        // **Case-insensitive dedup.** Windows env var lookups are
        // case-insensitive (CRT-side `getenv` ignores case), but
        // a Rust `HashSet<OsString>` is exact-match. Without
        // normalization the caller's `Path` and vcvarsall's `PATH`
        // are treated as different keys and BOTH flow into the
        // helper's `--env` list — and on the helper side any env
        // block builder that doesn't also dedup case-insensitively
        // ships both to the child, where override order is then a
        // function of insertion order rather than a documented
        // contract. Matches the [`crate::commands::rebuild`]
        // `find_env_case_insensitive` precedent for the same
        // hazard on the path.
        let caller_keys_lower: std::collections::HashSet<String> = cmd
            .envs
            .iter()
            .map(|(k, _)| k.to_string_lossy().to_ascii_lowercase())
            .collect();
        if cmd.env_clear && !caller_keys_lower.contains("localappdata") {
            // CreateProcessW requires LOCALAPPDATA for AppContainer startup. Use
            // the writable runtime directory without inheriting the user's profile.
            let mut value = OsString::from("LOCALAPPDATA=");
            value.push(&self.spec.tmpdir);
            helper_cmd.arg("--env").arg(value);
        }
        match capture_msvc_env() {
            Ok(msvc_env) => {
                for (k, v) in msvc_env {
                    if caller_keys_lower.contains(&k.to_ascii_lowercase()) {
                        continue; // caller's explicit env wins
                    }
                    let mut kv = OsString::from(k);
                    kv.push("=");
                    kv.push(v);
                    helper_cmd.arg("--env").arg(kv);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "lpm_sandbox::windows_appcontainer",
                    "MSVC toolchain env capture failed: {e}. \
                     Native rebuilds inside the AppContainer will fail at \
                     cl.exe-not-found unless the caller supplied the MSVC \
                     env explicitly."
                );
            }
        }
        for (k, v) in &cmd.envs {
            let mut kv = OsString::from(k);
            kv.push("=");
            kv.push(v);
            helper_cmd.arg("--env").arg(kv);
        }

        helper_cmd
            .arg("--stdio-stdin")
            .arg(stdio_for_argv(cmd.stdin).as_str());
        helper_cmd
            .arg("--stdio-stdout")
            .arg(stdio_for_argv(cmd.stdout).as_str());
        helper_cmd
            .arg("--stdio-stderr")
            .arg(stdio_for_argv(cmd.stderr).as_str());

        // Default posture grants InternetClient; Strict omits it, leaving
        // no network capability.
        if matches!(self.posture, BackendPosture::Default) {
            helper_cmd.arg("--grant-internet-client");
        }

        // Separator + lifecycle child argv.
        helper_cmd.arg("--");
        helper_cmd.arg(&cmd.program);
        for a in &cmd.args {
            helper_cmd.arg(a);
        }

        // The parent connects its own stdio to the helper; the
        // helper inherits + forwards to the lifecycle child. The
        // helper also inherits LPM's environment: unless
        // `--env-clear` was passed, that is the base the lifecycle
        // child's environment is built on.
        helper_cmd.stdout(std::process::Stdio::from(cmd.stdout));
        helper_cmd.stderr(std::process::Stdio::from(cmd.stderr));
        helper_cmd.stdin(std::process::Stdio::from(cmd.stdin));

        let mut child = helper_cmd.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: format!(
                "failed to spawn lpm-sandbox-helper at {}: {e}",
                self.helper_path.display(),
            ),
        })?;
        if let Some(started) = started {
            track_run(&mut child, started)?;
        }
        Ok(child)
    }

    fn backend_name(&self) -> &'static str {
        "windows-appcontainer"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }

    fn posture(&self) -> SandboxPosture {
        match self.posture {
            BackendPosture::Strict => SandboxPosture::Strict,
            BackendPosture::Default => SandboxPosture::Default,
        }
    }
}

fn stdio_for_argv(s: SandboxStdio) -> StdioMode {
    match s {
        SandboxStdio::Inherit => StdioMode::Inherit,
        SandboxStdio::Piped => StdioMode::Piped,
        SandboxStdio::Null => StdioMode::Null,
    }
}

// ── Allow-set rendering ──────────────────────────────────────────────

/// Directories the lifecycle child needs Read access to. Mirrors
/// the cross-platform "reads broad" contract from
/// [`crate::seatbelt`] / [`crate::landlock_rules::describe_rules`].
///
/// System paths (`C:\Windows`, `C:\Windows\System32`, etc.) are NOT
/// listed — Windows ships them with an `ALL_APPLICATION_PACKAGES`
/// ACE that AppContainer processes match by default, so no extra
/// grant is needed.
///
/// The writable directories in the project ([`writable_allow_set`]) are
/// granted after these; DACLs are additive, so an overlap keeps write
/// access.
pub(crate) fn readable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    out.extend(crate::project_reads::allowed_project_reads(spec));
    out.extend(spec.dependency_read_dirs.iter().cloned());
    let nvm = spec.home_dir.join(".nvm").join("versions");
    out.push(nvm);
    out
}

/// The directories the lifecycle child may write, in a fixed order: the
/// package's own directory first, then the generated client directory of
/// a hoisted `@prisma/client` ([`crate::hoisted_prisma_client_dir`]), the
/// package's layout directory in `.lpm` when it has one
/// ([`crate::package_layout_write_dir`]), the per-user caches, the scratch
/// directory, and `sandboxWriteDirs` last. Matches the macOS Seatbelt
/// `file-write*` block and the Linux landlock read-write rules.
pub(crate) fn writable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(8 + spec.extra_write_dirs.len());
    out.push(spec.package_dir.clone());
    out.extend(crate::hoisted_prisma_client_dir(
        &spec.project_dir,
        &spec.package_dir,
        &spec.package_name,
    ));
    out.extend(crate::package_layout_write_dir(
        &spec.project_dir,
        &spec.package_dir,
    ));
    out.push(spec.home_dir.join(".cache"));
    out.push(spec.home_dir.join(".node-gyp"));
    out.push(spec.home_dir.join(".npm"));
    out.push(spec.tmpdir.clone());
    out.extend(spec.extra_write_dirs.iter().cloned());
    out
}

/// Enumerate PATH directories from the caller-supplied env that
/// need an explicit DACL grant for the AppContainer SID.
///
/// Skips directories that stock Windows already grants
/// `ALL_APPLICATION_PACKAGES` access on (System32, SysWOW64, the
/// bare Windows dir): re-applying the grant would only add walk
/// time without changing observable behavior.
///
/// Skips empty + non-existent entries silently — invalid PATH
/// entries are the user's bug to report, not ours to fail on.
///
/// Skips, with one warning per entry, an existing entry that holds the
/// project, the home directory or the LPM home, or is in the project's
/// `.lpm`, whose grant would reach what the sandbox keeps from scripts
/// there, such as `.lpm` and credentials, and one that isn't absolute,
/// which names a directory under wherever lpm runs rather than the
/// script's own.
///
/// Falls back to the parent's own PATH when the caller didn't
/// supply one. This keeps `cmd /c node install.js` working under
/// the install pipeline's typical `env_clear = true; envs =
/// sanitized` shape: the parent's PATH (already filtered through
/// `build_sanitized_env`) is the only PATH source.
fn tool_dirs_needing_explicit_grant(cmd: &SandboxedCommand, spec: &SandboxSpec) -> Vec<PathBuf> {
    let path_value: Option<OsString> = cmd
        .envs
        .iter()
        .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var_os("PATH"));
    let Some(path_raw) = path_value else {
        return Vec::new();
    };

    let system_root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);

    // A grant reaches the entry's whole tree.
    let held: Vec<PathBuf> = [
        Some(spec.project_dir.clone()),
        Some(spec.home_dir.clone()),
        lpm_common::LpmRoot::from_env()
            .ok()
            .map(|root| root.root().to_path_buf()),
    ]
    .into_iter()
    .flatten()
    .map(|path| std::fs::canonicalize(&path).unwrap_or(path))
    .collect();

    let state = std::fs::canonicalize(spec.project_dir.join(lpm_common::PROJECT_STATE_DIR)).ok();

    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for entry in std::env::split_paths(&path_raw) {
        if entry.as_os_str().is_empty() || !entry.exists() {
            continue;
        }
        if !entry.is_absolute() {
            warn_once_about_path_entry(&entry, "which isn't an absolute path");
            continue;
        }
        // Skip dirs already covered by stock Windows ACEs (no
        // perf benefit to re-walking System32). The starts_with
        // check is canonical-path-friendly because Windows PATH
        // entries are typically lowercase normalized in our env.
        if is_under_system_root(&entry, &system_root) {
            continue;
        }
        // Dedup canonicalized paths so case-only variants don't
        // double the DACL walk cost.
        let canon = std::fs::canonicalize(&entry).unwrap_or_else(|_| entry.clone());
        if held.iter().any(|held| held.starts_with(&canon)) {
            warn_once_about_path_entry(
                &entry,
                "which holds the project, the home directory or the LPM home",
            );
            continue;
        }
        if state.as_ref().is_some_and(|state| canon.starts_with(state)) {
            warn_once_about_path_entry(&entry, "which is in the project's .lpm");
            continue;
        }
        if !seen.insert(canon.clone()) {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Warns that `entry` gets no grant, once per entry in this process, as
/// every lifecycle script's spawn reads the same PATH.
fn warn_once_about_path_entry(entry: &std::path::Path, reason: &str) {
    static WARNED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.iter().any(|known| known == entry) {
        return;
    }
    warned.push(entry.to_path_buf());
    tracing::warn!(
        "lifecycle scripts get no read access to the PATH entry {}, {reason}",
        entry.display()
    );
}

fn is_under_system_root(candidate: &std::path::Path, system_root: &std::path::Path) -> bool {
    let Ok(c) = candidate.canonicalize() else {
        // If canonicalization fails (e.g. permissions on a parent
        // dir), be conservative and assume NOT system-rooted so
        // the caller still grants the path. Better to walk an
        // unnecessary dir than to leave the AppContainer unable
        // to access a tool the user expects in PATH.
        return false;
    };
    let s = system_root
        .canonicalize()
        .unwrap_or_else(|_| system_root.to_path_buf());
    c.starts_with(&s)
}

// ── Helper locator ───────────────────────────────────────────────────

const HELPER_FILE_NAME: &str = "lpm-sandbox-helper.exe";

/// Find `lpm-sandbox-helper.exe`: the file `LPM_SANDBOX_HELPER` names, else
/// the one beside the running executable, where the npm package puts it. A
/// relative override is refused: lpm starts the helper outside the sandbox,
/// and the path would resolve against the directory lpm runs in.
pub(crate) fn locate_sandbox_helper() -> Result<PathBuf, SandboxError> {
    let overridden = std::env::var_os("LPM_SANDBOX_HELPER")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(value) = overridden.as_ref().filter(|value| !value.is_absolute()) {
        return Err(SandboxError::HelperOverrideNotAbsolute {
            value: value.clone(),
        });
    }
    let beside = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .map(|directory| directory.join(HELPER_FILE_NAME))
    });
    let searched: Vec<PathBuf> = overridden.into_iter().chain(beside).collect();
    match searched.iter().find(|path| path.is_file()) {
        Some(path) => Ok(path.clone()),
        None => Err(SandboxError::HelperMissing { searched }),
    }
}

// ── MSVC toolchain env capture ───────────────────────────────────

/// Why the capture exists: AppContainer denies the COM activation
/// path `vswhere.exe` (and node-gyp's other VS discovery) uses, so
/// every native-rebuild fixture would break under Strict. The
/// parent (Medium IL, full COM) asks Microsoft's own
/// `vcvarsall.bat` to render the build env and we inject the
/// resulting env vars into the AppContainer child via the helper's
/// `--env` argv plumbing.
/// off vs hand-rolled VS discovery (`vcvarsall.bat` is Microsoft's
/// official setup entry point and rides their cross-version drift
/// surface; hand-rolled discovery would be ~5-10× the ongoing
/// maintenance load).
///
/// Caching: `OnceLock` so the ~50-200 ms vcvarsall invocation
/// fires at most once per `lpm-rs` process. Subsequent
/// `AppContainerSandbox::spawn` calls reuse the cached result.
static MSVC_ENV: OnceLock<Result<HashMap<String, String>, String>> = OnceLock::new();

/// Capture the MSVC build environment lazily. Returns a borrow of
/// the cached `Result` so the spawn path can render it into the
/// helper's `--env` argv without re-running vcvarsall.
fn capture_msvc_env() -> Result<&'static HashMap<String, String>, &'static str> {
    let cached = MSVC_ENV.get_or_init(do_capture_msvc_env);
    cached.as_ref().map_err(|s| s.as_str())
}

fn do_capture_msvc_env() -> Result<HashMap<String, String>, String> {
    // Step 1: locate vswhere.exe. Microsoft has shipped it at this
    // fixed path since VS 2017; an installation without it would
    // also be missing `vcvarsall.bat`, so there's no fallback.
    let vswhere = Path::new(VSWHERE);
    if !vswhere.exists() {
        return Err("vswhere.exe not found at the standard location; \
             Visual Studio / BuildTools 2017+ doesn't appear to be installed"
            .to_string());
    }

    // Step 2: ask vswhere for ALL VS install paths.
    //
    // Deliberately NO `-latest` and NO `-requires` filter:
    //
    // - `-latest` would return a single install — typically a
    //   newer IDE or Preview SKU. On hosts with side-by-side VS
    //   installs (common on dev machines: VS Preview for IDE +
    //   BuildTools for headless builds), the newest install often
    //   lacks the C++ workload, so `vcvarsall.bat` is absent.
    //   Picking that one and giving up would mask an older
    //   working BuildTools install with the workload present.
    //
    // - `-requires` would mask the cross-arch case:
    //   round-3 fix demonstrated that hardcoding
    //   `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`
    //   wouldn't match an ARM64-only host. Let `vcvarsall.bat`
    //   itself reject if the matching toolchain isn't installed
    //   for the host arch.
    //
    // Strategy: enumerate every install, pick the first one whose
    // `VC/Auxiliary/Build/vcvarsall.bat` exists. vswhere lists
    // installs newest-first by default, so this preserves the
    // "prefer newest" intent while gracefully falling back when
    // the newest install lacks the workload.
    let vs_root_output = Command::new(vswhere)
        .args([
            "-prerelease",
            "-property",
            "installationPath",
            "-products",
            "*",
        ])
        .current_dir(
            vswhere
                .parent()
                .expect("VSWHERE names a file inside a directory"),
        )
        .output()
        .map_err(|e| format!("vswhere.exe spawn failed: {e}"))?;
    if !vs_root_output.status.success() {
        return Err(format!(
            "vswhere.exe returned {:?}; stderr: {}",
            vs_root_output.status,
            String::from_utf8_lossy(&vs_root_output.stderr),
        ));
    }
    let vs_root_raw = String::from_utf8_lossy(&vs_root_output.stdout).into_owned();
    let candidate_roots: Vec<&str> = vs_root_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if candidate_roots.is_empty() {
        return Err("vswhere.exe returned no Visual Studio installations; \
             the host has the installer but no VS edition installed"
            .to_string());
    }

    // Step 3: build the full candidate list — every install whose
    // `vcvarsall.bat` exists, in vswhere's newest-first order.
    let candidate_vcvarsall: Vec<PathBuf> = candidate_roots
        .iter()
        .map(|root| {
            PathBuf::from(root)
                .join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("vcvarsall.bat")
        })
        .filter(|c| c.exists())
        .collect();
    if candidate_vcvarsall.is_empty() {
        return Err(format!(
            "none of the {n} Visual Studio install(s) reported by vswhere \
             contain vcvarsall.bat (no C/C++ workload installed)",
            n = candidate_roots.len(),
        ));
    }

    // Step 4: try each install in order. A `vcvarsall.bat` that's
    // PRESENT but produces a runtime error (wrong toolset for the
    // host arch, missing matching SDK, etc.) must NOT block
    // fallback to an older install whose batch file does succeed.
    // If the first vcvarsall candidate fails at runtime, keep searching instead
    // of returning eagerly.
    let target = MsvcTarget::from_env()?;
    let mut errors: Vec<String> = Vec::new();
    for vcvarsall in &candidate_vcvarsall {
        match try_capture_from_vcvarsall(vcvarsall, &target) {
            Ok(additions) => return Ok(additions),
            Err(e) => {
                errors.push(format!("{}: {e}", vcvarsall.display()));
            }
        }
    }
    Err(format!(
        "tried {n} Visual Studio install(s); none produced a usable MSVC env. \
         Per-install errors:\n  - {detail}",
        n = candidate_vcvarsall.len(),
        detail = errors.join("\n  - "),
    ))
}

/// Run `vcvarsall.bat <target>` for one install and parse its env
/// dump. Returns the additions/overrides on success; a
/// human-readable failure reason on any error so the caller can
/// aggregate per-install diagnostics.
fn try_capture_from_vcvarsall(
    vcvarsall: &std::path::Path,
    target: &MsvcTarget,
) -> Result<HashMap<String, String>, String> {
    let shell = MsvcCaptureShell::locate()?;
    let output = shell
        .vcvarsall_command(vcvarsall, target)?
        .output()
        .map_err(|e| format!("cmd.exe spawn for vcvarsall failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "vcvarsall.bat returned {:?}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    // Parse KEY=VALUE lines from stdout. vcvarsall prints banner
    // lines (e.g. `**********************************`,
    // `** Visual Studio ...`) before the `set` dump; skip lines
    // that don't contain `=` or whose key half contains a space
    // (banner-shaped output that snuck through).
    let dump = String::from_utf8_lossy(&output.stdout);
    let mut new_env: HashMap<String, String> = dump
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            if k.is_empty() || k.contains(' ') {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect();
    if new_env.is_empty() {
        return Err(
            "vcvarsall.bat exited 0 but produced no parseable KEY=VALUE lines; \
             possible Windows-version drift in the banner format"
                .to_string(),
        );
    }

    fn env_key(env: &HashMap<String, String>, name: &str) -> Option<String> {
        env.keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .cloned()
    }
    let inherited_path = std::env::var_os("PATH");
    if let Some(key) = env_key(&new_env, "PATH") {
        match msvc_path_over_inherited(
            &new_env[&key],
            &shell.search_path,
            inherited_path.as_deref(),
        ) {
            Some(path) => {
                new_env.insert(key, path);
            }
            None => {
                new_env.remove(&key);
            }
        }
    }
    // VsDevCmd saves the PATH it started with, unless a Developer Command
    // Prompt LPM runs in already saved the user's own; only a copy of the
    // capture's search PATH is swapped back for the inherited one.
    if let Some(key) = env_key(&new_env, VSCMD_PREINIT_PATH_ENV)
        && is_search_path(&new_env[&key], &shell.search_path)
    {
        match inherited_path.as_deref().and_then(std::ffi::OsStr::to_str) {
            Some(path) => {
                new_env.insert(key, path.to_string());
            }
            None => {
                new_env.remove(&key);
            }
        }
    }

    // Diff against the pre-spawn env. Anything vcvarsall added or
    // changed is what we need to inject into the child; values
    // unchanged from our env don't need to be set (they'd be
    // inherited anyway).
    // An inherited value that is not valid Unicode stays inherited: the
    // decoded dump cannot show whether vcvarsall changed it, and injecting
    // the decoded text would replace the real value.
    let pre_env: HashMap<OsString, OsString> = std::env::vars_os().collect();
    let mut additions = HashMap::new();
    for (k, v) in &new_env {
        if CAPTURE_ONLY_ENVS
            .iter()
            .any(|own| k.eq_ignore_ascii_case(own))
        {
            continue;
        }
        match pre_env.get(std::ffi::OsStr::new(k)) {
            Some(prev) if prev.to_str().is_none_or(|prev| prev == v) => {}
            _ => {
                additions.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(additions)
}

/// Where Microsoft has shipped `vswhere.exe` since Visual Studio 2017.
const VSWHERE: &str = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";

/// Makes cmd.exe leave the current directory out of its search for
/// commands named without a path.
const NO_CURRENT_DIRECTORY_SEARCH_ENV: &str = "NoDefaultCurrentDirectoryInExePath";

/// The capture's own settings, kept out of the environment handed to
/// lifecycle scripts.
const CAPTURE_ONLY_ENVS: [&str; 2] = [NO_CURRENT_DIRECTORY_SEARCH_ENV, "ComSpec"];

/// Where `VsDevCmd.bat` keeps the `PATH` it started with, to restore it.
const VSCMD_PREINIT_PATH_ENV: &str = "__VSCMD_PREINIT_PATH";

/// The shell the capture runs vcvarsall in, outside the sandbox: the
/// system's `cmd.exe`, and a `PATH` of only Windows' own directories and
/// the Visual Studio installer's (`vswhere`). LPM's inherited `PATH` isn't
/// trusted here — started from a package script, it leads with the
/// project's `node_modules\.bin`, where any dependency can place a
/// `reg.cmd`.
struct MsvcCaptureShell {
    cmd: PathBuf,
    search_path: String,
}

impl MsvcCaptureShell {
    fn locate() -> Result<Self, String> {
        let mut cmd = lpm_common::platform::windows_system_directory()
            .map_err(|e| format!("cannot locate the Windows system directory: {e}"))?;
        let system = cmd
            .to_str()
            .ok_or_else(|| format!("{} is not valid Unicode", cmd.display()))?;
        let windows = Path::new(system)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| format!("{system} has no parent directory"))?;
        let installer = Path::new(VSWHERE)
            .parent()
            .and_then(Path::to_str)
            .expect("VSWHERE names a file inside a directory");
        let search_path = format!(
            r"{system};{windows};{system}\Wbem;{system}\WindowsPowerShell\v1.0;{installer}"
        );
        cmd.push("cmd.exe");
        Ok(Self { cmd, search_path })
    }

    /// The `cmd.exe` invocation of `vcvarsall.bat <target> && set`.
    ///
    /// Nothing from the directory LPM was started in — usually a project
    /// root, which an untrusted repository controls — or from LPM's `PATH`
    /// may stand in for the tools the Visual Studio scripts call by bare
    /// name (`reg`, `where`, `findstr`, …): it starts in the Visual Studio
    /// directory holding `vcvarsall.bat`, skips the current directory and
    /// searches only the capture's `PATH` for commands, runs nested shells
    /// (pipes, `for /f`) through the same `cmd.exe`, and turns delayed
    /// expansion off (`/V:OFF`). `/D` skips the `AutoRun` commands of this
    /// shell, as cmd.exe does for the shells it starts for pipes; those it
    /// starts for `for /f` still run them, but they are the machine's and
    /// the user's own registry settings, not something a project supplies.
    fn vcvarsall_command(&self, vcvarsall: &Path, target: &MsvcTarget) -> Result<Command, String> {
        let build_dir = vcvarsall
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", vcvarsall.display()))?;
        // `raw_arg`, because `arg` would quote the whole `/C "…"` payload
        // again; `/S` makes cmd strip exactly the outermost pair of quotes.
        let mut command_line =
            OsString::with_capacity(vcvarsall.as_os_str().len() + target.0.len() + 32);
        command_line.push("/D /V:OFF /S /C \"\"");
        command_line.push(vcvarsall);
        command_line.push("\" ");
        command_line.push(&target.0);
        command_line.push(" && set\"");
        let mut command = Command::new(&self.cmd);
        command
            .raw_arg(command_line)
            .current_dir(build_dir)
            .env("PATH", &self.search_path)
            .env("ComSpec", &self.cmd)
            .env(NO_CURRENT_DIRECTORY_SEARCH_ENV, "1");
        Ok(command)
    }
}

/// `PATH` as vcvarsall left it, with the search `PATH` the capture ran with
/// — found as the same directories in the same order — swapped back for the
/// `PATH` LPM inherited, so lifecycle scripts see whatever Visual Studio put
/// before and after it around their usual `PATH`. A `PATH` in which that
/// sequence no longer appears is kept as vcvarsall left it. `None` when the
/// inherited `PATH` isn't Unicode: it has to stay inherited, since the
/// decoded text can't stand in for it.
fn msvc_path_over_inherited(
    captured: &str,
    search_path: &str,
    inherited: Option<&std::ffi::OsStr>,
) -> Option<String> {
    let inherited = match inherited {
        Some(path) => path.to_str()?,
        None => "",
    };
    let searched: Vec<&str> = search_path.split(';').collect();
    let entries: Vec<&str> = captured.split(';').filter(|e| !e.is_empty()).collect();
    let Some(start) = entries.windows(searched.len()).position(|window| {
        window
            .iter()
            .zip(&searched)
            .all(|(entry, searched)| same_directory(entry, searched))
    }) else {
        return Some(captured.to_string());
    };
    let mut parts: Vec<&str> = Vec::with_capacity(entries.len() + 1 - searched.len());
    parts.extend_from_slice(&entries[..start]);
    if !inherited.is_empty() {
        parts.push(inherited);
    }
    parts.extend_from_slice(&entries[start + searched.len()..]);
    Some(parts.join(";"))
}

/// Whether `value` is exactly the capture's search `PATH`.
fn is_search_path(value: &str, search_path: &str) -> bool {
    let mut entries = value.split(';').filter(|e| !e.is_empty());
    let mut searched = search_path.split(';');
    loop {
        match (entries.next(), searched.next()) {
            (Some(entry), Some(searched)) if same_directory(entry, searched) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// `PATH` entries naming the same directory, as Windows compares them:
/// ignoring ASCII case and a trailing backslash.
fn same_directory(entry: &str, searched: &str) -> bool {
    entry
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(searched.trim_end_matches('\\'))
}

/// What `vcvarsall.bat` is asked to set up: `LPM_MSVC_TARGET` when it is
/// set to something, otherwise the host architecture. It goes onto a
/// `cmd.exe` command line unquoted, so only words of vcvarsall's own
/// vocabulary are accepted — an architecture, `store`/`uwp`, an SDK
/// version, `-vcvars_ver=14.29` — made of letters, digits and `_ . = -`.
#[derive(Debug, PartialEq)]
struct MsvcTarget(String);

impl MsvcTarget {
    const ENV: &str = "LPM_MSVC_TARGET";

    fn from_env() -> Result<Self, String> {
        match std::env::var(Self::ENV) {
            Ok(value) if !value.trim().is_empty() => Self::parse(&value),
            Ok(_) | Err(std::env::VarError::NotPresent) => Self::parse(host_msvc_arch()),
            Err(std::env::VarError::NotUnicode(value)) => {
                Err(format!("{} {value:?} is not valid Unicode", Self::ENV))
            }
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        let words: Vec<&str> = value.split_ascii_whitespace().collect();
        let is_vcvarsall_word = |word: &&str| {
            word.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'=' | b'-'))
        };
        if words.is_empty() || !words.iter().all(is_vcvarsall_word) {
            return Err(format!(
                "{} {value:?} is not vcvarsall.bat arguments such as x64, arm64 or \
                 \"x64_arm64 10.0.22621.0 -vcvars_ver=14.29\"",
                Self::ENV,
            ));
        }
        Ok(Self(words.join(" ")))
    }
}

/// Best-effort host-arch token for `vcvarsall.bat`. The pattern
/// `vcvarsall.bat <arch>` accepts host-build pairs (`x64`,
/// `arm64`, `x86_x64`, etc.); we default to the host-only build
/// for the running architecture.
fn host_msvc_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        // Other Windows architectures aren't shipped by the lpm
        // release matrix; default to x64 which is the workspace's
        // primary target and let vcvarsall surface a clear error
        // if the host can't run it.
        "x64"
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxSpec;
    use std::path::PathBuf;

    fn make_spec() -> SandboxSpec {
        SandboxSpec {
            package_dir: PathBuf::from("C:/store/pkg@1"),
            project_dir: PathBuf::from("C:/proj"),
            package_name: "pkg".to_string(),
            package_version: "1.0.0".to_string(),
            store_root: PathBuf::from("C:/store"),
            home_dir: PathBuf::from("C:/Users/u"),
            tmpdir: PathBuf::from("C:/Users/u/AppData/Local/Temp"),
            read_project_full: false,
            secret_read_allow: Vec::new(),
            dependency_read_dirs: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn path_entries_holding_the_project_or_a_home_or_not_absolute_get_no_grant() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = home.join("proj");
        let tools = root.path().join("tools");
        let bin = project.join("node_modules").join(".bin");
        let lpm_bin = home.join(".lpm").join("bin");
        for directory in [&tools, &bin, &lpm_bin] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let spec = SandboxSpec {
            project_dir: project.clone(),
            home_dir: home.clone(),
            ..make_spec()
        };
        let certs = project.join(".lpm").join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        let path = std::env::join_paths([
            root.path(),
            home.as_path(),
            project.as_path(),
            tools.as_path(),
            bin.as_path(),
            lpm_bin.as_path(),
            certs.as_path(),
            std::path::Path::new("."),
            std::path::Path::new("tools"),
        ])
        .unwrap();
        let cmd = SandboxedCommand::new("cmd").envs_cleared([("PATH", path)]);

        assert_eq!(
            tool_dirs_needing_explicit_grant(&cmd, &spec),
            [tools, bin, lpm_bin]
        );
    }

    #[test]
    fn decide_appcontainer_posture_strict_when_deny_outbound_set() {
        assert_eq!(decide_appcontainer_posture(true), BackendPosture::Strict);
    }

    #[test]
    fn decide_appcontainer_posture_default_when_deny_outbound_unset() {
        assert_eq!(decide_appcontainer_posture(false), BackendPosture::Default);
    }

    #[test]
    fn writable_set_grants_the_package_but_not_project_state() {
        let spec = make_spec();
        let set = writable_allow_set(&spec);
        assert_eq!(
            set,
            vec![
                spec.package_dir.clone(),
                spec.home_dir.join(".cache"),
                spec.home_dir.join(".node-gyp"),
                spec.home_dir.join(".npm"),
                spec.tmpdir.clone(),
            ]
        );
    }

    #[test]
    fn writable_set_grants_a_hoisted_prisma_client_only_its_generated_client_dir() {
        let mut spec = make_spec();
        let node_modules = spec.project_dir.join("node_modules");
        spec.package_dir = node_modules.join("esbuild");
        assert!(
            !writable_allow_set(&spec)
                .iter()
                .any(|path| path.starts_with(&node_modules) && *path != spec.package_dir)
        );

        spec.package_name = "@prisma/client".into();
        spec.package_dir = node_modules.join("@prisma").join("client");
        let set = writable_allow_set(&spec);
        assert_eq!(set[1], node_modules.join(".prisma"));
        assert!(!set.contains(&node_modules));
    }

    #[test]
    fn writable_set_adds_the_package_s_own_layout_directory_and_extras_last() {
        let mut spec = make_spec();
        spec.package_dir = spec
            .project_dir
            .join(".lpm")
            .join("wrappers")
            .join("pkg@1.0.0")
            .join("node_modules")
            .join("pkg");
        spec.extra_write_dirs = vec![PathBuf::from("C:/extra1"), PathBuf::from("C:/extra2")];
        let set = writable_allow_set(&spec);

        let wrapper = spec
            .project_dir
            .join(".lpm")
            .join("wrappers")
            .join("pkg@1.0.0");
        assert_eq!(set[1], wrapper);
        assert!(!set.contains(&spec.project_dir.join(".lpm")));
        assert!(!set.contains(&spec.project_dir.join(".lpm").join("wrappers")));
        assert_eq!(
            set[set.len() - 2..],
            [PathBuf::from("C:/extra1"), PathBuf::from("C:/extra2")]
        );
    }

    #[test]
    fn a_package_keeps_one_appcontainer_per_project_within_the_windows_limit() {
        let project = Path::new(r"C:\Users\me\project");
        let name = appcontainer_name_for(project, "esbuild");

        assert_eq!(
            name,
            appcontainer_name_for(Path::new(r"c:/users/me/project/"), "esbuild")
        );
        assert_ne!(name, appcontainer_name_for(project, "sharp"));
        assert_ne!(
            name,
            appcontainer_name_for(Path::new(r"C:\Users\me\other"), "esbuild")
        );
        assert!(name.starts_with(APPCONTAINER_NAME));
        assert!(name.len() <= 64, "AppContainer profile name was {name:?}");
    }

    /// Finishes a run whose helper ended with an empty Job and left
    /// `record` behind, and says whether a take-back was started after
    /// it. The helper here is a script that only says it was started.
    fn a_take_back_follows_a_run_that_left(record: impl FnOnce(&str) -> Vec<u8>) -> bool {
        let folder = tempfile::tempdir().unwrap();
        let helper_path = folder.path().join("helper.cmd");
        std::fs::write(&helper_path, "@echo started> \"%~dp0started.txt\"\r\n").unwrap();
        let job_name = run_job_name();
        let record_path = folder.path().join("grants.json");
        std::fs::write(&record_path, record(&job_name)).unwrap();
        let job = ScriptJob::create(Some(&job_name)).expect("make the run's Job");
        let mut helper = Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/d", "/c", "exit"])
            .spawn()
            .expect("start a process to stand in for the run's helper");
        track_run(
            &mut helper,
            StartedRun {
                helper_path,
                name: "LpmFinishRunTest".to_owned(),
                record: record_path,
                job_name,
                job,
            },
        )
        .expect("keep the run");
        helper.wait().expect("the stand-in ends");

        finish_run(helper.id());

        folder.path().join("started.txt").exists()
    }

    #[test]
    fn a_run_that_stopped_at_an_unreadable_record_gets_no_take_back() {
        let names_the_run = |job: &str| {
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "trees": [],
                "run": { "jobs": [job] },
            }))
            .unwrap()
        };
        assert!(
            a_take_back_follows_a_run_that_left(names_the_run),
            "a record that still names the run is what a take-back is for"
        );

        assert!(
            !a_take_back_follows_a_run_that_left(|_| b"not a record".to_vec()),
            "a take-back can read the record no better than the run that stopped at it"
        );
    }

    #[test]
    fn a_run_whose_script_ran_before_its_record_became_unreadable_is_told_of() {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let folder = tempfile::tempdir().unwrap();
        let record = folder.path().join("grants.json");
        std::fs::write(&record, b"not a record").unwrap();
        let started = |job_name: String| StartedRun {
            helper_path: folder.path().join("helper.cmd"),
            name: "LpmFinishRunTest".to_owned(),
            record: record.clone(),
            job: ScriptJob::create(Some(&job_name)).expect("make the run's Job"),
            job_name,
        };
        let stopped_at_the_record = started(run_job_name());
        let ran_a_script = started(run_job_name());
        // It waits for input, so that it is still there to join the Job.
        let mut script = Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/d", "/c", "pause"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("start a process to stand in for the script");
        // SAFETY: both handles are open.
        let joined = unsafe {
            AssignProcessToJobObject(ran_a_script.job.as_raw(), script.as_raw_handle().cast())
        };
        drop(script.stdin.take());
        script.wait().expect("the stand-in ends");
        assert_ne!(joined, 0, "the stand-in joins the Job");
        ran_a_script
            .job
            .end_every_process(CLEANUP_WAIT)
            .expect("the Job counts the stand-in as ended");

        let nothing = AfterRun::of(&stopped_at_the_record);
        let told = AfterRun::of(&ran_a_script);

        assert!(matches!(nothing, AfterRun::Nothing), "{nothing:?}");
        assert!(matches!(told, AfterRun::Unknown(_)), "{told:?}");
    }

    /// A folder for identity records and a project beside it, with two
    /// scripts that stand in for the helper: one that fails as a cleanup
    /// that found the identity held does, and one that succeeds, writes
    /// down what it was started with and removes the grant record.
    struct Releases {
        folder: tempfile::TempDir,
    }

    impl Releases {
        fn new() -> Self {
            let folder = tempfile::tempdir().unwrap();
            std::fs::create_dir(folder.path().join("project")).unwrap();
            std::fs::write(
                folder.path().join("fails.cmd"),
                "@echo lpm-sandbox-helper: the identity is held 1>&2\r\n@exit /b 66\r\n",
            )
            .unwrap();
            std::fs::write(
                folder.path().join("works.cmd"),
                "@echo %*>> \"%~dp0released.txt\"\r\n\
                 :next\r\n\
                 @if \"%~1\"==\"\" exit /b 0\r\n\
                 @if \"%~1\"==\"--grant-record\" if exist \"%~2\" del \"%~2\"\r\n\
                 @shift\r\n\
                 @goto next\r\n",
            )
            .unwrap();
            Self { folder }
        }

        fn records(&self) -> PathBuf {
            self.folder.path().join("records")
        }

        fn project(&self) -> PathBuf {
            self.folder.path().join("project")
        }

        /// Records the identity of `package` in the project and what it
        /// was granted, as a run of its scripts does, and says where the
        /// identity is recorded.
        fn run_of(&self, package: &str) -> PathBuf {
            let name = appcontainer_name_for(&self.project(), package);
            record_identity(&self.records(), &name, &self.project(), package);
            std::fs::write(grant_record_path(&self.records(), &name), "{}").unwrap();
            identity_record_path(&self.records(), &name)
        }

        fn uninstall_of(
            &self,
            package: &str,
            helper: &str,
        ) -> Result<bool, crate::IdentityLeftBehind> {
            let helper = self.folder.path().join(helper);
            release_package_identity_in(&self.records(), || Ok(helper), &self.project(), package)
        }

        /// Sweeps, and says how many identities it took access from of
        /// packages that left the project, of projects that are gone, and
        /// what failed.
        fn sweep(&self) -> (usize, usize, Vec<SandboxError>) {
            let helper = self.folder.path().join("works.cmd");
            let released = release_identities_left_behind_in(&self.records(), || Ok(helper));
            (
                released.of_removed_packages,
                released.of_removed_projects,
                released.failed,
            )
        }

        /// How often the helper that works was started for `package`.
        fn releases_of(&self, package: &str) -> usize {
            let name = appcontainer_name_for(&self.project(), package);
            std::fs::read_to_string(self.folder.path().join("released.txt"))
                .unwrap_or_default()
                .lines()
                .filter(|started_with| started_with.contains(&name))
                .count()
        }
    }

    #[test]
    fn a_release_that_failed_when_its_package_left_is_tried_again_by_the_sweep() {
        let releases = Releases::new();
        let left = releases.run_of("left");
        releases.run_of("stays");

        let failed = releases.uninstall_of("left", "fails.cmd");
        let (released, of_gone_projects, failures) = releases.sweep();
        let (released_again, _, _) = releases.sweep();

        let failed = failed.expect_err("the helper failed");
        assert!(
            matches!(
                &failed.error,
                SandboxError::IdentityCleanupFailed { reason, .. }
                    if reason.contains("the identity is held")
            ),
            "{failed:?}"
        );
        assert_eq!(failed.unrecorded, None);
        assert_eq!(released, 1, "{failures:?}");
        assert_eq!(of_gone_projects, 0, "the project is still there");
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(released_again, 0, "one that was released isn't left behind");
        assert_eq!(releases.releases_of("left"), 1);
        assert_eq!(
            releases.releases_of("stays"),
            0,
            "a package still in its project keeps its identity"
        );
        assert!(
            left.exists(),
            "the record of a project that is still there stays for a run that has the package back"
        );
    }

    #[test]
    fn a_package_that_is_back_keeps_the_identity_its_failed_release_left_behind() {
        let releases = Releases::new();
        releases.run_of("back");
        let failed = releases.uninstall_of("back", "fails.cmd");

        let record = releases.run_of("back");
        let (released, _, failures) = releases.sweep();

        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(released, 0, "{failures:?}");
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(releases.releases_of("back"), 0);
        assert!(record.exists());
    }

    #[test]
    fn a_failed_release_is_recorded_over_a_record_that_can_t_be_parsed() {
        let releases = Releases::new();
        let record = releases.run_of("unparsable");
        std::fs::write(&record, "not a record").unwrap();

        let failed = releases.uninstall_of("unparsable", "fails.cmd");
        let (released, _, failures) = releases.sweep();

        assert_eq!(failed.expect_err("the helper failed").unrecorded, None);
        assert_eq!(released, 1, "{failures:?}");
        assert_eq!(releases.releases_of("unparsable"), 1);
    }

    #[test]
    fn a_failed_release_that_can_t_be_recorded_says_so() {
        let releases = Releases::new();
        let record = releases.run_of("unrecorded");
        let of_another_release = serde_json::json!({
            "version": IDENTITY_RECORD_VERSION + 1,
            "project": releases.project(),
            "package": "unrecorded",
        });
        std::fs::write(&record, serde_json::to_vec(&of_another_release).unwrap()).unwrap();

        let failed = releases.uninstall_of("unrecorded", "fails.cmd");
        let (released, _, failures) = releases.sweep();

        let unrecorded = failed.expect_err("the helper failed").unrecorded;
        assert!(
            unrecorded
                .as_deref()
                .is_some_and(|why| why.contains("another release of lpm wrote")),
            "{unrecorded:?}"
        );
        assert_eq!(released, 0, "{failures:?}");
        assert_eq!(
            std::fs::read(&record).unwrap(),
            serde_json::to_vec(&of_another_release).unwrap(),
            "another release's record is left as it is"
        );
    }

    #[test]
    fn a_release_that_works_leaves_nothing_and_the_sweep_takes_a_gone_project_s_identities() {
        let releases = Releases::new();
        let released_at_once = releases.run_of("uninstalled");
        let of_a_gone_project = releases.run_of("orphan");

        let uninstalled = releases.uninstall_of("uninstalled", "works.cmd");
        let never_ran = releases.uninstall_of("never-ran", "works.cmd");
        let (_, before, _) = releases.sweep();
        std::fs::remove_dir(releases.project()).unwrap();
        let (of_left_packages, after, failures) = releases.sweep();

        assert!(matches!(uninstalled, Ok(true)), "{uninstalled:?}");
        assert!(matches!(never_ran, Ok(false)), "{never_ran:?}");
        assert!(!released_at_once.exists());
        assert_eq!(before, 0, "the project is still there");
        assert_eq!(after, 1, "{failures:?}");
        assert_eq!(of_left_packages, 0, "no uninstall left it behind");
        assert!(!of_a_gone_project.exists());
    }

    /// The stand-in releases the identity as the helper does, then plays a
    /// run of the same package that was waiting for the identity: the run
    /// takes it as soon as the release lets go, and records and grants it
    /// before the process that asked for the release goes on.
    #[test]
    fn a_run_that_takes_the_identity_as_its_release_ends_stays_recorded() {
        let releases = Releases::new();
        let record = releases.run_of("waited");
        let name = appcontainer_name_for(&releases.project(), "waited");
        let grants = grant_record_path(&releases.records(), &name);
        let recorded_by_the_run = releases.folder.path().join("recorded-by-the-run.json");
        std::fs::copy(&record, &recorded_by_the_run).unwrap();
        std::fs::write(
            releases.folder.path().join("then-a-run.cmd"),
            format!(
                ":next\r\n\
                 @if \"%~1\"==\"\" goto run\r\n\
                 @if \"%~1\"==\"--grant-record\" if exist \"%~2\" del \"%~2\"\r\n\
                 @if \"%~1\"==\"--identity-record\" if exist \"%~2\" del \"%~2\"\r\n\
                 @shift\r\n\
                 @goto next\r\n\
                 :run\r\n\
                 @if not exist \"{record}\" copy /y \"{recorded}\" \"{record}\" >nul\r\n\
                 @echo {{}}> \"{grants}\"\r\n",
                record = record.display(),
                recorded = recorded_by_the_run.display(),
                grants = grants.display(),
            ),
        )
        .unwrap();

        let released = releases.uninstall_of("waited", "then-a-run.cmd");

        assert!(matches!(released, Ok(true)), "{released:?}");
        assert!(grants.exists(), "the run granted the identity again");
        assert!(
            record.exists(),
            "what the run was granted is found by the identity's record"
        );
    }

    #[test]
    fn an_identity_released_before_its_project_went_is_forgotten_without_being_counted() {
        let releases = Releases::new();
        let record = releases.run_of("left");
        let failed = releases.uninstall_of("left", "fails.cmd");
        let (released, _, _) = releases.sweep();

        std::fs::remove_dir(releases.project()).unwrap();
        let (of_left_packages, of_gone_projects, failures) = releases.sweep();

        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(released, 1, "the retry removed its access");
        assert_eq!(of_gone_projects, 0, "{failures:?}");
        assert_eq!(of_left_packages, 0, "{failures:?}");
        assert!(failures.is_empty(), "{failures:?}");
        assert!(!record.exists(), "a gone project's record goes");
    }

    #[test]
    fn what_a_cleanup_helper_warned_of_is_passed_on_apart_from_why_it_failed() {
        use std::os::windows::process::ExitStatusExt as _;

        let ended_with = std::process::ExitStatus::from_raw;
        let ((failed, worked, said_nothing), passed_on) = crate::helper_log::written_while(|| {
            (
                heard_from(
                    ended_with(66),
                    b"lpm-sandbox-helper: warning: couldn't take back C:\\a: denied\n\
                      lpm-sandbox-helper: the identity is held\n",
                    "cleaning up",
                ),
                heard_from(
                    ended_with(0),
                    b"lpm-sandbox-helper: warning: the record was unreadable\n",
                    "cleaning up",
                ),
                heard_from(ended_with(101), b"", "cleaning up"),
            )
        });

        assert_eq!(
            failed.as_deref(),
            Some("lpm-sandbox-helper: the identity is held")
        );
        assert_eq!(worked, None);
        assert_eq!(
            said_nothing.as_deref(),
            Some("the sandbox helper ended with exit code: 101")
        );
        assert_eq!(
            passed_on,
            "lpm-sandbox-helper: warning: couldn't take back C:\\a: denied (while cleaning up)\n\
             lpm-sandbox-helper: warning: the record was unreadable (while cleaning up)\n"
        );
    }

    /// A process that waits for input nobody sends, ended with the test.
    struct StandIn(Child);

    impl StandIn {
        fn start() -> Self {
            Self(
                Command::new(r"C:\Windows\System32\cmd.exe")
                    .args(["/d", "/c", "pause"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .expect("start a process to stand in"),
            )
        }
    }

    impl Drop for StandIn {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A run kept in `RUNS` until the test is done with it.
    struct KeptRun(u32);

    impl Drop for KeptRun {
        fn drop(&mut self) {
            RUNS.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.0);
        }
    }

    #[test]
    fn a_run_is_yet_to_start_its_script_until_a_process_joins_its_job() {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let folder = tempfile::tempdir().unwrap();
        let job_name = run_job_name();
        let mut helper = StandIn::start();
        let pid = helper.0.id();
        track_run(
            &mut helper.0,
            StartedRun {
                helper_path: folder.path().join("helper.cmd"),
                name: "LpmFinishRunTest".to_owned(),
                record: folder.path().join("grants.json"),
                job: ScriptJob::create(Some(&job_name)).expect("make the run's Job"),
                job_name: job_name.clone(),
            },
        )
        .expect("keep the run");
        let kept = KeptRun(pid);

        let before_a_script = script_is_yet_to_start(pid);
        let script = StandIn::start();
        let job = ScriptJob::open(&job_name).expect("open the run's Job as its helper does");
        // SAFETY: both handles are open.
        let joined =
            unsafe { AssignProcessToJobObject(job.as_raw(), script.0.as_raw_handle().cast()) };
        // The Job goes on counting a script that has ended.
        drop(script);
        let after_a_script = script_is_yet_to_start(pid);
        drop(kept);
        let once_released = script_is_yet_to_start(pid);

        assert_ne!(joined, 0, "the stand-in joins the Job");
        assert!(before_a_script, "no process has joined the run's Job yet");
        assert!(!after_a_script, "the Job has held a process");
        assert!(
            !once_released,
            "a run that isn't kept has no script to wait for"
        );
    }

    #[test]
    fn narrow_readable_set_excludes_project_root_but_keeps_toolchains() {
        let spec = make_spec();
        let set = readable_allow_set(&spec);
        assert!(
            !set.iter().any(|p| p == &spec.project_dir),
            "narrow reads must exclude the project root; got: {set:?}",
        );
        assert!(
            set.iter()
                .any(|p| p == &spec.home_dir.join(".nvm").join("versions")),
            "readable_allow_set must include ~/.nvm/versions for toolchain probes; got: {set:?}",
        );
    }

    #[test]
    fn locate_sandbox_helper_prefers_env_override() {
        // Create a tempfile that "looks like" the helper, set the
        // override, verify the locator returns it.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        // SAFETY: tests run with single-threaded `cargo test` by
        // default for this crate; the workspace doesn't `set_var`
        // from concurrent threads.
        unsafe {
            std::env::set_var("LPM_SANDBOX_HELPER", &path);
        }
        let located = locate_sandbox_helper();
        unsafe {
            std::env::remove_var("LPM_SANDBOX_HELPER");
        }
        assert_eq!(
            located.ok(),
            Some(path),
            "LPM_SANDBOX_HELPER override must win when the named file exists",
        );
    }

    #[test]
    fn a_relative_helper_override_is_refused_before_anything_is_looked_up() {
        for value in [
            r"tools\lpm-sandbox-helper.exe",
            r"C:tools\lpm-sandbox-helper.exe",
            r"\tools\lpm-sandbox-helper.exe",
        ] {
            unsafe {
                std::env::set_var("LPM_SANDBOX_HELPER", value);
            }
            let located = locate_sandbox_helper();
            unsafe {
                std::env::remove_var("LPM_SANDBOX_HELPER");
            }
            match located {
                Err(error @ SandboxError::HelperOverrideNotAbsolute { .. }) => {
                    assert!(
                        error.to_string().contains("isn't an absolute path"),
                        "{error}"
                    );
                }
                other => panic!("{value}: expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_missing_helper_is_refused_naming_every_place_looked() {
        let overridden = PathBuf::from(r"C:\does-not-exist\lpm-sandbox-helper.exe");
        unsafe {
            std::env::set_var("LPM_SANDBOX_HELPER", &overridden);
        }
        let located = locate_sandbox_helper();
        unsafe {
            std::env::remove_var("LPM_SANDBOX_HELPER");
        }
        let beside = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join(HELPER_FILE_NAME);
        match located {
            Ok(path) => assert_eq!(path, beside, "only the file beside the test may be found"),
            Err(SandboxError::HelperMissing { searched }) => {
                assert_eq!(searched, vec![overridden, beside]);
            }
            Err(other) => panic!("expected HelperMissing, got {other:?}"),
        }
    }

    const VCVARSALL_UNDER_TEST_ENV: &str = "LPM_TEST_VCVARSALL_UNDER_TEST";

    /// The capture runs outside the sandbox before any lifecycle script. The
    /// directory lpm was started in is usually a project root, which a cloned
    /// repository controls, and lpm started from a package script has the
    /// project's `node_modules\.bin` on `PATH`. The Visual Studio scripts call
    /// `reg`, `where`, `findstr` and others by bare name, so neither may supply
    /// them. The working directory is process-wide, so the parent re-runs this
    /// test in a child process started from the planted project.
    #[test]
    fn msvc_env_capture_never_runs_commands_planted_in_the_working_directory_or_on_path() {
        if let Some(vcvarsall) = std::env::var_os(VCVARSALL_UNDER_TEST_ENV) {
            let inherited_path = std::env::var("PATH").unwrap();
            let target = MsvcTarget::parse(host_msvc_arch()).unwrap();
            let additions = try_capture_from_vcvarsall(Path::new(&vcvarsall), &target).unwrap();
            assert_eq!(
                additions.get("LPM_TEST_MSVC_CAPTURED").map(String::as_str),
                Some("1"),
                "the capture must still return what vcvarsall.bat set",
            );
            assert!(
                !additions
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case(NO_CURRENT_DIRECTORY_SEARCH_ENV)),
                "the capture's own search hardening must not leak into lifecycle scripts",
            );
            let path = additions
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case("PATH").then_some(value))
                .expect("vcvarsall.bat prepended a directory to PATH");
            let (added, rest) = path.split_once(';').unwrap();
            assert!(added.ends_with(r"\fakebin"), "{path}");
            assert_eq!(
                rest, inherited_path,
                "lifecycle scripts keep the PATH lpm inherited, after what vcvarsall added",
            );
            if std::env::var_os(VSCMD_PREINIT_PATH_ENV).is_some() {
                assert_eq!(
                    additions.get(VSCMD_PREINIT_PATH_ENV),
                    None,
                    "a PATH a Developer Command Prompt already saved stays as it was",
                );
            } else {
                assert_eq!(
                    additions.get(VSCMD_PREINIT_PATH_ENV),
                    Some(&inherited_path),
                    "VsDevCmd's saved PATH is the one lpm inherited, not the capture's",
                );
            }
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("my project");
        let project_bin = project.join(r"node_modules\.bin");
        let build_dir = root
            .path()
            .join(r"Microsoft Visual Studio\VC\Auxiliary\Build");
        std::fs::create_dir_all(&project_bin).unwrap();
        std::fs::create_dir_all(&build_dir).unwrap();
        let marker = root.path().join("planted-command-ran.txt");
        for (dir, origin) in [(&project, "working directory"), (&project_bin, "PATH")] {
            for planted in ["reg.cmd", "findstr.cmd", "where.cmd"] {
                std::fs::write(
                    dir.join(planted),
                    format!(
                        "@echo {planted} from {origin}>>\"{}\"\r\n",
                        marker.display()
                    ),
                )
                .unwrap();
            }
        }
        let vcvarsall = build_dir.join("vcvarsall.bat");
        std::fs::write(
            &vcvarsall,
            "@echo off\r\n\
             reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v CurrentBuild >nul 2>&1 || exit /b 11\r\n\
             where cmd >nul 2>&1 || exit /b 12\r\n\
             echo vcvars| findstr vcvars >nul || exit /b 13\r\n\
             if not defined __VSCMD_PREINIT_PATH set \"__VSCMD_PREINIT_PATH=%PATH%\"\r\n\
             set \"PATH=%~dp0fakebin;%PATH%\"\r\n\
             set LPM_TEST_MSVC_CAPTURED=1\r\n\
             exit /b 0\r\n",
        )
        .unwrap();
        let mut path = project_bin.into_os_string();
        path.push(";");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        // Left to cmd.exe's usual search, `reg` is the planted one: first from
        // the working directory, then, with that skipped, from PATH.
        let cmd = lpm_common::platform::windows_system_directory()
            .unwrap()
            .join("cmd.exe");
        for (skip_working_directory, origin) in [(false, "working directory"), (true, "PATH")] {
            let mut shell = Command::new(&cmd);
            shell
                .args(["/D", "/C", "reg"])
                .current_dir(&project)
                .env("PATH", &path);
            if skip_working_directory {
                shell.env(NO_CURRENT_DIRECTORY_SEARCH_ENV, "1");
            } else {
                shell.env_remove(NO_CURRENT_DIRECTORY_SEARCH_ENV);
            }
            assert!(shell.status().unwrap().success());
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap().trim(),
                format!("reg.cmd from {origin}"),
            );
            std::fs::remove_file(&marker).unwrap();
        }

        // Started from a Developer Command Prompt, VsDevCmd keeps the PATH it
        // saved there, even one that begins with the capture's search PATH.
        let saved_by_developer_prompt = format!(
            r"{};C:\lpm-test-saved-path",
            MsvcCaptureShell::locate().unwrap().search_path
        );
        for saved_path in [None, Some(saved_by_developer_prompt.as_str())] {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "windows_appcontainer::tests::msvc_env_capture_never_runs_commands_planted_in_the_working_directory_or_on_path",
                    "--nocapture",
                ])
                .current_dir(&project)
                .env(VCVARSALL_UNDER_TEST_ENV, &vcvarsall)
                .env("PATH", &path)
                .env_remove(NO_CURRENT_DIRECTORY_SEARCH_ENV);
            match saved_path {
                Some(saved) => child.env(VSCMD_PREINIT_PATH_ENV, saved),
                None => child.env_remove(VSCMD_PREINIT_PATH_ENV),
            };
            let output = child.output().unwrap();

            assert!(
                !marker.exists(),
                "commands planted in the project ran during the MSVC env capture:\n{}",
                std::fs::read_to_string(&marker).unwrap_or_default().trim(),
            );
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
                "the capture in the child test process failed or didn't run \
                 (saved PATH {saved_path:?}):\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn vcvarsall_runs_in_the_system_cmd_from_its_directory_with_only_windows_tools_on_path() {
        let shell = MsvcCaptureShell::locate().unwrap();
        let system = lpm_common::platform::windows_system_directory().unwrap();
        let vcvarsall = Path::new(r"C:\VS & Tools (x86)\VC\Auxiliary\Build\vcvarsall.bat");
        let target = MsvcTarget::parse("x64_arm64 10.0.22621.0 -vcvars_ver=14.29").unwrap();
        let command = shell.vcvarsall_command(vcvarsall, &target).unwrap();

        assert_eq!(Path::new(command.get_program()), system.join("cmd.exe"));
        assert_eq!(command.get_current_dir(), vcvarsall.parent());
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            [std::ffi::OsStr::new(
                r#"/D /V:OFF /S /C ""C:\VS & Tools (x86)\VC\Auxiliary\Build\vcvarsall.bat" x64_arm64 10.0.22621.0 -vcvars_ver=14.29 && set""#
            )],
        );
        let env = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .and_then(|(_, value)| value)
                .map(std::ffi::OsStr::to_os_string)
        };
        assert_eq!(
            env("ComSpec"),
            Some(system.join("cmd.exe").into_os_string())
        );
        assert_eq!(env(NO_CURRENT_DIRECTORY_SEARCH_ENV), Some("1".into()));
        let path = env("PATH").unwrap();
        let path = path.to_str().unwrap();
        assert!(
            path.split(';').all(|entry| {
                Path::new(entry).starts_with(system.parent().unwrap())
                    || Path::new(VSWHERE).parent() == Some(Path::new(entry))
            }),
            "{path}",
        );
    }

    #[test]
    fn msvc_target_is_only_ever_vcvarsall_arguments() {
        assert_eq!(MsvcTarget::parse("arm64"), Ok(MsvcTarget("arm64".into())));
        assert_eq!(
            MsvcTarget::parse(" x64  store\t10.0.22621.0 -vcvars_ver=14.29 "),
            Ok(MsvcTarget(
                "x64 store 10.0.22621.0 -vcvars_ver=14.29".into()
            )),
        );
        for value in [
            "",
            " ",
            "x64 & calc",
            "x64\"",
            "arm64 && whoami",
            "x64|more",
            "x64 >out",
            "x64 <in",
            "x64^",
            "%PATH%",
            "!PATH!",
            "x64 (",
            "x64,arm64;",
        ] {
            assert!(MsvcTarget::parse(value).is_err(), "{value:?}");
        }
    }

    /// Where Visual Studio with the C++ tools is installed, the capture still
    /// sets up its compiler with only Windows' own directories to search.
    #[test]
    fn msvc_env_capture_sets_up_an_installed_visual_studio() {
        let has_vcvarsall = Command::new(VSWHERE)
            .args([
                "-prerelease",
                "-products",
                "*",
                "-property",
                "installationPath",
            ])
            .output()
            .is_ok_and(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|root| !root.is_empty())
                    .any(|root| {
                        Path::new(root)
                            .join(r"VC\Auxiliary\Build\vcvarsall.bat")
                            .exists()
                    })
            });
        if !has_vcvarsall {
            eprintln!("skipped: no Visual Studio with the C++ tools installed");
            return;
        }

        let additions = do_capture_msvc_env().unwrap();
        let value = |name: &str| {
            additions
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then(|| value.clone()))
                .or_else(|| std::env::var(name).ok())
        };
        for name in ["INCLUDE", "LIB", "VCToolsInstallDir"] {
            assert!(
                value(name).is_some_and(|value| !value.is_empty()),
                "{name} is not set"
            );
        }
        let path = value("PATH").unwrap();
        assert!(
            path.split(';')
                .any(|entry| Path::new(entry).join("cl.exe").is_file()),
            "cl.exe is not on PATH: {path}",
        );
    }

    #[test]
    fn msvc_path_puts_what_vcvarsall_added_around_the_inherited_path() {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStringExt;

        let searched = r"C:\Windows\system32;C:\Windows;C:\Installer";
        let inherited = OsStr::new(r"C:\project\node_modules\.bin;C:\Program Files\nodejs");
        assert_eq!(
            msvc_path_over_inherited(
                r"C:\VS\bin;C:\VS\tools;C:\WINDOWS\System32\;C:\Windows;C:\Installer;C:\VS\late",
                searched,
                Some(inherited),
            )
            .as_deref(),
            Some(
                r"C:\VS\bin;C:\VS\tools;C:\project\node_modules\.bin;C:\Program Files\nodejs;C:\VS\late"
            ),
        );
        assert_eq!(
            msvc_path_over_inherited(
                r"C:\VS\pre;C:\Windows\system32;C:\Windows;C:\Installer;C:\VS\late;C:\Windows\system32",
                searched,
                Some(inherited),
            )
            .as_deref(),
            Some(
                r"C:\VS\pre;C:\project\node_modules\.bin;C:\Program Files\nodejs;C:\VS\late;C:\Windows\system32"
            ),
            "only the search PATH itself is replaced; directories vcvarsall appended keep their order",
        );
        assert_eq!(
            msvc_path_over_inherited(
                r"C:\VS\bin;C:\Windows\system32;C:\Windows;C:\Installer;C:\VS\late",
                searched,
                None,
            )
            .as_deref(),
            Some(r"C:\VS\bin;C:\VS\late"),
            "with nothing inherited, only what vcvarsall added remains",
        );
        for rewritten in [
            r"C:\VS\only",
            r"C:\Windows\system32;C:\VS\between;C:\Windows;C:\Installer",
        ] {
            assert_eq!(
                msvc_path_over_inherited(rewritten, searched, Some(inherited)).as_deref(),
                Some(rewritten),
                "a PATH vcvarsall rewrote is kept as it left it",
            );
        }
        let not_unicode = std::ffi::OsString::from_wide(&[0x43, 0xD800]);
        assert_eq!(
            msvc_path_over_inherited(searched, searched, Some(&not_unicode)),
            None,
        );
    }

    #[test]
    fn only_the_whole_search_path_counts_as_the_captures_own_saved_path() {
        let searched = r"C:\Windows\system32;C:\Windows;C:\Installer";
        assert!(is_search_path(searched, searched));
        assert!(is_search_path(
            r"C:\WINDOWS\System32\;C:\Windows;C:\Installer;",
            searched
        ));
        for other in [
            r"C:\Windows\system32;C:\Windows",
            r"C:\Windows\system32;C:\Windows;C:\Installer;C:\saved",
            r"C:\Windows;C:\Windows\system32;C:\Installer",
            "",
        ] {
            assert!(!is_search_path(other, searched), "{other:?}");
        }

        // What a Developer Command Prompt saves is the user's PATH, which
        // usually starts with the same Windows directories.
        let search_path = MsvcCaptureShell::locate().unwrap().search_path;
        let system = lpm_common::platform::windows_system_directory().unwrap();
        let system = system.to_str().unwrap();
        let windows = Path::new(system).parent().unwrap().display();
        let user_path = format!(
            r"{system};{windows};{system}\Wbem;{system}\WindowsPowerShell\v1.0\;{system}\OpenSSH\;C:\Program Files\nodejs\"
        );
        assert!(!is_search_path(&user_path, &search_path), "{user_path}");
    }

    #[test]
    fn host_msvc_arch_returns_arm64_or_x64_for_supported_targets() {
        let arch = host_msvc_arch();
        assert!(
            matches!(arch, "arm64" | "x64" | "x86"),
            "unexpected host arch token: {arch}",
        );
    }
}
