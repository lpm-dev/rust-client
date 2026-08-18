//! Windows sandbox backend: Mandatory Integrity Control (Low IL) +
//! Job Object.
//!
//! # Mechanism
//!
//! Windows has no direct analog of landlock/Seatbelt's path-based
//! deny-default for the spawned child. The cleanest equivalent on
//! stable Rust + a `std::process::Child` return type is **Mandatory
//! Integrity Control**:
//!
//! 1. The parent marks each allow-set directory with a Low integrity
//!    label (a SACL entry of type `SYSTEM_MANDATORY_LABEL_ACE`). The
//!    label is **inheritable** so newly-created files inside also
//!    pick up the Low IL writeability.
//! 2. The child is launched with [`CREATE_SUSPENDED`] via
//!    [`std::os::windows::process::CommandExt::creation_flags`]. The
//!    suspended state means the child's primary thread hasn't run a
//!    single instruction yet.
//! 3. The parent opens the suspended child's primary token, swaps
//!    in a `TOKEN_MANDATORY_LABEL` carrying the `Low` integrity SID
//!    (`S-1-16-4096`), and writes it back with
//!    [`SetTokenInformation`]. The child now owns a Low IL primary
//!    token.
//! 4. The parent creates a Job Object with
//!    `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, attaches the suspended
//!    child via [`AssignProcessToJobObject`], and stashes the job
//!    handle on the returned `Child` wrapper so the Drop path
//!    terminates the entire process tree.
//! 5. The parent resumes the child via [`NtResumeProcess`] — an
//!    undocumented but ABI-stable since Windows XP `ntdll.dll`
//!    entry point. `std::process::Child` does not expose the
//!    primary thread handle, and going through ToolHelp32 to find
//!    the thread ID is brittle in the face of future thread-creation
//!    races; resuming via the process handle is the clean answer.
//!
//! # Posture mapping
//!
//! - [`SandboxPosture::Default`] (`deny_outbound_network = false`):
//!   Low IL filesystem-write containment. Reads are NOT restricted —
//!   Low IL processes can still read most user files (the brief's
//!   requirement is filesystem-WRITE containment). Network is
//!   allowed, matching the "relaxed default".
//! - [`SandboxPosture::Strict`] (`deny_outbound_network = true`):
//!   Windows cannot deliver the strict contract today — closing the
//!   network gap needs a Windows Filtering Platform (WFP) callout
//!   filter, deferred to a future phase. When the user requests strict
//!   and `allow_degraded = false`, the backend surfaces
//!   [`SandboxError::UnsupportedPlatform`] with the named
//!   remediations (`--no-sandbox`, `trustedDependencies`, drop back
//!   to default mode, opt into degraded). When `allow_degraded =
//!   true`, the backend constructs the Low IL filesystem sandbox and
//!   returns [`SandboxPosture::Degraded`] with `missing =
//!   "network-containment"` so `lpm doctor` and the per-install
//!   warning surface the gap honestly. The Linux strict-with-degraded
//!   precedent is the exact pattern we mirror here.
//!
//! # Persistence note
//!
//! Marking a directory with a Low IL label is a persistent ACL
//! change. Once `node_modules`, `~/.cache`, `~/.node-gyp`, `~/.npm`,
//! `package_dir`, `.husky`, `.lpm`, `tmpdir`, and any
//! `extra_write_dirs` carry the Low label, **any** Low IL process on
//! the host can write to them. In practice the only common Low IL
//! processes are browser sandboxes which don't touch user project
//! directories; the practical impact is near zero. The cost is
//! offset by gaining real filesystem-write containment for our
//! lifecycle-script child — the same trade-off landlock makes by
//! granting access to specific subdirs through inheritable rules.
//!
//! # Accepted-posture trade-off (M55)
//!
//! The Low IL label survives `lpm` process exit. After a lifecycle
//! script completes, the labelled directories remain writable by
//! every Low IL process on the host — not just our (now-gone)
//! lifecycle child. The audit threat model is a compromised Low IL
//! process (a browser renderer, or any low-integrity app) using the
//! persistent labels to poison `~/.npm`, `~/.cache`, `~/.node-gyp`,
//! or `node_modules` between `lpm` runs, so a later normal-IL
//! `lpm install / lpm run` picks up the planted bytes.
//!
//! The right fix is to revoke the Low IL label on every directory
//! we labelled when the sandboxed process exits, so the writeable
//! window matches the lifecycle script's lifetime. That requires
//! either:
//!
//! - tracking every labelled path in the parent (we already do this
//!   via `LABELED_ROOTS` for caching) AND running the revoke as a
//!   `Drop` or explicit teardown step, which would also need to
//!   handle the rare case where two concurrent `lpm` invocations
//!   labelled overlapping paths and only one finishes; or
//! - moving to the AppContainer backend (see
//!   [`crate::windows_appcontainer`]) which uses DACL grants on a
//!   per-token SID instead of integrity labels — the grants
//!   evaporate when the AppContainer profile is destroyed.
//!
//! The current backend prefers persistent Low IL labels because the
//! AppContainer flow has its own footguns (LowBox token attribute
//! quirks, package-family-name collisions across concurrent installs)
//! and is not yet the default. The AppContainer backend migration is
//! the long-term mitigation for the cross-IL poisoning class.

#![cfg(target_os = "windows")]

use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec,
    SandboxedCommand,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::{LazyLock, Mutex};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, GetSecurityDescriptorSacl, IsValidSid, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
    FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, OpenProcessToken, TerminateProcess};

/// `SE_GROUP_INTEGRITY` is the well-known constant attribute bit for
/// a SID-and-attributes entry that represents an integrity-level
/// group. Value is fixed at `0x00000020` since Windows Vista; the
/// constant is part of every Windows SDK winnt.h but not exposed by
/// `windows-sys 0.60`. Inlining one literal is cheaper than enabling
/// another (unrelated) feature flag.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

// ── Backend struct ───────────────────────────────────────────────────

/// Windows backend. See module docs for the mechanism
/// rationale. The struct is constructed by
/// [`crate::new_for_platform_with_options`] once per package; it
/// stashes the spec + decided posture so per-spawn calls render
/// deterministically without re-running the network-denial policy
/// decision.
///
/// `Debug` is derived so tests that pattern-match on a
/// `Result<Self, SandboxError>` can print the unexpected `Ok(Self)`
/// arm via `{other:?}` — same shape `linux::LandlockSandbox`'s test
/// surface uses.
#[derive(Debug)]
pub(crate) struct WindowsSandbox {
    spec: SandboxSpec,
    mode: SandboxMode,
    posture: BackendPosture,
}

/// Internal posture tag. Mirrors the Linux backend's two-step
/// decision: the caller's `deny_outbound_network` + `allow_degraded`
/// inputs land in one of these variants at `new()` time, then
/// `Sandbox::posture()` lowers it to the public [`SandboxPosture`]
/// enum.
#[derive(Debug, Clone)]
enum BackendPosture {
    /// Filesystem-write containment via Low IL. Network allowed.
    /// Reached for `deny_outbound_network = false` or for
    /// `deny_outbound_network = true && allow_degraded = true` (in
    /// which case the public posture is `Degraded` so the per-install
    /// warning surfaces the network gap).
    LowIl {
        /// `true` when the user requested strict but accepted the
        /// network-gap fallback. Drives the
        /// `Sandbox::posture()` switch between `Default` and
        /// `Degraded`.
        degraded_from_strict: bool,
    },
}

// ── Construction ─────────────────────────────────────────────────────

impl WindowsSandbox {
    pub(crate) fn new(
        spec: SandboxSpec,
        mode: SandboxMode,
        options: SandboxOptions,
    ) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => {
                let posture =
                    decide_posture(options.deny_outbound_network, options.allow_degraded)?;
                Ok(Self {
                    spec,
                    mode,
                    posture,
                })
            }
            // Linux precedent: landlock has no native observe-only
            // primitive, so LogOnly is rejected with a clear pointer
            // at `--no-sandbox` for compat debugging. Windows is in
            // the same boat — Mandatory Integrity Control has no
            // "audit-only" mode either; the honest answer is to
            // refuse rather than silently behave like Enforce or
            // silently allow.
            SandboxMode::LogOnly => Err(SandboxError::ModeNotSupportedOnPlatform {
                platform: "windows".to_string(),
                mode: SandboxMode::LogOnly,
                remediation: "Mandatory Integrity Control has no native observe-only \
                              primitive in To debug a sandbox false-positive, \
                              re-run with --no-sandbox. `--sandbox-log` remains available \
                              on macOS."
                    .to_string(),
            }),
            // Disabled never reaches this backend — the factory in
            // [`crate::new_for_platform_with_options`] short-circuits
            // to [`crate::NoopSandbox`] before dispatching. Defensive
            // error matches the macOS + Linux backends.
            SandboxMode::Disabled => Err(SandboxError::InvalidSpec {
                reason: "SandboxMode::Disabled reached WindowsSandbox — should have been \
                         routed to NoopSandbox by the factory"
                    .to_string(),
            }),
        }
    }
}

/// posture decision. Pure (inputs in, outcome out), mirrors
/// the Linux `decide_posture` shape. Factored out so the unit tests
/// pin the table without a Windows kernel.
fn decide_posture(
    deny_outbound_network: bool,
    allow_degraded: bool,
) -> Result<BackendPosture, SandboxError> {
    if !deny_outbound_network {
        return Ok(BackendPosture::LowIl {
            degraded_from_strict: false,
        });
    }
    // Strict requested. Windows can't deliver outbound network denial
    // without the degraded opt-in we refuse, symmetric with Linux's kernel-too-old path.
    if !allow_degraded {
        return Err(SandboxError::UnsupportedPlatform {
            platform: "windows".to_string(),
            remediation: strict_not_yet_supported_remediation(),
        });
    }
    Ok(BackendPosture::LowIl {
        degraded_from_strict: true,
    })
}

/// User-facing remediation for the strict-mode-not-yet-supported
/// path on Windows. Names every interim recourse so users can pick
/// the one that fits their workflow. Mirrors the Linux
/// `strict_remediation()` text shape — same options where they
/// apply.
fn strict_not_yet_supported_remediation() -> String {
    "ships Windows filesystem-write containment but \
     defers outbound-network denial to (the Windows \
     Filtering Platform layer). Remediation options: \
     (1) set `[sandbox] allow-degraded = true` in `~/.lpm/config.toml` \
     or `./lpm.toml` to fall back to filesystem-only containment \
     (NO outbound network denial); \
     (2) add the package to `package.json > lpm > trustedDependencies` \
     to skip the sandbox for this dependency; \
     (3) re-run with `--no-sandbox` to skip the sandbox wholesale for \
     one command; \
     (4) run `lpm config sandbox --set default` to drop back to the \
     recommended default posture (filesystem + env containment, \
     network allowed)."
        .to_string()
}

// ── Sandbox trait impl ───────────────────────────────────────────────

impl Sandbox for WindowsSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<Child, SandboxError> {
        for (index, path) in self.spec.extra_write_dirs.iter().enumerate() {
            crate::config::revalidate_effective_write_dir(path, index)?;
        }

        // Mark every writable directory in the allow-set with a Low
        // IL system mandatory label so the Low IL child can write
        // there. Idempotent — re-running the same install or running
        // a different package whose allow-set overlaps just re-applies
        // the same label.
        for path in writable_allow_set(&self.spec) {
            apply_low_il_label(&path)?;
        }

        // Build the std::process::Command exactly like the macOS /
        // Linux backends do. The Windows-specific bit is two extra
        // calls: `creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP)`
        // so the child starts paused and gets its own console process
        // group (parity with the Unix `process_group(0)` on the
        // other backends), then a post-spawn integrity-drop +
        // job-object-assign + resume sequence.
        let mut command = Command::new(&cmd.program);
        for a in &cmd.args {
            command.arg(a);
        }
        if cmd.env_clear {
            command.env_clear();
        }
        for (k, v) in &cmd.envs {
            command.env(k, v);
        }
        if let Some(dir) = &cmd.current_dir {
            command.current_dir(dir);
        }
        command.stdout(Stdio::from(cmd.stdout));
        command.stderr(Stdio::from(cmd.stderr));
        command.stdin(Stdio::from(cmd.stdin));

        // CREATE_SUSPENDED: primary thread of the child is created
        //                   suspended — we drop its IL before any
        //                   instruction runs.
        // CREATE_NEW_PROCESS_GROUP: gives the child its own console
        //                           process group so Ctrl+C in the
        //                           parent doesn't get forwarded into
        //                           the lifecycle script, matching
        //                           the Unix `process_group(0)`
        //                           semantic the other backends rely
        //                           on for the timeout-kill path.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        command.creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);

        let child = command.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: format!("CreateProcessW failed: {e}"),
        })?;

        // Drop the suspended child's integrity level to Low. The
        // process handle from `Child::as_raw_handle()` is owned by
        // the Child wrapper; we don't close it, we just open a token
        // off of it.
        let proc_handle = child.as_raw_handle() as HANDLE;
        if let Err(e) = drop_integrity_to_low(proc_handle) {
            // The child is still suspended — terminate it before
            // returning so we don't leak a stuck process. Drop on
            // `Child` would also terminate but only when the value is
            // dropped; killing eagerly is the cleaner failure shape.
            let _ = unsafe { TerminateProcess(proc_handle, 1) };
            return Err(e);
        }

        // Attach the child to a Job Object with KILL_ON_JOB_CLOSE so
        // a panic / timeout in the parent reliably tears down the
        // child + every descendant. The Job handle has to outlive
        // `Child::wait()` calls, so we stash it in the module-local
        // `JOB_TRACKER` (see `register_job_for_child` below) — the
        // trait return type is `std::process::Child` which has no
        // side channel for an opaque kernel handle, so we hold it
        // in the parent process's address space until at-exit
        // cleanup releases it.
        let job = match create_kill_on_close_job_and_attach(
            proc_handle,
            JobLimitProfile::LifecycleSandbox,
        ) {
            Ok(j) => j,
            Err(e) => {
                let _ = unsafe { TerminateProcess(proc_handle, 1) };
                return Err(e);
            }
        };

        // Resume the child. `NtResumeProcess` is undocumented but
        // ABI-stable since Windows XP; we declare its signature
        // inline below. Going through ToolHelp32 to find the primary
        // thread ID would also work but adds a syscall round trip
        // and a brittle enumeration loop for what amounts to a
        // one-liner here.
        if let Err(e) = resume_process(proc_handle) {
            let _ = unsafe { TerminateProcess(proc_handle, 1) };
            // The job handle's `Drop` will Close it and (because of
            // KILL_ON_JOB_CLOSE) terminate the child if it somehow
            // survived the TerminateProcess above.
            drop(job);
            return Err(e);
        }

        // Stash the job handle on a tracker so it lives as long as
        // the Child — when the user drops the Child, the tracker's
        // entry releases the handle and KILL_ON_JOB_CLOSE finishes
        // any straggler descendants.
        register_job_for_child(child.id(), job);

        Ok(child)
    }

    fn backend_name(&self) -> &'static str {
        "windows-il"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }

    fn posture(&self) -> SandboxPosture {
        match &self.posture {
            BackendPosture::LowIl {
                degraded_from_strict: false,
            } => SandboxPosture::Default,
            BackendPosture::LowIl {
                degraded_from_strict: true,
            } => SandboxPosture::Degraded {
                // Linux-shaped fields, repurposed for Windows. The
                // `kernel` field carries the platform identifier
                // (Linux fills it with the kernel version because
                // that's the dimension that drove its fallback;
                // Windows fills it with the OS family because the
                // strict-mode block is platform-wide, not
                // kernel-version dependent).
                kernel: detect_windows_version_string(),
                abi: "low-il",
                missing: "network-containment",
            },
        }
    }
}

pub(crate) fn spawn_tracked_command(command: &mut Command) -> Result<Child, SandboxError> {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    command.creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);

    let child = command.spawn().map_err(|error| SandboxError::SpawnFailed {
        reason: format!("CreateProcessW failed: {error}"),
    })?;
    let process_handle = child.as_raw_handle() as HANDLE;
    let job = match create_kill_on_close_job_and_attach(
        process_handle,
        JobLimitProfile::TreeTrackingOnly,
    ) {
        Ok(job) => job,
        Err(error) => {
            // SAFETY: the handle belongs to the suspended child returned by
            // CreateProcessW and remains valid while `child` is alive.
            let _ = unsafe { TerminateProcess(process_handle, 1) };
            return Err(error);
        }
    };

    if let Err(error) = resume_process(process_handle) {
        // SAFETY: the process is still suspended and the handle remains valid.
        let _ = unsafe { TerminateProcess(process_handle, 1) };
        drop(job);
        return Err(error);
    }

    register_job_for_child(child.id(), job);
    Ok(child)
}

// ── Allow-set rendering ──────────────────────────────────────────────

/// The list of directories the lifecycle child needs Low-IL write
/// access to. Mirrors the union of:
/// - macOS Seatbelt `file-write*` block ([`crate::seatbelt`])
/// - Linux landlock `ReadWrite` rules
///   ([`crate::landlock_rules::describe_rules`])
///
/// Order is deterministic so tests can pin "first writable allow is
/// package_dir" etc. without a sort step.
///
/// `pub(crate)` so the AppContainer backend
/// ([`crate::windows_appcontainer`]) can reuse the same writable
/// set when rendering its DACL grants. Both backends must agree on
/// what counts as writable so the user-visible contract doesn't
/// shift across backend swaps.
pub(crate) fn writable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(8 + spec.extra_write_dirs.len());
    out.push(spec.package_dir.clone());
    out.push(spec.project_dir.join("node_modules"));
    out.push(spec.project_dir.join(".husky"));
    out.push(spec.project_dir.join(".lpm"));
    out.push(spec.home_dir.join(".cache"));
    out.push(spec.home_dir.join(".node-gyp"));
    out.push(spec.home_dir.join(".npm"));
    out.push(spec.tmpdir.clone());
    for p in &spec.extra_write_dirs {
        out.push(p.clone());
    }
    out
}

// ── Low IL labelling helpers ─────────────────────────────────────────

/// Apply a Low integrity mandatory label to `path` and to every
/// existing descendant. The label is inheritable (`OICI` in SDDL —
/// Object + Container Inherit) so files + subdirs created inside
/// later also pick up the Low IL writeability via kernel inheritance.
///
/// **Why the recursive walk.** Win32's `OICI` inheritance flags are
/// NOT retroactive — they only fire at the moment a child object is
/// created. Existing files inside an already-populated directory
/// (e.g. a pre-existing `~/.cache`, or a freshly-extracted
/// `package_dir` whose contents the extractor wrote with the parent's
/// Medium IL) keep their original Medium IL label and remain
/// unwritable by the Low IL child. Without this walk, lifecycle
/// scripts that modify existing package files (codegen output, vendor
/// directories, etc.) would silently fail with "access denied" even
/// though the directory itself is correctly labelled. Walking the
/// tree once per install fixes this at the cost of one
/// `SetNamedSecurityInfoW` per existing descendant.
///
/// **Per-process caching.** Every call consults [`LABELED_ROOTS`]
/// before doing any kernel work. Once a path is labelled by this
/// process it stays Low-IL until external action changes the SACL,
/// so re-walking on every `Sandbox::spawn` would be pure waste — an
/// install with N lifecycle scripts would do N full walks over
/// `~/.cache`, `~/.npm`, `~/.node-gyp`, and tmpdir. New files created
/// inside the dir between two spawns inherit Low IL automatically
/// via OICI, so the second spawn doesn't need to re-touch them.
///
/// Idempotent: if `path` is already labelled Low IL, the second
/// `SetNamedSecurityInfoW` call would also be a no-op, but skipping
/// it entirely via the cache is faster.
///
/// Errors on the root surface as [`SandboxError::ProfileRenderFailed`]
/// with the path + Win32 last-error code so denial messages remain
/// actionable. Errors on individual descendants are logged at debug
/// level and swallowed (best-effort) — a single unlabel-able entry
/// (broken symlink, system file with a locked ACL) shouldn't fail
/// the entire install.
///
/// # Skipped paths
///
/// Paths that don't exist yet are silently skipped — the install
/// pipeline calls [`crate::prepare_writable_dirs`] first, which
/// creates the standard subset + `extra_write_dirs`. Any path that
/// still doesn't exist at this point (rare) resolves to a no-op
/// rather than a fatal error (matching landlock's "missing rule
/// path = skip with a debug log" posture).
fn apply_low_il_label(path: &Path) -> Result<(), SandboxError> {
    if !path.exists() {
        tracing::debug!(
            target: "lpm_sandbox::windows",
            "skip Low IL label on nonexistent path {}",
            path.display(),
        );
        return Ok(());
    }

    // Refuse reparse-point roots.
    //
    // `set_low_il_label_on` uses the name-form `SetNamedSecurityInfoW`
    // which follows reparse points by default — labelling a junction
    // root would apply Low IL writeability to its target, which may
    // resolve outside the intended allow-set tree (including an
    // attacker-controlled target if the user's profile dir was
    // compromised before lpm ran). silently followed; that
    // behaviour is now an explicit refusal.
    //
    // Remediation depends on which allow-set entry this path is. The
    // built-in roots (`~/.cache`, `~/.node-gyp`, `~/.npm`, plus the
    // four project-rooted entries) are appended unconditionally in
    // `writable_allow_set`; `sandboxWriteDirs` does NOT displace them.
    // On Windows `dirs::home_dir()` reads the profile from the
    // registry, so `HOME`/`USERPROFILE` env tweaks don't help either.
    // The error message below names the truthful per-class options.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if is_reparse_point(&meta) => {
            return Err(SandboxError::ProfileRenderFailed {
                reason: format!(
                    "allow-set root {p} is a reparse point (symlink / \
                     junction / mount point). The sandbox refuses to follow \
                     it because the kernel would apply Low IL writeability \
                     to the reparse-point's target, which may resolve \
                     outside the intended allow-set tree.\n\
                     \n\
                     Workarounds:\n\
                     \n\
                       * Replace the reparse point at {p} with a regular \
                         directory (delete the link, recreate as a real \
                         directory, restore contents). Works for every root \
                         class.\n\
                       * If {p} is your TEMP dir (Windows %TEMP%): set the \
                         `TMP` and `TEMP` environment variables to a regular \
                         directory before invoking lpm. `std::env::temp_dir()` \
                         honors them and lpm will compute a different tmpdir \
                         for the sandbox.\n\
                       * If {p} is an entry you declared via \
                         `sandboxWriteDirs` in `package.json`: edit the entry \
                         to point at the canonical target directly instead of \
                         through the reparse point.\n\
                       * Re-run with `--no-sandbox` to skip sandbox \
                         containment for one command (universal fallback).\n\
                     \n\
                     Note: `sandboxWriteDirs` cannot bypass this refusal for \
                     built-in roots (`~/.cache`, `~/.node-gyp`, `~/.npm`, and \
                     the project-rooted entries) — they are added to the \
                     allow-set unconditionally regardless of `sandboxWriteDirs` \
                     content.",
                    p = path.display(),
                ),
            });
        }
        Ok(_) => {} // regular file or dir — proceed
        Err(e) => {
            // The `path.exists()` check above passed, so a symlink_metadata
            // failure here is unexpected — surface it rather than silently
            // proceeding into the slow path on potentially stale state.
            return Err(SandboxError::ProfileRenderFailed {
                reason: format!("symlink_metadata({}) failed: {e}", path.display()),
            });
        }
    }

    // Fast-path: was this exact directory object labelled earlier
    // in this process? Two-axis identity check:
    //
    // 1. **Canonical path**: a caller passing `C:\foo`, `C:\foo\`,
    //    and the same path with a `\\?\` extended prefix all hit
    //    the same cache entry. Canonicalization can fail (junctions,
    //    locked dirs); if it does we fall through and re-label,
    //    which is correct (idempotent at the kernel layer) just
    //    slower.
    // 2. **NTFS file identity** (`FILE_ID_INFO` =
    //    `(VolumeSerialNumber, FILE_ID_128)`): catches the case
    //    where a lifecycle script deletes and recreates a writable
    //    root between two spawns. The new directory object has the
    //    same path but a different NTFS file ID, and it inherits
    //    Medium IL from its parent rather than carrying our Low IL
    //    label, so a path-only cache would incorrectly skip the
    //    re-label and the next Low IL child would be denied writes.
    //    The volume serial number guards against the (rare) case
    //    where the same path resolves to different volumes across
    //    spawn calls.
    //
    // Identity probing also fails gracefully — if we can't read the
    // file ID for any reason (path was just deleted, locked, etc.)
    // we fall through to the slow path rather than risk a stale
    // hit.
    let cache_key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let current_identity = fetch_directory_identity(path);
    if let Some(current) = current_identity
        && labelled_cache_lookup(&cache_key) == Some(current)
    {
        tracing::debug!(
            target: "lpm_sandbox::windows",
            "skip Low IL label on already-labelled path {} (identity match)",
            path.display(),
        );
        return Ok(());
    }

    // Build the SACL once, then re-use the pointer for every entry
    // in the walk. The descriptor outlives the borrow because
    // `_sd_guard` stays in this stack frame for the entire function.
    let sd_guard = build_low_il_security_descriptor(path)?;
    let sacl_ptr = extract_sacl_pointer(sd_guard.0, path)?;

    // Apply to the root first. A failure here is fatal because the
    // OICI inheritance on this directory is what gives newly-created
    // files Low IL writeability.
    set_low_il_label_on(path, sacl_ptr)?;

    // Walk existing descendants. Per-entry failures are
    // non-fatal: we log at debug and move on so a hidden /
    // permission-locked file doesn't fail the whole install.
    if path.is_dir() {
        relabel_existing_descendants(path, sacl_ptr);
    }

    // Cache the labelled root + its current NTFS identity so
    // subsequent spawns in the same lpm process skip the walk. New
    // files created inside this dir by the lifecycle child inherit
    // Low IL automatically (OICI), so the second spawn doesn't need
    // to retouch them. If identity probing failed at the start (it
    // was None), don't poison the cache — a future spawn will probe
    // again and either succeed or take the slow path.
    if let Some(identity) = current_identity {
        labelled_cache_insert(cache_key, identity);
    }

    Ok(())
}

/// NTFS file identity for a directory — `(volume_serial,
/// file_id_128)`. The pair is globally unique per "object that
/// currently lives at this path." Comparing identities at cache
/// lookup time catches the delete-and-recreate case where the path
/// is stable but the directory object underneath changed (and so
/// has lost any inheritable Low IL label).
type DirectoryIdentity = (u64, [u8; 16]);

/// Open a read-only handle to a directory and pull its NTFS file
/// identity via `GetFileInformationByHandleEx(FileIdInfo)`. Returns
/// `None` on any failure (path doesn't exist, access denied, junction,
/// non-NTFS volume that doesn't support FILE_ID_INFO, etc.) so the
/// caller can decide whether to skip the cache or use a weaker check.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is required to open a directory
/// handle on Windows — without it, `CreateFileW` returns
/// `ERROR_ACCESS_DENIED` for directories. The handle has no write
/// access, so opening a labelled root we don't have write perms on
/// is still safe.
///
/// `FILE_SHARE_*` flags are all set so we don't block writes,
/// renames, or deletes the lifecycle script might do concurrently
/// — the probe is read-only and shouldn't introduce contention.
fn fetch_directory_identity(path: &Path) -> Option<DirectoryIdentity> {
    if !path.exists() {
        return None;
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is null-terminated. The four NULL/0 args take
    // their documented "no security attributes / no template"
    // meaning. The returned handle is owned by us; we Close it via
    // the OwnedHandle RAII wrapper below.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let _h = OwnedHandle(handle);

    // SAFETY: FILE_ID_INFO is plain old data (u64 +
    // FILE_ID_128 which is `[u8; 16]`). All-zero is a valid bit
    // pattern.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    Some((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// Process-wide memo: which directory objects have already been
/// Low-IL-labelled by this lpm process. Keyed by canonicalized path,
/// valued by the NTFS identity present at label time. A subsequent
/// spawn hits the fast-path iff the path's current identity still
/// matches the cached one.
///
/// Lifetime is the lpm process. Killing + restarting lpm clears the
/// cache, which is correct: external actors (Windows updates,
/// `icacls /reset`) could have stripped the label and we'd want to
/// reapply it.
///
/// Wrapped in `LazyLock` so the inner `HashMap` initializes on first
/// access without the `Option` ceremony at every call site
/// (`HashMap::new()` isn't `const` on stable, but `LazyLock` — stable
/// since Rust 1.80, repo pinned to 1.94.0 — gives us the same lazy
/// init for free). A poisoned mutex (some other thread panicked while
/// holding the lock) is recovered rather than propagated — losing the
/// cache wastes work but shouldn't fail the install.
static LABELED_ROOTS: LazyLock<Mutex<HashMap<PathBuf, DirectoryIdentity>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn labelled_cache_lookup(path: &Path) -> Option<DirectoryIdentity> {
    let cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    cache.get(path).copied()
}

fn labelled_cache_insert(path: PathBuf, identity: DirectoryIdentity) {
    let mut cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    cache.insert(path, identity);
}

/// Test-only: drop every cached entry. Lets the per-test isolated
/// specs (which build fresh tempdirs each test) actually exercise
/// the full label path instead of hitting a stale cache from an
/// earlier test in the same binary.
#[cfg(test)]
fn reset_labelled_roots_cache_for_tests() {
    let mut cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    cache.clear();
}

/// Build the SDDL-derived security descriptor for the Low IL
/// mandatory label. Factored out of [`apply_low_il_label`] so the
/// recursive walker doesn't re-parse the same SDDL once per entry.
fn build_low_il_security_descriptor(path: &Path) -> Result<LocalDescriptor, SandboxError> {
    // SDDL form `S:(ML;OICI;NW;;;LW)`:
    //   S  = system ACL (mandatory labels live in the SACL)
    //   ML = mandatory label ACE type
    //   OICI = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE — files +
    //          subdirs inherit
    //   NW = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP — Low IL subjects
    //        can't write to higher-IL objects (this is the *default*
    //        policy for ML; spelling it out keeps the SDDL grep-able)
    //   LW = Low Mandatory Level (`S-1-16-4096`)
    let sddl: Vec<u16> = OsStr::new("S:(ML;OICI;NW;;;LW)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();

    // SAFETY: `sddl` is null-terminated; on success `sd` is allocated
    // via `LocalAlloc` and we own it (LocalFree below). On failure
    // `sd` stays null.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::ProfileRenderFailed {
            reason: format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with WIN32_ERROR={err} \
                 for path {}",
                path.display()
            ),
        });
    }
    Ok(LocalDescriptor(sd))
}

/// Pull the SACL pointer out of a parsed security descriptor. The
/// returned pointer is owned by `sd` — callers must keep the
/// `LocalDescriptor` alive for the duration of the SACL's use.
fn extract_sacl_pointer(sd: PSECURITY_DESCRIPTOR, path: &Path) -> Result<*mut ACL, SandboxError> {
    let mut sacl_present: i32 = 0;
    let mut sacl_ptr: *mut ACL = ptr::null_mut();
    let mut sacl_defaulted: i32 = 0;
    // SAFETY: `sd` was produced by ConvertString... and is owned by
    // the caller's `LocalDescriptor`. The three out-pointers are
    // valid stack locals.
    let got = unsafe {
        GetSecurityDescriptorSacl(sd, &mut sacl_present, &mut sacl_ptr, &mut sacl_defaulted)
    };
    if got == 0 || sacl_present == 0 || sacl_ptr.is_null() {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::ProfileRenderFailed {
            reason: format!(
                "GetSecurityDescriptorSacl produced no SACL (present={sacl_present}, win32={err}) \
                 for path {}",
                path.display()
            ),
        });
    }
    Ok(sacl_ptr)
}

/// Write the Low IL SACL to a single filesystem path. Returns a
/// fatal-shaped error so the root-call site can abort the install,
/// but the recursive walker swallows per-entry failures.
fn set_low_il_label_on(path: &Path, sacl_ptr: *mut ACL) -> Result<(), SandboxError> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide_path` is null-terminated. `sacl_ptr` is owned by
    // the caller's LocalDescriptor and outlives this call. `psidowner`,
    // `psidgroup`, `pdacl` are null — we're only writing the
    // mandatory label, leaving everything else untouched.
    let win = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl_ptr,
        )
    };
    if win != ERROR_SUCCESS {
        return Err(SandboxError::ProfileRenderFailed {
            reason: format!(
                "SetNamedSecurityInfoW failed with WIN32_ERROR={win} when labelling Low IL \
                 on path {}. The lifecycle child needs Low-IL-writable allow-set dirs; without \
                 this label the sandbox would deny legitimate writes.",
                path.display()
            ),
        });
    }
    Ok(())
}

/// True iff `metadata` describes a reparse point — symbolic links,
/// NTFS directory junctions, mount points, OneDrive placeholders, and
/// any other reparse-tagged objects.
///
/// **Why this and not `FileType::is_symlink()`.** On Windows
/// `std::fs::FileType::is_symlink()` returns `true` only for
/// `IO_REPARSE_TAG_SYMLINK`. Directory junctions
/// (`IO_REPARSE_TAG_MOUNT_POINT`, created by `mklink /J`) are NOT
/// flagged. Mount points and several other reparse tags are also
/// missed. Switching to the `FILE_ATTRIBUTE_REPARSE_POINT` bit closes
/// that gap because the filesystem sets it for every reparse-tagged
/// object regardless of the specific tag.
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Iteratively label every existing descendant of `root`. Per-entry
/// failures are logged at debug and swallowed because the root has
/// already been labelled successfully — the goal here is to retrofit
/// the label onto pre-existing files (since OICI inheritance only
/// applies at create-time), and a stuck file shouldn't abort the
/// install.
///
/// Uses an explicit stack rather than recursion so deep directory
/// trees (deeply nested `node_modules`, `.cache` with thousands of
/// hashed subdirs) don't risk stack overflow.
///
/// **Reparse-point skip.** Every entry
/// whose `FILE_ATTRIBUTE_REPARSE_POINT` bit is set — symbolic links,
/// NTFS directory junctions, mount points, OneDrive placeholders — is
/// skipped with a `tracing::debug!` line and not descended into.
/// Rationale:
///
/// - `SetNamedSecurityInfoW` follows reparse points by default, so
///   labelling a symlink or junction inside the allow-set would apply
///   Low IL writeability to its TARGET, potentially outside the
///   allow-set tree.
/// - Junction recursion via `read_dir` follows the reparse point;
///   descending into a planted junction would walk + label arbitrary
///   subtrees. The `!ft.is_symlink()` recursion guard only
///   caught `IO_REPARSE_TAG_SYMLINK` — junctions
///   (`IO_REPARSE_TAG_MOUNT_POINT`) sailed through it.
///
/// Skipping reparse points entirely doesn't lose coverage in practice
/// because the LPM linker's own junctions point INSIDE the allow-set
/// (e.g. `<project>/node_modules/<pkg>` → `<project>/.lpm/wrappers/...`
/// and both `node_modules` and `.lpm` are independently labelled
/// allow-set roots), so the target subtree is reached via the regular
/// path traversal of its own root.
fn relabel_existing_descendants(root: &Path, sacl_ptr: *mut ACL) {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(it) => it,
            Err(e) => {
                tracing::debug!(
                    target: "lpm_sandbox::windows",
                    "skip relabel of {}: read_dir failed: {e}",
                    dir.display(),
                );
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();

            // Pull metadata WITHOUT following symlinks. `DirEntry::metadata`
            // on Windows uses `GetFileAttributesExW` with no traversal, so
            // the result describes the entry itself, not any target it
            // points at — exactly what the reparse-point check needs.
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(
                        target: "lpm_sandbox::windows",
                        "skip relabel of {}: metadata failed: {e}",
                        path.display(),
                    );
                    continue;
                }
            };

            // S1: refuse to label or recurse through reparse points.
            if is_reparse_point(&meta) {
                tracing::debug!(
                    target: "lpm_sandbox::windows",
                    "skip reparse point {} during walk \
                     (target not labelled to prevent escape outside allow-set)",
                    path.display(),
                );
                continue;
            }

            if let Err(e) = set_low_il_label_on(&path, sacl_ptr) {
                tracing::debug!(
                    target: "lpm_sandbox::windows",
                    "skip relabel of {}: {e}",
                    path.display(),
                );
            }
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
}

/// RAII wrapper for a `LocalAlloc`'d security descriptor. `LocalFree`
/// returns `NULL` on success, but we don't read the return.
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was produced by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
            // which allocates the descriptor via `LocalAlloc`. The
            // free path is `LocalFree`, idempotent against null.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

// ── Token integrity drop ────────────────────────────────────────────

/// Open the suspended process's primary token, swap in a
/// `TOKEN_MANDATORY_LABEL` carrying the Low integrity SID, and write
/// it back. The process is still suspended at this point — the new
/// label takes effect when [`resume_process`] fires.
fn drop_integrity_to_low(process_handle: HANDLE) -> Result<(), SandboxError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process_handle` is owned by the `Child` and remains
    // open until the Child is dropped. On success the token handle
    // is ours to close.
    let ok = unsafe {
        OpenProcessToken(
            process_handle,
            TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
            &mut token,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!(
                "OpenProcessToken on the suspended sandboxed child failed with WIN32_ERROR={err}"
            ),
        });
    }
    let _token_guard = OwnedHandle(token);

    // Build the Low IL SID via ConvertStringSidToSidW — far simpler
    // than AllocateAndInitializeSid for a well-known SID and avoids
    // pulling in extra windows-sys symbols for one literal.
    let low_il: Vec<u16> = OsStr::new("S-1-16-4096")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `low_il` is null-terminated. On success `sid` is owned
    // by us and freed via `LocalFree` (NOT `FreeSid` — sids from
    // `ConvertStringSidToSidW` are LocalAlloc'd per MSDN).
    let ok = unsafe { ConvertStringSidToSidW(low_il.as_ptr(), &mut sid) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!("ConvertStringSidToSidW(S-1-16-4096) failed with WIN32_ERROR={err}"),
        });
    }
    let _sid_guard = LocalSid(sid);

    // Defensive: confirm the SID parsed to a valid form. Cheap, and
    // catches a future malformed-literal regression at write time
    // rather than as an opaque SetTokenInformation failure.
    let valid = unsafe { IsValidSid(sid) };
    if valid == 0 {
        return Err(SandboxError::SpawnFailed {
            reason: "IsValidSid rejected the parsed Low IL SID; SID literal is malformed"
                .to_string(),
        });
    }

    // SetTokenInformation(TokenIntegrityLevel, &TOKEN_MANDATORY_LABEL).
    // The label SID is referenced by pointer — the underlying SID
    // memory must remain valid through the syscall, which is why we
    // stack-allocate the struct here and hold `_sid_guard` until
    // function exit.
    let tml = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    // SAFETY: `tml.Label.Sid` points to a valid SID owned by
    // `_sid_guard`. The size passed reflects the struct itself; the
    // kernel reads the SID through the pointer. Documented call
    // pattern.
    let ok = unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &tml as *const _ as *const _,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!(
                "SetTokenInformation(TokenIntegrityLevel=Low) failed with WIN32_ERROR={err}. \
                 The sandboxed child kept its parent integrity level — refusing to resume the \
                 process rather than running with full medium-IL access."
            ),
        });
    }
    Ok(())
}

/// RAII wrapper for a HANDLE we own (e.g. the duplicated process
/// token). Closes via `CloseHandle` on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle ownership is exclusive; CloseHandle is
            // idempotent against null and safe to call on any value
            // returned by an OpenProcessToken success.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for a `LocalAlloc`'d SID (produced by
/// `ConvertStringSidToSidW`). Free via `LocalFree`, not `FreeSid` —
/// MSDN is explicit on this.
struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SID was LocalAlloc'd by
            // ConvertStringSidToSidW; LocalFree returns the original
            // handle on failure (NULL on success), but we ignore the
            // return because there's no recovery at drop time.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

// ── Job Object ──────────────────────────────────────────────────────

/// Create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and
/// attach the given process handle. The returned `OwnedHandle` must
/// outlive the child — closing the handle terminates every member
/// process, which is exactly what we want on the parent's drop /
/// timeout-kill paths.
#[derive(Clone, Copy)]
enum JobLimitProfile {
    LifecycleSandbox,
    TreeTrackingOnly,
}

fn configure_job_limits(info: &mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION, profile: JobLimitProfile) {
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if matches!(profile, JobLimitProfile::LifecycleSandbox) {
        info.BasicLimitInformation.LimitFlags |=
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.BasicLimitInformation.ActiveProcessLimit = 512;
        info.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
    }
}

fn create_kill_on_close_job_and_attach(
    process_handle: HANDLE,
    profile: JobLimitProfile,
) -> Result<OwnedHandle, SandboxError> {
    // SAFETY: `CreateJobObjectW(NULL, NULL)` is the documented form
    // for an unnamed Job Object; we own the returned handle.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!("CreateJobObjectW failed with WIN32_ERROR={err}"),
        });
    }
    let job_owned = OwnedHandle(job);

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    // Defense-in-depth DoS caps (M21):
    //   ACTIVE_PROCESS — caps process count INSIDE this job (job-scoped,
    //     not user-scoped — closes the fork-bomb gap the Unix
    //     `RLIMIT_NPROC` can't fully close).
    //   PROCESS_MEMORY — per-process commit cap, the OOM-trigger
    //     analog. ~2 GiB per descendant; node-gyp + electron builds
    //     legitimately reach into the GiB range so going much
    //     lower breaks legitimate scripts.
    //   KILL_ON_JOB_CLOSE — preserved from the prior contract.
    configure_job_limits(&mut info, profile);
    // SAFETY: documented call pattern; size matches the struct.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!(
                "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed with WIN32_ERROR={err}"
            ),
        });
    }

    // SAFETY: documented call. Child is still suspended so no race
    // with self-initiated thread / process creation by the child.
    let ok = unsafe { AssignProcessToJobObject(job, process_handle) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(SandboxError::SpawnFailed {
            reason: format!(
                "AssignProcessToJobObject failed with WIN32_ERROR={err}. The suspended sandbox \
                 child can't be attached to its kill-tree group; refusing to resume rather than \
                 leak a process not subject to the timeout-kill path."
            ),
        });
    }
    Ok(job_owned)
}

// ── Process resume ──────────────────────────────────────────────────

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Undocumented but ABI-stable since Windows XP. Resumes all
    /// suspended threads of the target process. Returns an
    /// NTSTATUS — 0 (`STATUS_SUCCESS`) on success, anything else on
    /// failure. The function is exported by `ntdll.dll` and has been
    /// used by Sysinternals tools (Process Explorer, etc.) since
    /// 2004; treating it as stable is industry standard.
    fn NtResumeProcess(process_handle: HANDLE) -> i32;
}

/// Resume a suspended process. See [`NtResumeProcess`] for the
/// stability rationale.
fn resume_process(process_handle: HANDLE) -> Result<(), SandboxError> {
    // SAFETY: `process_handle` is the Child's handle and remains open
    // until the Child drops. `NtResumeProcess` only reads the handle.
    let status = unsafe { NtResumeProcess(process_handle) };
    if status != 0 {
        return Err(SandboxError::SpawnFailed {
            reason: format!(
                "NtResumeProcess failed with NTSTATUS=0x{status:08x}. The sandboxed child \
                 stays suspended; we terminate it rather than leak a stuck process."
            ),
        });
    }
    Ok(())
}

// ── Job-handle lifetime tracker ─────────────────────────────────────

/// Tracker mapping PIDs of currently-live sandboxed children to their
/// Job Object handles. The Job Object's `KILL_ON_JOB_CLOSE` limit
/// means closing the last handle to the Job tears down the entire
/// process tree — so we keep the handle alive as long as the parent
/// is interested in the Child.
///
/// Two leak vectors avoided:
/// 1. If we returned the Job handle to the caller, callers would
///    have to remember to close it. The `Sandbox::spawn` trait
///    returns `std::process::Child`, which doesn't have a side
///    channel for opaque resource handles, so we maintain the
///    binding internally.
/// 2. If we dropped the Job handle immediately, the Job's
///    `KILL_ON_JOB_CLOSE` would terminate the child instantly — the
///    opposite of what we want. Holding the handle in the tracker
///    until the Child's PID is forgotten avoids that.
///
/// A reaper thread isn't necessary — children that exit normally
/// leave a zombie Job Object whose last handle release happens
/// (a) when the user wires up a Drop-on-Child mechanism (we don't,
/// because we can't extend std::process::Child), or (b) when the
/// parent process exits and the OS reaps it. For the
/// (b) cleanup is sufficient: lifecycle scripts complete in seconds,
/// the parent (`lpm`) exits quickly, and the OS frees the handle.
/// The sole production consumer (`wait_with_timeout` in
/// `lpm-cli/src/commands/rebuild.rs`) explicitly calls
/// `release_sandbox_tracker` on normal exit and `terminate_sandbox_tree`
/// on the timeout-kill path, so no leak occurs in practice.
///
/// Layering an explicit reaper thread would require duplicating the
/// child's process handle inside `Sandbox::spawn` before returning
/// the `Child` (otherwise `OpenProcess(SYNCHRONIZE, pid)` inside the
/// reaper races PID reuse) and extending tracker entries to carry
/// both handles. That's the right shape if `--jobs=N≥2` or
/// watch-mode ever ships; until then the OS-on-exit fallback is
/// sufficient.
fn register_job_for_child(pid: u32, job: OwnedHandle) {
    let mut table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
    // Insert under the child's PID. Duplicate-PID registration is
    // unreachable in the current call graph (the kernel won't recycle
    // a PID while the parent still holds a process handle, and the
    // Job handle in the tracker keeps the kernel object alive until
    // release/terminate fires). If a future caller ever does double-
    // register, `insert` drops the prior `OwnedHandle`, which closes
    // the old Job — KILL_ON_JOB_CLOSE then fires on an already-empty
    // Job and is harmless. We deliberately do NOT pin overwrite vs
    // reject as a contract; either is acceptable.
    table.insert(pid, job);
}

/// Module-local tracker mapping a sandboxed child's PID to its Job
/// Object handle. `HashMap` so `release_sandbox_tracker_entry` and
/// `terminate_sandbox_tree` are O(1) instead of `Vec::position`'s
/// O(n). At realistic single-digit concurrency the difference is
/// invisible, but the shape is correct for the future `--jobs=N`
/// path and aligns with the `LABELED_ROOTS` sibling cache above.
///
/// Wrapped in `LazyLock` rather than `Mutex<Option<HashMap>>` —
/// `HashMap::new()` isn't `const` on stable, but `LazyLock` (stable
/// since Rust 1.80, repo pinned to 1.94.0) provides the same lazy
/// init without the `Option` ceremony at every call site.
static JOB_TRACKER: LazyLock<Mutex<HashMap<u32, OwnedHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// `OwnedHandle` needs `Send` to live inside a `Mutex<Vec<...>>`. The
// underlying HANDLE is a kernel handle — kernel objects are
// thread-safe per Win32's documented semantics. The `*mut c_void`
// pointer type is what prevents the auto-impl; we assert it here.
//
// SAFETY: HANDLE is a kernel-managed value, not a thread-local
// pointer. Sending one across threads is the documented call
// pattern (e.g. spawning a thread to wait on a Job).
unsafe impl Send for OwnedHandle {}

/// Terminate the Job Object tree associated with `pid` and release
/// the cached handle. Used by the install pipeline's timeout-kill
/// path so that `TerminateProcess(child, _)` on the root child is
/// followed by a kill of every descendant — without this call, the
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` policy doesn't fire because
/// the tracker still owns a handle, leaving grandchild processes
/// alive after a sandbox timeout.
///
/// Idempotent: missing entries (already-cleaned, never-registered,
/// PID-reused) are silent no-ops.
pub(crate) fn terminate_sandbox_tree(pid: u32) {
    let mut table = match JOB_TRACKER.lock() {
        Ok(g) => g,
        // A poisoned mutex means another thread panicked while
        // holding the lock. Recover and continue — losing a kill
        // here is strictly worse than aborting the parent.
        Err(p) => p.into_inner(),
    };
    if let Some(entry) = table.remove(&pid) {
        // SAFETY: `entry.0` is the kernel Job Object we created
        // and exclusively own via the tracker entry; `TerminateJobObject`
        // is documented as safe to call from any thread. The
        // `OwnedHandle` is dropped at end of scope below, closing
        // the kernel handle — pure resource reclamation since the
        // Job has already been terminated.
        unsafe {
            TerminateJobObject(entry.0, 1);
        }
    }
}

/// Release the tracker entry for a sandboxed child that exited on
/// its own (no timeout, no panic). Closes the Job handle, which the
/// kernel reclaims along with the now-empty Job. Skipping this leaks
/// one HANDLE per lifecycle script for the lifetime of the parent —
/// fine for `lpm install` (seconds) but a slow accumulation for any
/// long-running lpm parent (watch-mode, daemon).
///
/// Idempotent: missing entries are silent no-ops.
pub(crate) fn release_sandbox_tracker_entry(pid: u32) {
    let mut table = match JOB_TRACKER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    table.remove(&pid);
}

// ── Windows version probe ───────────────────────────────────────────

/// Best-effort Windows version string for the
/// [`SandboxPosture::Degraded`] `kernel` field. Reads the registry
/// build number via the `RtlGetVersion` ntdll entry point, which is
/// the recommended modern alternative to `GetVersionExW` (which
/// honors application manifests and lies about the OS version on
/// older binaries).
///
/// Falls back to the literal `"windows"` if the probe fails — the
/// `required` axis on the warning line is what matters; the detected
/// kernel string is display-only.
fn detect_windows_version_string() -> String {
    // Avoid pulling in another windows-sys feature for a single
    // call. The `RtlGetVersion` declaration is inline.
    //
    // Note on Default: `[u16; 128]` (the `csd` field, holding the
    // service pack display string) doesn't have a `Default` impl on
    // stable Rust — derives don't work for arrays > 32 elements as
    // `[u16; 128]` doesn't impl `Default` on stable. We zero-init via `std::mem::zeroed()`
    // instead, which is fine because every field is a plain integer
    // / array of integers (no Drop, no UB on the all-zero pattern).
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // Fields after `build` are filled by RtlGetVersion but unused by us
    struct RtlOsversioninfoexw {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        csd: [u16; 128],
        sp_major: u16,
        sp_minor: u16,
        suite: u16,
        product: u8,
        reserved: u8,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(info: *mut RtlOsversioninfoexw) -> i32;
    }
    // SAFETY: `RtlOsversioninfoexw` is plain old data — every field
    // is `u32` / `u16` / `u8` / `[u16; 128]`. The all-zero pattern
    // is a valid bit-pattern for each; no Drop, no NonZero, no
    // references. `RtlGetVersion` will overwrite `size` and the
    // version fields before we read them.
    let mut info: RtlOsversioninfoexw = unsafe { std::mem::zeroed() };
    info.size = std::mem::size_of::<RtlOsversioninfoexw>() as u32;
    // SAFETY: `info` is stack-allocated; `RtlGetVersion` writes
    // through the pointer up to `info.size` bytes.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status != 0 {
        return "windows".to_string();
    }
    format!("windows-{}.{}.{}", info.major, info.minor, info.build)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// a spec with non-existent fake paths. Safe for any
    /// test that doesn't reach the `apply_low_il_label` syscall (pure
    /// decision-table tests, construction tests, allow-set ordering
    /// pins) because the fake paths never get touched.
    ///
    /// **Do NOT use this fixture for spawn-based tests.** Spawn
    /// applies Low IL labels to every entry of the allow-set, and
    /// real `home_dir` / `tmpdir` values here would persistently
    /// relabel the developer's actual `~/.cache`, `~/.npm`, `~/.node-gyp`,
    /// and `%TEMP%` directories. Spawn tests use
    /// [`isolated_spec`] which roots every allow-set entry inside a
    /// per-test tempdir.
    fn realistic_spec() -> SandboxSpec {
        // Fake roots that don't exist — `apply_low_il_label` early-
        // returns on missing paths so this is safe for the
        // syscall-free tests that use it.
        let fake_home = PathBuf::from(r"C:\lpm-sandbox-test\fake-home");
        let fake_tmp = PathBuf::from(r"C:\lpm-sandbox-test\fake-tmp");
        SandboxSpec {
            package_dir: fake_home.join(".lpm/store/testpkg@0.1.0"),
            project_dir: fake_home.join("lpm-sandbox-test-project"),
            package_name: "testpkg".into(),
            package_version: "0.1.0".into(),
            store_root: fake_home.join(".lpm/store"),
            home_dir: fake_home,
            tmpdir: fake_tmp,
            secret_read_allow: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    /// Spec rooted at a caller-provided tempdir so spawn-based tests
    /// don't relabel the developer's real `~/.cache`, `~/.npm`,
    /// `~/.node-gyp`, or `%TEMP%` Low IL. Creates `package_dir` +
    /// `project_dir` on disk so `apply_low_il_label` actually exercises
    /// `SetNamedSecurityInfoW` (the "missing path = skip" branch is
    /// covered separately by `apply_low_il_label_on_nonexistent_path_is_a_noop`).
    fn isolated_spec(tmp_root: &Path) -> SandboxSpec {
        let pkg_dir = tmp_root.join("store").join("pkg@1.0.0");
        let project_dir = tmp_root.join("proj");
        let home_dir = tmp_root.join("isolated-home");
        let tmpdir = tmp_root.join("isolated-tmp");
        std::fs::create_dir_all(&pkg_dir).expect("create package_dir for isolated spec");
        std::fs::create_dir_all(&project_dir).expect("create project_dir for isolated spec");
        std::fs::create_dir_all(&home_dir).expect("create home_dir for isolated spec");
        std::fs::create_dir_all(&tmpdir).expect("create tmpdir for isolated spec");
        SandboxSpec {
            package_dir: pkg_dir,
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: tmp_root.join("store"),
            home_dir,
            tmpdir,
            secret_read_allow: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    /// Decision-table pin: relaxed default succeeds without consulting
    /// the `allow_degraded` knob. Mirrors the Linux `decide_posture`
    /// test convention so the table stays grep-able across platforms.
    #[test]
    fn decide_posture_default_returns_lowil_not_degraded() {
        let p = decide_posture(false, false).expect("relaxed default must succeed");
        match p {
            BackendPosture::LowIl {
                degraded_from_strict,
            } => assert!(!degraded_from_strict, "relaxed default isn't a fallback"),
        }

        // `allow_degraded` is irrelevant when network isn't denied —
        // V1 floor analog. The decision must be identical whether
        // the user opted in or not, and the public posture must be
        // `Default` in both cases.
        let p = decide_posture(false, true).expect("opt-in with no denial must succeed");
        match p {
            BackendPosture::LowIl {
                degraded_from_strict,
            } => assert!(!degraded_from_strict),
        }
    }

    #[test]
    fn decide_posture_strict_without_degraded_opt_in_refuses() {
        match decide_posture(true, false) {
            Err(SandboxError::UnsupportedPlatform {
                platform,
                remediation,
            }) => {
                assert_eq!(platform, "windows");
                assert!(
                    remediation.contains("allow-degraded"),
                    "remediation must name the degraded opt-in: {remediation}"
                );
                assert!(
                    remediation.contains("--no-sandbox"),
                    "remediation must name the wholesale escape hatch: {remediation}"
                );
                assert!(
                    remediation.contains("trustedDependencies"),
                    "remediation must name the per-package trust escape: {remediation}"
                );
                assert!(
                    remediation.contains("lpm config sandbox"),
                    "remediation must name the wizard shortcut to drop back to default: {remediation}"
                );
                assert!(
                    remediation.contains("Filtering Platform")
                        || remediation.contains("network denial"),
                    "remediation must name the outbound-network gap: {remediation}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn decide_posture_strict_with_degraded_opt_in_returns_degraded() {
        let p = decide_posture(true, true).expect("strict + allow_degraded must succeed");
        match p {
            BackendPosture::LowIl {
                degraded_from_strict,
            } => assert!(
                degraded_from_strict,
                "strict + allow_degraded must report degraded for the per-install warning"
            ),
        }
    }

    /// Allow-set ordering pin so we don't accidentally drop a required
    /// dir during a future refactor. The contract is a UNION of the
    /// macOS Seatbelt `file-write*` block and the Linux landlock
    /// ReadWrite rules; if a path needs Low IL on Windows it has to
    /// appear in this list.
    #[test]
    fn writable_allow_set_contains_required_dirs_in_canonical_order() {
        let spec = realistic_spec();
        let v = writable_allow_set(&spec);
        let s = v
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(s[0].ends_with("testpkg@0.1.0"), "package_dir first: {s:?}");
        let joined = s.join("\n");
        assert!(joined.contains("node_modules"));
        assert!(joined.contains(".husky"));
        assert!(joined.contains(".lpm"));
        assert!(joined.contains(".cache"));
        assert!(joined.contains(".node-gyp"));
        assert!(joined.contains(".npm"));
    }

    #[test]
    fn writable_allow_set_includes_extras_at_end() {
        let mut spec = realistic_spec();
        spec.extra_write_dirs.push(PathBuf::from(r"C:\extra1"));
        spec.extra_write_dirs.push(PathBuf::from(r"C:\extra2"));
        let v = writable_allow_set(&spec);
        // Two extras at the end, in input order.
        assert_eq!(v.len(), 8 + 2);
        assert_eq!(v[v.len() - 2], PathBuf::from(r"C:\extra1"));
        assert_eq!(v[v.len() - 1], PathBuf::from(r"C:\extra2"));
    }

    #[test]
    fn windows_version_string_starts_with_known_prefix() {
        // The probe always returns something; we only pin the
        // prefix so the regex log scrapers (and the
        // `degraded_warning_line` format) stay parseable.
        let s = detect_windows_version_string();
        assert!(
            s.starts_with("windows"),
            "version string must lead with `windows`: {s}",
        );
    }

    #[test]
    fn new_rejects_logonly_with_mode_specific_error() {
        // Mirrors the landlock backend's LogOnly contract. Runs on
        // any host (cfg gate is at the crate level; this test only
        // compiles on Windows, but the mode-check predates any
        // syscall so it's environment-independent).
        match WindowsSandbox::new(
            realistic_spec(),
            SandboxMode::LogOnly,
            SandboxOptions::default(),
        ) {
            Err(SandboxError::ModeNotSupportedOnPlatform {
                platform,
                mode,
                remediation,
            }) => {
                assert_eq!(platform, "windows");
                assert_eq!(mode, SandboxMode::LogOnly);
                assert!(
                    remediation.contains("--no-sandbox"),
                    "remediation must name the interim workaround: {remediation}"
                );
                assert!(
                    !remediation.contains("--unsafe-full-env"),
                    "legacy partner flag must be gone: {remediation}",
                );
                assert!(
                    remediation.contains("macOS"),
                    "remediation should mention --sandbox-log is available on macOS"
                );
            }
            Ok(_) => panic!("LogOnly on Windows must be rejected by WindowsSandbox::new"),
            Err(other) => panic!("expected ModeNotSupportedOnPlatform, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_disabled_mode_defensively() {
        // Symmetric guard with macOS + Linux backends; the factory
        // should never route Disabled here, but if it does we bail
        // with a clear error instead of installing an unnecessary
        // IL drop.
        match WindowsSandbox::new(
            realistic_spec(),
            SandboxMode::Disabled,
            SandboxOptions::default(),
        ) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("Disabled"));
                assert!(reason.contains("NoopSandbox"));
            }
            Ok(_) => panic!("Disabled mode must be rejected by WindowsSandbox::new"),
            Err(other) => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn new_default_options_returns_default_posture() {
        // default mode: filesystem-write containment only,
        // no network denial. Construction succeeds on any reachable
        // Windows host (no kernel-version gate — Mandatory Integrity
        // Control has been in every Windows release since Vista).
        let sb = WindowsSandbox::new(
            realistic_spec(),
            SandboxMode::Enforce,
            SandboxOptions::default(),
        )
        .expect("default mode must construct cleanly on any Windows host");
        assert_eq!(sb.backend_name(), "windows-il");
        assert_eq!(sb.posture(), SandboxPosture::Default);
    }

    #[test]
    fn new_strict_without_degraded_opt_in_surfaces_unsupported() {
        // The strict path is the follow-up; without the
        // degraded opt-in we refuse with a remediation block naming
        // every recourse.
        let opts = SandboxOptions {
            deny_outbound_network: true,
            allow_degraded: false,
            build_cache_isolation: false,
        };
        match WindowsSandbox::new(realistic_spec(), SandboxMode::Enforce, opts) {
            Err(SandboxError::UnsupportedPlatform { platform, .. }) => {
                assert_eq!(platform, "windows");
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[test]
    fn new_strict_with_degraded_opt_in_returns_degraded_posture() {
        let opts = SandboxOptions {
            deny_outbound_network: true,
            allow_degraded: true,
            build_cache_isolation: false,
        };
        let sb = WindowsSandbox::new(realistic_spec(), SandboxMode::Enforce, opts)
            .expect("strict + allow_degraded must construct cleanly");
        assert_eq!(sb.backend_name(), "windows-il");
        match sb.posture() {
            SandboxPosture::Degraded {
                kernel,
                abi,
                missing,
            } => {
                assert!(kernel.starts_with("windows"));
                assert_eq!(abi, "low-il");
                assert_eq!(missing, "network-containment");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn apply_low_il_label_on_nonexistent_path_is_a_noop() {
        // missing paths in the allow set get skipped
        // with a tracing::debug line, matching landlock's
        // `tracing::debug!("landlock: skip ...")` shape. A skip is
        // not an error.
        let nonexistent = PathBuf::from(r"C:\lpm-sandbox-test-nonexistent-46.2");
        assert!(!nonexistent.exists(), "guard: path must not exist");
        apply_low_il_label(&nonexistent).expect("nonexistent path must be a no-op skip, not error");
    }

    /// follow-up — re-labelling the same root twice in
    /// the same process must hit the cache fast-path and skip the
    /// recursive walk. Without the cache, installs with multiple
    /// lifecycle scripts would re-walk every existing descendant of
    /// `~/.cache`, `~/.npm`, `~/.node-gyp`, and tmpdir once per
    /// script — a Windows-only performance regression that wouldn't
    /// surface in single-script installs.
    ///
    /// We pin the cache behavior via the labelled_cache_lookup
    /// helper rather than timing because (a) the first label
    /// already shouldn't be slow on a tiny tempdir and (b) timing
    /// assertions are flaky under CI load.
    #[test]
    fn apply_low_il_label_is_cached_per_process() {
        reset_labelled_roots_cache_for_tests();
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("cache-pin");
        std::fs::create_dir_all(&target).unwrap();
        // Seed a file inside so the recursive walk has something
        // non-trivial to do on the first call.
        std::fs::write(target.join("seed.txt"), b"hello").unwrap();

        let canonical = std::fs::canonicalize(&target).expect("canonicalize");
        assert!(
            labelled_cache_lookup(&canonical).is_none(),
            "cache must start empty after reset"
        );

        apply_low_il_label(&target).expect("first label must succeed");
        let first_identity = labelled_cache_lookup(&canonical)
            .expect("first label must populate the cache so subsequent spawns skip the walk");

        // Second call: must hit the fast-path. The cache entry's
        // identity stays the same because the directory object
        // hasn't been touched between the two calls.
        apply_low_il_label(&target).expect("second label must be a cache hit, not an error");
        let second_identity =
            labelled_cache_lookup(&canonical).expect("cache entry must persist across spawns");
        assert_eq!(
            first_identity, second_identity,
            "cached NTFS identity must not change when the directory object is unchanged"
        );
    }

    /// round-3 follow-up — delete-and-recreate
    /// invalidation. If a lifecycle script removes one of the
    /// allow-set dirs and recreates it (rare but legitimate — some
    /// build steps wipe `dist/` or a cache root before re-populating),
    /// the new directory object inherits Medium IL from its parent
    /// rather than carrying our Low IL label. A path-only cache
    /// would incorrectly short-circuit the next spawn's relabel and
    /// the next Low IL child would be denied writes inside the
    /// recreated dir.
    ///
    /// The fix keys the cache on `(canonical_path, NTFS file
    /// identity)`. This test pins it: label, delete + recreate at
    /// the same path (which produces a new NTFS file ID), call
    /// `apply_low_il_label` again, and assert the cache's identity
    /// entry actually changed — proving the function did the work
    /// rather than blindly short-circuiting.
    #[test]
    fn apply_low_il_label_reinvalidates_when_directory_is_recreated() {
        reset_labelled_roots_cache_for_tests();
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("recreate-pin");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("v1.txt"), b"first").unwrap();
        let canonical = std::fs::canonicalize(&target).expect("canonicalize v1");

        apply_low_il_label(&target).expect("first label");
        let id_v1 = labelled_cache_lookup(&canonical).expect("v1 cached");

        // Recreate at the same path with different contents. NTFS
        // hands out a new FileId for the new object, so the
        // identity-aware cache must invalidate and re-label.
        std::fs::remove_dir_all(&target).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("v2.txt"), b"second").unwrap();
        // Re-canonicalize to make sure the path shape is identical
        // even after the recreate (it should be — same parent,
        // same name).
        let canonical_v2 = std::fs::canonicalize(&target).expect("canonicalize v2");
        assert_eq!(
            canonical, canonical_v2,
            "same path must canonicalize to the same key"
        );

        apply_low_il_label(&target).expect("re-label after recreate");
        let id_v2 = labelled_cache_lookup(&canonical).expect("v2 cached");
        assert_ne!(
            id_v1, id_v2,
            "cache must rebind to the new NTFS identity after delete + recreate — \
             a path-only cache would short-circuit here and leave the new dir \
             Medium IL"
        );
    }

    /// End-to-end Low IL spawn: launch `cmd.exe /c echo` under the
    /// backend, confirm it exits 0. This exercises the full
    /// CREATE_SUSPENDED -> drop IL -> Job assign -> NtResumeProcess
    /// chain. `cmd.exe` itself is on the system path and runs fine at
    /// Low IL because the directories it reads are all High/Medium IL
    /// (Low IL processes read up freely; only writes-up are denied).
    ///
    /// Uses [`isolated_spec`] so the Low IL label application doesn't
    /// touch the developer's real `~/.cache` / `~/.npm` /
    /// `~/.node-gyp` / `%TEMP%` — those would otherwise be
    /// persistently relabeled by every test run.
    #[test]
    fn spawns_a_trivial_benign_command_under_enforce() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sb = WindowsSandbox::new(
            isolated_spec(tmp.path()),
            SandboxMode::Enforce,
            SandboxOptions::default(),
        )
        .expect("construction must succeed");
        // Match the env requirements documented on
        // `write_into_package_dir_under_enforce_succeeds`: cmd.exe
        // can't load ntdll without SYSTEMROOT/COMSPEC/WINDIR, and
        // tests in CI may run with a stripped parent env.
        let pass = |k: &str| -> (String, std::ffi::OsString) {
            (k.to_string(), std::env::var_os(k).unwrap_or_default())
        };
        let cmd = SandboxedCommand::new("cmd.exe")
            .arg("/c")
            .arg("exit 0")
            .envs_cleared([
                pass("PATH"),
                pass("SYSTEMROOT"),
                pass("COMSPEC"),
                pass("WINDIR"),
            ]);
        let mut child = sb.spawn(cmd).expect("spawn under enforce");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "cmd.exe /c exit 0 under sandbox must exit 0 — got {status:?}"
        );
    }

    /// **Core sandbox contract** — a write to a path OUTSIDE the
    /// allow-set must be denied. This is the brief's
    /// minimum: filesystem-write containment. Without this property
    /// holding, the backend wouldn't actually be a sandbox.
    ///
    /// The forbidden path is a sibling of the allow-set tempdir
    /// under `%TEMP%`'s parent — outside `package_dir`, outside
    /// `project_dir`, outside `tmpdir` (which is set to the test's
    /// own `%TEMP%` so the spec's allow-set entry doesn't cover the
    /// parent). The Low IL child cannot write there because the
    /// path retains its default Medium IL label, and `NW` (no-write-
    /// up) blocks the access at the kernel layer.
    ///
    /// A regression that drops the IL-label application (or applies
    /// the label too broadly) would let this write succeed, which
    /// is exactly the failure mode this test pins.
    #[test]
    fn write_outside_allow_set_under_enforce_is_denied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let spec = isolated_spec(tmp.path());

        // Forbidden target — a sibling under the tempdir root,
        // OUTSIDE every entry of `writable_allow_set`. The path has
        // no IL label applied, so it stays at the default Medium IL
        // and a Low IL child cannot write there. Using the tempdir
        // (not the user's real HOME) keeps the negative-control
        // target out of the developer's namespace.
        let forbidden_root = tmp.path().join("forbidden-area");
        std::fs::create_dir_all(&forbidden_root).unwrap();
        let forbidden = forbidden_root.join(format!(
            "lpm-sandbox-forbidden-write-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&forbidden);

        let sb = WindowsSandbox::new(spec, SandboxMode::Enforce, SandboxOptions::default())
            .expect("construction must succeed");

        let pass = |k: &str| -> (String, std::ffi::OsString) {
            (k.to_string(), std::env::var_os(k).unwrap_or_default())
        };
        let mut cmd = SandboxedCommand::new("cmd.exe")
            .arg("/c")
            .arg(format!("echo leak > \"{}\"", forbidden.display()))
            .envs_cleared([
                pass("PATH"),
                pass("SYSTEMROOT"),
                pass("COMSPEC"),
                pass("WINDIR"),
            ]);
        cmd.stdout = crate::SandboxStdio::Null;
        cmd.stderr = crate::SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            !status.success(),
            "Low IL sandbox must deny write to a Medium-IL forbidden path — got status \
             {status:?}. If the exit succeeded, either the IL drop didn't take effect or \
             the path got accidentally labelled Low IL via an over-broad allow-set entry."
        );
        assert!(
            !forbidden.exists(),
            "sandbox escape: the forbidden file was created at {} despite the Low IL \
             child not being supposed to write there",
            forbidden.display()
        );
    }

    /// Write into a Low-IL-labelled allow-set dir succeeds. Confirms
    /// that `apply_low_il_label` actually grants writeability — a
    /// Low IL child writing into a still-medium-IL dir would be
    /// denied.
    ///
    /// **Env caveat**: `cmd.exe` needs more than just `PATH` to
    /// resolve its own DLL load chain — at minimum `SYSTEMROOT`,
    /// `COMSPEC`, and `WINDIR` (the first to find ntdll.dll +
    /// kernel32.dll under `%SYSTEMROOT%\System32`, the others used
    /// by cmd.exe's startup). Without them, `cmd.exe /c echo > file`
    /// exits non-zero before it even tries the redirect. The
    /// `envs_cleared` call below explicitly preserves them so the
    /// test exercises the IL containment (the actual contract under
    /// test) rather than env-scrubbing.
    /// follow-up — pre-existing files inside the allow-set
    /// must be writable by the Low IL child. The kernel's OICI
    /// inheritance is not retroactive: only files created AFTER the
    /// label is applied pick it up via inheritance. Existing files
    /// keep their original (typically Medium IL) label and would
    /// reject the Low IL child's writes unless we explicitly relabel
    /// them.
    ///
    /// This pin catches a regression that drops the recursive walk
    /// in [`apply_low_il_label`]. Without the walk, the assertion
    /// below fails because `cmd.exe`'s redirect into the pre-existing
    /// `existing.txt` hits ERROR_ACCESS_DENIED at the kernel's MIC
    /// check.
    #[test]
    fn write_to_preexisting_file_in_package_dir_under_enforce_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Neutralise the post-KB5089549/KB5092762 Windows 26200 behavior
        // where an inherited AppContainer Capability SID ACE blocks Low IL
        // writes regardless of the rest of the descriptor. See
        // [`test_strip_inherited_capability_sids`] for the full diagnosis.
        // Strip at the tempdir-root level BEFORE creating child dirs so
        // descendants inherit a clean DAC (no Capability SID) from the
        // start. Stripping AFTER children exist leaves the relabel call
        // unable to modify the SACL because the strip mutates the DACL
        // shape that `SetNamedSecurityInfoW` validates against.
        test_strip_inherited_capability_sids(tmp.path());
        let spec = isolated_spec(tmp.path());
        let pkg_dir = spec.package_dir.clone();

        // Pre-create a file BEFORE the sandbox is constructed.
        // Whatever Medium IL the test process has when it writes
        // here is what the file carries — and that's exactly the
        // file shape the recursive walk has to flip down to Low IL
        // before the spawn happens.
        let existing = pkg_dir.join("existing.txt");
        std::fs::write(&existing, b"before\r\n").expect("seed existing file");

        let sb = WindowsSandbox::new(spec, SandboxMode::Enforce, SandboxOptions::default())
            .expect("construction must succeed");

        let pass = |k: &str| -> (String, std::ffi::OsString) {
            (k.to_string(), std::env::var_os(k).unwrap_or_default())
        };
        let mut cmd = SandboxedCommand::new("cmd.exe")
            .arg("/c")
            .arg("echo after > existing.txt")
            .current_dir(&pkg_dir)
            .envs_cleared([
                pass("PATH"),
                pass("SYSTEMROOT"),
                pass("COMSPEC"),
                pass("WINDIR"),
            ]);
        cmd.stdout = crate::SandboxStdio::Null;
        cmd.stderr = crate::SandboxStdio::Piped;
        let mut child = sb.spawn(cmd).expect("spawn");
        let mut stderr = Vec::new();
        if let Some(mut s) = child.stderr.take() {
            use std::io::Read;
            let _ = s.read_to_end(&mut stderr);
        }
        let status = child.wait().expect("wait");
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(
            status.success(),
            "write to a PRE-EXISTING file inside the Low-IL allow-set must succeed \
             (the recursive walk in apply_low_il_label is what makes this work); \
             got {status:?}; cmd.exe stderr: {stderr_str}"
        );
        // Read back to confirm the contents changed.
        let contents = std::fs::read_to_string(&existing).expect("read back");
        assert!(
            contents.contains("after"),
            "the Low IL child's write didn't actually land — got: {contents:?}"
        );
    }

    #[test]
    fn write_into_package_dir_under_enforce_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // See the matching call in
        // `write_to_preexisting_file_in_package_dir_under_enforce_succeeds`
        // and [`test_strip_inherited_capability_sids`] for the full
        // diagnosis of the Windows 26200 + KB5089549/KB5092762 behavior
        // change. Strip at the tempdir-root level BEFORE creating
        // children so they inherit a clean DAC.
        test_strip_inherited_capability_sids(tmp.path());
        let spec = isolated_spec(tmp.path());
        let pkg_dir = spec.package_dir.clone();
        let sb = WindowsSandbox::new(spec, SandboxMode::Enforce, SandboxOptions::default())
            .expect("construction must succeed");

        // Preserve the env vars cmd.exe needs for its own loader.
        // The PATH passthrough alone leaves the shell unable to
        // resolve its DLL search path, which masks the IL contract
        // under test.
        let pass = |k: &str| -> (String, std::ffi::OsString) {
            (k.to_string(), std::env::var_os(k).unwrap_or_default())
        };
        // Sidestep cmd.exe's flaky in-shell path quoting by setting
        // the child's working directory to `pkg_dir` and writing to
        // a relative filename. The cross-platform `tempfile::tempdir()`
        // can return paths with `\\?\` prefix or other shapes that
        // `cmd.exe /c "echo > <quoted absolute>"` fails to parse
        // ("The filename, directory name, or volume label syntax is
        // incorrect.") even when the file system path itself is
        // valid. With `current_dir` + relative target, the syntax
        // is uniform regardless of the absolute path shape — and
        // the test still pins what it claims: a Low IL child writing
        // a file inside a Low-IL-labelled allow-set dir.
        let mut cmd = SandboxedCommand::new("cmd.exe")
            .arg("/c")
            .arg("echo hi > marker.txt")
            .current_dir(&pkg_dir)
            .envs_cleared([
                pass("PATH"),
                pass("SYSTEMROOT"),
                pass("COMSPEC"),
                pass("WINDIR"),
            ]);
        // Capture stderr so a future failure surfaces the actual
        // diagnosis (path quoting, IL denial, etc.) instead of an
        // opaque exit code.
        cmd.stdout = crate::SandboxStdio::Null;
        cmd.stderr = crate::SandboxStdio::Piped;
        let mut child = sb.spawn(cmd).expect("spawn");
        let mut stderr = Vec::new();
        if let Some(mut s) = child.stderr.take() {
            use std::io::Read;
            let _ = s.read_to_end(&mut stderr);
        }
        let status = child.wait().expect("wait");
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(
            status.success(),
            "write to package_dir under Low IL must succeed, got {status:?}; \
             cmd.exe stderr: {stderr_str}"
        );
        assert!(
            pkg_dir.join("marker.txt").exists(),
            "Low IL-labelled package_dir must accept writes from the Low IL child"
        );
    }

    // ── Reparse-point hardening ───────────────────────────

    // Test-only windows-sys symbols. Kept inside `mod tests` so the
    // lib build doesn't carry these as unused imports.
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{ACE_HEADER, EqualSid, GetAce, SYSTEM_MANDATORY_LABEL_ACE};

    /// `SYSTEM_MANDATORY_LABEL_ACE_TYPE` per winnt.h. Not exposed by
    /// windows-sys 0.60; inlined the same way `SE_GROUP_INTEGRITY` is
    /// at module scope.
    const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;

    /// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` per winnt.h — the mask
    /// value the shipped SDDL writes (`NW` in `S:(ML;OICI;NW;;;LW)`).
    const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x01;

    /// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` as an `AceFlags`
    /// byte (the `OICI` half of the shipped SDDL). The module-scope
    /// constants in windows-sys are `ACE_FLAGS = u32`; `AceFlags` in
    /// `ACE_HEADER` is `u8`, so we inline the byte value here.
    const OICI_FLAGS_BYTE: u8 = 0x01 | 0x02;

    /// Test-only oracle: returns `true` iff `path`'s
    /// `LABEL_SECURITY_INFORMATION` SACL contains a
    /// `SYSTEM_MANDATORY_LABEL_ACE` matching the EXACT shape the
    /// production code writes — `S:(ML;OICI;NW;;;LW)`:
    ///
    /// - `AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE` (0x11)
    /// - `AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) ==
    ///   OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`
    /// - `Mask == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` (0x01)
    /// - SID equals `S-1-16-4096` via `EqualSid`
    ///
    /// Strictly stronger than "any Low IL ACE" so a regression that
    /// ships a different SACL shape (different inheritance, different
    /// mask) fails the readback tests rather than silently passing.
    ///
    /// Independent of the production label path — this is a fresh
    /// implementation written for tests so the new ACE parser isn't
    /// self-certifying.
    fn test_read_has_low_il_ace(path: &Path) -> bool {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut sacl_ptr: *mut ACL = ptr::null_mut();

        // SAFETY: documented call; on success `sd` is LocalAlloc'd and we
        // free it via `LocalDescriptor`. `sacl_ptr` aliases into `sd`'s
        // allocation and is valid for the lifetime of the descriptor.
        let win = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl_ptr,
                &mut sd,
            )
        };
        if win != ERROR_SUCCESS {
            return false;
        }
        let _sd_guard = LocalDescriptor(sd);

        if sacl_ptr.is_null() {
            return false;
        }
        // SAFETY: ACL points into `sd`; AceCount is the documented
        // first read for ACE traversal.
        let ace_count = unsafe { (*sacl_ptr).AceCount };

        // Parse the Low IL SID once for the per-ACE EqualSid compare.
        let low_il_str: Vec<u16> = OsStr::new("S-1-16-4096")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut low_il_sid: PSID = ptr::null_mut();
        // SAFETY: documented call; on success the SID is LocalAlloc'd.
        let ok = unsafe { ConvertStringSidToSidW(low_il_str.as_ptr(), &mut low_il_sid) };
        if ok == 0 {
            return false;
        }
        let _sid_guard = LocalSid(low_il_sid);

        for i in 0..ace_count {
            let mut ace_ptr: *mut core::ffi::c_void = ptr::null_mut();
            // SAFETY: GetAce reads the ACE at index `i` from `sacl_ptr`;
            // documented bounds-checked call.
            let got = unsafe { GetAce(sacl_ptr, i as u32, &mut ace_ptr) };
            if got == 0 || ace_ptr.is_null() {
                continue;
            }
            // SAFETY: ACE_HEADER is the universal prefix every ACE
            // starts with; reading it is safe regardless of the
            // specific ACE type.
            let header: &ACE_HEADER = unsafe { &*(ace_ptr as *const ACE_HEADER) };
            if header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                continue;
            }
            if header.AceFlags & OICI_FLAGS_BYTE != OICI_FLAGS_BYTE {
                continue;
            }
            // SAFETY: AceType matches, so the ACE is at least
            // `sizeof(SYSTEM_MANDATORY_LABEL_ACE)` for the fixed prefix
            // (the embedded SID is variable-length data past the
            // struct boundary).
            let ml_ace: &SYSTEM_MANDATORY_LABEL_ACE =
                unsafe { &*(ace_ptr as *const SYSTEM_MANDATORY_LABEL_ACE) };
            if ml_ace.Mask != SYSTEM_MANDATORY_LABEL_NO_WRITE_UP {
                continue;
            }
            // The embedded SID's first byte is at the address of
            // `SidStart` per winnt.h's variable-length-tail convention.
            let sid_ptr: PSID = &ml_ace.SidStart as *const u32 as *mut core::ffi::c_void;
            // SAFETY: `sid_ptr` is the embedded SID; `low_il_sid` is
            // our LocalAlloc'd reference SID. Both are valid for the
            // duration of EqualSid's read.
            let equal = unsafe { EqualSid(sid_ptr, low_il_sid) };
            if equal != 0 {
                return true;
            }
        }
        false
    }

    /// Test-only: override any inherited mandatory label on `path` by
    /// writing an explicit Medium IL OICI ACE via `icacls /setintegritylevel`.
    /// This is needed because some developer hosts (and CI hosts that
    /// re-use disk state between jobs) carry a persistent Low IL OICI
    /// label on `%TEMP%` from earlier dev iterations — the persistence
    /// hazard. Without overriding, every
    /// `tempfile::tempdir()`-rooted test path inherits Low IL from
    /// `%TEMP%`, which breaks negative assertions like "target must
    /// not carry Low IL."
    ///
    /// **Why `icacls` and not `SetNamedSecurityInfoW` with
    /// `PROTECTED_SACL_SECURITY_INFORMATION`.** The direct syscall
    /// approach requires `SE_SECURITY_NAME` (admin) — observed
    /// returning `ERROR_PRIVILEGE_NOT_HELD` (1314) under a normal
    /// developer test run. `icacls /setintegritylevel medium` writes
    /// an explicit Medium IL OICI ACE that takes precedence over the
    /// inherited Low IL on the same path, and explicit ACEs flow to
    /// children at create time instead of the original inherited Low
    /// IL. Writing Medium IL requires no privilege because our test
    /// process is itself Medium IL — equal-level labels are
    /// unconditionally permitted.
    ///
    /// Call this on a tempdir root right after creation; descendants
    /// created inside will inherit the explicit Medium IL ACE, which
    /// the oracle returns `false` for.
    fn test_strip_inherited_label(path: &Path) {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/setintegritylevel")
            .arg("(OI)(CI)medium")
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "icacls /setintegritylevel failed on {}: stdout={} stderr={}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        // Verify the override actually neutralised any inherited Low IL.
        assert!(
            !test_read_has_low_il_ace(path),
            "test_strip_inherited_label({}): path still carries Low IL after \
             icacls /setintegritylevel medium — the host's inheritance state \
             may be unusual",
            path.display(),
        );
    }

    /// Strip every inherited AppContainer Capability SID ACE from `path`'s
    /// DAC. Used by the Low-IL write-success tests to neutralise an
    /// environmental contamination that breaks the test contract on hosts
    /// whose `%TEMP%` carries an inherited Capability SID grant (e.g. from
    /// prior AppContainer-using software — Edge, Windows Sandbox, the
    /// AppContainer helper test fixtures).
    ///
    /// # Why this is needed
    ///
    /// Empirically, on Windows 11 26200 with KB5089549/KB5092762 installed,
    /// a Low IL process is DENIED `FILE_ADD_FILE` on a Low-IL-labelled
    /// directory if the directory's DAC contains an AppContainer Capability
    /// SID grant (`S-1-15-2-*`) — even when the DAC also explicitly grants
    /// the user `Full Control` AND the mandatory label policy is the
    /// standard `(OI)(CI)(NW)`. The kernel treats the Capability SID
    /// presence as a gate: Low IL subjects without a matching capability
    /// in their token are refused write access regardless of the rest of
    /// the descriptor.
    ///
    /// Production directories `apply_low_il_label` is asked to relabel
    /// (`~/.lpm/store/<pkg>`, `<project>/node_modules`, `~/.cache`,
    /// `~/.node-gyp`, `~/.npm`) live OUTSIDE `%TEMP%` and are not exposed
    /// to this inheritance, so the production Low IL fallback is unaffected
    /// on a typical layout. The contamination only matters for the
    /// `tmpdir` allow-set entry AND for tests whose fixtures live under
    /// `tempfile::tempdir()` (= `%TEMP%`).
    ///
    /// # What this helper does
    ///
    /// 1. Disable inheritance on `path` via `icacls /inheritance:d` —
    ///    this severs inheritance from the parent AND copies every
    ///    previously-inherited ACE as an explicit ACE on `path`, so the
    ///    user/SYSTEM/Administrators grants survive the sever. Using
    ///    `/inheritance:r` instead would REMOVE the inherited ACEs (the
    ///    common icacls footgun — the `r`/`d` flag pair has opposite
    ///    "remove" semantics from what the letter abbreviation suggests).
    /// 2. Enumerate the resulting DAC via `icacls` output and extract
    ///    every `S-1-15-2-*` SID literal.
    /// 3. Remove each extracted SID with `icacls /remove`.
    ///
    /// Idempotent: a path without any Capability SIDs gets steps 1-3 with
    /// step 3 a no-op. The user's, SYSTEM's, and Administrators' grants
    /// survive untouched because step 1 copies them as explicit and step
    /// 3's removal is keyed by the `S-1-15-2-` prefix.
    ///
    /// Callers must invoke this BEFORE `apply_low_il_label` because the
    /// label call doesn't touch the DAC — once the Capability SID is in
    /// the DAC, the kernel veto stands.
    fn test_strip_inherited_capability_sids(path: &Path) {
        // Step 1: disable inheritance AND copy currently-inherited ACEs
        // as explicit. `/inheritance:d` is the "copy then sever" flag —
        // `/inheritance:r` is the "drop then sever" flag and is the wrong
        // one here: it would strip the user's inherited Full Control and
        // leave the directory un-writable by the test process.
        let out = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:d")
            .output()
            .expect("icacls /inheritance:d");
        assert!(
            out.status.success(),
            "icacls /inheritance:d failed on {}: stdout={} stderr={}",
            path.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        // Step 2: enumerate Capability SIDs in the now-flat DAC.
        let listing = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .expect("icacls list");
        let stdout = String::from_utf8_lossy(&listing.stdout);
        let mut capability_sids: Vec<String> = Vec::new();
        for line in stdout.lines() {
            // Each ACE is `<sid-or-name>:<rights>`. Capability SIDs render
            // as their literal SID form (`S-1-15-2-...`) because icacls
            // can't resolve them to a friendly name. Split on the trailing
            // `:` to isolate the SID, then accept only those starting with
            // the AppContainer-package prefix.
            for token in line.split_whitespace() {
                if let Some(idx) = token.rfind(':') {
                    let sid = &token[..idx];
                    if sid.starts_with("S-1-15-2-") && !capability_sids.iter().any(|s| s == sid) {
                        capability_sids.push(sid.to_string());
                    }
                }
            }
        }

        // Step 3: remove each Capability SID.
        for sid in &capability_sids {
            // `*` prefix tells icacls to interpret the literal as a SID
            // rather than try to resolve it as a friendly name.
            let starred = format!("*{sid}");
            let rm = std::process::Command::new("icacls")
                .arg(path)
                .arg("/remove")
                .arg(&starred)
                .output()
                .expect("icacls /remove");
            assert!(
                rm.status.success(),
                "icacls /remove {starred} failed on {}: stdout={} stderr={}",
                path.display(),
                String::from_utf8_lossy(&rm.stdout),
                String::from_utf8_lossy(&rm.stderr),
            );
        }
    }

    /// Create an NTFS directory junction at `link` pointing at `target`.
    /// Uses `cmd /c mklink /J` because there's no std primitive for
    /// junctions. Junctions don't require admin privileges (unlike
    /// symbolic links).
    fn create_junction_for_test(link: &Path, target: &Path) -> std::io::Result<()> {
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "mklink /J failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )));
        }
        Ok(())
    }

    /// Try to create a directory symlink. Returns `None` if the host
    /// lacks the `SeCreateSymbolicLinkPrivilege` (developer mode off,
    /// not running elevated); tests that depend on a directory symlink
    /// should soft-skip in that case.
    fn try_create_dir_symlink_or_skip(target: &Path, link: &Path) -> Option<()> {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => Some(()),
            // ERROR_PRIVILEGE_NOT_HELD = 1314
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!(
                    "test skipped: dir symlink creation requires developer mode or \
                     SeCreateSymbolicLinkPrivilege"
                );
                None
            }
            Err(e) => panic!("unexpected symlink_dir error: {e}"),
        }
    }

    /// Try to create a file symlink. Same soft-skip contract as
    /// [`try_create_dir_symlink_or_skip`].
    fn try_create_file_symlink_or_skip(target: &Path, link: &Path) -> Option<()> {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => Some(()),
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!(
                    "test skipped: file symlink creation requires developer mode or \
                     SeCreateSymbolicLinkPrivilege"
                );
                None
            }
            Err(e) => panic!("unexpected symlink_file error: {e}"),
        }
    }

    // ── `is_reparse_point` helper tests ──────────────────────────────

    #[test]
    fn is_reparse_point_returns_false_for_regular_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let plain = tmp.path().join("plain-dir");
        std::fs::create_dir_all(&plain).unwrap();
        let meta = std::fs::symlink_metadata(&plain).expect("symlink_metadata");
        assert!(
            !is_reparse_point(&meta),
            "regular directory must not be flagged as a reparse point"
        );
    }

    #[test]
    fn is_reparse_point_detects_junction() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target-dir");
        let junction = tmp.path().join("junction-link");
        std::fs::create_dir_all(&target).unwrap();
        create_junction_for_test(&junction, &target).expect("mklink /J must succeed");

        let meta = std::fs::symlink_metadata(&junction).expect("symlink_metadata of junction");
        assert!(
            is_reparse_point(&meta),
            "is_reparse_point must catch NTFS directory junctions \
             (IO_REPARSE_TAG_MOUNT_POINT) — the gap that `is_symlink()` misses"
        );
    }

    #[test]
    fn is_reparse_point_detects_directory_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("real-dir");
        let link = tmp.path().join("symlink");
        std::fs::create_dir_all(&target).unwrap();
        if try_create_dir_symlink_or_skip(&target, &link).is_none() {
            return;
        }

        let meta = std::fs::symlink_metadata(&link).expect("symlink_metadata of link");
        assert!(
            is_reparse_point(&meta),
            "is_reparse_point must catch directory symbolic links"
        );
    }

    // ── Oracle tests ─────────────────────────────────────────────────

    #[test]
    fn test_read_has_low_il_ace_returns_false_on_unlabelled_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Sever any inherited Low IL from `%TEMP%` (some dev/CI hosts
        // carry a persistent label there from prior work).
        test_strip_inherited_label(tmp.path());
        let plain = tmp.path().join("unlabelled");
        std::fs::create_dir_all(&plain).unwrap();
        assert!(
            !test_read_has_low_il_ace(&plain),
            "freshly-created directory must not carry a Low IL ACE"
        );
    }

    #[test]
    fn test_read_has_low_il_ace_returns_true_after_apply() {
        reset_labelled_roots_cache_for_tests();
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("apply-target");
        std::fs::create_dir_all(&target).unwrap();
        apply_low_il_label(&target).expect("apply must succeed on a regular dir");
        assert!(
            test_read_has_low_il_ace(&target),
            "after apply_low_il_label, the on-disk SACL must carry the \
             OICI+NW+LowIL ACE shape the oracle expects"
        );
    }

    // ── Root-refusal contract ────────────────────────────────────────

    #[test]
    fn apply_low_il_label_refuses_reparse_point_root_junction() {
        let tmp = tempfile::tempdir().expect("tempdir");
        test_strip_inherited_label(tmp.path());
        let target = tmp.path().join("junction-target");
        let junction = tmp.path().join("junction-root");
        std::fs::create_dir_all(&target).unwrap();
        create_junction_for_test(&junction, &target).expect("mklink /J");

        match apply_low_il_label(&junction) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(
                    reason.contains("reparse point"),
                    "error must name `reparse point`: {reason}"
                );
            }
            Ok(()) => panic!(
                "apply_low_il_label MUST refuse a junction root \
                 (S1 contract); the silent-follow behaviour is the \
                 gap this PR closes"
            ),
            Err(other) => panic!("expected ProfileRenderFailed, got {other:?}"),
        }

        // Independent assertion via the test oracle: the junction's
        // target must NOT have been labelled. A regression that
        // accidentally follows the junction would fail this.
        assert!(
            !test_read_has_low_il_ace(&target),
            "junction target must NOT carry Low IL — the root refusal \
             must reject BEFORE any SetNamedSecurityInfoW call"
        );
    }

    #[test]
    fn apply_low_il_label_refuses_reparse_point_root_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        test_strip_inherited_label(tmp.path());
        let target = tmp.path().join("symlink-target");
        let symlink = tmp.path().join("symlink-root");
        std::fs::create_dir_all(&target).unwrap();
        if try_create_dir_symlink_or_skip(&target, &symlink).is_none() {
            return;
        }

        match apply_low_il_label(&symlink) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(
                    reason.contains("reparse point"),
                    "error must name `reparse point`: {reason}"
                );
            }
            Ok(()) => panic!("apply_low_il_label MUST refuse a symlink root"),
            Err(other) => panic!("expected ProfileRenderFailed, got {other:?}"),
        }

        assert!(
            !test_read_has_low_il_ace(&target),
            "symlink target must NOT carry Low IL — root refusal precedes \
             any label syscall"
        );
    }

    #[test]
    fn apply_low_il_label_root_refusal_message_is_truthful() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("truth-target");
        let junction = tmp.path().join("truth-junction");
        std::fs::create_dir_all(&target).unwrap();
        create_junction_for_test(&junction, &target).expect("mklink /J");

        let err = apply_low_il_label(&junction).expect_err("must refuse the junction root");
        let reason = match err {
            SandboxError::ProfileRenderFailed { reason } => reason,
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        };

        // Path appears so users can identify which root is at fault.
        assert!(
            reason.contains(&junction.display().to_string()),
            "error must name the offending path: {reason}"
        );

        // Truthful workaround #1: replace the reparse point.
        assert!(
            reason.contains("Replace the reparse point"),
            "error must offer 'replace with regular directory' as the \
             universal workaround: {reason}"
        );

        // Truthful workaround #2: TMP/TEMP for the tmpdir case.
        assert!(
            reason.contains("TMP") && reason.contains("TEMP"),
            "error must name the TMP/TEMP env-var workaround for the \
             tmpdir case: {reason}"
        );

        // Truthful workaround #3: --no-sandbox as universal fallback.
        assert!(
            reason.contains("--no-sandbox"),
            "error must name --no-sandbox as the universal fallback: {reason}"
        );

        // Disclaimer: sandboxWriteDirs does NOT bypass for built-in roots.
        // If a future regression re-introduces 'declare via sandboxWriteDirs'
        // as the only fix, this assertion fails.
        assert!(
            reason.contains("sandboxWriteDirs cannot bypass")
                || reason.contains("cannot bypass this refusal"),
            "error must explicitly disclaim sandboxWriteDirs as a bypass \
             for built-in roots: {reason}"
        );
    }

    // ── Walk-skip contract ──────────────────────────────────────────

    #[test]
    fn relabel_walk_does_not_label_junction_target_contents() {
        reset_labelled_roots_cache_for_tests();
        let tmp = tempfile::tempdir().expect("tempdir");
        test_strip_inherited_label(tmp.path());

        // The allow-set root we'll label.
        let allow_root = tmp.path().join("allow-root");
        std::fs::create_dir_all(&allow_root).unwrap();

        // An "outside" subtree the test owns but that lives OUTSIDE the
        // allow-set tree we'll label.
        let outside = tmp.path().join("outside-tree");
        let outside_subdir = outside.join("subdir");
        let outside_file = outside.join("secret.txt");
        std::fs::create_dir_all(&outside_subdir).unwrap();
        std::fs::write(&outside_file, b"secret").unwrap();
        std::fs::write(outside_subdir.join("nested.txt"), b"nested").unwrap();

        // A junction INSIDE the allow-root pointing OUT to the
        // outside subtree. This is the planted-attack shape S1
        // addresses.
        let junction_inside = allow_root.join("junction-escape");
        create_junction_for_test(&junction_inside, &outside).expect("mklink /J");

        // Run the label. Walks the allow-root tree, finds the junction
        // inside, must SKIP it without descending or labelling.
        apply_low_il_label(&allow_root).expect("label allow-root");

        // Allow-root itself must be labelled.
        assert!(
            test_read_has_low_il_ace(&allow_root),
            "allow-set root must carry Low IL after apply"
        );

        // The S1 contract: the junction's target tree must NOT be labelled.
        assert!(
            !test_read_has_low_il_ace(&outside),
            "junction target must NOT be labelled — walking through the \
             junction would escape the allow-set"
        );
        assert!(
            !test_read_has_low_il_ace(&outside_subdir),
            "junction-target subdir must NOT be labelled"
        );
        assert!(
            !test_read_has_low_il_ace(&outside_file),
            "junction-target file must NOT be labelled"
        );
    }

    #[test]
    fn relabel_walk_does_not_label_symlink_target() {
        reset_labelled_roots_cache_for_tests();
        let tmp = tempfile::tempdir().expect("tempdir");
        test_strip_inherited_label(tmp.path());
        let allow_root = tmp.path().join("symlink-allow-root");
        std::fs::create_dir_all(&allow_root).unwrap();

        // Outside target file the symlink points at.
        let outside_file = tmp.path().join("outside-secret.txt");
        std::fs::write(&outside_file, b"secret").unwrap();

        // File symlink inside the allow-set pointing OUT.
        let symlink_inside = allow_root.join("symlink-escape");
        if try_create_file_symlink_or_skip(&outside_file, &symlink_inside).is_none() {
            return;
        }

        apply_low_il_label(&allow_root).expect("label allow-root");

        assert!(
            test_read_has_low_il_ace(&allow_root),
            "allow-set root must carry Low IL"
        );
        assert!(
            !test_read_has_low_il_ace(&outside_file),
            "symlink target must NOT be labelled — labelling the symlink \
             would cause SetNamedSecurityInfoW to follow it and apply \
             Low IL to the target file outside the allow-set"
        );
    }

    // ── JOB_TRACKER idempotency pins ────────────────────────────────
    //
    // Both `release_sandbox_tracker_entry` and `terminate_sandbox_tree`
    // document themselves as "Idempotent: missing entries are silent
    // no-ops." These tests pin that contract — calling either on a
    // PID that was never registered must not panic and must leave the
    // tracker untouched. They deliberately do NOT pin behavior on
    // duplicate-PID re-register —
    // that case is unreachable in the current call graph (kernel
    // PID-reuse is blocked while the parent holds a process handle),
    // so locking it as a contract would over-specify.

    #[test]
    fn release_sandbox_tracker_entry_on_unknown_pid_is_noop() {
        // PID chosen so it cannot collide with a real Windows PID
        // (kernel PIDs are multiples of 4 and the high bit is never
        // set in user-mode space).
        release_sandbox_tracker_entry(0xFFFF_FFFE);
        let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            !table.contains_key(&0xFFFF_FFFE),
            "release on unknown PID must not insert an entry"
        );
    }

    #[test]
    fn terminate_sandbox_tree_on_unknown_pid_is_noop() {
        // No registration before this — the call must short-circuit
        // before any TerminateJobObject syscall.
        terminate_sandbox_tree(0xFFFF_FFFD);
        let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            !table.contains_key(&0xFFFF_FFFD),
            "terminate on unknown PID must not insert an entry"
        );
    }

    #[test]
    fn tracked_commands_use_kill_on_close_without_lifecycle_resource_caps() {
        // SAFETY: the Windows information struct accepts the all-zero initial state.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

        configure_job_limits(&mut info, JobLimitProfile::TreeTrackingOnly);

        assert_eq!(
            info.BasicLimitInformation.LimitFlags,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        );
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 0);
        assert_eq!(info.ProcessMemoryLimit, 0);
    }

    #[test]
    fn lifecycle_jobs_retain_process_and_memory_caps() {
        // SAFETY: the Windows information struct accepts the all-zero initial state.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

        configure_job_limits(&mut info, JobLimitProfile::LifecycleSandbox);

        assert_ne!(
            info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            0
        );
        assert_ne!(
            info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            0
        );
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 512);
        assert_eq!(info.ProcessMemoryLimit, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn tracked_command_is_attached_before_resume_and_terminated_as_a_job() {
        let mut command = Command::new("cmd.exe");
        command
            .args(["/D", "/S", "/C", "ping -n 30 127.0.0.1 >NUL"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_tracked_command(&mut command).expect("spawn tracked command");
        let pid = child.id();
        {
            let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
            assert!(table.contains_key(&pid));
        }

        terminate_sandbox_tree(pid);
        let status = child.wait().expect("reap terminated tracked command");
        assert!(!status.success());
        let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!table.contains_key(&pid));
    }

    #[test]
    fn normally_exited_tracked_command_releases_its_job_entry() {
        let mut command = Command::new("cmd.exe");
        command
            .args(["/D", "/S", "/C", "exit /b 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_tracked_command(&mut command).expect("spawn tracked command");
        let pid = child.id();

        let status = child.wait().expect("wait for tracked command");
        assert!(status.success());
        {
            let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
            assert!(table.contains_key(&pid));
        }

        release_sandbox_tracker_entry(pid);
        let table = JOB_TRACKER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!table.contains_key(&pid));
    }

    fn tracked_descendant_fixture(exit_root: bool) -> (tempfile::TempDir, PathBuf, Command) {
        let directory = tempfile::tempdir().expect("create tracked descendant fixture");
        let pid_file = directory.path().join("descendant.pid");
        let script = directory.path().join("spawn-descendant.ps1");
        let escaped_pid_file = pid_file.to_string_lossy().replace('\'', "''");
        let root_action = if exit_root {
            "exit 0"
        } else {
            "Start-Sleep -Seconds 30"
        };
        std::fs::write(
            &script,
            format!(
                "$ErrorActionPreference = 'Stop'\n$ping = Join-Path $env:SystemRoot 'System32\\PING.EXE'\n$child = Start-Process -FilePath $ping -ArgumentList @('-n','30','127.0.0.1') -PassThru\nSet-Content -LiteralPath '{escaped_pid_file}' -Value $child.Id -NoNewline\n{root_action}\n"
            ),
        )
        .expect("write tracked descendant fixture");
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        (directory, pid_file, command)
    }

    fn wait_for_descendant_pid(pid_file: &std::path::Path, root: &mut Child) -> u32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(value) = std::fs::read_to_string(pid_file)
                && let Ok(pid) = value.parse()
            {
                return pid;
            }
            if std::time::Instant::now() >= deadline {
                let root_status = root.try_wait().expect("inspect tracked root status");
                let pid_contents = std::fs::read_to_string(pid_file);
                panic!(
                    "tracked descendant did not publish its PID; root status: \
                     {root_status:?}; PID file: {pid_contents:?}"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn windows_process_exists(pid: u32) -> bool {
        let output = Command::new("tasklist.exe")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .expect("query Windows process table");
        String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
    }

    fn assert_process_exits(pid: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while windows_process_exists(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "tracked descendant {pid} remained alive"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn terminating_a_tracked_job_kills_its_descendant() {
        let (_directory, pid_file, mut command) = tracked_descendant_fixture(false);
        let mut root = spawn_tracked_command(&mut command).expect("spawn tracked root");
        let descendant = wait_for_descendant_pid(&pid_file, &mut root);

        terminate_sandbox_tree(root.id());
        let status = root.wait().expect("reap terminated tracked root");

        assert!(!status.success());
        assert_process_exits(descendant);
    }

    #[test]
    fn releasing_a_normally_exited_job_kills_its_surviving_descendant() {
        let (_directory, pid_file, mut command) = tracked_descendant_fixture(true);
        let mut root = spawn_tracked_command(&mut command).expect("spawn tracked root");
        let root_pid = root.id();
        let descendant = wait_for_descendant_pid(&pid_file, &mut root);
        let status = root.wait().expect("wait for normally exited root");
        assert!(status.success());
        assert!(windows_process_exists(descendant));

        release_sandbox_tracker_entry(root_pid);

        assert_process_exits(descendant);
    }
}
