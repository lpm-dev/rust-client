//! Windows sandbox backend: Mandatory Integrity Control (Low IL) +
//! Job Object. Phase 46.2.
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
//!   allowed, matching the Phase 46.1-rework "relaxed default".
//! - [`SandboxPosture::Strict`] (`deny_outbound_network = true`):
//!   Windows cannot deliver the strict contract today — closing the
//!   network gap needs a Windows Filtering Platform (WFP) callout
//!   filter, deferred to Phase 46.3. When the user requests strict
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

#![cfg(target_os = "windows")]

use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec,
    SandboxedCommand,
};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, LocalFree,
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
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenProcessToken, TerminateProcess,
};

/// `SE_GROUP_INTEGRITY` is the well-known constant attribute bit for
/// a SID-and-attributes entry that represents an integrity-level
/// group. Value is fixed at `0x00000020` since Windows Vista; the
/// constant is part of every Windows SDK winnt.h but not exposed by
/// `windows-sys 0.60`. Inlining one literal is cheaper than enabling
/// another (unrelated) feature flag.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

// ── Backend struct ───────────────────────────────────────────────────

/// Phase 46.2 Windows backend. See module docs for the mechanism
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
        /// Phase 46.2 network-gap fallback. Drives the
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
                let posture = decide_posture(options.deny_outbound_network, options.allow_degraded)?;
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
                              primitive in Phase 46.2. To debug a sandbox false-positive, \
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

/// Phase 46.2 posture decision. Pure (inputs in, outcome out), mirrors
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
    // today — that's Phase 46.3's WFP work. Without the degraded
    // opt-in we refuse, symmetric with Linux's kernel-too-old path.
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
    "Phase 46.2 ships Windows filesystem-write containment but \
     defers outbound-network denial to Phase 46.3 (the Windows \
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
        let job = match create_kill_on_close_job_and_attach(proc_handle) {
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

// ── Allow-set rendering ──────────────────────────────────────────────

/// The list of directories the lifecycle child needs Low-IL write
/// access to. Mirrors the union of:
/// - macOS Seatbelt `file-write*` block ([`crate::seatbelt`])
/// - Linux landlock `ReadWrite` rules
///   ([`crate::landlock_rules::describe_rules`])
///
/// Order is deterministic so tests can pin "first writable allow is
/// package_dir" etc. without a sort step.
fn writable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
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

    // Fast-path: was this exact path labelled earlier in this
    // process? Canonicalize first so a caller passing `C:\foo`,
    // `C:\foo\`, and the same path with a `\\?\` extended prefix
    // all hit the same cache entry. Canonicalization can fail
    // (junctions, locked dirs); if it does we fall through and
    // re-label, which is correct (idempotent at the kernel layer)
    // just slower.
    let cache_key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if labelled_cache_contains(&cache_key) {
        tracing::debug!(
            target: "lpm_sandbox::windows",
            "skip Low IL label on already-labelled path {}",
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

    // Cache the labelled root so subsequent spawns in the same lpm
    // process skip the walk. New files created inside this dir by
    // the lifecycle child inherit Low IL automatically (OICI), so
    // the second spawn doesn't need to retouch them.
    labelled_cache_insert(cache_key);

    Ok(())
}

/// Process-wide memo: which paths have already been Low-IL-labelled
/// by this lpm process. See [`apply_low_il_label`] for the rationale.
///
/// Lifetime is the lpm process. Killing + restarting lpm clears the
/// cache, which is correct: external actors (Windows updates,
/// `icacls /reset`) could have stripped the label and we'd want to
/// reapply it.
///
/// Stored as `Option<HashSet>` because `HashSet::new()` isn't `const`
/// on stable Rust; we lazy-init on first access. A poisoned mutex
/// (some other thread panicked while holding the lock) is recovered
/// rather than propagated — losing the cache wastes work but
/// shouldn't fail the install.
static LABELED_ROOTS: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

fn labelled_cache_contains(path: &Path) -> bool {
    let cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    cache.as_ref().is_some_and(|s| s.contains(path))
}

fn labelled_cache_insert(path: PathBuf) {
    let mut cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    cache.get_or_insert_with(HashSet::new).insert(path);
}

/// Test-only: drop every cached entry. Lets the per-test isolated
/// specs (which build fresh tempdirs each test) actually exercise
/// the full label path instead of hitting a poisoned cache from an
/// earlier test in the same binary.
#[cfg(test)]
fn reset_labelled_roots_cache_for_tests() {
    let mut cache = LABELED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    *cache = Some(HashSet::new());
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
fn extract_sacl_pointer(
    sd: PSECURITY_DESCRIPTOR,
    path: &Path,
) -> Result<*mut ACL, SandboxError> {
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
/// Symlinks are NOT followed — we label the link object itself but
/// don't traverse into the target. This matches the macOS Seatbelt
/// and Linux landlock posture: scripts are allow-set restricted by
/// their canonicalized destination, not by aliasing.
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
            if let Err(e) = set_low_il_label_on(&path, sacl_ptr) {
                tracing::debug!(
                    target: "lpm_sandbox::windows",
                    "skip relabel of {}: {e}",
                    path.display(),
                );
            }
            // Recurse into directories only — skip symlinks so we
            // don't escape the allow-set tree by walking through an
            // attacker-planted link. `file_type()` reads the
            // metadata without following symlinks.
            if let Ok(ft) = entry.file_type()
                && ft.is_dir()
                && !ft.is_symlink()
            {
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
fn create_kill_on_close_job_and_attach(process_handle: HANDLE) -> Result<OwnedHandle, SandboxError> {
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
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
/// parent process exits and the OS reaps it. For Phase 46.2 the
/// (b) cleanup is sufficient: lifecycle scripts complete in seconds,
/// the parent (`lpm`) exits quickly, and the OS frees the handle.
/// Phase 46.3 can layer an explicit reaper if memory pressure
/// surfaces from long-running parents (the rebuild-watch loop, say).
fn register_job_for_child(pid: u32, job: OwnedHandle) {
    let mut table = JOB_TRACKER.lock().expect("job tracker mutex");
    table.push((pid, job));
}

/// Module-local tracker; intentionally tiny (Vec of pairs) — the
/// number of in-flight sandboxed children at any moment in a real
/// install is small (single-digit). A HashMap is overkill.
static JOB_TRACKER: Mutex<Vec<(u32, OwnedHandle)>> = Mutex::new(Vec::new());

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
    if let Some(idx) = table.iter().position(|(p, _)| *p == pid) {
        let job_handle = table[idx].1.0;
        // SAFETY: `job_handle` is the kernel Job Object we created
        // and exclusively own via the tracker entry; `TerminateJobObject`
        // is documented as safe to call from any thread.
        unsafe {
            TerminateJobObject(job_handle, 1);
        }
        // Drop the entry — `OwnedHandle::Drop` closes the kernel
        // handle. The Job has already been terminated, so closing
        // is just resource reclamation at this point.
        table.remove(idx);
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
    if let Some(idx) = table.iter().position(|(p, _)| *p == pid) {
        table.remove(idx);
    }
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
    // of 2026-05. We zero-init the struct via `std::mem::zeroed()`
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

    /// Phase 46.2: a spec with non-existent fake paths. Safe for any
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
                    remediation.contains("Phase 46.3"),
                    "remediation must name the follow-up phase that closes the gap: {remediation}"
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
        // Phase 46.2 default mode: filesystem-write containment only,
        // no network denial. Construction succeeds on any reachable
        // Windows host (no kernel-version gate — Mandatory Integrity
        // Control has been in every Windows release since Vista).
        let sb = WindowsSandbox::new(
            realistic_spec(),
            SandboxMode::Enforce,
            SandboxOptions::default(),
        )
        .expect("Phase 46.2 default mode must construct cleanly on any Windows host");
        assert_eq!(sb.backend_name(), "windows-il");
        assert_eq!(sb.posture(), SandboxPosture::Default);
    }

    #[test]
    fn new_strict_without_degraded_opt_in_surfaces_unsupported() {
        // The strict path is the Phase 46.3 follow-up; without the
        // degraded opt-in we refuse with a remediation block naming
        // every recourse.
        let opts = SandboxOptions {
            deny_outbound_network: true,
            allow_degraded: false,
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
        // Phase 46.2: missing paths in the allow set get skipped
        // with a tracing::debug line, matching landlock's
        // `tracing::debug!("landlock: skip ...")` shape. A skip is
        // not an error.
        let nonexistent = PathBuf::from(r"C:\lpm-sandbox-test-nonexistent-46.2");
        assert!(!nonexistent.exists(), "guard: path must not exist");
        apply_low_il_label(&nonexistent).expect("nonexistent path must be a no-op skip, not error");
    }

    /// Phase 46.2 follow-up — re-labelling the same root twice in
    /// the same process must hit the cache fast-path and skip the
    /// recursive walk. Without the cache, installs with multiple
    /// lifecycle scripts would re-walk every existing descendant of
    /// `~/.cache`, `~/.npm`, `~/.node-gyp`, and tmpdir once per
    /// script — a Windows-only performance regression that wouldn't
    /// surface in single-script installs.
    ///
    /// We pin the cache behavior via the labelled_cache_contains
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
            !labelled_cache_contains(&canonical),
            "cache must start empty after reset"
        );

        apply_low_il_label(&target).expect("first label must succeed");
        assert!(
            labelled_cache_contains(&canonical),
            "first label must populate the cache so subsequent spawns skip the walk"
        );

        // Second call: hits the fast-path. The contract is "no
        // error" + "still cached"; the actual short-circuit lives
        // inside apply_low_il_label, observable through a
        // tracing::debug! line in production but not visible from
        // here. The cache-membership assertion is the durable pin.
        apply_low_il_label(&target).expect("second label must be a cache hit, not an error");
        assert!(
            labelled_cache_contains(&canonical),
            "cache entry must persist across spawns"
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
    /// allow-set must be denied. This is the Phase 46.2 brief's
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
            "lpm-sandbox-phase46.2-forbidden-{}.txt",
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
    /// Phase 46.2 follow-up — pre-existing files inside the allow-set
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
            .envs_cleared([pass("PATH"), pass("SYSTEMROOT"), pass("COMSPEC"), pass("WINDIR")]);
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
            .envs_cleared([pass("PATH"), pass("SYSTEMROOT"), pass("COMSPEC"), pass("WINDIR")]);
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
}
