//! AppContainer launcher backend for `lpm-sandbox-helper.exe`.
//!
//! Design overview: see
//! [`private/46.3-pr2-network-denial.md`](../../../../private/46.3-pr2-network-denial.md).
//! The high-level flow:
//!
//! 1. **SID create-or-reuse.** Call
//!    [`CreateAppContainerProfile`] for the stable
//!    [`helper_protocol::APPCONTAINER_NAME`]; on
//!    `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)` fall back to
//!    [`DeriveAppContainerSidFromAppContainerName`] for the same
//!    name. Both paths yield the same SID (the SID is derived from
//!    the name) so subsequent DACL grants are idempotent across
//!    runs.
//! 2. **Allow-set DACL grants.** For each `--readable-dir` and
//!    `--writable-dir` from the parent, walk the tree once (skipping
//!    reparse points per the PR-1 contract) and add an inheritable
//!    DACL ACE granting the AppContainer SID the matching access
//!    rights. ACEs are added with [`SetEntriesInAclW`], merged into
//!    the existing DACL via [`GetNamedSecurityInfoW`] +
//!    [`SetNamedSecurityInfoW`] so user-owned explicit ACEs are
//!    preserved.
//! 3. **STARTUPINFOEXW + SECURITY_CAPABILITIES.** Build a process
//!    creation attribute list carrying
//!    [`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`]. Strict mode
//!    ships an empty capability list (default-deny including
//!    outbound network); Default mode ships one
//!    `InternetClient` capability SID.
//! 4. **Job Object + spawn + wait.** Create a Job Object with
//!    `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `CreateProcessW` with
//!    `CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT |
//!    CREATE_NEW_PROCESS_GROUP`, assign the suspended child to the
//!    job BEFORE resuming (kill-tree parity), `ResumeThread`,
//!    `WaitForSingleObject(INFINITE)`, propagate the child's exit
//!    code.
//!
//! ## Cleanup-on-crash story
//!
//! Helper death — including a crash partway through DACL setup —
//! triggers `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` once the Job
//! Object handle is the last reference, which the helper's RAII
//! guard ensures on every exit path. The lifecycle child cannot
//! outlive the helper.
//!
//! The DACL ACEs we add **persist** past the install — idempotent
//! across runs, near-zero disk impact, simpler than tearing down
//! grants on every exit (which would race with concurrent lpm
//! invocations on the same host).

#![cfg(target_os = "windows")]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    HLOCAL, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    UNPROTECTED_DACL_SECURITY_INFORMATION, WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::helper_protocol::{HelperArgs, StdioMode, split_env_entry};

/// `SE_GROUP_ENABLED` from winnt.h. The Attributes field of every
/// `SID_AND_ATTRIBUTES` inside a `SECURITY_CAPABILITIES.Capabilities`
/// array must carry this bit — otherwise the capability SID is
/// present in the token but DISABLED, and AppContainer denies the
/// matching resources as if it weren't listed.
///
/// windows-sys exposes this constant under `Win32_System_SystemServices`
/// which we don't otherwise need; inlining the literal mirrors the
/// `SE_GROUP_INTEGRITY` pattern in [`crate::windows`].
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

// ── Error type ───────────────────────────────────────────────────────

/// Failure shape for the AppContainer launcher. Each variant carries
/// the named API call + the Win32 error code so a failure on a
/// developer host is self-diagnosable without re-running under a
/// debugger.
#[derive(Debug, thiserror::Error)]
pub enum AppContainerError {
    /// `CreateAppContainerProfile` returned an HRESULT other than
    /// `S_OK` or `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
    #[error("CreateAppContainerProfile({name}) failed with HRESULT 0x{hresult:08X}")]
    CreateProfile {
        /// AppContainer name we tried to register.
        name: String,
        /// HRESULT returned by the Win32 call.
        hresult: i32,
    },
    /// `DeriveAppContainerSidFromAppContainerName` failed on the
    /// already-exists fallback path.
    #[error(
        "DeriveAppContainerSidFromAppContainerName({name}) failed with HRESULT 0x{hresult:08X}"
    )]
    DeriveSid {
        /// AppContainer name we tried to derive.
        name: String,
        /// HRESULT returned by the Win32 call.
        hresult: i32,
    },
    /// `CreateWellKnownSid` failed building the `InternetClient`
    /// capability SID.
    #[error("CreateWellKnownSid(InternetClient) failed with Win32 error {last_error}")]
    WellKnownSid {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// Reading the existing DACL via `GetNamedSecurityInfoW` failed.
    #[error("GetNamedSecurityInfoW({path}) failed with Win32 error {win32_error}")]
    ReadDacl {
        /// Path whose DACL we tried to read.
        path: PathBuf,
        /// `WIN32_ERROR` returned by the call (NOT GetLastError —
        /// `GetNamedSecurityInfoW` returns the error directly).
        win32_error: u32,
    },
    /// `SetEntriesInAclW` failed merging the AppContainer ACE.
    #[error("SetEntriesInAclW({path}) failed with Win32 error {win32_error}")]
    MergeDacl {
        /// Path whose DACL we were updating.
        path: PathBuf,
        /// `WIN32_ERROR` returned by the call.
        win32_error: u32,
    },
    /// `SetNamedSecurityInfoW` failed writing the merged DACL back.
    #[error("SetNamedSecurityInfoW({path}) failed with Win32 error {win32_error}")]
    WriteDacl {
        /// Path we tried to update.
        path: PathBuf,
        /// `WIN32_ERROR` returned by the call.
        win32_error: u32,
    },
    /// The supplied root path is a reparse point (symlink / junction).
    /// PR-1 contract: refuse rather than silently follow.
    #[error(
        "allow-set root {path} is a reparse point (symlink / junction / mount point); refusing to follow it because the DACL grant would apply to the reparse-point target, potentially outside the intended allow-set tree"
    )]
    ReparsePointRoot {
        /// Path that resolved to a reparse point.
        path: PathBuf,
    },
    /// `InitializeProcThreadAttributeList` failed sizing or
    /// initializing the attribute list buffer.
    #[error("InitializeProcThreadAttributeList failed with Win32 error {last_error}")]
    InitAttrList {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `UpdateProcThreadAttribute` failed attaching the
    /// `SECURITY_CAPABILITIES` attribute.
    #[error(
        "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed with Win32 error {last_error}"
    )]
    UpdateAttrList {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `CreateJobObjectW` returned NULL.
    #[error("CreateJobObjectW failed with Win32 error {last_error}")]
    CreateJob {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `SetInformationJobObject` failed configuring KILL_ON_JOB_CLOSE.
    #[error("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed with Win32 error {last_error}")]
    ConfigureJob {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `CreateProcessW` failed.
    #[error("CreateProcessW({program:?}) failed with Win32 error {last_error}")]
    CreateProcess {
        /// Program path we tried to spawn.
        program: OsString,
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `AssignProcessToJobObject` failed (the lifecycle child is
    /// still suspended at this point, so we'll terminate it via the
    /// process-info handle in the error path).
    #[error("AssignProcessToJobObject failed with Win32 error {last_error}")]
    AssignJob {
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `CreateFileW(NUL, ...)` failed opening the `Null` stdio
    /// stand-in.
    #[error("CreateFileW(NUL, {role}) failed with Win32 error {last_error}")]
    OpenNul {
        /// Which stdio role (`stdin`, `stdout`, `stderr`).
        role: &'static str,
        /// `GetLastError` reading.
        last_error: u32,
    },
    /// `WaitForSingleObject` returned an unexpected value while
    /// waiting for the lifecycle child.
    #[error("WaitForSingleObject(child) returned unexpected value 0x{wait_result:08X}")]
    Wait {
        /// Raw value returned by `WaitForSingleObject`.
        wait_result: u32,
    },
    /// `GetExitCodeProcess` failed extracting the lifecycle child's
    /// exit code after it terminated.
    #[error("GetExitCodeProcess failed with Win32 error {last_error}")]
    ExitCode {
        /// `GetLastError` reading.
        last_error: u32,
    },
}

// ── RAII guards ──────────────────────────────────────────────────────

/// Wraps a `LocalAlloc`-managed PSID. AppContainer SIDs returned by
/// `CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName`
/// must be freed with `LocalFree`.
struct SidGuard(PSID);

impl Drop for SidGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: documented free-path for SIDs returned by
            // the AppContainer profile / derive APIs.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

/// Wraps any handle whose lifetime ends with `CloseHandle`. Used for
/// the Job Object, the child's process handle, the child's primary
/// thread handle, and any NUL stdio handles we opened.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` was produced by a Win32 call that
            // returned a handle this guard owns. Idempotent for the
            // sentinel values we check above.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl HandleGuard {
    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

/// Wraps any `LocalAlloc`-managed pointer (ACLs, security
/// descriptors). `LocalFree` is the documented free-path.
struct LocalAllocGuard(*mut std::ffi::c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was produced by `SetEntriesInAclW` or
            // `GetNamedSecurityInfoW`'s out parameters; both are
            // `LocalAlloc`'d and require `LocalFree`.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

/// Wraps an `InitializeProcThreadAttributeList`-allocated attribute
/// list. The destructor calls `DeleteProcThreadAttributeList` first
/// (frees internal references), then the Box drop reclaims the
/// underlying byte buffer.
struct AttrListGuard {
    /// Owns the byte buffer that backs the attribute list.
    _buf: Box<[u8]>,
    /// Pointer into the buffer that `InitializeProcThreadAttributeList`
    /// initialized. Borrowed by `STARTUPINFOEXW.lpAttributeList`.
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttrListGuard {
    fn list(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttrListGuard {
    fn drop(&mut self) {
        if !self.list.is_null() {
            // SAFETY: `self.list` was produced by
            // `InitializeProcThreadAttributeList` on the buffer we
            // still own. `DeleteProcThreadAttributeList` is the
            // documented teardown; the buffer itself is freed by
            // the Box drop after this.
            unsafe {
                DeleteProcThreadAttributeList(self.list);
            }
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────

/// Run the helper's AppContainer spawn dance against `args`.
///
/// Returns the lifecycle child's exit code on success. Setup
/// failures (DACL grant, SID derive, profile create) and spawn
/// failures all surface as [`AppContainerError`] with a named
/// variant so stderr is self-diagnosable.
pub fn run_appcontainer_spawn(args: HelperArgs) -> Result<i32, AppContainerError> {
    // 1. Derive (or create) the AppContainer SID. Idempotent across
    //    runs: same name → same SID → same DACL grants.
    let sid = create_or_reuse_appcontainer_sid(&args.appcontainer_name)?;

    // 2. Apply DACL grants on the allow-set. Writable entries get
    //    R+W+X; readable entries get R+X. Order doesn't matter —
    //    DACLs are additive. Entries that appear in both lists end
    //    up R+W+X (last grant wins because each pass merges over the
    //    previous DACL state).
    //
    // Spec-derived allow-set entries (readable_dirs + writable_dirs)
    // use STRICT semantics: a root-level grant failure is fatal
    // because those paths come from the install pipeline's own
    // configuration (package_dir, project_dir, ~/.cache,
    // tmpdir, sandboxWriteDirs entries) and a failure means the
    // sandbox can't be constructed correctly — surface the error
    // rather than silently dropping containment.
    //
    // PATH-derived tool dirs (best_effort_readable_dirs) use the
    // BEST-EFFORT path: a root-level failure logs WARN but the
    // spawn proceeds. This handles the SYSTEM-owned-tool-dir case
    // (e.g. `C:\Program Files\nodejs` is owned by SYSTEM and
    // unprivileged `lpm.exe` can't modify its DACL). The lifecycle
    // child either succeeds (script doesn't need that tool, or the
    // tool happens to be in a user-writable location) or fails
    // downstream with a clearer "tool not found" error than a hard
    // sandbox-setup failure would give.
    for dir in &args.readable_dirs {
        grant_dacl_ace_to_tree(
            dir,
            sid.0,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            /* strict_root */ true,
        )?;
    }
    for dir in &args.writable_dirs {
        grant_dacl_ace_to_tree(
            dir,
            sid.0,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
            /* strict_root */ true,
        )?;
    }
    for dir in &args.best_effort_readable_dirs {
        grant_dacl_ace_to_tree(
            dir,
            sid.0,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            /* strict_root */ false,
        )?;
    }

    // 3. Build SECURITY_CAPABILITIES — empty for Strict, one
    //    InternetClient SID for Default.
    let mut internet_sid_buf = vec![0u8; 64];
    let internet_attrs = if args.grant_internet_client {
        Some(build_capability_attr(
            WinCapabilityInternetClientSid,
            &mut internet_sid_buf,
        )?)
    } else {
        None
    };
    let mut sec_caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid.0,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut caps_storage: [SID_AND_ATTRIBUTES; 1];
    if let Some(attr) = internet_attrs {
        caps_storage = [attr];
        sec_caps.Capabilities = caps_storage.as_mut_ptr();
        sec_caps.CapabilityCount = 1;
    }

    // 4. Allocate the attribute list and attach SECURITY_CAPABILITIES.
    let attr_list = init_attribute_list_with_caps(&mut sec_caps)?;

    // 5. Create the Job Object now so it exists before we spawn —
    //    the suspended child gets assigned to it BEFORE we resume,
    //    so a misbehaving child can't fork off descendants outside
    //    the job's kill-tree.
    let job = create_kill_on_close_job()?;

    // 6. Build stdio handles. Inherit/Piped → forward our own
    //    GetStdHandle. Null → open NUL with inheritable flag.
    let stdio = open_stdio_handles(&args)?;

    // 7. Render the command line + environment + working dir. We
    //    deliberately do NOT pass `lpApplicationName` (kept NULL)
    //    so Windows parses argv[0] from `lpCommandLine` AND
    //    searches PATH — the install pipeline frequently passes
    //    bare program names (`cmd.exe`, `node`, `npm`) that resolve
    //    via System32 / nvm dirs / etc. With
    //    `lpApplicationName` set, `CreateProcessW` treats it as a
    //    literal path and a bare name fails with ERROR_FILE_NOT_FOUND.
    //    Quoting in `quote_arg_for_cmdline` ensures the first token
    //    is unambiguously the program path even when it contains
    //    spaces.
    let cmdline_wide = build_command_line_wide(&args.program, &args.program_args);
    let env_wide = build_environment_block(&args.envs, args.env_clear);
    let working_dir_wide = args
        .working_dir
        .as_ref()
        .map(|p| to_wide_with_nul(p.as_os_str()));

    // 8. Build STARTUPINFOEXW with the attribute list + stdio handles.
    //    The base StartupInfo is the inner field; the EX wrapper
    //    carries the attribute list pointer.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdio.stdin;
    startup.StartupInfo.hStdOutput = stdio.stdout;
    startup.StartupInfo.hStdError = stdio.stderr;
    startup.lpAttributeList = attr_list.list();

    // 9. CreateProcessW + AssignProcessToJobObject + ResumeThread + wait.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let creation_flags = CREATE_SUSPENDED
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NEW_PROCESS_GROUP
        | CREATE_UNICODE_ENVIRONMENT;
    // SAFETY: All pointer arguments live for the duration of the
    // call: cmdline_wide, env_wide, working_dir_wide are owned
    // `Vec<u16>` in this stack frame; startup is a stack local
    // with a valid attribute list; pi is a freshly-zeroed out
    // param.
    let ok = unsafe {
        CreateProcessW(
            // lpApplicationName = NULL — see comment at
            // `build_command_line_wide` call above. Windows parses
            // argv[0] from the cmdline AND walks PATH for it.
            ptr::null(),
            // lpCommandLine is documented as `LPWSTR` (mutable) —
            // Win32 may write into it. We give it ownership-of-a-
            // mutable-slice via `as_ptr() as *mut _` because our
            // Vec<u16> outlives the call.
            cmdline_wide.as_ptr() as *mut _,
            ptr::null(),
            ptr::null(),
            1, // bInheritHandles = TRUE so the child sees stdio
            creation_flags,
            env_wide.as_ptr() as *const _,
            working_dir_wide
                .as_ref()
                .map_or(ptr::null(), |v| v.as_ptr()),
            &startup.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::CreateProcess {
            program: args.program,
            last_error: last,
        });
    }
    // Take ownership of the returned handles immediately so any
    // early-return path closes them.
    let child_proc = HandleGuard(pi.hProcess);
    let child_thread = HandleGuard(pi.hThread);

    // Assign to the job BEFORE resuming so any descendants the
    // child spawns are inside the job's kill-tree from the start.
    // SAFETY: child_proc holds a valid handle; job is alive on
    // this stack frame.
    let ok = unsafe { AssignProcessToJobObject(job.as_raw(), child_proc.as_raw()) };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::AssignJob { last_error: last });
    }

    // SAFETY: child_thread holds a valid suspended-thread handle.
    let prev = unsafe { ResumeThread(child_thread.as_raw()) };
    if prev == u32::MAX {
        // ResumeThread returning -1 indicates failure. The job
        // still owns the suspended child, so dropping `job` will
        // KILL_ON_JOB_CLOSE-fire and reap it.
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::AssignJob { last_error: last });
    }

    // SAFETY: child_proc handle is open for the wait.
    let wait_result = unsafe { WaitForSingleObject(child_proc.as_raw(), u32::MAX) };
    // 0 = WAIT_OBJECT_0; any other value (WAIT_FAILED, WAIT_TIMEOUT
    // with INFINITE timeout — shouldn't happen) is an error.
    if wait_result != 0 {
        return Err(AppContainerError::Wait { wait_result });
    }

    // SAFETY: child_proc handle is still open; we just observed its
    // signal state so the exit code is finalized.
    let mut exit_code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(child_proc.as_raw(), &mut exit_code) };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::ExitCode { last_error: last });
    }
    // Exit codes >= 0x80000000 are Windows STATUS_* values
    // (signaling crashes, access violations, etc.); cast through
    // the u32→i32 reinterpretation so the helper's caller can
    // observe the same numeric value the lifecycle child saw.
    Ok(exit_code as i32)
}

// ── SID create-or-reuse ──────────────────────────────────────────────

/// Round-trip a stable AppContainer name into a usable SID, creating
/// the profile on first call and reusing the existing one on
/// subsequent calls.
///
/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7` is the
/// expected steady-state return — the profile dir at
/// `%USERPROFILE%\AppData\Local\Packages\<name>\` persists across
/// reboots until explicitly deleted via `DeleteAppContainerProfile`,
/// which we deliberately don't call (the profile persists until explicitly deleted).
fn create_or_reuse_appcontainer_sid(name: &str) -> Result<SidGuard, AppContainerError> {
    let wide_name = str_to_wide_with_nul(name);
    // Display name + description show up in the per-user
    // AppContainer profile registry; keep them descriptive so an
    // admin auditing AppContainer profiles can identify lpm.
    let wide_display = str_to_wide_with_nul("LPM Sandbox Lifecycle Child");
    let wide_desc =
        str_to_wide_with_nul("Sandbox container for npm-package lifecycle scripts spawned by lpm");

    let mut sid: PSID = ptr::null_mut();
    // SAFETY: All pointers reference Vec<u16>s owned in this frame.
    // The output `sid` is `LocalAlloc`'d and dropped by SidGuard.
    let hr = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_display.as_ptr(),
            wide_desc.as_ptr(),
            ptr::null(),
            0,
            &mut sid,
        )
    };
    // S_OK on first create.
    if hr == 0 {
        return Ok(SidGuard(sid));
    }
    // 0x800700B7 = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS).
    let already_exists_hr = 0x8007_0000u32 as i32 | (ERROR_ALREADY_EXISTS as i32 & 0xFFFF);
    if hr == already_exists_hr {
        // Profile registered in a prior run. Derive the SID for the
        // same name to keep DACL grants idempotent across runs.
        let mut sid2: PSID = ptr::null_mut();
        // SAFETY: wide_name lives in this frame.
        let hr2 =
            unsafe { DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut sid2) };
        if hr2 == 0 {
            return Ok(SidGuard(sid2));
        }
        return Err(AppContainerError::DeriveSid {
            name: name.to_owned(),
            hresult: hr2,
        });
    }
    Err(AppContainerError::CreateProfile {
        name: name.to_owned(),
        hresult: hr,
    })
}

/// Resolve a well-known capability SID into a `SID_AND_ATTRIBUTES`
/// suitable for the `SECURITY_CAPABILITIES.Capabilities` array.
///
/// Uses the caller-supplied `sid_buf` so the SID's memory lives in
/// the same stack frame as the `SECURITY_CAPABILITIES` struct — no
/// allocation churn, and the buffer's lifetime is the spawn call.
fn build_capability_attr(
    well_known: WELL_KNOWN_SID_TYPE,
    sid_buf: &mut [u8],
) -> Result<SID_AND_ATTRIBUTES, AppContainerError> {
    let mut size = sid_buf.len() as u32;
    // SAFETY: sid_buf is mut-borrowed and big enough; the API
    // writes at most `*size` bytes and updates `*size` with the
    // actual length.
    let ok = unsafe {
        CreateWellKnownSid(
            well_known,
            ptr::null_mut(),
            sid_buf.as_mut_ptr() as PSID,
            &mut size,
        )
    };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::WellKnownSid { last_error: last });
    }
    Ok(SID_AND_ATTRIBUTES {
        Sid: sid_buf.as_mut_ptr() as PSID,
        // SE_GROUP_ENABLED is mandatory in capability SID
        // attributes: an attribute of 0 leaves the capability
        // disabled and AppContainer denies the matching resources
        // as if it weren't listed. The plan's positive-control
        // smoke test (Default mode + outbound TCP) fails closed
        // without this bit.
        Attributes: SE_GROUP_ENABLED,
    })
}

// ── DACL grant + walker ──────────────────────────────────────────────

/// Apply an inheritable DACL ACE granting `sid` the given access
/// mask to `root` and every existing descendant.
///
/// **Reparse-point handling (PR-1 contract).** A reparse-point root
/// (junction / symlink / mount point) is refused — `SetNamedSecurityInfoW`
/// follows reparse points and would apply the grant to the
/// reparse-point target, potentially outside the intended allow-set
/// tree. Reparse-point descendants are skipped with a debug log.
///
/// **Idempotency.** The ACE is merged into the existing DACL via
/// `GetNamedSecurityInfoW` + `SetEntriesInAclW`. Repeated calls
/// with the same SID + access mask are no-ops at the kernel layer
/// (`SetEntriesInAclW` deduplicates identical ACEs).
fn grant_dacl_ace_to_tree(
    root: &Path,
    sid: PSID,
    access_mask: u32,
    strict_root: bool,
) -> Result<(), AppContainerError> {
    // The root must exist + must not be a reparse point. Missing
    // paths are silently skipped (matches windows.rs's existing
    // posture for the SACL walker).
    let meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(_) => {
            tracing::debug!(
                target: "lpm_sandbox::helper_appcontainer",
                "skip DACL grant on nonexistent path {}",
                root.display(),
            );
            return Ok(());
        }
    };
    if is_reparse_point(&meta) {
        if strict_root {
            // Spec-derived entries are under the install pipeline's
            // control — a reparse-point root means the
            // `sandboxWriteDirs` / spec config points at a junction
            // or symlink, which the PR-1 contract refuses to follow
            // (would apply the grant to the link's TARGET,
            // potentially outside the allow-set). Surface to the
            // user so they can fix their config.
            return Err(AppContainerError::ReparsePointRoot {
                path: root.to_path_buf(),
            });
        }
        // Best-effort (PATH-derived tool dirs): Windows ships a lot
        // of PATH entries as junctions/symlinks (per-user OneDrive
        // links, virtual-store redirections, `winget` shims). Per
        // the same "warn-and-continue" contract that covers
        // SYSTEM-owned DACL failures, a reparse-point root on a
        // best-effort entry logs WARN and the spawn proceeds — the
        // pre-fix behavior of hard-aborting on the first PATH-entry
        // junction defeats the entire best-effort lane.
        tracing::warn!(
            target: "lpm_sandbox::helper_appcontainer",
            "best-effort DACL grant on {} skipped: reparse point (junction / \
             symlink / mount point). The AppContainer child will not be able to \
             read this subtree; lifecycle scripts that depend on tools at this \
             path will fail with their own access-denied / not-found errors.",
            root.display(),
        );
        return Ok(());
    }

    // Root-grant failure handling depends on `strict_root`:
    //
    // - **Strict (spec-derived allow-set entries):** any failure
    //   here is fatal. These paths are under the install
    //   pipeline's control (package_dir, project_dir, ~/.cache,
    //   tmpdir, sandboxWriteDirs, ~/.nvm/versions) and the user-
    //   owned + already-existing invariants hold by construction;
    //   a failure means something deeper is broken and the
    //   sandbox can't deliver its contract.
    //
    // - **Best-effort (PATH-derived tool dirs):** failure is
    //   logged at WARN and the spawn proceeds. The common case is
    //   Win32 error 5 (ERROR_ACCESS_DENIED) on SYSTEM-owned tool
    //   dirs like `C:\Program Files\nodejs` — unprivileged
    //   `lpm.exe` can't modify their DACL. The AppContainer child
    //   ends up unable to read that subtree; if a lifecycle
    //   script actually needs it the script's own failure (e.g.
    //   "'node' is not recognized as an internal or external
    //   command") is a clearer error surface than a hard sandbox-
    //   setup failure that prints a raw Win32 error code.
    if let Err(e) = set_dacl_ace_on(root, sid, access_mask) {
        if strict_root {
            return Err(e);
        }
        tracing::warn!(
            target: "lpm_sandbox::helper_appcontainer",
            "best-effort DACL grant on {} failed: {e}. AppContainer child will not \
             be able to read this subtree; lifecycle scripts that depend on tools \
             in this path will fail with their own access-denied / not-found errors.",
            root.display(),
        );
        // Don't walk — the root grant didn't land so descendants
        // can't be reached anyway.
        return Ok(());
    }

    // Walk pre-existing descendants. OICI inheritance on the root
    // covers FUTURE files created inside, but already-extracted
    // package files (extractor wrote them with the parent's DACL)
    // need explicit grants. Per-entry failures are logged and
    // swallowed so a single stuck file doesn't fail the install.
    if meta.is_dir() {
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(it) => it,
                Err(e) => {
                    tracing::debug!(
                        target: "lpm_sandbox::helper_appcontainer",
                        "skip DACL walk of {}: read_dir failed: {e}",
                        dir.display(),
                    );
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let m = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(
                            target: "lpm_sandbox::helper_appcontainer",
                            "skip DACL grant on {}: metadata failed: {e}",
                            path.display(),
                        );
                        continue;
                    }
                };
                if is_reparse_point(&m) {
                    tracing::debug!(
                        target: "lpm_sandbox::helper_appcontainer",
                        "skip reparse point {} during DACL walk \
                         (target not granted to prevent escape outside allow-set)",
                        path.display(),
                    );
                    continue;
                }
                if let Err(e) = set_dacl_ace_on(&path, sid, access_mask) {
                    tracing::debug!(
                        target: "lpm_sandbox::helper_appcontainer",
                        "skip DACL grant on {}: {e}",
                        path.display(),
                    );
                }
                if m.is_dir() {
                    stack.push(path);
                }
            }
        }
    }

    Ok(())
}

/// Single-path DACL ACE grant. Reads the current DACL, merges the
/// new ACE via `SetEntriesInAclW`, and writes it back —
/// preserving every pre-existing explicit ACE on the path.
fn set_dacl_ace_on(path: &Path, sid: PSID, access_mask: u32) -> Result<(), AppContainerError> {
    let wide_path = to_wide_with_nul(path.as_os_str());

    // Build the EXPLICIT_ACCESS_W carrying the new ACE.
    let mut trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_GROUP,
        // When TrusteeForm == TRUSTEE_IS_SID, the SDK contract is
        // that `ptstrName` holds the SID pointer (cast). Documented
        // pattern.
        ptstrName: sid as *mut u16,
    };
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: GRANT_ACCESS,
        // OICI: object-inherit + container-inherit so files +
        // subdirs created later pick up the grant.
        grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        Trustee: trustee,
    };
    // Silence the unused-write lint — Trustee is read by the
    // closure via `ea.Trustee` reference.
    let _ = &mut trustee;

    // Read the current DACL so we can merge instead of replace.
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: wide_path Vec<u16> outlives the call; out params are
    // freshly initialized.
    let err = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(AppContainerError::ReadDacl {
            path: path.to_path_buf(),
            win32_error: err,
        });
    }
    let _sd_guard = LocalAllocGuard(sd as *mut _);

    // Merge into a new DACL.
    let mut new_dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `ea` is a valid EXPLICIT_ACCESS_W on this stack
    // frame; `old_dacl` is owned by `_sd_guard`; `new_dacl` out
    // param is freshly null.
    let err = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
    if err != ERROR_SUCCESS {
        return Err(AppContainerError::MergeDacl {
            path: path.to_path_buf(),
            win32_error: err,
        });
    }
    let _new_dacl_guard = LocalAllocGuard(new_dacl as *mut _);

    // Apply. UNPROTECTED_DACL_SECURITY_INFORMATION keeps inherited
    // ACEs flowing from the parent dir.
    // SAFETY: wide_path lives; new_dacl is non-null + valid.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(AppContainerError::WriteDacl {
            path: path.to_path_buf(),
            win32_error: err,
        });
    }
    Ok(())
}

fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// ── Attribute list (PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES) ──

/// Initialize a single-slot attribute list and bind it to the
/// supplied `SECURITY_CAPABILITIES`. The returned [`AttrListGuard`]
/// owns the byte buffer + cleans up the kernel-side handle in
/// `Drop`.
///
/// The `sec_caps` pointer MUST outlive the attribute list — the
/// list stores a raw pointer into it, NOT a copy. Caller keeps the
/// struct alive on the stack until after `CreateProcessW` returns.
fn init_attribute_list_with_caps(
    sec_caps: &mut SECURITY_CAPABILITIES,
) -> Result<AttrListGuard, AppContainerError> {
    // Two-call idiom: first call with NULL list + 0 size returns
    // the required size via *out; second call allocates the buffer
    // and initializes.
    let mut size: usize = 0;
    // SAFETY: list pointer is NULL on the sizing call; size is a
    // mut out param.
    unsafe {
        InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
    }
    // The sizing call returns FALSE with last-error
    // ERROR_INSUFFICIENT_BUFFER (122). That's expected; we ignore
    // the BOOL return and trust the size.
    if size == 0 {
        // Defensive: if Windows somehow reported zero needed bytes
        // we'd allocate nothing and the subsequent init call would
        // fail. Surface the failure here.
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::InitAttrList { last_error: last });
    }
    let mut buf = vec![0u8; size].into_boxed_slice();
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = buf.as_mut_ptr() as *mut _;
    // SAFETY: buf is sized to `size`; list points into it.
    let ok = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::InitAttrList { last_error: last });
    }
    // SAFETY: sec_caps is borrowed for the lifetime of the
    // attribute list; the caller keeps both alive together.
    let ok = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            sec_caps as *mut _ as *const _,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        // Best-effort teardown of the attribute list before we
        // hand back the error so the kernel-side reference is
        // released. The Box drop reclaims the buffer.
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err(AppContainerError::UpdateAttrList { last_error: last });
    }
    Ok(AttrListGuard { _buf: buf, list })
}

// ── Job Object ───────────────────────────────────────────────────────

/// Create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
/// When the helper exits — for any reason — the job handle drops,
/// which fires KILL_ON_JOB_CLOSE and reaps every descendant of the
/// lifecycle child. The lifecycle child cannot outlive the helper.
fn create_kill_on_close_job() -> Result<HandleGuard, AppContainerError> {
    // SAFETY: NULL attributes + NULL name produces an unnamed
    // anonymous job; documented call shape.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::CreateJob { last_error: last });
    }
    let job_guard = HandleGuard(job);

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: info is stack-local and lives for the call.
    let ok = unsafe {
        SetInformationJobObject(
            job_guard.as_raw(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        let last = unsafe { GetLastError() };
        return Err(AppContainerError::ConfigureJob { last_error: last });
    }
    Ok(job_guard)
}

// ── Stdio handles ────────────────────────────────────────────────────

/// The three child stdio handles, ready to drop into
/// `STARTUPINFOW.hStd*`. `_owned` keeps any helper-opened NUL
/// handles alive until after `CreateProcessW` returns.
struct ChildStdio {
    stdin: HANDLE,
    stdout: HANDLE,
    stderr: HANDLE,
    /// NUL handles we opened ourselves (Null mode). Closed via
    /// `Drop` on this struct after the spawn completes.
    _owned: Vec<HandleGuard>,
}

fn open_stdio_handles(args: &HelperArgs) -> Result<ChildStdio, AppContainerError> {
    let mut owned: Vec<HandleGuard> = Vec::new();
    let stdin = stdio_handle(args.stdio_stdin, "stdin", &mut owned)?;
    let stdout = stdio_handle(args.stdio_stdout, "stdout", &mut owned)?;
    let stderr = stdio_handle(args.stdio_stderr, "stderr", &mut owned)?;
    Ok(ChildStdio {
        stdin,
        stdout,
        stderr,
        _owned: owned,
    })
}

fn stdio_handle(
    mode: StdioMode,
    role: &'static str,
    owned: &mut Vec<HandleGuard>,
) -> Result<HANDLE, AppContainerError> {
    match mode {
        // Inherit and Piped are observationally identical from the
        // helper's perspective: in both cases the parent connected
        // our stdio (terminal or pipe) and we forward it to the
        // child by passing the same handles. The distinction
        // matters only on the parent side, which already wired the
        // pipe vs the terminal into the helper's stdio when it
        // spawned us.
        StdioMode::Inherit | StdioMode::Piped => {
            let id = match role {
                "stdin" => STD_INPUT_HANDLE,
                "stdout" => STD_OUTPUT_HANDLE,
                "stderr" => STD_ERROR_HANDLE,
                _ => unreachable!("role must be stdin/stdout/stderr"),
            };
            // SAFETY: GetStdHandle is documented to accept the
            // three STD_*_HANDLE constants and return a non-owning
            // handle that the helper already owns through inheritance.
            let h = unsafe { GetStdHandle(id) };
            // Ensure the handle is inheritable so CreateProcessW
            // with bInheritHandles=TRUE actually passes it. The CRT
            // sets up std handles this way by default but a
            // misbehaving parent could have cleared the flag.
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                unsafe {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
                }
            }
            Ok(h)
        }
        StdioMode::Null => {
            // Open NUL with inheritable bInheritHandle so CreateProcessW
            // passes it to the child.
            let wide = str_to_wide_with_nul("NUL");
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: ptr::null_mut(),
                bInheritHandle: 1,
            };
            let (access, share) = if role == "stdin" {
                (FILE_GENERIC_READ, FILE_SHARE_READ)
            } else {
                (
                    FILE_GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                )
            };
            // SAFETY: wide lives; sa lives.
            let h = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    access,
                    share,
                    &sa,
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if h == INVALID_HANDLE_VALUE {
                let last = unsafe { GetLastError() };
                return Err(AppContainerError::OpenNul {
                    role,
                    last_error: last,
                });
            }
            owned.push(HandleGuard(h));
            Ok(h)
        }
    }
}

// ── Command line + environment block builders ─────────────────────

/// Build a `LPWSTR` command line from program + args following the
/// `CommandLineToArgvW` quoting rules. Result is a null-terminated
/// UTF-16 buffer suitable for `CreateProcessW`'s `lpCommandLine`.
///
/// `program` is also embedded as argv[0] so the lifecycle child
/// sees a sensible `_argv[0]`. We keep `lpApplicationName` set
/// separately to the program path so Windows uses the explicit
/// path rather than re-parsing argv[0].
fn build_command_line_wide(program: &OsStr, args: &[OsString]) -> Vec<u16> {
    let mut s = String::new();
    s.push_str(&quote_arg_for_cmdline(&program.to_string_lossy()));
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg_for_cmdline(&a.to_string_lossy()));
    }
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

/// Quote a single argv element per `CommandLineToArgvW`'s parsing
/// rules. Reference: Microsoft documentation for argv parsing in
/// commercial CRTs.
fn quote_arg_for_cmdline(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '"' || c == '\n' || c == '\u{0B}')
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Double every preceding backslash + escape the
                // quote itself.
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push('\\');
                out.push('"');
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                out.push(other);
            }
        }
    }
    // Double trailing backslashes so they don't escape the closing
    // quote.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Build the Unicode environment block: `KEY=VALUE\0KEY=VALUE\0...\0\0`.
///
/// When `env_clear` is false the helper's own env is the base layer
/// (parent inherited from grandparent, so this is the lpm-rs
/// process env). Explicit `--env` entries are merged on top —
/// duplicates from `--env` override the inherited value, mirroring
/// `Command::env` semantics.
fn build_environment_block(envs: &[OsString], env_clear: bool) -> Vec<u16> {
    use std::collections::BTreeMap;
    // BTreeMap so the resulting env block is sorted by key — same
    // ordering CRTs expect and easier to diff in tests. Windows
    // doesn't require sorted env, but stable order avoids spurious
    // diffs.
    //
    // **Case-insensitive dedup.** Windows env-var lookups are
    // case-insensitive at the CRT layer (`getenv` ignores case),
    // but a Rust `BTreeMap<OsString, _>` treats `PATH` and `Path`
    // as separate keys. If we don't dedup case-insensitively, both
    // entries flow into the child's env block and which one the
    // CRT returns is then a function of CRT internals (in
    // practice the first one wins for `getenv`, but other code
    // paths — including some node-gyp/python tooling — read the
    // raw env block and pick the last match). Either way, the
    // override contract documented at
    // [`crate::commands::rebuild`]'s `find_env_case_insensitive`
    // helper is broken. Match that precedent here.
    //
    // Map: lower-cased key → (original-case key, value). Last
    // insertion wins for both the override semantics AND the
    // casing in the emitted block.
    let mut combined: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    if !env_clear {
        for (k, v) in std::env::vars_os() {
            let lower = k.to_string_lossy().to_ascii_lowercase();
            combined.insert(lower, (k, v));
        }
    }
    for entry in envs {
        if let Some((k, v)) = split_env_entry(entry) {
            let lower = k.to_string_lossy().to_ascii_lowercase();
            combined.insert(lower, (k, v));
        }
    }
    let mut wide: Vec<u16> = Vec::new();
    for (k, v) in combined.values() {
        wide.extend(k.encode_wide());
        wide.push(b'=' as u16);
        wide.extend(v.encode_wide());
        wide.push(0);
    }
    // Final double-NUL terminator.
    wide.push(0);
    wide
}

// ── Wide-string helpers ──────────────────────────────────────────────

fn str_to_wide_with_nul(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn to_wide_with_nul(s: &OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::GetLengthSid;

    #[test]
    fn quote_arg_for_cmdline_passes_simple_args_unmodified() {
        assert_eq!(quote_arg_for_cmdline("simple"), "simple");
        assert_eq!(
            quote_arg_for_cmdline("C:/Windows/System32/cmd.exe"),
            "C:/Windows/System32/cmd.exe",
        );
    }

    #[test]
    fn quote_arg_for_cmdline_quotes_args_with_spaces() {
        assert_eq!(quote_arg_for_cmdline("hello world"), "\"hello world\"");
        assert_eq!(
            quote_arg_for_cmdline("C:\\Program Files\\node.exe"),
            "\"C:\\Program Files\\node.exe\"",
        );
    }

    #[test]
    fn quote_arg_for_cmdline_escapes_embedded_quotes() {
        assert_eq!(quote_arg_for_cmdline(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn quote_arg_for_cmdline_doubles_trailing_backslashes_to_avoid_escaping_close_quote() {
        // `C:\foo\` inside an arg containing a space must become
        // `"C:\foo\\"` so the closing quote isn't escaped.
        assert_eq!(
            quote_arg_for_cmdline("C:\\foo with space\\"),
            "\"C:\\foo with space\\\\\"",
        );
    }

    #[test]
    fn quote_arg_for_cmdline_doubles_backslashes_before_internal_quote() {
        // `a\"b` must become `"a\\\"b"` — the single backslash
        // before the quote needs doubling + the quote needs
        // escaping.
        assert_eq!(quote_arg_for_cmdline(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn build_command_line_wide_emits_null_terminated_utf16() {
        let cmdline = build_command_line_wide(
            OsStr::new("C:/Windows/System32/cmd.exe"),
            &[OsString::from("/c"), OsString::from("exit 0")],
        );
        assert_eq!(*cmdline.last().expect("must have terminator"), 0);
        let decoded = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        // /c is bare; "exit 0" contains a space → quoted.
        assert_eq!(decoded, "C:/Windows/System32/cmd.exe /c \"exit 0\"");
    }

    #[test]
    fn build_environment_block_emits_sorted_key_equals_value_with_terminators() {
        let envs = vec![OsString::from("FOO=bar"), OsString::from("ALPHA=1")];
        let block = build_environment_block(&envs, true);
        // Trailing double-NUL terminator: the last entry's NUL +
        // the block terminator.
        assert_eq!(block[block.len() - 1], 0);
        let s = String::from_utf16_lossy(&block);
        // BTreeMap sort → ALPHA first.
        assert!(
            s.starts_with("ALPHA=1\u{0}FOO=bar\u{0}\u{0}"),
            "block: {s:?}",
        );
    }

    #[test]
    fn build_environment_block_dedups_keys_case_insensitively_last_casing_wins() {
        // Caller-supplied env contains both `PATH` and `Path` —
        // pre-fix this produced two entries in the env block and
        // the lifecycle child's CRT lookup was order-of-insertion
        // dependent. Post-fix: the LAST insertion's casing AND
        // value wins.
        let envs = vec![
            OsString::from("PATH=/first"),
            OsString::from("Path=/second"),
        ];
        let block = build_environment_block(&envs, true);
        let s = String::from_utf16_lossy(&block);
        // Only ONE entry for the logical key — the last-casing
        // form should be `Path` with value `/second`.
        let path_entries: Vec<&str> = s
            .split('\u{0}')
            .filter(|seg| {
                seg.eq_ignore_ascii_case("PATH=/first") || seg.eq_ignore_ascii_case("Path=/second")
            })
            .collect();
        // Strict equality on the surviving entry's casing + value.
        assert_eq!(
            path_entries.len(),
            1,
            "case-insensitive dedup must leave exactly one PATH entry; got {path_entries:?} in block: {s:?}",
        );
        assert_eq!(
            path_entries[0], "Path=/second",
            "last-insertion casing AND value must win; got {:?}",
            path_entries[0],
        );
    }

    #[test]
    fn build_environment_block_with_env_clear_skips_inherited_vars() {
        // Sentinel name that's vanishingly unlikely to exist in the
        // ambient env. Set + verify it appears WITHOUT env_clear and
        // is absent WITH env_clear.
        let sentinel = "LPM_HELPER_TEST_SENTINEL_DO_NOT_USE";
        // SAFETY: tests are single-threaded by default; the
        // workspace doesn't `set_var` from concurrent threads.
        unsafe {
            std::env::set_var(sentinel, "yes");
        }
        let block_with_inherit = build_environment_block(&[], false);
        let block_cleared = build_environment_block(&[], true);
        unsafe {
            std::env::remove_var(sentinel);
        }
        let s_inherit = String::from_utf16_lossy(&block_with_inherit);
        let s_cleared = String::from_utf16_lossy(&block_cleared);
        assert!(
            s_inherit.contains(sentinel),
            "without env_clear, helper's env must be inherited: {s_inherit:?}",
        );
        assert!(
            !s_cleared.contains(sentinel),
            "with env_clear, helper's env must NOT be inherited: {s_cleared:?}",
        );
    }

    #[test]
    fn create_or_reuse_appcontainer_sid_returns_stable_sid_across_calls() {
        // The first call creates the profile; the second hits the
        // ERROR_ALREADY_EXISTS path and derives the same SID.
        // Both calls must succeed; their SIDs must compare equal.
        let name = "LpmHelperUnitTest";
        let a = create_or_reuse_appcontainer_sid(name).expect("first call");
        let b = create_or_reuse_appcontainer_sid(name).expect("second call");
        // Compare SIDs byte-by-byte via GetLengthSid + memcmp. PSIDs
        // are well-known group SIDs of equal length when derived
        // from the same name.
        let len_a = unsafe { GetLengthSid(a.0) };
        let len_b = unsafe { GetLengthSid(b.0) };
        assert_eq!(len_a, len_b, "SID lengths must match across calls");
        assert!(len_a > 0);
        let bytes_a = unsafe { std::slice::from_raw_parts(a.0 as *const u8, len_a as usize) };
        let bytes_b = unsafe { std::slice::from_raw_parts(b.0 as *const u8, len_b as usize) };
        assert_eq!(
            bytes_a, bytes_b,
            "AppContainer SID for the same name must be stable across calls",
        );
    }

    #[test]
    fn grant_dacl_ace_to_tree_silently_skips_nonexistent_root() {
        let nonexistent =
            std::env::temp_dir().join("lpm-helper-test-nonexistent-path-12345-do-not-create");
        assert!(!nonexistent.exists());
        let sid =
            create_or_reuse_appcontainer_sid("LpmHelperSkipNonexistentTest").expect("derive SID");
        grant_dacl_ace_to_tree(
            &nonexistent,
            sid.0,
            FILE_GENERIC_READ,
            /* strict_root */ true,
        )
        .expect("nonexistent path must be a no-op skip, not error");
    }

    #[test]
    fn grant_dacl_ace_to_tree_succeeds_on_regular_dir() {
        // Create a temp directory + a child file, then verify the
        // DACL grant operation succeeds. The post-condition check
        // (DACL actually contains an ACE for our SID) is left to
        // the helper integration tests since GetExplicitEntriesFromAclW
        // adds a lot of FFI surface for one verification.
        let tmp = tempfile::tempdir().expect("tempdir");
        let child = tmp.path().join("file.txt");
        std::fs::write(&child, b"x").expect("write child file");
        let sid = create_or_reuse_appcontainer_sid("LpmHelperRegularDirTest").expect("derive SID");
        grant_dacl_ace_to_tree(
            tmp.path(),
            sid.0,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            /* strict_root */ true,
        )
        .expect("grant on regular dir must succeed");
    }

    /// Pins the strict-vs-best-effort split on root-grant failure:
    ///
    ///   - `strict_root = true` propagates the failure as `Err`,
    ///   - `strict_root = false` swallows it (logs WARN, returns
    ///     `Ok`).
    ///
    /// A regression that silently downgrades strict allow-set
    /// entries to best-effort would let a misconfigured install
    /// pipeline weaken containment without surfacing the issue.
    #[test]
    fn grant_dacl_ace_to_tree_distinguishes_strict_from_best_effort_on_root_failure() {
        // Use `C:\Windows\System32` as a guaranteed-unwritable
        // root (owned by SYSTEM, even Administrators get an
        // implicit "Modify" deny on the DACL itself unless they
        // take ownership). The grant will fail with
        // ERROR_ACCESS_DENIED for an unprivileged process.
        let unwritable = std::path::Path::new(r"C:\Windows\System32");
        if !unwritable.exists() {
            // Defensive — should always exist on Windows.
            eprintln!("skipping: System32 not at expected path");
            return;
        }
        // Unique profile name so this test doesn't race against
        // the sibling `create_or_reuse_appcontainer_sid_*` tests
        // for `CreateAppContainerProfile`'s session-state. Cargo
        // runs unit tests in parallel by default and a contended
        // first call has been observed to return non-S_OK +
        // non-ALREADY_EXISTS here.
        let sid = create_or_reuse_appcontainer_sid("LpmHelperBestEffortRootGrantTest")
            .expect("derive SID");

        // strict_root = true: failure propagates.
        let strict_result = grant_dacl_ace_to_tree(
            unwritable,
            sid.0,
            FILE_GENERIC_READ,
            /* strict_root */ true,
        );
        assert!(
            matches!(
                strict_result,
                Err(AppContainerError::WriteDacl { .. }) | Err(AppContainerError::ReadDacl { .. })
            ),
            "strict_root=true must propagate root-grant failure on an unwritable dir; got {strict_result:?}",
        );

        // strict_root = false: failure is swallowed; returns Ok.
        let best_effort_result = grant_dacl_ace_to_tree(
            unwritable,
            sid.0,
            FILE_GENERIC_READ,
            /* strict_root */ false,
        );
        assert!(
            best_effort_result.is_ok(),
            "strict_root=false must swallow root-grant failure (WARN + continue); got {best_effort_result:?}",
        );
    }

    /// Reparse-point roots must honor `strict_root` too: a junction
    /// in a spec-derived (strict) allow-set entry is a config bug
    /// and must surface as `Err(ReparsePointRoot)`. A junction in
    /// a PATH-derived best-effort entry — `winget` shims,
    /// per-user OneDrive redirections, virtual-store links — is
    /// common on real Windows and must warn-and-continue, matching
    /// the rest of the best-effort lane.
    #[test]
    fn grant_dacl_ace_to_tree_reparse_point_honors_strict_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real");
        let junction = tmp.path().join("junction");
        std::fs::create_dir(&real_dir).expect("create real dir");
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &junction.to_string_lossy(),
                &real_dir.to_string_lossy(),
            ])
            .status();
        let Ok(s) = status else {
            eprintln!("skipping: mklink /J unavailable in this environment");
            return;
        };
        if !s.success() {
            eprintln!("skipping: mklink /J failed (junction creation unsupported here)");
            return;
        }

        let sid = create_or_reuse_appcontainer_sid("LpmHelperReparseTest").expect("derive SID");

        // Strict: refuse with named error.
        let strict_result = grant_dacl_ace_to_tree(
            &junction,
            sid.0,
            FILE_GENERIC_READ,
            /* strict_root */ true,
        );
        assert!(
            matches!(
                strict_result,
                Err(AppContainerError::ReparsePointRoot { .. })
            ),
            "strict_root=true must refuse a reparse-point root; got {strict_result:?}",
        );

        // Best-effort: warn + continue. Pre-patch the reparse-point branch
        // returned Err before the strict_root check fired, so a PATH-derived
        // best-effort dir that happened to be a junction (common on Windows)
        // hard-aborted the entire spawn.
        let best_effort_result = grant_dacl_ace_to_tree(
            &junction,
            sid.0,
            FILE_GENERIC_READ,
            /* strict_root */ false,
        );
        assert!(
            best_effort_result.is_ok(),
            "strict_root=false must downgrade reparse-point refusal to WARN+continue; got {best_effort_result:?}",
        );
    }
}
