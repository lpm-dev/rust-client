//! Windows process-tree tracking: Job Objects that keep a child and every
//! process it starts in one group the parent can terminate.
//!
//! [`spawn_tracked_command`] starts the child suspended, attaches it to a
//! Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then
//! resumes it, so no descendant can escape the group. The Job handle lives
//! in [`JOB_TRACKER`] under the child's PID until
//! [`release_sandbox_tracker_entry`] or [`terminate_sandbox_tree`] closes
//! it. Lifecycle scripts don't go through here: the AppContainer helper
//! ([`crate::helper_appcontainer`]) holds their Job Object itself.

#![cfg(target_os = "windows")]

use crate::SandboxError;
use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::ptr;
use std::sync::{LazyLock, Mutex};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{CREATE_SUSPENDED, TerminateProcess};

pub(crate) fn spawn_tracked_command(command: &mut Command) -> Result<Child, SandboxError> {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    command.creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);

    let child = command.spawn().map_err(|error| SandboxError::SpawnFailed {
        reason: format!("CreateProcessW failed: {error}"),
    })?;
    let process_handle = child.as_raw_handle() as HANDLE;
    let job = match create_kill_on_close_job_and_attach(process_handle) {
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

/// RAII wrapper for a HANDLE we own (a Job Object). Closes via `CloseHandle` on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle ownership is exclusive; CloseHandle is
            // idempotent against null and safe to call on any value
            // returned by a CreateJobObjectW success.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// ── Job Object ──────────────────────────────────────────────────────

fn configure_job_limits(info: &mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION) {
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
}

/// Create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and
/// attach the given process handle. The returned `OwnedHandle` must
/// outlive the child — closing the handle terminates every member
/// process, which is exactly what we want on the parent's drop /
/// timeout-kill paths.
fn create_kill_on_close_job_and_attach(
    process_handle: HANDLE,
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
    configure_job_limits(&mut info);
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
                "AssignProcessToJobObject failed with WIN32_ERROR={err}. The suspended \
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
                "NtResumeProcess failed with NTSTATUS=0x{status:08x}. The child stays \
                 suspended; we terminate it rather than leak a stuck process."
            ),
        });
    }
    Ok(())
}

// ── Job-handle lifetime tracker ─────────────────────────────────────

/// Keeps a tracked child's Job Object open under its PID. Closing the last
/// handle to the Job tears down the whole tree (`KILL_ON_JOB_CLOSE`), so the
/// handle can't be dropped at spawn time, and [`spawn_tracked_command`]
/// returns a plain `std::process::Child`, which has no room for it. Callers
/// release the entry on normal exit ([`release_sandbox_tracker_entry`]) and
/// terminate it on timeout ([`terminate_sandbox_tree`]); entries a caller
/// never releases are closed when the process exits.
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

/// Tracked children's Job Object handles by PID.
static JOB_TRACKER: LazyLock<Mutex<HashMap<u32, OwnedHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// `OwnedHandle` needs `Send` to live inside a `Mutex<HashMap<...>>`. The
// underlying HANDLE is a kernel handle — kernel objects are
// thread-safe per Win32's documented semantics. The `*mut c_void`
// pointer type is what prevents the auto-impl; we assert it here.
//
// SAFETY: HANDLE is a kernel-managed value, not a thread-local
// pointer. Sending one across threads is the documented call
// pattern (e.g. spawning a thread to wait on a Job).
unsafe impl Send for OwnedHandle {}

/// Terminate the Job Object tree associated with `pid` and release
/// the cached handle. Used by timeout-kill paths so that
/// `TerminateProcess(child, _)` on the root child is followed by a
/// kill of every descendant — without this call, the
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` policy doesn't fire because
/// the tracker still owns a handle, leaving grandchild processes
/// alive after a timeout.
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

/// Release the tracker entry for a tracked child that exited on its
/// own (no timeout, no panic). Closes the Job handle, which also ends
/// any descendant the child left running. Skipping this leaks one
/// HANDLE per tracked command for the lifetime of the parent.
///
/// Idempotent: missing entries are silent no-ops.
pub(crate) fn release_sandbox_tracker_entry(pid: u32) {
    let mut table = match JOB_TRACKER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    table.remove(&pid);
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Stdio;

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
    fn tracked_commands_use_kill_on_close_without_resource_caps() {
        // SAFETY: the Windows information struct accepts the all-zero initial state.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

        configure_job_limits(&mut info);

        assert_eq!(
            info.BasicLimitInformation.LimitFlags,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        );
        assert_eq!(info.BasicLimitInformation.ActiveProcessLimit, 0);
        assert_eq!(info.ProcessMemoryLimit, 0);
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
