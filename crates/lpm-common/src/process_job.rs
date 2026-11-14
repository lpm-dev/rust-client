//! Windows Job objects that end a process tree together.
//!
//! Windows keeps no process group a parent can signal, and a process whose
//! parent has exited keeps that parent's ID, so walking parent IDs misses
//! it. A Job holds every process started inside it instead: start the root
//! suspended with [`SUSPENDED`], [`ProcessJob::assign`] it, then
//! [`resume`] it, and nothing it starts runs outside the Job.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Child;

/// The creation flag that starts a process suspended, so it can join a Job
/// before it runs.
pub const SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

/// A Job that ends every process in it when its last handle closes, as when
/// lpm exits or is killed.
#[derive(Debug)]
pub struct ProcessJob(OwnedHandle);

impl ProcessJob {
    /// A new Job. With `allow_breakaway`, a process in it that asks to start
    /// a child outside it (`CREATE_BREAKAWAY_FROM_JOB`) may, as a Unix
    /// process may leave its group with `setsid`; without it, such a request
    /// fails.
    pub fn new(allow_breakaway: bool) -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: null security and name pointers request a new anonymous Job.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW returned a new handle that nothing else owns.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        // SAFETY: a zeroed limit structure sets no limits.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | if allow_breakaway {
                JOB_OBJECT_LIMIT_BREAKAWAY_OK
            } else {
                0
            };
        // SAFETY: the Job handle and the structure outlive the call.
        let configured = unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Puts `child`, started with [`SUSPENDED`], in the Job.
    pub fn assign(&self, child: &Child) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: both handles stay open for the call.
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Ends every process in the Job.
    pub fn terminate(&self) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: the Job handle stays open for the call.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Lets `child`, started with [`SUSPENDED`], run.
pub fn resume(child: &Child) -> io::Result<()> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
    }
    // SAFETY: `child` owns this process handle for the call.
    let status = unsafe { NtResumeProcess(child.as_raw_handle()) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "resuming process {} failed: {status:#x}",
            child.id()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, Stdio};

    fn spawn_in(job: &ProcessJob, command: &mut Command) -> Child {
        let child = command.creation_flags(SUSPENDED).spawn().unwrap();
        job.assign(&child).unwrap();
        resume(&child).unwrap();
        child
    }

    /// A grandchild whose parent has already exited, which a walk of parent
    /// IDs can't find, still ends with the Job.
    #[test]
    fn ending_the_job_ends_a_process_whose_parent_has_exited() {
        let job = ProcessJob::new(true).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("grandchild.pid");
        let script = format!(
            "const child = require('child_process').spawn(process.execPath, \
             ['-e', 'setInterval(() => {{}}, 1000)'], {{ detached: true, stdio: 'ignore' }}); \
             require('fs').writeFileSync({:?}, String(child.pid)); child.unref();",
            pid_file.display().to_string()
        );
        let mut parent = spawn_in(
            &job,
            Command::new("node")
                .args(["-e", &script])
                .stdin(Stdio::null()),
        );
        assert!(parent.wait().unwrap().success());
        let grandchild: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(process_is_running(grandchild), "the grandchild never ran");

        job.terminate().unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process_is_running(grandchild) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !process_is_running(grandchild),
            "the grandchild outlived its Job"
        );
    }

    #[test]
    fn closing_the_job_ends_what_runs_in_it() {
        let job = ProcessJob::new(true).unwrap();
        let mut child = spawn_in(
            &job,
            Command::new("node").args(["-e", "setInterval(() => {}, 1000)"]),
        );

        drop(job);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            child.try_wait().unwrap().is_some(),
            "closing the Job left its process running"
        );
    }

    fn process_is_running(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess returns a handle closed below, or null.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut code = 0;
        // SAFETY: the handle is open and `code` outlives the call.
        let queried = unsafe { GetExitCodeProcess(handle, &mut code) } != 0;
        // SAFETY: the handle came from OpenProcess above.
        unsafe { CloseHandle(handle) };
        queried && code == STILL_ACTIVE as u32
    }
}
