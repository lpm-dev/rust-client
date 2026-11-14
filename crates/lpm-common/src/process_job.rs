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
use std::time::{Duration, Instant};

/// The creation flag that starts a process suspended, so it can join a Job
/// before it runs.
pub const SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

/// A Job that ends every process in it when its last handle closes, as when
/// lpm exits or is killed.
///
/// No process can leave it, not even silently. Node's libuv puts each child
/// it starts in a Job of its own whose processes' children break away from
/// it silently, and such a breakaway climbs every enclosing Job that permits
/// breakaway, so a Job that permitted it would lose the dev server that
/// `npm run dev` starts through cmd.exe. As a Unix process group does, the
/// Job also ends a daemon or a browser that a process in it starts.
#[derive(Debug)]
pub struct ProcessJob(OwnedHandle);

impl ProcessJob {
    pub fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
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
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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

    /// Ends every process in the Job, then waits up to `timeout` for them to
    /// be gone, as their ports and files are released only then; whether
    /// they all were.
    pub fn end(&self, timeout: Duration) -> io::Result<bool> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: the Job handle stays open for the call.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.wait_until_empty(timeout)
    }

    /// Waits up to `timeout` for every process in the Job to exit, ending
    /// none; whether they all did.
    pub fn wait_until_empty(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.active_processes()? == 0 {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// How many processes in the Job are still running.
    pub fn active_processes(&self) -> io::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };
        // SAFETY: a zeroed accounting structure is a valid output buffer.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the Job handle and the structure outlive the call.
        let queried = unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut info).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
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

    /// A process found by the ID it wrote to `pid_file`, held open so its
    /// ID can't name another process later.
    struct WatchedProcess(OwnedHandle);

    impl WatchedProcess {
        fn from_pid_file(pid_file: &std::path::Path) -> Self {
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            let pid = loop {
                if let Some(pid) = std::fs::read_to_string(pid_file)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok())
                {
                    break pid;
                }
                assert!(Instant::now() < deadline, "the process never wrote its ID");
                std::thread::sleep(Duration::from_millis(20));
            };
            // SAFETY: OpenProcess returns a new handle owned below, or null.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            assert!(!handle.is_null(), "process {pid} is already gone");
            // SAFETY: the handle is new and owned by nothing else.
            Self(unsafe { OwnedHandle::from_raw_handle(handle) })
        }

        fn exits_within(&self, timeout: Duration) -> bool {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: the handle stays open for the call.
            let waited = unsafe { WaitForSingleObject(self.0.as_raw_handle(), millis) };
            waited == WAIT_OBJECT_0
        }
    }

    /// A grandchild whose parent has already exited, which a walk of parent
    /// IDs can't find, still ends with the Job.
    #[test]
    fn ending_the_job_ends_a_process_whose_parent_has_exited() {
        let job = ProcessJob::new().unwrap();
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
        let grandchild = WatchedProcess::from_pid_file(&pid_file);
        assert!(
            !grandchild.exits_within(Duration::ZERO),
            "the grandchild never ran"
        );

        assert!(job.end(Duration::from_secs(5)).unwrap());

        assert!(
            grandchild.exits_within(Duration::from_secs(5)),
            "the grandchild outlived its Job"
        );
    }

    /// A Job's processes may outlive its root: waiting for the Job waits for
    /// them, and ends none.
    #[test]
    fn waiting_for_a_job_waits_for_what_outlives_its_root_without_ending_it() {
        let job = ProcessJob::new().unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("worker.js"),
            "const fs = require('fs');\n\
             const poll = setInterval(() => {\n\
               if (fs.existsSync('release')) {\n\
                 clearInterval(poll);\n\
                 setTimeout(() => fs.writeFileSync('done', ''), 300);\n\
               }\n\
             }, 10);\n",
        )
        .unwrap();
        let mut root = spawn_in(
            &job,
            Command::new("cmd")
                .args(["/d", "/c", "start /b node worker.js"])
                .current_dir(directory.path())
                .stdin(Stdio::null()),
        );
        assert!(root.wait().unwrap().success());
        assert!(
            !job.wait_until_empty(Duration::ZERO).unwrap(),
            "the worker never ran"
        );

        std::fs::write(directory.path().join("release"), b"").unwrap();
        assert!(job.wait_until_empty(Duration::from_secs(10)).unwrap());

        assert!(
            directory.path().join("done").exists(),
            "the worker was ended rather than waited for"
        );
    }

    /// node puts cmd.exe in a Job of its own, whose processes' children break
    /// away from it silently: the server cmd.exe starts, as in `npm run dev`,
    /// must stay in the service's Job.
    #[test]
    fn ending_the_job_ends_what_a_child_of_node_starts_through_cmd() {
        let job = ProcessJob::new().unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("server.js"),
            "require('fs').writeFileSync('server.pid', String(process.pid));\n\
             setInterval(() => {}, 1000);\n",
        )
        .unwrap();
        let mut node = spawn_in(
            &job,
            Command::new("node")
                .args([
                    "-e",
                    "require('child_process').spawn('cmd.exe', ['/d', '/c', 'node server.js'], \
                     { stdio: 'ignore' }); setInterval(() => {}, 1000);",
                ])
                .current_dir(directory.path())
                .stdin(Stdio::null()),
        );
        let server = WatchedProcess::from_pid_file(&directory.path().join("server.pid"));

        assert!(job.end(Duration::from_secs(5)).unwrap());

        assert!(
            server.exits_within(Duration::from_secs(5)),
            "the server cmd.exe started left the Job"
        );
        let _ = node.wait();
    }

    #[test]
    fn closing_the_job_ends_what_runs_in_it() {
        let job = ProcessJob::new().unwrap();
        let mut child = spawn_in(
            &job,
            Command::new("node").args(["-e", "setInterval(() => {}, 1000)"]),
        );
        assert_eq!(job.active_processes().unwrap(), 1);

        drop(job);

        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            child.try_wait().unwrap().is_some(),
            "closing the Job left its process running"
        );
    }
}
