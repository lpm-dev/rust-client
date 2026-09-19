//! Bounded output from short, non-interactive subprocess probes.

use std::io::{self, Read};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Capture stdout with a deadline and byte limit. Discard stderr and close stdin.
///
/// The probe runs in an owned process group or Windows Job so cleanup also
/// reaches descendants that retain stdout after their parent exits.
pub fn output_capped(
    command: &mut Command,
    timeout: Duration,
    stdout_limit: usize,
) -> io::Result<Output> {
    let started = Instant::now();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut probe = Probe::spawn(command)?;
    let mut reader = probe
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe stdout is unavailable"))?;
    prepare_reader(&reader)?;
    let mut stdout = Vec::with_capacity(stdout_limit.min(4096));
    let mut buffer = [0_u8; 4096];
    let mut eof = false;
    loop {
        if started.elapsed() >= timeout {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "probe timed out"));
        }
        if !eof {
            match read_available(&mut reader, &mut buffer) {
                Ok(Some(0)) => eof = true,
                Ok(Some(count)) => {
                    if count > stdout_limit.saturating_sub(stdout.len()) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "probe stdout exceeds its byte limit",
                        ));
                    }
                    stdout.extend_from_slice(&buffer[..count]);
                    continue;
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if eof && probe.exited()? {
            probe.terminate_tree();
            let status = probe.child.wait()?;
            probe.reaped = true;
            return Ok(Output {
                status,
                stdout,
                stderr: Vec::new(),
            });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Own captured subprocess groups across a sequence of commands, such as script hooks.
/// Groups remain alive until the session ends. Root processes stay unreaped so a
/// recycled process identifier cannot redirect final cleanup.
#[derive(Default)]
pub struct CaptureSession {
    processes: Vec<Probe>,
}

impl CaptureSession {
    /// Capture bounded stdout and stderr. The callback can request a stop signal.
    /// Allow 500 ms for cancellation cleanup, and 250 ms to drain inherited pipes.
    pub fn capture_output(
        &mut self,
        command: &mut Command,
        stream_limit: usize,
        mut cancellation_signal: impl FnMut(u32) -> Option<i32>,
    ) -> io::Result<Output> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process = Probe::spawn(command)?;
        let mut stdout_pipe = process
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout unavailable"))?;
        let mut stderr_pipe = process
            .child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("stderr unavailable"))?;
        prepare_reader(&stdout_pipe)?;
        prepare_reader(&stderr_pipe)?;
        let mut stdout = Vec::with_capacity(stream_limit.min(4096));
        let mut stderr = Vec::with_capacity(stream_limit.min(4096));
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut exited = None;
        let mut cancelled_at = None;
        let mut buffer = [0_u8; 16384];
        loop {
            if cancelled_at.is_none()
                && let Some(signal) = cancellation_signal(process.child.id())
            {
                process.signal_tree(signal);
                for previous in &mut self.processes {
                    previous.signal_tree(signal);
                }
                cancelled_at = Some(Instant::now());
            }
            if cancelled_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(500)) {
                process.terminate_tree();
                for previous in &mut self.processes {
                    previous.terminate_tree();
                }
            }
            if exited.is_none()
                && let Some(status) = process.status()?
            {
                exited = Some((status, Instant::now()));
            }
            let mut progressed = false;
            if !stdout_eof {
                match read_available(&mut stdout_pipe, &mut buffer) {
                    Ok(Some(0)) => stdout_eof = true,
                    Ok(Some(count)) => {
                        progressed = true;
                        stdout.extend_from_slice(
                            &buffer[..count.min(stream_limit.saturating_sub(stdout.len()))],
                        );
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            if !stderr_eof {
                match read_available(&mut stderr_pipe, &mut buffer) {
                    Ok(Some(0)) => stderr_eof = true,
                    Ok(Some(count)) => {
                        progressed = true;
                        stderr.extend_from_slice(
                            &buffer[..count.min(stream_limit.saturating_sub(stderr.len()))],
                        );
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            for previous in &mut self.processes {
                if let Some(pipe) = previous.child.stdout.as_mut() {
                    match read_available(pipe, &mut buffer) {
                        Ok(Some(0)) => previous.child.stdout = None,
                        Ok(Some(count)) => {
                            progressed = true;
                            stdout.extend_from_slice(
                                &buffer[..count.min(stream_limit.saturating_sub(stdout.len()))],
                            );
                        }
                        Ok(None) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error),
                    }
                }
                if let Some(pipe) = previous.child.stderr.as_mut() {
                    match read_available(pipe, &mut buffer) {
                        Ok(Some(0)) => previous.child.stderr = None,
                        Ok(Some(count)) => {
                            progressed = true;
                            stderr.extend_from_slice(
                                &buffer[..count.min(stream_limit.saturating_sub(stderr.len()))],
                            );
                        }
                        Ok(None) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            if let Some((status, at)) = exited
                && ((stdout_eof && stderr_eof && !progressed)
                    || at.elapsed() >= Duration::from_millis(250))
                && cancelled_at.is_none_or(|at| at.elapsed() >= Duration::from_millis(500))
            {
                process.child.stdout = Some(stdout_pipe);
                process.child.stderr = Some(stderr_pipe);
                self.processes.push(process);
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

struct Probe {
    child: Child,
    reaped: bool,
    #[cfg(windows)]
    job: Option<std::os::windows::io::OwnedHandle>,
}

impl Probe {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
            command.creation_flags(CREATE_SUSPENDED);
        }
        let probe = Self {
            child: command.spawn()?,
            reaped: false,
            #[cfg(windows)]
            job: None,
        };
        #[cfg(windows)]
        let probe = {
            let mut probe = probe;
            probe.job = Some(windows_job(&probe.child)?);
            resume(&probe.child)?;
            probe
        };
        Ok(probe)
    }

    fn exited(&mut self) -> io::Result<bool> {
        Ok(self.status()?.is_some())
    }

    #[cfg(unix)]
    fn status(&self) -> io::Result<Option<std::process::ExitStatus>> {
        use std::os::unix::process::ExitStatusExt;
        // SAFETY: waitid observes our owned child without reaping it, preserving
        // the process-group identifier until the session drops its Probe.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            if libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if info.si_pid() == 0 {
                return Ok(None);
            }
            let raw = if info.si_code == libc::CLD_EXITED {
                info.si_status() << 8
            } else {
                info.si_status()
            };
            Ok(Some(std::process::ExitStatus::from_raw(raw)))
        }
    }

    #[cfg(windows)]
    fn status(&self) -> io::Result<Option<std::process::ExitStatus>> {
        use std::os::windows::{io::AsRawHandle, process::ExitStatusExt};
        use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        // SAFETY: Child owns the process handle, and code points to valid storage.
        unsafe {
            let result = WaitForSingleObject(self.child.as_raw_handle(), 0);
            if result == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            if result != WAIT_OBJECT_0 {
                return Ok(None);
            }
            let mut code = 0;
            if GetExitCodeProcess(self.child.as_raw_handle(), &mut code) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(std::process::ExitStatus::from_raw(code)))
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn status(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn signal_tree(&mut self, signal: i32) {
        #[cfg(unix)]
        // SAFETY: the unreaped child reserves this dedicated process-group ID.
        unsafe {
            libc::kill(-(self.child.id() as i32), signal);
        }
        #[cfg(not(unix))]
        {
            let _ = signal;
            self.terminate_tree();
        }
    }

    fn terminate_tree(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: our unreaped child owns this dedicated process-group ID.
            unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        }
        #[cfg(windows)]
        drop(self.job.take());
        let _ = self.child.kill();
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if !self.reaped {
            self.terminate_tree();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn prepare_reader(reader: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = reader.as_raw_fd();
    // SAFETY: the pipe descriptor remains owned by reader; only its flags change.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags == -1 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_reader<T>(_reader: &T) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn read_available(
    reader: &mut (impl Read + std::os::fd::AsRawFd),
    buffer: &mut [u8],
) -> io::Result<Option<usize>> {
    match reader.read(buffer) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        result => result.map(Some),
    }
}

#[cfg(windows)]
fn read_available(
    reader: &mut (impl Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> io::Result<Option<usize>> {
    use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0;
    // SAFETY: reader owns the pipe handle and available is writable u32 storage.
    let ok = unsafe {
        PeekNamedPipe(
            reader.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            Ok(Some(0))
        } else {
            Err(error)
        };
    }
    if available == 0 {
        return Ok(None);
    }
    let count = buffer.len().min(available as usize);
    reader.read(&mut buffer[..count]).map(Some)
}

#[cfg(not(any(unix, windows)))]
fn read_available<T>(_reader: &mut T, _buffer: &mut [u8]) -> io::Result<Option<usize>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded probes are unavailable",
    ))
}

#[cfg(windows)]
fn windows_job(child: &Child) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    // SAFETY: null security/name pointers request a new anonymous Job.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateJobObjectW returned a new handle owned by this scope.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: a zeroed Job limit structure represents disabled limits.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the Job, suspended child and structure remain valid throughout.
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of_val(&info) as u32,
        ) != 0
            && AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) != 0
    };
    if !configured {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

#[cfg(windows)]
fn resume(child: &Child) -> io::Result<()> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
    }
    // SAFETY: Child owns this suspended process handle. Job assignment is complete.
    let status = unsafe { NtResumeProcess(child.as_raw_handle()) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "probe resume failed: {status:#x}"
        )));
    }
    Ok(())
}
