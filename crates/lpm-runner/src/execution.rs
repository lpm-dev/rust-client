//! Foreground command execution with a signal lifetime owned by the caller.

use lpm_common::LpmError;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Keep stop handlers active for a command or an entire file-watch session.
pub struct ExecutionSignals {
    signal: Arc<AtomicUsize>,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
}

impl ExecutionSignals {
    pub fn new() -> Result<Self, LpmError> {
        let signals = Self {
            signal: Arc::new(AtomicUsize::new(0)),
            #[cfg(unix)]
            registrations: Vec::with_capacity(2),
        };
        #[cfg(unix)]
        let signals = {
            let mut signals = signals;
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signals
                    .registrations
                    .push(signal_hook::flag::register_usize(
                        signal,
                        Arc::clone(&signals.signal),
                        signal as usize,
                    )?);
            }
            signals
        };
        Ok(signals)
    }

    pub fn is_stopped(&self) -> bool {
        self.signal.load(Ordering::Acquire) != 0
    }

    pub fn check(&self) -> Result<(), LpmError> {
        let signal = self.signal.load(Ordering::Acquire);
        if signal == 0 {
            Ok(())
        } else {
            Err(LpmError::ExitCode(128 + signal as i32))
        }
    }

    pub fn capture(&self, command: &mut Command) -> Result<crate::shell::CapturedOutput, LpmError> {
        self.capture_in_session(
            command,
            &mut lpm_common::process_output::CaptureSession::default(),
        )
    }

    pub fn capture_in_session(
        &self,
        command: &mut Command,
        session: &mut lpm_common::process_output::CaptureSession,
    ) -> Result<crate::shell::CapturedOutput, LpmError> {
        self.check()?;
        #[cfg(unix)]
        let mut stopped_descendants = None;
        let result = session.capture_output_with_spawn(
            command,
            lpm_common::TASK_OUTPUT_CAPTURE_BYTES + 1,
            |_pid| {
                let signal = self.signal.load(Ordering::Acquire) as i32;
                if signal == 0 {
                    return None;
                }
                #[cfg(unix)]
                if stopped_descendants.is_none() {
                    let snapshot = crate::ports::descendant_process_snapshot(_pid);
                    snapshot.signal_surviving_descendants(_pid, signal);
                    stopped_descendants = Some((_pid, snapshot));
                }
                Some(signal)
            },
            crate::env_access::spawn,
        );
        #[cfg(unix)]
        if let Some((pid, snapshot)) = stopped_descendants {
            snapshot.signal_surviving_descendants(pid, libc::SIGKILL);
        }
        let output = result?;
        let bounded_text = |bytes: &[u8]| {
            let limit = lpm_common::TASK_OUTPUT_CAPTURE_BYTES;
            let mut text = String::from_utf8_lossy(bytes).into_owned();
            if text.len() > limit {
                let mut end = limit;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&format!(
                    "[output truncated at {} MiB]\n",
                    limit / (1024 * 1024)
                ));
            }
            text
        };
        let status = output.status;
        #[cfg(unix)]
        let status = if self.is_stopped() {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(self.signal.load(Ordering::Acquire) as i32)
        } else {
            status
        };
        Ok(crate::shell::CapturedOutput {
            status,
            stdout: bounded_text(&output.stdout),
            stderr: bounded_text(&output.stderr),
        })
    }

    /// Preserve the foreground group so interactive children can read stdin.
    pub fn run(&self, command: &mut Command) -> Result<ExitStatus, LpmError> {
        self.check()?;
        // Registered before the spawn, so an exit that happens first still
        // leaves a wakeup behind.
        #[cfg(unix)]
        let wake = ChildOrStopWake::new()?;
        let mut child = crate::env_access::spawn(command)?;
        #[cfg(not(unix))]
        let started = std::time::Instant::now();
        loop {
            #[cfg(unix)]
            wake.clear();
            if self.is_stopped() {
                #[cfg(unix)]
                crate::ports::stop_child_process_tree(
                    &mut child,
                    self.signal.load(Ordering::Acquire) as i32,
                )?;
                #[cfg(not(unix))]
                crate::ports::terminate_child_process_tree(&mut child)?;
                self.check()?;
            }
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) => {
                    let _ = crate::ports::terminate_child_process_tree(&mut child);
                    return Err(error.into());
                }
            }
            #[cfg(unix)]
            wake.wait();
            #[cfg(not(unix))]
            std::thread::sleep(std::time::Duration::from_millis(
                if started.elapsed() < std::time::Duration::from_millis(100) {
                    1
                } else {
                    10
                },
            ));
        }
    }
}

#[cfg(unix)]
const WAKE_BACKSTOP_MS: libc::c_int = 1_000;

/// Wakes a waiting thread when any child process exits or a stop signal
/// arrives, through a self-pipe the signal handlers write to.
#[cfg(unix)]
struct ChildOrStopWake {
    read: std::os::unix::net::UnixStream,
    registrations: Vec<signal_hook::SigId>,
}

#[cfg(unix)]
impl ChildOrStopWake {
    fn new() -> std::io::Result<Self> {
        let (read, write) = std::os::unix::net::UnixStream::pair()?;
        read.set_nonblocking(true)?;
        let mut wake = Self {
            read,
            registrations: Vec::with_capacity(3),
        };
        for signal in [
            signal_hook::consts::SIGCHLD,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ] {
            wake.registrations
                .push(signal_hook::low_level::pipe::register(
                    signal,
                    write.try_clone()?,
                )?);
        }
        Ok(wake)
    }

    /// Consume pending wakeups. Callers clear before checking state, so a
    /// signal that arrives during the check wakes the next wait.
    fn clear(&self) {
        let mut buffer = [0_u8; 64];
        while matches!(std::io::Read::read(&mut &self.read, &mut buffer), Ok(read) if read > 0) {}
    }

    fn wait(&self) {
        use std::os::fd::AsRawFd;

        let mut descriptor = libc::pollfd {
            fd: self.read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // The timeout is a backstop for a process that inherited a signal
        // mask blocking these signals on every thread.
        // SAFETY: `descriptor` is a valid pollfd for the duration of the call.
        // An interrupted or failed poll only makes the caller check again.
        unsafe {
            libc::poll(&mut descriptor, 1, WAKE_BACKSTOP_MS);
        }
    }
}

#[cfg(unix)]
impl Drop for ChildOrStopWake {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

#[cfg(unix)]
impl Drop for ExecutionSignals {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    }

    #[test]
    fn run_returns_the_child_exit_status() {
        let signals = ExecutionSignals::new().unwrap();

        let status = signals.run(&mut shell("exit 7")).unwrap();

        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn run_returns_a_child_that_exits_before_the_wait_starts() {
        let signals = ExecutionSignals::new().unwrap();
        let mut command = shell("kill -KILL $$");

        let status = signals.run(&mut command).unwrap();

        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn run_stops_the_child_when_a_stop_signal_arrives() {
        let signals = ExecutionSignals::new().unwrap();
        let flag = Arc::clone(&signals.signal);
        // Records the stop the way the SIGTERM handler does, then wakes the
        // wait with SIGCHLD. Raising SIGTERM itself would stop every other
        // test sharing this process.
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            flag.store(libc::SIGTERM as usize, Ordering::Release);
            signal_hook::low_level::raise(signal_hook::consts::SIGCHLD).unwrap();
        });
        let started = std::time::Instant::now();

        let result = signals.run(&mut shell("sleep 30"));
        stopper.join().unwrap();

        assert!(matches!(result, Err(LpmError::ExitCode(143))), "{result:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1_300),
            "the stop must wake the wait rather than its backstop timeout"
        );
    }
}
