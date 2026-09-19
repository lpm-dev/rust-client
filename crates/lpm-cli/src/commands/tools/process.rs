use super::{Captured, StdioMode, ToolOutcome, apply_stdio, runner_error};
use lpm_common::LpmError;
use lpm_runner::execution::ExecutionSignals;
use std::process::Command;
use std::sync::Arc;

pub(super) async fn run(
    mut command: Command,
    stdio: StdioMode,
    signals: Arc<ExecutionSignals>,
) -> ToolOutcome {
    tokio::task::spawn_blocking(move || {
        apply_stdio(&mut command, stdio);
        let result = match stdio {
            StdioMode::Inherit => signals.run(&mut command).map(|status| ToolOutcome {
                exit_code: Some(lpm_runner::shell::exit_code(&status)),
                ..Default::default()
            }),
            StdioMode::Capture => signals.capture(&mut command).map(|output| ToolOutcome {
                exit_code: Some(lpm_runner::shell::exit_code(&output.status)),
                captured: Captured {
                    stdout: output.stdout,
                    stderr: output.stderr,
                },
                error: None,
            }),
        };
        result.unwrap_or_else(runner_error)
    })
    .await
    .unwrap_or_else(|error| runner_error(LpmError::Script(format!("tool task failed: {error}"))))
}

pub(super) fn write_json(
    value: &serde_json::Value,
    signals: &ExecutionSignals,
) -> Result<(), LpmError> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let reporting_cancelled_run = signals.is_stopped();
        let started = std::time::Instant::now();
        let stdout = std::io::stdout().lock();
        let fd = stdout.as_raw_fd();
        // SAFETY: stdout owns this descriptor for the complete write and restore scope.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: fd remains owned by the stdout lock.
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(std::io::Error::last_os_error().into());
        }
        struct RestoreFlags(i32, i32);
        impl Drop for RestoreFlags {
            fn drop(&mut self) {
                // SAFETY: the stdout lock outlives this guard.
                unsafe {
                    libc::fcntl(self.0, libc::F_SETFL, self.1);
                }
            }
        }
        let _restore = RestoreFlags(fd, flags);
        let mut bytes = text.as_bytes();
        while !bytes.is_empty() {
            // Give a cancelled child a bounded chance to report its captured diagnostics.
            if !reporting_cancelled_run
                || started.elapsed() >= std::time::Duration::from_millis(500)
            {
                signals.check()?;
            }
            // SAFETY: bytes is a valid readable slice and fd remains open.
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if written > 0 {
                bytes = &bytes[written as usize..];
                continue;
            }
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    let mut ready = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: ready points to one initialized poll descriptor.
                    if unsafe { libc::poll(&mut ready, 1, 10) } == -1 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error.into());
                        }
                    }
                }
                std::io::ErrorKind::BrokenPipe => return Err(LpmError::ExitCode(1)),
                _ => return Err(error.into()),
            }
        }
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        std::io::stdout().lock().write_all(text.as_bytes())?;
    }
    signals.check()
}
