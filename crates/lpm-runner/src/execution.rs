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
        let result =
            session.capture_output(command, lpm_common::TASK_OUTPUT_CAPTURE_BYTES, |_pid| {
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
            });
        #[cfg(unix)]
        if let Some((pid, snapshot)) = stopped_descendants {
            snapshot.signal_surviving_descendants(pid, libc::SIGKILL);
        }
        let output = result?;
        let bounded_text = |bytes: &[u8]| {
            let mut text = String::new();
            crate::shell::append_capped_output(&mut text, &String::from_utf8_lossy(bytes));
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
        let mut child = command.spawn()?;
        let started = std::time::Instant::now();
        loop {
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
            let poll_ms = if started.elapsed() < std::time::Duration::from_millis(100) {
                1
            } else {
                10
            };
            std::thread::sleep(std::time::Duration::from_millis(poll_ms));
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
