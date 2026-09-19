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
