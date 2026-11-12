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
        #[cfg(windows)]
        console_interrupts::listen(&signals.signal);
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
        #[cfg(windows)]
        let mut interrupts = console_interrupts::Presses::default();
        let result = session.capture_output_with_spawn(
            command,
            lpm_common::TASK_OUTPUT_CAPTURE_BYTES + 1,
            |_pid| {
                let signal = self.signal.load(Ordering::Acquire) as i32;
                if signal == 0 {
                    return None;
                }
                #[cfg(windows)]
                if !interrupts.pressed_again() {
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
        let wait = self.prepare_wait()?;
        let mut child = crate::env_access::spawn(command)?;
        wait.wait(&mut child)
    }

    /// Prepares to wait on a child that the caller spawns next. Created
    /// before the spawn, so an exit that happens first still wakes the wait.
    pub fn prepare_wait(&self) -> Result<ChildWait<'_>, LpmError> {
        self.check()?;
        Ok(ChildWait {
            signals: self,
            #[cfg(unix)]
            wake: ChildOrStopWake::new()?,
        })
    }
}

/// A wait on one child that forwards SIGINT and SIGTERM to it and its
/// descendants, then reports the interruption as exit code 128 + signal.
pub struct ChildWait<'a> {
    signals: &'a ExecutionSignals,
    #[cfg(unix)]
    wake: ChildOrStopWake,
}

impl ChildWait<'_> {
    pub fn wait(self, child: &mut std::process::Child) -> Result<ExitStatus, LpmError> {
        #[cfg(not(unix))]
        let started = std::time::Instant::now();
        #[cfg(windows)]
        let mut interrupts = console_interrupts::Presses::default();
        loop {
            #[cfg(unix)]
            self.wake.clear();
            #[cfg(unix)]
            if self.signals.is_stopped() {
                crate::ports::stop_child_process_tree(
                    child,
                    self.signals.signal.load(Ordering::Acquire) as i32,
                )?;
                self.signals.check()?;
            }
            // The child shares the console, so it got the interrupt too and
            // ends as it sees fit; a second one stops it.
            #[cfg(windows)]
            if self.signals.is_stopped() && interrupts.pressed_again() {
                crate::ports::terminate_child_process_tree(child)?;
                self.signals.check()?;
            }
            #[cfg(not(any(unix, windows)))]
            if self.signals.is_stopped() {
                crate::ports::terminate_child_process_tree(child)?;
                self.signals.check()?;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.signals.check()?;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = crate::ports::terminate_child_process_tree(child);
                    return Err(error.into());
                }
            }
            #[cfg(unix)]
            self.wake.wait();
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

#[cfg(windows)]
impl Drop for ExecutionSignals {
    fn drop(&mut self) {
        console_interrupts::stop_listening(&self.signal);
    }
}

/// Ctrl+C and Ctrl+Break at the console, while an [`ExecutionSignals`]
/// lives: recorded in it as SIGINT or SIGBREAK, without ending lpm. The
/// foreground child shares the console, so it gets the event too and
/// decides for itself, as under cmd.exe; ending lpm at once left a batch
/// file it ran asking "Terminate batch job (Y/N)?" while the shell read the
/// keyboard too. A second press stops the child.
#[cfg(windows)]
mod console_interrupts {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, Once, PoisonError};
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::core::BOOL;

    pub(super) const SIGINT: usize = 2;
    const SIGBREAK: usize = 21;

    static LISTENERS: Mutex<Vec<Arc<AtomicUsize>>> = Mutex::new(Vec::new());
    static PRESSES: AtomicUsize = AtomicUsize::new(0);
    static HANDLER: Once = Once::new();

    pub(super) fn signal_for(event: u32) -> Option<usize> {
        match event {
            CTRL_C_EVENT => Some(SIGINT),
            CTRL_BREAK_EVENT => Some(SIGBREAK),
            _ => None,
        }
    }

    /// Runs on a thread of its own that Windows starts for the event.
    unsafe extern "system" fn on_console_event(event: u32) -> BOOL {
        let Some(signal) = signal_for(event) else {
            return FALSE;
        };
        let listeners = LISTENERS.lock().unwrap_or_else(PoisonError::into_inner);
        if listeners.is_empty() {
            // Nothing runs in the foreground: end lpm, as before.
            return FALSE;
        }
        count_press();
        for listener in listeners.iter() {
            listener.store(signal, Ordering::Release);
        }
        TRUE
    }

    pub(super) fn listen(signal: &Arc<AtomicUsize>) {
        HANDLER.call_once(|| {
            // SAFETY: the handler is a plain function that lives for the
            // whole process. Should Windows refuse it, Ctrl+C ends lpm, as
            // it did before there was one.
            unsafe { SetConsoleCtrlHandler(Some(on_console_event), TRUE) };
        });
        LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(signal));
    }

    pub(super) fn stop_listening(signal: &Arc<AtomicUsize>) {
        LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|listener| !Arc::ptr_eq(listener, signal));
    }

    pub(super) fn count_press() {
        PRESSES.fetch_add(1, Ordering::AcqRel);
    }

    /// The presses a wait has seen since the interrupt it is ending for.
    #[derive(Default)]
    pub(super) struct Presses {
        first: Option<usize>,
    }

    impl Presses {
        /// Whether the console was interrupted again since this was first
        /// asked, after an interrupt.
        pub(super) fn pressed_again(&mut self) -> bool {
            let presses = PRESSES.load(Ordering::Acquire);
            *self.first.get_or_insert(presses) < presses
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn ping(seconds: u32) -> Command {
        let mut command = Command::new("ping");
        command
            .args(["-n", &(seconds + 1).to_string(), "127.0.0.1"])
            .stdout(std::process::Stdio::null());
        command
    }

    /// Ctrl+C reaches the foreground child too, as it shares the console, so
    /// lpm waits for it to end as cmd.exe does, rather than end first and
    /// leave a batch file asking "Terminate batch job (Y/N)?".
    #[test]
    fn a_console_interrupt_waits_for_the_child_to_end() {
        let signals = ExecutionSignals::new().unwrap();
        let flag = Arc::clone(&signals.signal);
        // Records the interrupt the way the console handler does, without
        // raising one that every test in this process would get.
        let interrupter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            flag.store(console_interrupts::SIGINT, Ordering::Release);
        });
        let started = std::time::Instant::now();

        let result = signals.run(&mut ping(2));
        interrupter.join().unwrap();

        assert!(matches!(result, Err(LpmError::ExitCode(130))), "{result:?}");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(1_500),
            "the child was stopped instead of left to end"
        );
    }

    /// A second Ctrl+C stops the child, which the first didn't: one that
    /// ignores it, or doesn't share the console.
    #[test]
    fn a_second_console_interrupt_stops_the_child() {
        let signals = ExecutionSignals::new().unwrap();
        let flag = Arc::clone(&signals.signal);
        let interrupter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            flag.store(console_interrupts::SIGINT, Ordering::Release);
            std::thread::sleep(std::time::Duration::from_millis(300));
            console_interrupts::count_press();
        });
        let started = std::time::Instant::now();

        let result = signals.run(&mut ping(30));
        interrupter.join().unwrap();

        assert!(matches!(result, Err(LpmError::ExitCode(130))), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn console_events_map_to_the_signals_they_stand_for() {
        use windows_sys::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT,
        };
        assert_eq!(console_interrupts::signal_for(CTRL_C_EVENT), Some(2));
        assert_eq!(console_interrupts::signal_for(CTRL_BREAK_EVENT), Some(21));
        assert_eq!(console_interrupts::signal_for(CTRL_CLOSE_EVENT), None);
    }
}
