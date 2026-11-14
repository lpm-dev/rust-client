//! Foreground command execution with a signal lifetime owned by the caller.

use lpm_common::LpmError;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The exit status of a process that Ctrl+C's or Ctrl+Break's default
/// handler ended.
#[cfg(windows)]
pub(crate) const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;

/// Whether a child that exited did so in a stop lpm has recorded, as
/// `recorded` reports. Windows runs lpm's console handler on a thread it
/// starts for the event, so a child the same Ctrl+C or Ctrl+Break ended,
/// with [`STATUS_CONTROL_C_EXIT`], can exit before lpm has recorded it; for
/// such a child this waits briefly for the record.
#[cfg(windows)]
pub(crate) fn exit_follows_console_stop(status: ExitStatus, recorded: impl Fn() -> bool) -> bool {
    if status.code() == Some(STATUS_CONTROL_C_EXIT as i32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while !recorded() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    recorded()
}

/// Keep stop handlers active for a command or an entire file-watch session.
pub struct ExecutionSignals {
    signal: Arc<AtomicUsize>,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
    /// Console interrupts seen while this lived.
    #[cfg(windows)]
    presses: Arc<AtomicUsize>,
    #[cfg(windows)]
    listener: u64,
    /// Runs once lpm waits for the interrupt behind a child's exit, so a
    /// test can record one exactly then.
    #[cfg(all(test, windows))]
    on_await_interrupt: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl ExecutionSignals {
    pub fn new() -> Result<Self, LpmError> {
        let signals = Self {
            signal: Arc::new(AtomicUsize::new(0)),
            #[cfg(unix)]
            registrations: Vec::with_capacity(2),
            #[cfg(windows)]
            presses: Arc::new(AtomicUsize::new(0)),
            #[cfg(windows)]
            listener: 0,
            #[cfg(all(test, windows))]
            on_await_interrupt: std::sync::Mutex::new(None),
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
        let signals = {
            let mut signals = signals;
            signals.listener = console_interrupts::listen(console_interrupts::Reaction::Record {
                signal: Arc::clone(&signals.signal),
                presses: Arc::clone(&signals.presses),
            });
            signals
        };
        Ok(signals)
    }

    /// Whether the console was interrupted more than once: the child, which
    /// got the first interrupt itself, is then stopped.
    #[cfg(windows)]
    fn pressed_again(&self) -> bool {
        self.presses.load(Ordering::Acquire) > 1
    }

    /// Waits for the interrupt behind a child's `STATUS_CONTROL_C_EXIT`, so
    /// lpm reports which interrupt it was rather than the child's status.
    #[cfg(windows)]
    fn await_the_interrupt_behind(&self, status: ExitStatus) {
        #[cfg(test)]
        if status.code() == Some(STATUS_CONTROL_C_EXIT as i32)
            && let Some(hook) = self
                .on_await_interrupt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        {
            hook();
        }
        exit_follows_console_stop(status, || self.is_stopped());
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
                #[cfg(windows)]
                if !self.pressed_again() {
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
        // The child got the interrupt too and may have ended well; the run
        // was interrupted all the same, and lpm exits with 128 + signal.
        #[cfg(windows)]
        self.await_the_interrupt_behind(status);
        #[cfg(windows)]
        let status = if self.is_stopped() {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(128 + self.signal.load(Ordering::Acquire) as u32)
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
            if self.signals.is_stopped() && self.signals.pressed_again() {
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
                    #[cfg(windows)]
                    self.signals.await_the_interrupt_behind(status);
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
        console_interrupts::stop_listening(self.listener);
    }
}

/// Whether a console event has started a shutdown, through a
/// [`ConsoleStop`]: the processes that share lpm's console got the event
/// too, and are stopping themselves.
#[cfg(windows)]
pub(crate) fn console_stopping() -> bool {
    console_interrupts::stopping()
}

/// What made a [`ConsoleStop`] call its stop.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleStopEvent {
    /// Ctrl+C or Ctrl+Break.
    Interrupt,
    /// The console window is closing; writing to it may fail.
    Close,
}

/// While it lives, the console's Ctrl+C and Ctrl+Break, and the closing of
/// its window, call a stop instead of ending lpm, as SIGINT, SIGTERM and
/// SIGHUP stop `lpm dev` on Unix. Closing the window still ends lpm, about
/// five seconds after the call at most, so the stop starts the shutdown and
/// lpm finishes it in that time.
#[cfg(windows)]
pub(crate) struct ConsoleStop {
    listener: u64,
}

#[cfg(windows)]
impl ConsoleStop {
    pub(crate) fn new(on_stop: impl Fn(ConsoleStopEvent) + Send + Sync + 'static) -> Self {
        Self {
            listener: console_interrupts::listen(console_interrupts::Reaction::Stop(Arc::new(
                on_stop,
            ))),
        }
    }

    /// Calls this stop alone, as the console handler would, without raising
    /// an event that every test in the process would get.
    #[cfg(test)]
    pub(crate) fn fire_for_test(&self, event: ConsoleStopEvent) {
        if let Some(stop) = console_interrupts::stop_of(self.listener) {
            stop(event);
        }
    }
}

#[cfg(windows)]
impl Drop for ConsoleStop {
    fn drop(&mut self) {
        console_interrupts::stop_listening(self.listener);
    }
}

/// Ctrl+C, Ctrl+Break and the window's closing at the console, while a
/// listener lives, without ending lpm.
///
/// An [`ExecutionSignals`] records Ctrl+C and Ctrl+Break as SIGINT or
/// SIGBREAK. The foreground child shares the console, so it gets the event
/// too and decides for itself, as under cmd.exe; ending lpm at once left a
/// batch file it ran asking "Terminate batch job (Y/N)?" while the shell
/// read the keyboard too. A second press stops the child.
///
/// A [`ConsoleStop`] is called for each, and for the window's closing.
#[cfg(windows)]
mod console_interrupts {
    use super::ConsoleStopEvent;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, Once, PoisonError};
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::core::BOOL;

    pub(super) const SIGINT: usize = 2;
    const SIGBREAK: usize = 21;

    /// How long the handler keeps lpm alive for its shutdown once the window
    /// closes. Windows ends the process sooner, five seconds after the event
    /// by default, and lpm ends itself as soon as its shutdown is done.
    const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

    pub(super) type Stop = Arc<dyn Fn(ConsoleStopEvent) + Send + Sync>;

    /// What a listener does with an event.
    pub(super) enum Reaction {
        /// A live `ExecutionSignals`: records Ctrl+C and Ctrl+Break as the
        /// signal they stand for, and counts the presses.
        Record {
            signal: Arc<AtomicUsize>,
            presses: Arc<AtomicUsize>,
        },
        /// A live `ConsoleStop`: called for Ctrl+C, Ctrl+Break and the
        /// window's closing.
        Stop(Stop),
    }

    struct Listener {
        id: u64,
        reaction: Reaction,
    }

    /// A listener's reaction, copied out of the lock for one event.
    pub(super) enum ReactionHandle {
        Record {
            signal: Arc<AtomicUsize>,
            presses: Arc<AtomicUsize>,
        },
        Stop(Stop),
    }

    impl Listener {
        fn reaction_handle(&self) -> ReactionHandle {
            match &self.reaction {
                Reaction::Record { signal, presses } => ReactionHandle::Record {
                    signal: Arc::clone(signal),
                    presses: Arc::clone(presses),
                },
                Reaction::Stop(stop) => ReactionHandle::Stop(Arc::clone(stop)),
            }
        }
    }

    static LISTENERS: Mutex<Vec<Listener>> = Mutex::new(Vec::new());
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    static HANDLER: Once = Once::new();

    pub(super) fn signal_for(event: u32) -> Option<usize> {
        match event {
            CTRL_C_EVENT => Some(SIGINT),
            CTRL_BREAK_EVENT => Some(SIGBREAK),
            _ => None,
        }
    }

    /// Records one interrupt, `signal`, in a listener.
    pub(super) fn notify(signal: &AtomicUsize, presses: &AtomicUsize, value: usize) {
        signal.store(value, Ordering::Release);
        presses.fetch_add(1, Ordering::AcqRel);
    }

    /// Set once a `ConsoleStop` has been called: lpm has a shutdown under
    /// way, which outlives the listeners, as `lpm dev` releases its tunnel,
    /// proxy routes and hosts-file entries after its services stop. Later
    /// events then leave lpm running, as a signal does on Unix once its
    /// handler's actions are gone.
    static STOPPING: AtomicBool = AtomicBool::new(false);

    /// Runs on a thread of its own that Windows starts for the event.
    unsafe extern "system" fn on_console_event(event: u32) -> BOOL {
        // Copied out under the lock: a stop may take time, and the shutdown
        // it starts drops listeners.
        let listeners = LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(Listener::reaction_handle)
            .collect::<Vec<_>>();
        if dispatch(event, &listeners, &STOPPING, CLOSE_GRACE) {
            TRUE
        } else {
            FALSE
        }
    }

    /// What lpm does with console `event` for `listeners`; whether it
    /// handled the event rather than leaving Windows to end lpm. On the
    /// window's closing it waits `close_grace` before returning, as Windows
    /// ends lpm when it returns.
    pub(super) fn dispatch(
        event: u32,
        listeners: &[ReactionHandle],
        stopping: &AtomicBool,
        close_grace: std::time::Duration,
    ) -> bool {
        let signal = signal_for(event);
        let closing = event == CTRL_CLOSE_EVENT;
        if signal.is_none() && !closing {
            return false;
        }
        if let Some(signal) = signal {
            for listener in listeners {
                if let ReactionHandle::Record {
                    signal: record,
                    presses,
                } = listener
                {
                    notify(record, presses, signal);
                }
            }
        }
        let stops: Vec<&Stop> = listeners
            .iter()
            .filter_map(|listener| match listener {
                ReactionHandle::Stop(stop) => Some(stop),
                ReactionHandle::Record { .. } => None,
            })
            .collect();
        let stop_event = if closing {
            ConsoleStopEvent::Close
        } else {
            ConsoleStopEvent::Interrupt
        };
        for stop in &stops {
            stopping.store(true, Ordering::Release);
            // A panic can't unwind out of the console handler, so one here
            // would abort lpm before its cleanup.
            let stop = std::panic::AssertUnwindSafe(|| stop(stop_event));
            if std::panic::catch_unwind(stop).is_err() {
                tracing::debug!("a console stop panicked");
            }
        }
        let shutting_down = !stops.is_empty() || stopping.load(Ordering::Acquire);
        if closing {
            // Only a shutdown has anything to finish; otherwise the closing
            // window ends lpm, as before.
            if !shutting_down {
                return false;
            }
            std::thread::sleep(close_grace);
            return true;
        }
        // Without a listener or a shutdown, nothing runs in the foreground:
        // end lpm, as before.
        !listeners.is_empty() || shutting_down
    }

    pub(super) fn listen(reaction: Reaction) -> u64 {
        HANDLER.call_once(|| {
            // SAFETY: the handler is a plain function that lives for the
            // whole process.
            if unsafe { SetConsoleCtrlHandler(Some(on_console_event), TRUE) } == 0 {
                tracing::debug!(
                    "Windows refused lpm's console handler, so Ctrl+C ends lpm at once: {}",
                    std::io::Error::last_os_error()
                );
            }
        });
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Listener { id, reaction });
        id
    }

    pub(super) fn stopping() -> bool {
        STOPPING.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn stop_of(id: u64) -> Option<Stop> {
        LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|listener| listener.id == id)
            .and_then(|listener| match &listener.reaction {
                Reaction::Stop(stop) => Some(Arc::clone(stop)),
                Reaction::Record { .. } => None,
            })
    }

    pub(super) fn stop_listening(id: u64) {
        LISTENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|listener| listener.id != id);
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
        let (flag, presses) = (Arc::clone(&signals.signal), Arc::clone(&signals.presses));
        // Records the interrupt the way the console handler does, without
        // raising one that every test in this process would get.
        let interrupter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            console_interrupts::notify(&flag, &presses, console_interrupts::SIGINT);
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
        let (flag, presses) = (Arc::clone(&signals.signal), Arc::clone(&signals.presses));
        let interrupter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            console_interrupts::notify(&flag, &presses, console_interrupts::SIGINT);
            std::thread::sleep(std::time::Duration::from_millis(300));
            console_interrupts::notify(&flag, &presses, console_interrupts::SIGINT);
        });
        let started = std::time::Instant::now();

        let result = signals.run(&mut ping(30));
        interrupter.join().unwrap();

        assert!(matches!(result, Err(LpmError::ExitCode(130))), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    /// A captured child that ends well on Ctrl+C still reports the
    /// interruption, as lpm exits with it, so a `--json` envelope built
    /// from the status doesn't say the run succeeded.
    #[test]
    fn a_captured_child_that_ends_well_on_an_interrupt_reports_it() {
        let signals = ExecutionSignals::new().unwrap();
        let (flag, presses) = (Arc::clone(&signals.signal), Arc::clone(&signals.presses));
        let interrupter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            console_interrupts::notify(&flag, &presses, console_interrupts::SIGINT);
        });

        let output = signals.capture(&mut ping(1)).unwrap();
        interrupter.join().unwrap();

        assert_eq!(output.status.code(), Some(130));
    }

    /// A child that exits as Ctrl+C's default handler ends a process.
    fn ended_by_the_console() -> Command {
        let mut command = Command::new("cmd");
        command.args([
            "/D",
            "/C",
            "exit",
            &(STATUS_CONTROL_C_EXIT as i32).to_string(),
        ]);
        command
    }

    /// Windows runs lpm's handler on a thread it starts for the interrupt,
    /// which can come after the child the same interrupt ended has exited:
    /// lpm still reports the interruption, not the child's status.
    /// Records Ctrl+C only once lpm has seen the child's exit and waits for
    /// the interrupt behind it, as when Windows runs lpm's handler late.
    fn interrupt_once_lpm_waits_for_it(signals: &ExecutionSignals) {
        let (flag, presses) = (Arc::clone(&signals.signal), Arc::clone(&signals.presses));
        *signals.on_await_interrupt.lock().unwrap() = Some(Box::new(move || {
            console_interrupts::notify(&flag, &presses, console_interrupts::SIGINT);
        }));
    }

    #[test]
    fn a_child_the_console_interrupt_ended_first_reports_the_interruption() {
        let signals = ExecutionSignals::new().unwrap();
        interrupt_once_lpm_waits_for_it(&signals);

        let result = signals.run(&mut ended_by_the_console());

        assert!(matches!(result, Err(LpmError::ExitCode(130))), "{result:?}");
    }

    #[test]
    fn a_captured_child_the_console_interrupt_ended_first_reports_the_interruption() {
        let signals = ExecutionSignals::new().unwrap();
        interrupt_once_lpm_waits_for_it(&signals);

        let output = signals.capture(&mut ended_by_the_console()).unwrap();

        assert_eq!(output.status.code(), Some(130));
    }

    /// With no interrupt behind it, such a status is the child's own.
    #[test]
    fn a_child_that_exits_as_interrupted_without_an_interrupt_keeps_its_status() {
        let signals = ExecutionSignals::new().unwrap();

        let status = signals.run(&mut ended_by_the_console()).unwrap();

        assert_eq!(status.code(), Some(STATUS_CONTROL_C_EXIT as i32));
    }

    #[test]
    fn a_console_stop_is_called_while_it_lives_and_released_when_dropped() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let stop = ConsoleStop::new(move |event| recorded.lock().unwrap().push(event));
        let listener = stop.listener;

        stop.fire_for_test(ConsoleStopEvent::Interrupt);
        stop.fire_for_test(ConsoleStopEvent::Close);
        drop(stop);

        assert_eq!(
            *calls.lock().unwrap(),
            [ConsoleStopEvent::Interrupt, ConsoleStopEvent::Close]
        );
        assert!(console_interrupts::stop_of(listener).is_none());
    }

    fn stop_recording(
        calls: &Arc<std::sync::Mutex<Vec<ConsoleStopEvent>>>,
    ) -> console_interrupts::ReactionHandle {
        let calls = Arc::clone(calls);
        console_interrupts::ReactionHandle::Stop(Arc::new(move |event| {
            calls.lock().unwrap().push(event);
        }))
    }

    #[test]
    fn a_console_event_reaches_each_listener_as_its_kind_takes_it() {
        use windows_sys::Win32::System::Console::CTRL_C_EVENT;
        let (signal, presses) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listeners = [
            console_interrupts::ReactionHandle::Record {
                signal: Arc::clone(&signal),
                presses: Arc::clone(&presses),
            },
            stop_recording(&calls),
        ];
        let stopping = std::sync::atomic::AtomicBool::new(false);

        let handled = console_interrupts::dispatch(
            CTRL_C_EVENT,
            &listeners,
            &stopping,
            std::time::Duration::ZERO,
        );

        assert!(handled, "lpm keeps running");
        assert_eq!(signal.load(Ordering::Acquire), console_interrupts::SIGINT);
        assert_eq!(presses.load(Ordering::Acquire), 1);
        assert_eq!(*calls.lock().unwrap(), [ConsoleStopEvent::Interrupt]);
        assert!(stopping.load(Ordering::Acquire), "a shutdown is under way");
    }

    #[test]
    fn a_closing_window_is_a_stop_s_to_handle_and_ends_lpm_run_as_before() {
        use windows_sys::Win32::System::Console::CTRL_CLOSE_EVENT;
        let record = console_interrupts::ReactionHandle::Record {
            signal: Arc::new(AtomicUsize::new(0)),
            presses: Arc::new(AtomicUsize::new(0)),
        };
        let stopping = std::sync::atomic::AtomicBool::new(false);
        assert!(
            !console_interrupts::dispatch(
                CTRL_CLOSE_EVENT,
                &[record],
                &stopping,
                std::time::Duration::ZERO
            ),
            "`lpm run` lets the closing window end it"
        );

        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        assert!(console_interrupts::dispatch(
            CTRL_CLOSE_EVENT,
            &[stop_recording(&calls)],
            &stopping,
            std::time::Duration::ZERO
        ));
        assert_eq!(*calls.lock().unwrap(), [ConsoleStopEvent::Close]);
    }

    /// Once a stop has run, lpm finishes its shutdown after the listeners
    /// are gone, rather than letting a later press or the window's closing
    /// end it with its cleanup half done.
    #[test]
    fn a_shutdown_under_way_keeps_lpm_running_with_no_listener_left() {
        use windows_sys::Win32::System::Console::{CTRL_C_EVENT, CTRL_CLOSE_EVENT};
        let idle = std::sync::atomic::AtomicBool::new(false);
        assert!(!console_interrupts::dispatch(
            CTRL_C_EVENT,
            &[],
            &idle,
            std::time::Duration::ZERO
        ));

        let stopping = std::sync::atomic::AtomicBool::new(true);
        assert!(console_interrupts::dispatch(
            CTRL_C_EVENT,
            &[],
            &stopping,
            std::time::Duration::ZERO
        ));
        assert!(console_interrupts::dispatch(
            CTRL_CLOSE_EVENT,
            &[],
            &stopping,
            std::time::Duration::ZERO
        ));
    }

    #[test]
    fn a_stop_that_panics_leaves_the_others_and_lpm_running() {
        use windows_sys::Win32::System::Console::CTRL_C_EVENT;
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listeners = [
            console_interrupts::ReactionHandle::Stop(Arc::new(|_| panic!("a stop that panics"))),
            stop_recording(&calls),
        ];
        let stopping = std::sync::atomic::AtomicBool::new(false);

        assert!(console_interrupts::dispatch(
            CTRL_C_EVENT,
            &listeners,
            &stopping,
            std::time::Duration::ZERO
        ));
        assert_eq!(*calls.lock().unwrap(), [ConsoleStopEvent::Interrupt]);
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
