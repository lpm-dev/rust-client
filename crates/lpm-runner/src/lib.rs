//! Script execution engine for LPM.
//!
//! Provides:
//! - `run_script()` — execute package.json scripts with `.bin` PATH injection and pre/post hooks
//! - `exec_file()` — run a JS/TS file directly (auto-detect runtime)
//! - `dlx()` — run a package binary without installing it into the project
//! - PATH injection for `node_modules/.bin`
//! - Pre/post script hook execution (npm convention)
//!
//! # Architecture
//!
//! ```text
//! lpm-runner
//! ├── bin_path   — discover .bin dirs, build PATH
//! ├── hooks      — pre/post script detection and execution
//! ├── script     — package.json script execution with full env
//! ├── shell      — cross-platform shell abstraction
//! ├── exec       — direct file execution (JS/TS)
//! └── dlx        — temporary package execution
//! ```

pub mod bin_path;
pub mod dag;
pub mod dev_endpoint;
pub mod dev_session;
pub mod dlx;
pub mod dotenv;
pub mod env_access;
pub mod exec;
pub mod execution;
pub mod hooks;
pub mod isolate;
pub mod local_domains;
pub mod lpm_json;
pub mod npm_context;
pub mod orchestrator;
pub mod ports;
pub mod ready;
pub mod script;
pub mod service_graph;
pub mod shell;
pub mod task_graph;
pub mod ts_transform;

#[cfg(test)]
mod test_support;

pub type ShutdownStartedCallback =
    Box<dyn FnOnce() -> Result<(), lpm_common::LpmError> + Send + 'static>;

pub(crate) fn invoke_shutdown_started(
    callback: &mut Option<ShutdownStartedCallback>,
) -> Result<(), lpm_common::LpmError> {
    #[cfg(windows)]
    {
        invoke_shutdown_started_while(callback, crate::execution::console_closing)
    }
    #[cfg(not(windows))]
    {
        callback.take().map_or(Ok(()), |callback| callback())
    }
}

/// Runs `callback` once, on a thread of its own, and returns what it
/// returns, unless the console window is or starts `closing` first: lpm then
/// stops waiting for it. Windows ends lpm within about five seconds of the
/// window's closing, which stopping the services and releasing what the
/// session holds need more than, say, a tunnel's acknowledgement of a stop.
#[cfg(any(windows, test))]
fn invoke_shutdown_started_while(
    callback: &mut Option<ShutdownStartedCallback>,
    closing: impl Fn() -> bool,
) -> Result<(), lpm_common::LpmError> {
    use std::sync::mpsc::RecvTimeoutError;

    let Some(callback) = callback.take() else {
        return Ok(());
    };
    // Kept here as well, so that lpm runs it itself where no thread starts.
    let slot = std::sync::Arc::new(parking_lot::Mutex::new(Some(callback)));
    let on_thread = std::sync::Arc::clone(&slot);
    // Dropped as the callback returns or panics, which ends the wait.
    let (running, finished) = std::sync::mpsc::channel::<()>();
    let started = std::thread::Builder::new()
        .name("lpm-shutdown-started".to_string())
        .spawn(move || {
            let _running = running;
            let callback = on_thread.lock().take();
            callback.map_or(Ok(()), |callback| callback())
        });
    let Ok(thread) = started else {
        let callback = slot.lock().take();
        return callback.map_or(Ok(()), |callback| callback());
    };
    loop {
        if closing() {
            return Ok(());
        }
        match finished.recv_timeout(std::time::Duration::from_millis(50)) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                return thread
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// On a closing console window, what lpm does as its shutdown begins,
    /// such as asking a tunnel to stop, isn't waited for: Windows ends lpm
    /// within about five seconds, which stopping the services and releasing
    /// what the session holds need.
    #[test]
    fn a_closing_window_does_not_wait_for_what_the_shutdown_begins_with() {
        let (started, started_rx) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let mut callback: Option<ShutdownStartedCallback> = Some(Box::new(move || {
            started.send(()).unwrap();
            let _ = released.recv_timeout(Duration::from_secs(2));
            Err(lpm_common::LpmError::Tunnel("acknowledged late".into()))
        }));

        let result = invoke_shutdown_started_while(&mut callback, || true);
        let ran = started_rx.recv_timeout(Duration::from_secs(10));
        let _ = release.send(());

        assert!(result.is_ok(), "{result:?}");
        assert!(callback.is_none());
        assert!(ran.is_ok(), "the shutdown began without it");
    }

    /// A window that closes while lpm waits for what its shutdown began
    /// with, as after a Ctrl+C, ends the wait too.
    #[test]
    fn a_window_closing_during_the_wait_ends_it() {
        let (started, started_rx) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let mut callback: Option<ShutdownStartedCallback> = Some(Box::new(move || {
            started.send(()).unwrap();
            let _ = released.recv_timeout(Duration::from_secs(3));
            Err(lpm_common::LpmError::Tunnel("acknowledged late".into()))
        }));
        let closing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closes = std::sync::Arc::clone(&closing);
        let closer = std::thread::spawn(move || {
            started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            closes.store(true, std::sync::atomic::Ordering::Release);
        });

        let began = std::time::Instant::now();
        let result = invoke_shutdown_started_while(&mut callback, || {
            closing.load(std::sync::atomic::Ordering::Acquire)
        });
        let waited = began.elapsed();
        let _ = release.send(());
        closer.join().unwrap();

        assert!(result.is_ok(), "{result:?}");
        assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    }

    #[test]
    fn a_panic_in_what_the_shutdown_begins_with_reaches_the_shutdown() {
        let mut callback: Option<ShutdownStartedCallback> =
            Some(Box::new(|| panic!("the tunnel's stop panicked")));

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            invoke_shutdown_started_while(&mut callback, || false)
        }));

        assert!(outcome.is_err());
    }

    #[test]
    fn an_open_console_waits_for_what_the_shutdown_begins_with() {
        let mut callback: Option<ShutdownStartedCallback> = Some(Box::new(|| {
            Err(lpm_common::LpmError::Tunnel("acknowledged late".into()))
        }));

        let result = invoke_shutdown_started_while(&mut callback, || false);

        assert!(result.is_err());
        assert!(callback.is_none());
    }
}
