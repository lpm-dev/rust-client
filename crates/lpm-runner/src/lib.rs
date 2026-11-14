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
    invoke_shutdown_started_while(callback, crate::execution::console_closing())
}

/// Runs `callback` once. While the console window is `closing`, it runs on a
/// thread of its own, which lpm doesn't wait for: Windows ends lpm within
/// about five seconds, which stopping the services and releasing what the
/// session holds need more than, say, a tunnel's acknowledgement of a stop.
fn invoke_shutdown_started_while(
    callback: &mut Option<ShutdownStartedCallback>,
    closing: bool,
) -> Result<(), lpm_common::LpmError> {
    let Some(callback) = callback.take() else {
        return Ok(());
    };
    if !closing {
        return callback();
    }
    let started = std::thread::Builder::new()
        .name("lpm-shutdown-started".to_string())
        .spawn(move || {
            if let Err(error) = callback() {
                tracing::debug!(%error, "the shutdown's first step failed as the window closed");
            }
        });
    if let Err(error) = started {
        tracing::debug!(%error, "could not begin the shutdown's first step as the window closed");
    }
    Ok(())
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

        let result = invoke_shutdown_started_while(&mut callback, true);
        let ran = started_rx.recv_timeout(Duration::from_secs(10));
        let _ = release.send(());

        assert!(result.is_ok(), "{result:?}");
        assert!(callback.is_none());
        assert!(ran.is_ok(), "the shutdown began without it");
    }

    #[test]
    fn an_open_console_waits_for_what_the_shutdown_begins_with() {
        let mut callback: Option<ShutdownStartedCallback> = Some(Box::new(|| {
            Err(lpm_common::LpmError::Tunnel("acknowledged late".into()))
        }));

        let result = invoke_shutdown_started_while(&mut callback, false);

        assert!(result.is_err());
        assert!(callback.is_none());
    }
}
