//! `lpm-sandbox-helper.exe` — AppContainer launcher.
//!
//! See [`crates/lpm-sandbox/src/helper_protocol.rs`](../helper_protocol.rs)
//! for the argv contract and design rationale.
//!
//! ## Why a separate binary
//!
//! Stable Rust's `std::process::Command::spawn` uses `STARTUPINFOW`,
//! not `STARTUPINFOEXW`. AppContainer's `SECURITY_CAPABILITIES` must
//! be attached at process-create time via
//! `STARTUPINFOEX.lpAttributeList`. The
//! `windows_process_extensions_raw_attribute` feature
//! ([rust-lang/rust#114854](https://github.com/rust-lang/rust/issues/114854))
//! is the gated API for injecting raw attribute lists into
//! `Command` — still nightly on Rust 1.95 (the workspace MSRV).
//! Rather than wait for stabilization or `mem::transmute` into
//! `Child`'s private layout, the parent (`lpm.exe`) spawns this
//! helper via the regular `Command::spawn`, and this helper does
//! the `STARTUPINFOEXW` dance itself.
//!
//! ## Non-Windows builds
//!
//! `cargo build --workspace` on Linux / macOS compiles every
//! declared `[[bin]]` target — Cargo does NOT silently skip
//! emission. To keep workspace CI green on POSIX runners we ship an
//! explicit non-Windows stub `main()` that prints a one-line
//! diagnostic and exits with a non-zero status. The release
//! workflow only copies the helper into `cli-win32-x64`, so the
//! stub never reaches end users (see release.yml and
//! `npm/cli-win32-x64/package.json`).

#[cfg(target_os = "windows")]
fn main() {
    windows_main::run();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    // The helper is Windows-only. This stub exists so the workspace
    // builds cleanly on POSIX runners; the helper binary is never
    // invoked from a non-Windows `lpm.exe` (the factory in
    // `crates/lpm-sandbox/src/lib.rs::platform_backend` cfg-gates
    // the AppContainer path on `target_os = "windows"`).
    eprintln!(
        "lpm-sandbox-helper is Windows-only and should never be invoked on a \
         non-Windows host. If you reached this error message, the npm package's \
         platform selection or your local build wiring is mis-shipping the \
         helper across platforms."
    );
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
mod windows_main {
    use lpm_sandbox::helper_protocol::{HelperArgs, ParseError, parse_argv};

    /// Argv parse failed for a reason other than version mismatch.
    /// Distinct exit code so the parent's integration tests can
    /// tell argv shape breaks apart from runtime failures.
    pub(crate) const EXIT_ARGV_PARSE: i32 = 64;
    /// Argv parsed but `--protocol-version` didn't match
    /// [`lpm_sandbox::helper_protocol::PROTOCOL_VERSION`]. Distinct
    /// from `EXIT_ARGV_PARSE` so the integration test
    /// `helper_rejects_protocol_version_mismatch` can pin the exact
    /// failure mode and the parent's locator can route a
    /// version-mismatch fallback differently from a generic broken
    /// helper.
    pub(crate) const EXIT_PROTOCOL_MISMATCH: i32 = 65;
    /// Helper ran but AppContainer setup or spawn failed. The
    /// stderr line carries the named reason.
    pub(crate) const EXIT_HELPER_FAILED: i32 = 66;

    pub fn run() -> ! {
        let argv = std::env::args_os().skip(1);
        let args = match parse_argv(argv) {
            Ok(args) => args,
            Err(e) => {
                eprintln!("lpm-sandbox-helper: argv parse failed: {e}");
                // ProtocolVersionMismatch is its own exit code so
                // the parent can distinguish "helper present but
                // stale" from "helper present and accepting argv
                // but AppContainer construction failed."
                let code = match e {
                    ParseError::ProtocolVersionMismatch { .. } => EXIT_PROTOCOL_MISMATCH,
                    _ => EXIT_ARGV_PARSE,
                };
                std::process::exit(code);
            }
        };
        match dispatch(args) {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(msg) => {
                eprintln!("lpm-sandbox-helper: {msg}");
                std::process::exit(EXIT_HELPER_FAILED);
            }
        }
    }

    /// AppContainer setup / spawn / wait. Returns the lifecycle
    /// child's exit code on the success path; an `Err(String)` here
    /// is a setup-time failure (DACL grant, profile create, etc.)
    /// and gets surfaced on stderr with [`EXIT_HELPER_FAILED`].
    fn dispatch(args: HelperArgs) -> Result<i32, String> {
        lpm_sandbox::helper_appcontainer::run_appcontainer_spawn(args).map_err(|e| e.to_string())
    }
}
