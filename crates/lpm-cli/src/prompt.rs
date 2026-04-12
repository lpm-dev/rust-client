//! Shared prompt helpers for interactive CLI commands.
//!
//! Lifted from `commands::add` during Phase 32 Phase 7 so both `add.rs`
//! and `upgrade.rs` (and any future interactive command) share the same
//! Ctrl+C / cancellation handling.

use lpm_common::LpmError;

/// Convert a cliclack error to an LpmError.
/// Detects Ctrl+C (user cancellation) and exits cleanly with code 130.
pub fn prompt_err(e: impl std::fmt::Display) -> LpmError {
    let msg = e.to_string();
    // cliclack returns "user cancelled" or similar on Ctrl+C
    if msg.contains("cancel") || msg.contains("interrupt") {
        eprintln!("\n  Operation cancelled.");
        std::process::exit(130); // Standard SIGINT exit code
    }
    LpmError::Registry(msg)
}
