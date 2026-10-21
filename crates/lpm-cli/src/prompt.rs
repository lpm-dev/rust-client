//! Shared prompt helpers for interactive CLI commands.
//!
//! Lifted from `commands::add` so both the add command
//! and `upgrade.rs` (and any future interactive command) share the same
//! Ctrl+C / cancellation handling.

use lpm_common::LpmError;

/// Sanitizes externally controlled text before handing it to an interactive TUI.
pub fn untrusted(text: impl std::fmt::Display) -> String {
    lpm_common::sanitize_terminal_inline(&text.to_string()).into_owned()
}

/// Exit status for a command the user ended at an interactive prompt.
pub const PROMPT_CANCELLED_EXIT_CODE: i32 = 130;

/// Cancellation-aware error mapping for cliclack prompt results.
pub trait PromptResultExt<T> {
    /// Map a prompt failure to an [`LpmError`], treating a cancelled prompt as
    /// the user ending the command.
    ///
    /// cliclack reports Esc and Ctrl-C alike as
    /// [`std::io::ErrorKind::Interrupted`] after rendering its own
    /// `Operation cancelled.` footer. A cancellation becomes
    /// [`LpmError::ExitCode`] with the SIGINT status, which unwinds through the
    /// caller's cleanup and exits without an error report. Any other failure is
    /// converted by `other`.
    fn map_prompt_err(self, other: impl FnOnce(std::io::Error) -> LpmError) -> Result<T, LpmError>;
}

impl<T> PromptResultExt<T> for std::io::Result<T> {
    #[inline]
    fn map_prompt_err(self, other: impl FnOnce(std::io::Error) -> LpmError) -> Result<T, LpmError> {
        self.map_err(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted {
                LpmError::ExitCode(PROMPT_CANCELLED_EXIT_CODE)
            } else {
                other(error)
            }
        })
    }
}

/// Convert a cliclack error to an LpmError.
/// Detects Ctrl+C (user cancellation) and exits cleanly with code 130.
pub fn prompt_err(e: impl std::fmt::Display) -> LpmError {
    let msg = e.to_string();
    // cliclack returns "user cancelled" or similar on Ctrl+C
    if msg.contains("cancel") || msg.contains("interrupt") {
        eprintln!("\n  Operation cancelled.");
        std::process::exit(PROMPT_CANCELLED_EXIT_CODE);
    }
    LpmError::Registry(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_prompt_becomes_the_interrupt_exit_status() {
        let result: std::io::Result<()> = Err(std::io::ErrorKind::Interrupted.into());

        let error = result
            .map_prompt_err(|_| unreachable!("a cancellation must not reach the caller's mapping"))
            .unwrap_err();

        assert!(matches!(
            error,
            LpmError::ExitCode(PROMPT_CANCELLED_EXIT_CODE)
        ));
    }

    #[test]
    fn other_prompt_failures_use_the_caller_mapping() {
        let result: std::io::Result<()> = Err(std::io::Error::other("terminal closed"));

        let error = result
            .map_prompt_err(|error| LpmError::Script(format!("prompt failed: {error}")))
            .unwrap_err();

        assert!(
            matches!(&error, LpmError::Script(message) if message == "prompt failed: terminal closed"),
            "{error:?}"
        );
    }

    #[test]
    fn answered_prompts_pass_through_unchanged() {
        let result: std::io::Result<&str> = Ok("answer");

        assert_eq!(
            result
                .map_prompt_err(|_| unreachable!("an answer has no failure to map"))
                .unwrap(),
            "answer"
        );
    }
}
