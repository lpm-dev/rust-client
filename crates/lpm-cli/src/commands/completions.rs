//! `lpm completions <shell>` — emit a shell completion script to stdout.
//!
//! Mirrors the convention used by `gh`, `cargo`, `pnpm`, `bun`, and `npm`:
//! the user pipes the output into the shell's completion-load path
//! (`~/.zfunc/_lpm`, `/etc/bash_completion.d/lpm`, etc.) or sources it
//! directly from a profile snippet.
//!
//! Examples:
//! ```text
//! lpm completions zsh > "${fpath[1]}/_lpm"
//! lpm completions bash > /etc/bash_completion.d/lpm
//! lpm completions fish > ~/.config/fish/completions/lpm.fish
//! lpm completions powershell | Out-String | Invoke-Expression
//! ```
//!
//! The generator is driven by the live `Cli` clap definition, so flags
//! and subcommands stay in sync with the binary at every release.

use clap::CommandFactory;
use clap_complete::Shell;
use lpm_common::LpmError;
use std::io;

/// Run the `lpm completions <shell>` command.
///
/// Writes the completion script for `shell` to stdout. The `bin_name`
/// argument is hardcoded to `"lpm"` — the user-facing alias users actually
/// invoke — rather than `env!("CARGO_BIN_NAME")` (which would emit
/// `lpm-rs` / `lpm-bin` and produce completions that never trigger).
pub fn run(shell: Shell) -> Result<(), LpmError> {
    let mut cmd = crate::Cli::command();
    clap_complete::generate(shell, &mut cmd, "lpm", &mut io::stdout());
    Ok(())
}
