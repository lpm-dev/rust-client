//! CLI-layer color-policy init.
//!
//! The policy state and [`Painted`] trait live in [`lpm_common::color`] so
//! every crate can shadow `OwoColorize` through one shared trait. This
//! module owns the CLI-only pieces:
//!
//! - [`ColorChoice`] clap [`ValueEnum`].
//! - [`init`] — parses `(--color, FORCE_COLOR, NO_COLOR, is_terminal)`,
//!   sets the global state in [`lpm_common::color`], also calls
//!   [`owo_colors::set_override`] so any future `if_supports_color` call
//!   sites obey the same policy, and installs a no-color [`cliclack`] theme
//!   when disabled.
//! - [`NoColorTheme`] — cliclack [`Theme`] override that returns
//!   [`console::Style::new`] (unstyled) for every color hook and emits the
//!   layout symbols without any ANSI wrapping.

use clap::ValueEnum;
use cliclack::{Theme, ThemeState};
use console::{Emoji, Style};
use lpm_common::color::{self, ColorChoice as ResolvedChoice};
use std::io::IsTerminal;

/// Color-output mode requested on the CLI. Mirrors cargo's `--color` enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[clap(rename_all = "lower")]
pub enum ColorChoice {
    /// Always emit ANSI, even when stdout isn't a TTY.
    Always,
    /// Respect `FORCE_COLOR` / `NO_COLOR`, then fall back to stdout TTY
    /// detection. Default.
    Auto,
    /// Never emit ANSI.
    Never,
}

impl From<ColorChoice> for ResolvedChoice {
    fn from(c: ColorChoice) -> Self {
        match c {
            ColorChoice::Always => Self::Always,
            ColorChoice::Auto => Self::Auto,
            ColorChoice::Never => Self::Never,
        }
    }
}

/// Resolve the color policy and apply it process-wide.
///
/// Must run BEFORE any styled output is emitted — call site is at the top of
/// `async_main` after `Cli::parse`. The policy is single-write: re-calls
/// overwrite, but in production this fires exactly once.
pub fn init(cli: Option<ColorChoice>) {
    let force = env_force_color();
    let no_color = env_no_color();
    let is_tty = std::io::stdout().is_terminal();
    let enabled = color::resolve(cli.map(Into::into), force, no_color, is_tty);
    color::set_enabled(enabled);
    owo_colors::set_override(enabled);
    if !enabled {
        cliclack::set_theme(NoColorTheme);
    }
}

/// `FORCE_COLOR` honored when set to any non-empty value, per the Node /
/// npm convention. Empty value is treated as unset to match how shells
/// expand a literally-empty env var.
fn env_force_color() -> bool {
    std::env::var_os("FORCE_COLOR").is_some_and(|v| !v.is_empty())
}

/// `NO_COLOR` honored when set to any non-empty value, per
/// <https://no-color.org>.
fn env_no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// cliclack [`Theme`] that strips every color hook to [`Style::new()`].
///
/// Symbols (`◇`, `│`, `✓`, `▲`, etc.) are plain UTF-8 — they pass through
/// unchanged. Only the surrounding ANSI wrappers are suppressed. Override
/// every method on the trait that wraps a symbol in a color so the
/// `info_symbol` / `warning_symbol` / `error_symbol` / `active_symbol` /
/// `submit_symbol` defaults don't sneak ANSI back in.
pub struct NoColorTheme;

impl Theme for NoColorTheme {
    fn bar_color(&self, _state: &ThemeState) -> Style {
        Style::new()
    }
    fn state_symbol_color(&self, _state: &ThemeState) -> Style {
        Style::new()
    }
    fn info_symbol(&self) -> String {
        Emoji("●", "•").to_string()
    }
    fn warning_symbol(&self) -> String {
        Emoji("▲", "!").to_string()
    }
    fn error_symbol(&self) -> String {
        Emoji("■", "x").to_string()
    }
    fn active_symbol(&self) -> String {
        Emoji("◆", "*").to_string()
    }
    fn submit_symbol(&self) -> String {
        Emoji("◇", "o").to_string()
    }
    fn radio_symbol(&self, state: &ThemeState, selected: bool) -> String {
        match state {
            ThemeState::Active if selected => Emoji("●", ">").to_string(),
            ThemeState::Active => Emoji("○", " ").to_string(),
            _ => String::new(),
        }
    }
    fn checkbox_symbol(&self, state: &ThemeState, selected: bool, _active: bool) -> String {
        // Without color, the active/inactive distinction collapses (the
        // upstream theme differentiates by hue, not glyph). Render selected
        // vs unselected via the glyph alone.
        match state {
            ThemeState::Active | ThemeState::Error(_) => {
                if selected {
                    Emoji("◼", "[+]").to_string()
                } else {
                    Emoji("◻", "[ ]").to_string()
                }
            }
            _ => String::new(),
        }
    }
    fn checkbox_style(&self, _state: &ThemeState, _selected: bool, _active: bool) -> Style {
        Style::new()
    }
    fn input_style(&self, _state: &ThemeState) -> Style {
        Style::new()
    }
    fn placeholder_style(&self, _state: &ThemeState) -> Style {
        Style::new()
    }
}
