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
use std::ffi::OsStr;
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
/// Must run BEFORE any styled output is emitted — the call site is at the
/// **top of `fn main()`**, before the `--version` fast path and the
/// bare-`lpm install` fast lane both emit. The policy is single-write: a
/// re-call overwrites, but production fires this exactly once.
///
/// The `cli` arg comes from [`peek_color_choice_from_argv`] when invoked
/// pre-`Cli::parse` — the pre-scan is the only way to honor `--color`
/// before clap runs.
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

/// Argv pre-scan for `--color=<value>` or `--color <value>`.
///
/// Honors the flag before [`clap::Parser::parse`] runs, so the version /
/// bare-install fast paths in `main()` (which both emit styled output
/// before reaching `async_main` where clap parses) can resolve the policy
/// correctly. Returns `None` when the flag isn't present or carries an
/// unknown value — `init` then falls back to env + TTY detection, and
/// clap will surface the typo via its own value-enum validation later.
pub fn peek_color_choice_from_argv<I, S>(args: I) -> Option<ColorChoice>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let s = arg.as_ref().to_str()?;
        if let Some(value) = s.strip_prefix("--color=") {
            return parse_choice(value);
        }
        if s == "--color"
            && let Some(next) = iter.next()
        {
            return parse_choice(next.as_ref().to_str()?);
        }
    }
    None
}

fn parse_choice(value: &str) -> Option<ColorChoice> {
    match value {
        "always" => Some(ColorChoice::Always),
        "auto" => Some(ColorChoice::Auto),
        "never" => Some(ColorChoice::Never),
        _ => None,
    }
}

/// `FORCE_COLOR` honored per Node / npm / cargo convention:
///
/// - `0` or `false` → forced off (overrides `NO_COLOR` agreement and
///   stdout TTY detection).
/// - Any other non-empty value (`1`, `2`, `3`, `true`, …) → forced on.
/// - Unset or empty → no opinion (fall through to `NO_COLOR` / TTY).
///
/// Returning [`Option<bool>`] keeps "no opinion" distinct from
/// "forced off" so the resolver can apply `FORCE_COLOR=0` as a hard
/// override of `NO_COLOR=unset`.
fn env_force_color() -> Option<bool> {
    let raw = std::env::var_os("FORCE_COLOR")?;
    if raw.is_empty() {
        return None;
    }
    let s = raw.to_str()?;
    Some(!matches!(s, "0" | "false"))
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

#[cfg(test)]
mod tests {
    use super::*;

    // ─── peek_color_choice_from_argv ───────────────────────────────────

    #[test]
    fn peek_handles_equals_form() {
        let argv = ["lpm", "install", "--color=never"];
        assert_eq!(peek_color_choice_from_argv(argv), Some(ColorChoice::Never));
    }

    #[test]
    fn peek_handles_space_separated_form() {
        let argv = ["lpm", "--color", "always", "install"];
        assert_eq!(peek_color_choice_from_argv(argv), Some(ColorChoice::Always));
    }

    #[test]
    fn peek_accepts_auto() {
        let argv = ["lpm", "--color=auto"];
        assert_eq!(peek_color_choice_from_argv(argv), Some(ColorChoice::Auto));
    }

    #[test]
    fn peek_returns_none_when_flag_absent() {
        let argv = ["lpm", "install", "--json"];
        assert_eq!(peek_color_choice_from_argv(argv), None);
    }

    #[test]
    fn peek_returns_none_for_unknown_value() {
        // Defer to clap's value-enum validation for typo reporting; the
        // pre-scan must not panic or guess.
        let argv = ["lpm", "--color=rainbow"];
        assert_eq!(peek_color_choice_from_argv(argv), None);
    }

    #[test]
    fn peek_returns_none_when_space_value_missing() {
        let argv = ["lpm", "--color"];
        assert_eq!(peek_color_choice_from_argv(argv), None);
    }

    #[test]
    fn peek_finds_first_occurrence() {
        let argv = ["lpm", "--color=never", "--color=always", "install"];
        assert_eq!(peek_color_choice_from_argv(argv), Some(ColorChoice::Never));
    }

    // ─── env_force_color parser ────────────────────────────────────────

    fn run_with_force_color<F: FnOnce()>(value: Option<&str>, body: F) {
        // SAFETY: each test runs serially inside a single `cargo test`
        // process. `set_var` / `remove_var` are not re-entrant but the
        // sequence here is straight-line — no parallel reads of the env.
        // The serial mutex below guards against parallel test execution
        // racing on the same variable.
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap();
        let prior = std::env::var_os("FORCE_COLOR");
        // SAFETY: unsafe set_env is on stable as of Rust 1.86; the lock
        // makes this serial across this module's tests.
        unsafe {
            match value {
                Some(v) => std::env::set_var("FORCE_COLOR", v),
                None => std::env::remove_var("FORCE_COLOR"),
            }
        }
        body();
        unsafe {
            match prior {
                Some(v) => std::env::set_var("FORCE_COLOR", v),
                None => std::env::remove_var("FORCE_COLOR"),
            }
        }
    }

    #[test]
    fn force_color_unset_returns_none() {
        run_with_force_color(None, || {
            assert_eq!(env_force_color(), None);
        });
    }

    #[test]
    fn force_color_empty_returns_none() {
        run_with_force_color(Some(""), || {
            assert_eq!(env_force_color(), None);
        });
    }

    #[test]
    fn force_color_zero_returns_some_false() {
        run_with_force_color(Some("0"), || {
            assert_eq!(env_force_color(), Some(false));
        });
    }

    #[test]
    fn force_color_false_returns_some_false() {
        run_with_force_color(Some("false"), || {
            assert_eq!(env_force_color(), Some(false));
        });
    }

    #[test]
    fn force_color_one_returns_some_true() {
        run_with_force_color(Some("1"), || {
            assert_eq!(env_force_color(), Some(true));
        });
    }

    #[test]
    fn force_color_truthy_levels_return_some_true() {
        for v in ["2", "3", "true", "yes"] {
            run_with_force_color(Some(v), || {
                assert_eq!(
                    env_force_color(),
                    Some(true),
                    "FORCE_COLOR={v} should be truthy"
                );
            });
        }
    }
}
