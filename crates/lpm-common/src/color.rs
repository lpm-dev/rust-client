//! Process-wide color output policy and styling trait.
//!
//! The policy is initialized once at CLI startup and read by [`Painted`] on
//! every styling call. Callers in deep code paths see plain or ANSI-styled
//! strings based on a single global flag, with no per-call configuration
//! threading.
//!
//! ## Precedence (resolved at init time)
//!
//! 1. `--color={always,auto,never}` CLI flag (the canonical override).
//! 2. `FORCE_COLOR` env (any non-empty value) → forced on.
//! 3. `NO_COLOR` env (any non-empty value, per <https://no-color.org>) →
//!    forced off.
//! 4. stdout `is_terminal()` → auto.
//!
//! ## Why a trait rather than per-method gating
//!
//! 800+ direct `OwoColorize` call sites across the workspace would each need
//! a policy check at the call site. Shadowing `OwoColorize` with a
//! [`Painted`] trait that already consults the policy gives every call site
//! the gate for free; migrating a file is mechanical
//! (`use owo_colors::OwoColorize` → `use lpm_common::color::Painted`).
//!
//! Chained calls (`text.green().bold()`) work because [`Painted`] is
//! implemented for `String` as well as `&str` — the inner `green()` returns
//! a `String` that the outer `bold()` picks back up on the same trait.

use std::sync::atomic::{AtomicU8, Ordering};

/// Internal tristate: not-yet-initialized, enabled, disabled. Using a single
/// `AtomicU8` instead of `OnceLock<bool>` so reads on the hot path are a
/// single relaxed load — no spinlock, no allocation, branch-predictable.
static STATE: AtomicU8 = AtomicU8::new(STATE_UNINIT);

const STATE_UNINIT: u8 = 0;
const STATE_ENABLED: u8 = 1;
const STATE_DISABLED: u8 = 2;

/// Set the global color state. Called exactly once by the CLI entry point
/// after the `--color` flag is parsed. Re-calls overwrite (useful in tests
/// that need to flip the policy between assertions); production code calls
/// this once at startup.
pub fn set_enabled(enabled: bool) {
    STATE.store(
        if enabled {
            STATE_ENABLED
        } else {
            STATE_DISABLED
        },
        Ordering::Relaxed,
    );
}

/// Read the current color state. Defaults to `true` when [`set_enabled`] has
/// not been called yet — the early-init paths that run before the CLI parse
/// don't style output, so this default is only exercised in tests that
/// inspect helpers without first calling `set_enabled`.
#[inline]
pub fn enabled() -> bool {
    // Relaxed is correct: we only need atomicity on the byte itself, not
    // ordering relative to other memory.
    matches!(STATE.load(Ordering::Relaxed), STATE_ENABLED | STATE_UNINIT)
}

/// Policy-aware shadow of the `OwoColorize` color/style methods.
///
/// Every method returns a plain [`String`] when the policy is disabled and
/// an ANSI-wrapped string when enabled. Chainable on `String` so
/// `text.green().bold()` works the same as the `OwoColorize` original.
///
/// Only the methods actually used in the workspace are shadowed (verified by
/// a `grep -E` audit on 2026-05-15). Adding a new color/style is a one-line
/// addition here.
pub trait Painted {
    fn green(&self) -> String;
    fn red(&self) -> String;
    fn yellow(&self) -> String;
    fn cyan(&self) -> String;
    fn blue(&self) -> String;
    fn magenta(&self) -> String;
    fn white(&self) -> String;
    fn bold(&self) -> String;
    fn dimmed(&self) -> String;
    fn italic(&self) -> String;
    fn underline(&self) -> String;
    fn bright_red(&self) -> String;
    fn bright_green(&self) -> String;
    fn bright_yellow(&self) -> String;
    fn bright_cyan(&self) -> String;
    fn bright_blue(&self) -> String;
    fn bright_magenta(&self) -> String;
    fn bright_white(&self) -> String;
    fn bright_black(&self) -> String;
    fn on_red(&self) -> String;
}

impl<T: std::fmt::Display + ?Sized> Painted for T {
    fn green(&self) -> String {
        paint(self, "\x1b[32m", "\x1b[39m")
    }
    fn red(&self) -> String {
        paint(self, "\x1b[31m", "\x1b[39m")
    }
    fn yellow(&self) -> String {
        paint(self, "\x1b[33m", "\x1b[39m")
    }
    fn cyan(&self) -> String {
        paint(self, "\x1b[36m", "\x1b[39m")
    }
    fn blue(&self) -> String {
        paint(self, "\x1b[34m", "\x1b[39m")
    }
    fn magenta(&self) -> String {
        paint(self, "\x1b[35m", "\x1b[39m")
    }
    fn white(&self) -> String {
        paint(self, "\x1b[37m", "\x1b[39m")
    }
    fn bold(&self) -> String {
        paint(self, "\x1b[1m", "\x1b[22m")
    }
    fn dimmed(&self) -> String {
        paint(self, "\x1b[2m", "\x1b[22m")
    }
    fn italic(&self) -> String {
        paint(self, "\x1b[3m", "\x1b[23m")
    }
    fn underline(&self) -> String {
        paint(self, "\x1b[4m", "\x1b[24m")
    }
    fn bright_red(&self) -> String {
        paint(self, "\x1b[91m", "\x1b[39m")
    }
    fn bright_green(&self) -> String {
        paint(self, "\x1b[92m", "\x1b[39m")
    }
    fn bright_yellow(&self) -> String {
        paint(self, "\x1b[93m", "\x1b[39m")
    }
    fn bright_cyan(&self) -> String {
        paint(self, "\x1b[96m", "\x1b[39m")
    }
    fn bright_blue(&self) -> String {
        paint(self, "\x1b[94m", "\x1b[39m")
    }
    fn bright_magenta(&self) -> String {
        paint(self, "\x1b[95m", "\x1b[39m")
    }
    fn bright_white(&self) -> String {
        paint(self, "\x1b[97m", "\x1b[39m")
    }
    fn bright_black(&self) -> String {
        paint(self, "\x1b[90m", "\x1b[39m")
    }
    fn on_red(&self) -> String {
        paint(self, "\x1b[41m", "\x1b[49m")
    }
}

#[inline]
fn paint<T: std::fmt::Display + ?Sized>(value: &T, open: &str, close: &str) -> String {
    if enabled() {
        format!("{open}{value}{close}")
    } else {
        value.to_string()
    }
}

/// Pure resolver: turn a `(cli, force, no_color, is_tty)` quartet into the
/// resolved color-enabled state. Extracted so unit tests can exercise the
/// precedence chain without touching the process environment.
pub fn resolve(cli: Option<ColorChoice>, force: bool, no_color: bool, is_tty: bool) -> bool {
    match cli {
        Some(ColorChoice::Always) => true,
        Some(ColorChoice::Never) => false,
        Some(ColorChoice::Auto) | None => {
            if force {
                true
            } else if no_color {
                false
            } else {
                is_tty
            }
        }
    }
}

/// Color-output mode requested by the user. Mirrors cargo's `--color` enum
/// for familiarity.
///
/// Kept in `lpm-common` so the same enum value passes through any crate that
/// needs to log the resolved choice (e.g., `lpm doctor` reporting the active
/// policy source).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColorChoice {
    Always,
    Auto,
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that mutate `STATE` serialize on this mutex so default parallel
    /// `cargo test` doesn't race them against each other. Per-module rather
    /// than per-process: only the four `painted_*` tests below touch shared
    /// state.
    static STATE_LOCK: Mutex<()> = Mutex::new(());

    // ─── resolve() — precedence chain ─────────────────────────────────

    #[test]
    fn cli_always_wins_over_no_color_env() {
        assert!(resolve(
            Some(ColorChoice::Always),
            /*force*/ false,
            /*no_color*/ true,
            /*is_tty*/ false
        ));
    }

    #[test]
    fn cli_never_wins_over_force_color_env() {
        assert!(!resolve(
            Some(ColorChoice::Never),
            /*force*/ true,
            /*no_color*/ false,
            /*is_tty*/ true
        ));
    }

    #[test]
    fn cli_auto_yields_to_force_color() {
        assert!(resolve(
            Some(ColorChoice::Auto),
            /*force*/ true,
            /*no_color*/ false,
            /*is_tty*/ false
        ));
    }

    #[test]
    fn cli_auto_yields_to_no_color() {
        assert!(!resolve(
            Some(ColorChoice::Auto),
            /*force*/ false,
            /*no_color*/ true,
            /*is_tty*/ true
        ));
    }

    #[test]
    fn force_color_beats_no_color_when_both_set() {
        // Precedence pins FORCE_COLOR above NO_COLOR — Node/npm convention.
        assert!(resolve(
            None, /*force*/ true, /*no_color*/ true, false
        ));
    }

    #[test]
    fn defaults_to_is_tty_when_nothing_overrides() {
        assert!(resolve(None, false, false, true));
        assert!(!resolve(None, false, false, false));
    }

    // ─── Painted — gated ANSI emission ────────────────────────────────

    #[test]
    fn painted_emits_ansi_when_enabled() {
        let _g = STATE_LOCK.lock().unwrap();
        set_enabled(true);
        assert_eq!("hi".green(), "\x1b[32mhi\x1b[39m");
        assert_eq!("hi".bold(), "\x1b[1mhi\x1b[22m");
    }

    #[test]
    fn painted_returns_plain_when_disabled() {
        let _g = STATE_LOCK.lock().unwrap();
        set_enabled(false);
        assert_eq!("hi".green(), "hi");
        assert_eq!("hi".bold(), "hi");
        assert_eq!("hi".dimmed(), "hi");
        set_enabled(true);
    }

    #[test]
    fn painted_chains_through_string() {
        let _g = STATE_LOCK.lock().unwrap();
        set_enabled(true);
        let s = "hi".green().bold();
        assert!(s.contains("\x1b[32m"));
        assert!(s.contains("\x1b[1m"));
    }

    #[test]
    fn painted_chain_collapses_when_disabled() {
        let _g = STATE_LOCK.lock().unwrap();
        set_enabled(false);
        let s = "hi".green().bold();
        assert_eq!(s, "hi");
        set_enabled(true);
    }
}
