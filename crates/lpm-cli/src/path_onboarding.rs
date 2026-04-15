//! PATH onboarding banner (Phase 37 M3.6).
//!
//! After a successful `lpm install -g`, the package's commands live as
//! shims inside `~/.lpm/bin/`. Those shims are useless until that
//! directory is on the user's `$PATH`. Without proactive guidance the
//! user types `eslint`, gets "command not found," and has no idea why.
//!
//! M3.6 adds a one-time banner that:
//!
//! 1. Detects whether `bin_dir` is already on `$PATH`.
//! 2. If on PATH: silently writes the marker so we never nag again,
//!    even if PATH later changes.
//! 3. If NOT on PATH AND the marker doesn't exist: prints a shell-
//!    specific export line, then writes the marker.
//! 4. If the marker already exists: does nothing visible (we already
//!    informed the user once; we trust them not to need a reminder
//!    after every install).
//!
//! The marker lives at `~/.lpm/.path-hint-shown` (already plumbed via
//! `LpmRoot::path_hint_marker`). Its presence — not its contents — is
//! the signal; we still touch a small body so an operator inspecting
//! the file sees what it's for.
//!
//! ## Why a struct return value
//!
//! Callers that emit JSON (e.g. `install -g --json`) need the hint
//! surfaced in their structured output, not as side-channel stdout
//! chatter. `PathHintReport` lets `print_success` include the data
//! verbatim. In human mode, this module prints the banner directly
//! (stdout via `crate::output`) and the caller doesn't have to thread
//! formatting through.
//!
//! ## Testability
//!
//! The "is bin_dir on PATH?" check and the shell detection are pure
//! functions with explicit `&str` inputs (`is_bin_dir_on_path_str`,
//! `detect_shell_kind_from_env`). Side-effecting integration is in
//! `maybe_show_path_hint`, which composes them with env reads and
//! marker I/O. The pure functions get the bulk of the test coverage.

use crate::output;
use lpm_common::LpmRoot;
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

/// Per-platform PATH separator. Compile-time constant — `cfg`-gated
/// because the alternative (`std::env::join_paths` and similar) is
/// overkill for a single character.
#[cfg(target_os = "windows")]
const PATH_SEP: char = ';';
#[cfg(not(target_os = "windows"))]
const PATH_SEP: char = ':';

/// Outcome of a single onboarding-hint pass. Returned to the caller
/// for structured-output integration. `print_success` in install_global
/// embeds the relevant fields in its JSON body.
#[derive(Debug, Clone)]
pub struct PathHintReport {
    /// Where the shims live (`~/.lpm/bin/`). Absolute path.
    pub bin_dir: PathBuf,
    /// True when `bin_dir` was found on the resolved `$PATH`.
    pub on_path: bool,
    /// True when the marker already existed at the start of this call —
    /// tells the caller "we've informed this user before."
    pub marker_already_present: bool,
    /// True when this invocation actually printed the banner (only
    /// happens once per host: NOT on PATH AND no prior marker).
    pub banner_printed: bool,
}

/// Detected shell kind for the banner's instructions. Unknown is the
/// fallback when `$SHELL` is empty / unrecognised — we still print a
/// generic "add to your PATH" line so the user gets *something* useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Pwsh,
    Cmd,
    Unknown,
}

impl ShellKind {
    /// Filename of the shell's interactive-init file, relative to `$HOME`.
    /// `None` for Unknown / Cmd / Pwsh where we don't want to advertise
    /// a specific path (multiple plausible locations on Windows; we'd
    /// rather say "add to your PATH" than name the wrong file).
    fn rc_filename(self) -> Option<&'static str> {
        match self {
            ShellKind::Bash => Some(".bashrc"),
            ShellKind::Zsh => Some(".zshrc"),
            ShellKind::Fish => Some(".config/fish/config.fish"),
            ShellKind::Pwsh | ShellKind::Cmd | ShellKind::Unknown => None,
        }
    }

    /// Shell-syntax line that prepends `bin_dir` to PATH.
    fn export_line(self, bin_dir: &Path) -> String {
        let p = bin_dir.display();
        match self {
            ShellKind::Bash | ShellKind::Zsh => format!(r#"export PATH="{p}:$PATH""#),
            ShellKind::Fish => format!(r#"set -gx PATH {p} $PATH"#),
            ShellKind::Pwsh => format!(r#"$Env:PATH = "{p};$Env:PATH""#),
            ShellKind::Cmd => format!(r#"setx PATH "{p};%PATH%""#),
            ShellKind::Unknown => format!(r#"PATH="{p}:$PATH""#),
        }
    }
}

/// Pure detection from a `$SHELL`-shaped string. Tests pass arbitrary
/// values; production calls `detect_shell_kind` which reads `$SHELL`.
pub fn detect_shell_kind_from_env(shell_env: Option<&str>) -> ShellKind {
    // Windows: `$SHELL` is rarely set; fall back to `$ComSpec` /
    // `$PSModulePath` heuristics. On non-Windows hosts these branches
    // are unreachable but harmless.
    let shell = match shell_env {
        Some(s) if !s.is_empty() => s.to_lowercase(),
        _ => return ShellKind::Unknown,
    };
    // `$SHELL` is a path like `/bin/zsh` (or `C:\...\pwsh.exe` on
    // Windows / WSL). `Path::file_name` only honours the host
    // platform's separator, so on Unix we'd misidentify a Windows-
    // style path as one giant filename. Split on both separators
    // manually for portability.
    let basename = shell
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(shell.as_str())
        .to_lowercase();

    // Strip a trailing `.exe` so Windows-Git-Bash-style paths still match.
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);

    match basename {
        "bash" => ShellKind::Bash,
        "zsh" => ShellKind::Zsh,
        "fish" => ShellKind::Fish,
        "pwsh" | "powershell" => ShellKind::Pwsh,
        "cmd" => ShellKind::Cmd,
        _ => ShellKind::Unknown,
    }
}

fn detect_shell_kind() -> ShellKind {
    detect_shell_kind_from_env(std::env::var("SHELL").ok().as_deref())
}

/// Pure PATH-membership check. Splits `path_env` on the platform
/// separator, normalises trailing separators, compares against
/// `bin_dir`. Symlinks are NOT resolved — we want to match what the
/// user literally wrote in their shell init (cheap + matches their
/// mental model). False negatives there would resurface as a banner
/// they've already addressed; the marker dampens that to one printing.
pub fn is_bin_dir_on_path_str(bin_dir: &Path, path_env: &str) -> bool {
    if path_env.is_empty() {
        return false;
    }
    for entry in path_env.split(PATH_SEP) {
        if entry.is_empty() {
            continue;
        }
        let trimmed: &str = entry.trim_end_matches(['/', '\\']);
        if trimmed.is_empty() {
            // This was the root — `/` or `\\`. Not equal to bin_dir.
            continue;
        }
        if Path::new(trimmed) == bin_dir {
            return true;
        }
    }
    false
}

fn is_bin_dir_on_path(bin_dir: &Path) -> bool {
    let path_env = std::env::var("PATH").unwrap_or_default();
    is_bin_dir_on_path_str(bin_dir, &path_env)
}

/// Idempotent banner pass. Safe to call after every successful global
/// install — the marker check makes the visible output strictly
/// at-most-once per host, and the on-PATH check short-circuits before
/// any printing.
///
/// Marker write failures are logged at debug level and don't fail the
/// caller. The worst case is the banner re-prints next install — mildly
/// annoying, never harmful.
pub fn maybe_show_path_hint(root: &LpmRoot, json_output: bool) -> PathHintReport {
    let bin_dir = root.bin_dir();
    let marker_path = root.path_hint_marker();
    let marker_already_present = marker_path.exists();
    let on_path = is_bin_dir_on_path(&bin_dir);

    // Two no-banner branches:
    //   - on_path: silently mark; we never need to nag this user.
    //   - marker_already_present: we've nagged before. Trust them.
    //     (Even if PATH was changed away — re-asking would be hostile.)
    if on_path || marker_already_present {
        if !marker_already_present {
            write_marker_best_effort(&marker_path);
        }
        return PathHintReport {
            bin_dir,
            on_path,
            marker_already_present,
            banner_printed: false,
        };
    }

    // First run, not on PATH. Print (only in human mode) and mark.
    let banner_printed = if json_output {
        // JSON callers surface `path_hint` in their own output; this
        // module doesn't write to stdout under --json so the JSON
        // response stays a single document.
        false
    } else {
        print_banner(&bin_dir, detect_shell_kind());
        true
    };
    write_marker_best_effort(&marker_path);

    PathHintReport {
        bin_dir,
        on_path: false,
        marker_already_present: false,
        banner_printed,
    }
}

fn print_banner(bin_dir: &Path, shell: ShellKind) {
    println!();
    output::warn(&format!(
        "{} is not on your PATH.",
        bin_dir.display().to_string().bold()
    ));
    output::info("Globally-installed command shims live there. Add it to your shell init:");

    println!();
    println!("    {}", shell.export_line(bin_dir).bold());
    println!();

    match shell.rc_filename() {
        Some(rc) => output::info(&format!(
            "Then `source ~/{rc}` (or open a new shell) to pick up the change.",
        )),
        None => output::info(
            "Then open a new shell (or run the equivalent reload command for your shell) \
             to pick up the change.",
        ),
    }
    println!();
    output::info(
        "(This message is shown only once. To suppress earlier, run `lpm global bin` to \
         confirm the directory and add it manually.)",
    );
    println!();
}

fn write_marker_best_effort(marker_path: &Path) {
    if let Some(parent) = marker_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::debug!(
            "path-hint marker: could not create parent {}: {e}",
            parent.display()
        );
        return;
    }
    if let Err(e) = std::fs::write(
        marker_path,
        "lpm: PATH onboarding hint shown - see `lpm global bin`\n",
    ) {
        tracing::debug!(
            "path-hint marker: write to {} failed: {e}",
            marker_path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests in this module mutate `$PATH`, which is process-global and
    /// shared across the whole `cargo test` binary. Parallel access
    /// would let one test's set_var stomp another's read mid-call.
    /// Serialise via this lock — the integration-flavoured tests below
    /// take it, the pure unit tests don't need to.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Set `$PATH` for the duration of `body`, restore on drop.
    /// `body` runs while we hold the env lock — no parallel test can
    /// observe a torn PATH state. RAII via a guard struct: cleanup
    /// runs even on panic.
    fn with_path_env<R>(value: &str, body: impl FnOnce() -> R) -> R {
        struct PathGuard {
            prev: Option<String>,
        }
        impl Drop for PathGuard {
            fn drop(&mut self) {
                unsafe {
                    match self.prev.take() {
                        Some(v) => std::env::set_var("PATH", v),
                        None => std::env::remove_var("PATH"),
                    }
                }
            }
        }
        // Mutex poisoning is fine for tests — recover and continue;
        // the next test will set PATH explicitly anyway.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("PATH").ok();
        unsafe {
            std::env::set_var("PATH", value);
        }
        let _restore = PathGuard { prev };
        body()
    }

    // ─── Shell detection ─────────────────────────────────────────────

    #[test]
    fn detect_shell_recognises_common_unix_shells() {
        assert_eq!(
            detect_shell_kind_from_env(Some("/bin/bash")),
            ShellKind::Bash
        );
        assert_eq!(
            detect_shell_kind_from_env(Some("/usr/bin/zsh")),
            ShellKind::Zsh
        );
        assert_eq!(
            detect_shell_kind_from_env(Some("/opt/homebrew/bin/fish")),
            ShellKind::Fish
        );
    }

    #[test]
    fn detect_shell_handles_windows_exe_suffix() {
        assert_eq!(
            detect_shell_kind_from_env(Some("C:\\Program Files\\PowerShell\\7\\pwsh.exe")),
            ShellKind::Pwsh
        );
        assert_eq!(
            detect_shell_kind_from_env(Some("C:\\Windows\\System32\\cmd.exe")),
            ShellKind::Cmd
        );
    }

    #[test]
    fn detect_shell_is_case_insensitive() {
        assert_eq!(detect_shell_kind_from_env(Some("/bin/ZSH")), ShellKind::Zsh);
    }

    #[test]
    fn detect_shell_returns_unknown_for_empty_or_unrecognised() {
        assert_eq!(detect_shell_kind_from_env(None), ShellKind::Unknown);
        assert_eq!(detect_shell_kind_from_env(Some("")), ShellKind::Unknown);
        assert_eq!(
            detect_shell_kind_from_env(Some("/bin/tcsh")),
            ShellKind::Unknown
        );
    }

    // ─── Export-line shape per shell ─────────────────────────────────

    #[test]
    fn export_line_includes_bin_dir_and_shell_appropriate_syntax() {
        let bin_dir = Path::new("/home/user/.lpm/bin");
        // bash uses double-quoted export
        let bash = ShellKind::Bash.export_line(bin_dir);
        assert!(bash.starts_with("export PATH="));
        assert!(bash.contains("/home/user/.lpm/bin"));
        assert!(bash.contains("$PATH"));

        // zsh uses identical syntax to bash here
        assert_eq!(ShellKind::Zsh.export_line(bin_dir), bash);

        // fish has its own set syntax
        let fish = ShellKind::Fish.export_line(bin_dir);
        assert!(fish.starts_with("set -gx PATH"));
        assert!(fish.contains("/home/user/.lpm/bin"));

        // pwsh uses $Env:PATH
        let pwsh = ShellKind::Pwsh.export_line(bin_dir);
        assert!(pwsh.contains("$Env:PATH"));

        // cmd uses setx
        let cmd_line = ShellKind::Cmd.export_line(bin_dir);
        assert!(cmd_line.starts_with("setx PATH"));
        assert!(cmd_line.contains("%PATH%"));

        // Unknown still produces a usable POSIX-ish export
        let unknown = ShellKind::Unknown.export_line(bin_dir);
        assert!(unknown.contains("/home/user/.lpm/bin"));
    }

    // ─── PATH-membership check ───────────────────────────────────────

    fn join_path(parts: &[&str]) -> String {
        parts.join(&PATH_SEP.to_string())
    }

    #[test]
    fn path_member_check_finds_exact_match() {
        let bin = Path::new("/home/user/.lpm/bin");
        let path = join_path(&["/usr/local/bin", "/home/user/.lpm/bin", "/usr/bin"]);
        assert!(is_bin_dir_on_path_str(bin, &path));
    }

    #[test]
    fn path_member_check_handles_trailing_separator() {
        let bin = Path::new("/home/user/.lpm/bin");
        // Common in shell init: trailing slash on the directory entry.
        let path = join_path(&["/usr/bin", "/home/user/.lpm/bin/"]);
        assert!(
            is_bin_dir_on_path_str(bin, &path),
            "trailing slash on PATH entry must still match the bin_dir"
        );
    }

    #[test]
    fn path_member_check_returns_false_when_absent() {
        let bin = Path::new("/home/user/.lpm/bin");
        let path = join_path(&["/usr/local/bin", "/usr/bin", "/bin"]);
        assert!(!is_bin_dir_on_path_str(bin, &path));
    }

    #[test]
    fn path_member_check_returns_false_for_empty_path() {
        let bin = Path::new("/home/user/.lpm/bin");
        assert!(!is_bin_dir_on_path_str(bin, ""));
    }

    #[test]
    fn path_member_check_skips_empty_components() {
        // PATH like `:/usr/bin:` (leading/trailing/double colon) is
        // common and means "current dir." We must not match those.
        let bin = Path::new("/home/user/.lpm/bin");
        let path = join_path(&["", "/usr/bin", ""]);
        assert!(!is_bin_dir_on_path_str(bin, &path));
    }

    #[test]
    fn path_member_check_does_not_match_prefix_of_longer_dir() {
        // `~/.lpm/bin-extra` must not match `~/.lpm/bin`.
        let bin = Path::new("/home/user/.lpm/bin");
        let path = join_path(&["/home/user/.lpm/bin-extra"]);
        assert!(!is_bin_dir_on_path_str(bin, &path));
    }

    // ─── Integration: maybe_show_path_hint state machine ─────────────

    #[test]
    fn hint_does_not_print_when_already_on_path_and_writes_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin = root.bin_dir();
        let report = with_path_env(&bin.display().to_string(), || {
            maybe_show_path_hint(&root, false)
        });

        assert!(report.on_path);
        assert!(!report.banner_printed);
        assert!(!report.marker_already_present);
        assert!(
            root.path_hint_marker().exists(),
            "marker must be written even on the silent on-PATH branch"
        );
    }

    #[test]
    fn hint_does_not_print_in_json_mode_but_marks_and_reports() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let report = with_path_env("", || maybe_show_path_hint(&root, true));

        assert!(!report.on_path);
        assert!(
            !report.banner_printed,
            "JSON mode must not write the banner to stdout — caller embeds the report instead"
        );
        assert!(root.path_hint_marker().exists());
    }

    #[test]
    fn hint_skips_when_marker_already_present_even_when_off_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Pre-create the marker so the "we already informed this user"
        // branch fires.
        std::fs::create_dir_all(root.path_hint_marker().parent().unwrap()).unwrap();
        std::fs::write(root.path_hint_marker(), b"already").unwrap();

        let report = with_path_env("", || maybe_show_path_hint(&root, false));

        assert!(report.marker_already_present);
        assert!(!report.banner_printed);
        assert!(!report.on_path);
        // Marker contents must remain — we don't overwrite an existing one.
        let body = std::fs::read(root.path_hint_marker()).unwrap();
        assert_eq!(body, b"already");
    }

    #[test]
    fn hint_first_run_off_path_in_human_mode_prints_and_marks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // No marker exists yet, PATH does not contain bin_dir.
        let report = with_path_env("/usr/bin:/bin", || maybe_show_path_hint(&root, false));

        assert!(!report.on_path);
        assert!(!report.marker_already_present);
        assert!(
            report.banner_printed,
            "first off-PATH run in human mode must print the banner"
        );
        assert!(root.path_hint_marker().exists());
    }
}
