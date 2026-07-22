//! Slim terminal renderer for the install pipeline.
//!
//! Distinct from `crate::output`, which wraps cliclack's bordered-gutter
//! style. The install pipeline is non-interactive: it emits status lines
//! that complete and stay on screen, never prompts. cliclack's box gutter
//! adds visual noise (`│`, `┌`, `◇`, `●`, `◆`) for a flow that doesn't
//! need it, so this module bypasses cliclack entirely and prints plain
//! lines with single-glyph prefixes.
//!
//! Color palette (consistent across slim UI surfaces):
//!   * `›` blue   — phase / progress line
//!   * `⠦⠴⠇⠸` blue — live spinner frames, settling to `›` / `✓` / `✗` / `!`
//!   * `✓` green  — success terminus, per-package verified, status values
//!   * `✗` red    — failure terminus
//!   * `!` yellow — warning / advisory line (e.g. audit summary)
//!   * `+` green  — direct-dep change in the post-install diff list
//!   * `-` red    — removed entry in an uninstall / prune diff list
//!   * `●` green/dim — active/inactive status bullet
//!   * body roles — section yellow+bold, subject yellow, path/key cyan,
//!     URL blue, label/hint dimmed, shell keyword magenta, masked secret red
//!
//! Caller is responsible for `if json_output { … } else { install_ui::… }`
//! gating; this module never inspects `--json`.
//!
//! **Stream.** Every line goes to **stderr** (`eprintln!`). Matches the
//! cliclack code path that this module replaces — install progress is
//! progress, not the "answer" of the command. Keeps stdout reserved for
//! `--json` envelopes and for output piped to another tool.
//!
//! **ANSI reset hardening.** Every line is prefixed with [`reset_prefix`]
//! — `\x1b[0m` when colors are enabled, empty otherwise. Cliclack's
//! `▲` warning / `●` info shapes sometimes emit ANSI attributes
//! (dim / color) without a clean reset before the newline, and any
//! subsequent `eprintln!` on stderr inherits the open attribute until
//! something closes it. The defensive prefix means each slim-UI line
//! starts from a known-clean ANSI state regardless of what cliclack
//! left behind — a `+ pkg@version` line will never inherit a dim or
//! color attribute from a warning printed above it.
//!
//! **Terminal trust boundary.** The color/role helpers in this module accept
//! one untrusted inline field: they sanitize it before applying LPM-owned ANSI
//! styling. The line emitters accept trusted UI strings assembled from static
//! text and those helpers. Do not pass an already-styled composite back through
//! a role helper, because field sanitization intentionally removes embedded
//! terminal sequences before applying the requested style.

use lpm_common::color::Painted;
use std::io::{IsTerminal, Write as _};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const SPINNER_FRAMES: [&str; 4] = ["⠦", "⠴", "⠇", "⠸"];
const SPINNER_INTERVAL: Duration = Duration::from_millis(80);

static ACTIVE_SPINNER: OnceLock<Mutex<Option<ActiveSpinner>>> = OnceLock::new();
static NEXT_SPINNER_ID: AtomicU64 = AtomicU64::new(1);

struct ActiveSpinner {
    id: u64,
    message: String,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum LineKind {
    Phase,
    Done,
    Failed,
    Warn,
    Skipped,
}

/// Handle returned by [`spin`].
///
/// Dropping a live spinner settles it to a persisted `›` phase line. Prefer
/// calling [`Spinner::done`], [`Spinner::failed`], [`Spinner::warn`], or
/// [`Spinner::settle`] so the transcript records the intended outcome.
pub struct Spinner {
    id: Option<u64>,
    message: String,
}

impl Spinner {
    /// Settle the spinner to `› {message}`.
    pub fn settle(mut self) {
        self.settle_as(LineKind::Phase, None);
    }

    /// Settle the spinner to `✓ {message}`.
    pub fn done(mut self, message: &str) {
        self.settle_as(LineKind::Done, Some(message));
    }

    /// Settle the spinner to `✗ {message}`.
    pub fn failed(mut self, message: &str) {
        self.settle_as(LineKind::Failed, Some(message));
    }

    /// Settle the spinner to `! {message}`.
    pub fn warn(mut self, message: &str) {
        self.settle_as(LineKind::Warn, Some(message));
    }

    fn settle_as(&mut self, kind: LineKind, replacement: Option<&str>) {
        let Some(id) = self.id.take() else {
            if let Some(message) = replacement {
                emit_line(kind, message);
            }
            return;
        };

        let message = replacement.unwrap_or(&self.message);
        if !settle_active_spinner(Some(id), kind, message) {
            emit_line(kind, message);
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let message = self.message.clone();
            let _ = settle_active_spinner(Some(id), LineKind::Phase, &message);
        }
    }
}

/// ANSI full-reset (`SGR 0`) prefix, gated on the global color policy.
///
/// Empty string when colors are disabled (`NO_COLOR`, `--color=never`,
/// non-TTY pipe) so we don't emit a literal escape sequence into a
/// piped file. Always-emitted when colors are on, even if the previous
/// terminal state is unknown — that's the point.
#[inline]
fn reset_prefix() -> &'static str {
    if lpm_common::color::enabled() {
        "\x1b[0m"
    } else {
        ""
    }
}

#[inline]
fn active_spinner() -> &'static Mutex<Option<ActiveSpinner>> {
    ACTIVE_SPINNER.get_or_init(|| Mutex::new(None))
}

fn take_active_spinner(id: Option<u64>) -> Option<ActiveSpinner> {
    let mut active = active_spinner()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match (id, active.as_ref()) {
        (Some(expected), Some(spinner)) if spinner.id != expected => None,
        _ => active.take(),
    }
}

fn settle_active_spinner(id: Option<u64>, kind: LineKind, message: &str) -> bool {
    let Some(spinner) = take_active_spinner(id) else {
        return false;
    };

    spinner.stop.store(true, Ordering::Release);
    let _ = spinner.thread.join();
    eprintln!("\r\x1b[2K{}", format_line(kind, message));
    true
}

fn settle_any_active_spinner() {
    let message = {
        let active = active_spinner()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        active.as_ref().map(|spinner| spinner.message.clone())
    };
    if let Some(message) = message {
        let _ = settle_active_spinner(None, LineKind::Phase, &message);
    }
}

#[inline]
fn spinner_animation_enabled(stderr_is_terminal: bool, color_enabled: bool) -> bool {
    stderr_is_terminal && color_enabled
}

fn should_animate_spinner() -> bool {
    spinner_animation_enabled(
        std::io::stderr().is_terminal(),
        lpm_common::color::enabled(),
    )
}

fn format_line(kind: LineKind, msg: &str) -> String {
    format!("{}{} {msg}", reset_prefix(), glyph(kind))
}

fn glyph(kind: LineKind) -> String {
    match kind {
        LineKind::Phase => "›".blue(),
        LineKind::Done => "✓".green(),
        LineKind::Failed => "✗".red(),
        LineKind::Warn => "!".yellow(),
        LineKind::Skipped => "○".dimmed(),
    }
}

fn emit_line(kind: LineKind, msg: &str) {
    settle_any_active_spinner();
    eprintln!("{}", format_line(kind, msg));
}

fn static_spin_fallback_line(msg: &str) -> String {
    format_line(LineKind::Phase, msg)
}

/// Start a TTY-gated slim spinner for long-running work.
///
/// Non-interactive stderr, disabled color, and test pipes degrade to the same
/// static `› {msg}` line as [`phase`], preserving byte-for-byte pipe output.
pub fn spin(msg: &str) -> Spinner {
    settle_any_active_spinner();

    if !should_animate_spinner() {
        eprintln!("{}", static_spin_fallback_line(msg));
        return Spinner {
            id: None,
            message: msg.to_owned(),
        };
    }

    let id = NEXT_SPINNER_ID.fetch_add(1, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let message = msg.to_owned();
    let thread_message = message.clone();

    let thread = thread::spawn(move || {
        let mut frame_index = 0usize;
        let mut stderr = std::io::stderr();
        while !thread_stop.load(Ordering::Acquire) {
            let frame = SPINNER_FRAMES[frame_index % SPINNER_FRAMES.len()].blue();
            let _ = write!(
                stderr,
                "\r\x1b[2K{}{} {thread_message}",
                reset_prefix(),
                frame
            );
            let _ = stderr.flush();
            frame_index = frame_index.wrapping_add(1);
            thread::sleep(SPINNER_INTERVAL);
        }
    });

    *active_spinner()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ActiveSpinner {
        id,
        message: message.clone(),
        stop,
        thread,
    });

    Spinner {
        id: Some(id),
        message,
    }
}

/// Phase / progress line: `› {msg}`.
///
/// Persistent (stays on screen after the next phase fires). Calling `phase`
/// while a [`spin`] handle is active settles that spinner to a `›` transcript
/// line before printing this one.
pub fn phase(msg: &str) {
    emit_line(LineKind::Phase, msg);
}

pub fn with_firewall_badge(message: String, active: bool) -> String {
    if active {
        format!("{message} - 🔥 LPM Firewall active")
    } else {
        message
    }
}

/// Short, user-facing form of a registry URL. Strips the `registry.`
/// subdomain prefix so `https://registry.npmjs.org/` renders as
/// `npmjs.org`. Falls back to a stable `"registry"` label when the URL
/// can't be parsed (rare; suggests a misconfigured registry, which the
/// install will surface elsewhere with a louder error).
pub fn short_registry_host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .map_or_else(
            || "registry".to_owned(),
            |h| h.strip_prefix("registry.").map(str::to_owned).unwrap_or(h),
        )
}

/// Success terminus: `✓ {msg}`.
pub fn done(msg: &str) {
    emit_line(LineKind::Done, msg);
}

/// Failure terminus: `✗ {msg}`.
pub fn failed(msg: &str) {
    emit_line(LineKind::Failed, msg);
}

/// Advisory / warning line: `! {msg}`.
///
/// Used for the audit summary, peer-dependency mismatch notices, and
/// any other non-fatal but operator-relevant signal.
pub fn warn(msg: &str) {
    emit_line(LineKind::Warn, msg);
}

pub fn skipped(msg: &str) {
    emit_line(LineKind::Skipped, msg);
}

/// Plain detail row that belongs to the slim transcript.
pub fn detail(msg: &str) {
    settle_any_active_spinner();
    eprintln!("{}{}", reset_prefix(), msg);
}

fn diff_entry(glyph: &str, name: &str, version: Option<&str>, hint: Option<&str>) {
    settle_any_active_spinner();
    let name = lpm_common::sanitize_terminal_inline(name);
    let mut suffix = String::new();
    if let Some(version) = version {
        suffix.push('@');
        suffix.push_str(&lpm_common::sanitize_terminal_inline(version));
    }
    if let Some(hint) = hint {
        suffix.push(' ');
        suffix.push_str(&lpm_common::sanitize_terminal_inline(hint));
    }

    if suffix.is_empty() {
        eprintln!("{}{glyph} {name}", reset_prefix());
    } else {
        eprintln!("{}{glyph} {name}{}", reset_prefix(), suffix.dimmed());
    }
}

/// Direct-dependency diff entry: `+ {name}@{version}{?hint}`.
///
/// `name` renders unstyled; `@{version}` and the optional `hint` render
/// dimmed so the package name is the visual anchor of the line.
/// `hint` is for "(v6.0.3 available)" / "(deprecated)" / "(offline)" —
/// caller passes the parenthesized suffix verbatim.
pub fn plus(name: &str, version: &str, hint: Option<&str>) {
    diff_entry(&"+".green(), name, Some(version), hint);
}

/// Removal diff entry: `- {name}{?@version}{?hint}`.
///
/// Used by uninstall / prune style flows. `name` renders unstyled; the
/// optional `@{version}` and optional `hint` render dimmed so the removed
/// thing remains the visual anchor of the line.
pub fn minus(name: &str, version: Option<&str>, hint: Option<&str>) {
    diff_entry(&"-".red(), name, version, hint);
}

/// Removal diff entry where the removed target version is the acted-on
/// subject, not low-priority metadata.
pub fn minus_target(name: &str, version: Option<&str>, hint: Option<&str>) {
    settle_any_active_spinner();
    let name = lpm_common::sanitize_terminal_inline(name);

    let mut suffix = String::new();
    if let Some(version) = version {
        let version = lpm_common::sanitize_terminal_inline(version);
        suffix.push_str(&"@".dimmed());
        suffix.push_str(&version.yellow());
    }
    if let Some(hint) = hint {
        let hint = lpm_common::sanitize_terminal_inline(hint);
        suffix.push(' ');
        suffix.push_str(&hint.dimmed());
    }

    eprintln!("{}{} {name}{suffix}", reset_prefix(), "-".red());
}

/// Render a Duration as a short human string suitable for inlining in
/// the "Done · installed N packages in {dur}" line.
///
/// Mirrors the cargo / pnpm convention: sub-second → "Xms", otherwise
/// "X.XXs" with two-decimal precision. Returned uncolored so the
/// caller can opt into `.green()` where the spec calls for it.
pub fn format_duration(d: std::time::Duration) -> String {
    let total_ms = d.as_millis();
    if total_ms < 1000 {
        format!("{total_ms}ms")
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

/// Dim helper — wraps `Painted::dimmed` so callers can avoid pulling
/// the trait in directly when they only need one dim call.
pub fn dim(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).dimmed()
}

/// Bold helper.
pub fn bold(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).bold()
}

/// Yellow helper for the subject/tool/target role.
pub fn yellow(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).yellow()
}

/// Section-header helper: yellow + bold.
pub fn section(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).yellow().bold()
}

/// Cyan helper for path/scope/identifier/key/flag roles.
pub fn cyan(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).cyan()
}

/// URL helper: blue for `http(s)://…` values.
pub fn url(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).blue()
}

/// Green helper for success/status-value roles.
pub fn green(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).green()
}

/// Named status-value helper for grep-able call sites.
pub fn status_ok(text: &str) -> String {
    green(text)
}

/// Status bullet: green when active, dim when inactive.
pub fn bullet(active: bool) -> String {
    if active {
        "●".green()
    } else {
        "●".dimmed()
    }
}

/// Magenta helper for shell keywords such as `export` and `local`.
pub fn magenta(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).magenta()
}

/// Compact quota meter used by account/cache status surfaces.
pub fn usage_bar(used: u64, limit: u64, width: usize) -> String {
    if width == 0 || limit == 0 {
        return String::new();
    }

    let filled = usage_bar_filled_cells(used, limit, width);
    let empty = width - filled;
    let filled_segment = "█".repeat(filled);
    let empty_segment = "░".repeat(empty);

    if lpm_common::color::enabled() {
        format!(
            "{}{}",
            filled_segment.green(),
            empty_segment.green().dimmed()
        )
    } else {
        format!("{filled_segment}{empty_segment}")
    }
}

/// Yellow badge for compact role/status labels such as `admin`.
pub fn yellow_badge(text: &str) -> String {
    badge(text, "\x1b[1;33;48;5;236m")
}

fn badge(text: &str, open: &str) -> String {
    let text = lpm_common::sanitize_terminal_inline(text);
    let padded = format!(" {text} ");
    if lpm_common::color::enabled() {
        format!("{open}{padded}\x1b[0m")
    } else {
        padded
    }
}

fn usage_bar_filled_cells(used: u64, limit: u64, width: usize) -> usize {
    if width == 0 || used == 0 || limit == 0 {
        return 0;
    }

    let numerator = (used as u128) * (width as u128);
    let denominator = limit as u128;
    let filled = numerator.div_ceil(denominator);
    filled.min(width as u128) as usize
}

/// Red helper (for the vulnerability count in the audit advisory).
pub fn red(text: &str) -> String {
    lpm_common::sanitize_terminal_inline(text).red()
}

/// Pluralize "package": returns `"package"` for `count == 1`, else
/// `"packages"`. Pulled into a helper so every install-pipeline line
/// (`Installing X package(s)`, `Done · installed X package(s)`,
/// `X of Y package(s) verified`, the verbose footer's lockfile count)
/// agrees on the same singular/plural rule.
#[inline]
pub fn packages_word(count: usize) -> &'static str {
    if count == 1 { "package" } else { "packages" }
}

/// Render the audit-after-install advisory body. Caller wraps this in
/// [`warn`] to get the leading `!` glyph.
///
/// Coloring (per the slim-UI spec):
///   * `{N} vulnerabilit{y|ies}` is **red** when N > 0, otherwise plain
///   * `{N} suspicious` is plain
///   * the elapsed time is plain
///   * the trailing `— run \`lpm audit\`` hint is dimmed
///
/// Returns just the message body (no `!` prefix, no trailing newline).
pub fn format_audit_advisory(
    packages_audited: usize,
    vulnerabilities: usize,
    suspicious: usize,
    elapsed_ms: u128,
) -> String {
    let pkg_word = packages_word(packages_audited);
    let vuln_word = if vulnerabilities == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let vuln_segment = if vulnerabilities > 0 {
        format!("{vulnerabilities} {vuln_word}").red()
    } else {
        format!("{vulnerabilities} {vuln_word}")
    };
    let hint = "— run `lpm audit`".dimmed();
    format!(
        "Audited {packages_audited} {pkg_word}, {vuln_segment}, {suspicious} suspicious in {elapsed_ms}ms {hint}"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        LineKind, format_line, spinner_animation_enabled, static_spin_fallback_line,
        usage_bar_filled_cells,
    };

    #[test]
    fn usage_bar_rounds_visible_fraction_up_to_one_cell() {
        assert_eq!(usage_bar_filled_cells(3, 100, 10), 1);
    }

    #[test]
    fn usage_bar_matches_design_examples() {
        assert_eq!(usage_bar_filled_cells(32, 100, 10), 4);
        assert_eq!(usage_bar_filled_cells(28, 100, 10), 3);
        assert_eq!(usage_bar_filled_cells(18, 100, 10), 2);
    }

    #[test]
    fn usage_bar_clamps_over_limit_to_full_width() {
        assert_eq!(usage_bar_filled_cells(125, 100, 10), 10);
    }

    #[test]
    fn usage_bar_stays_empty_without_usage_or_limit() {
        assert_eq!(usage_bar_filled_cells(0, 100, 10), 0);
        assert_eq!(usage_bar_filled_cells(50, 0, 10), 0);
        assert_eq!(usage_bar_filled_cells(50, 100, 0), 0);
    }

    #[test]
    fn spinner_animation_requires_tty_and_color() {
        assert!(spinner_animation_enabled(true, true));
        assert!(!spinner_animation_enabled(false, true));
        assert!(!spinner_animation_enabled(true, false));
    }

    #[test]
    fn spinner_non_tty_line_matches_static_phase_line() {
        let phase_line = format_line(LineKind::Phase, "Resolving dependencies");
        let fallback_line = static_spin_fallback_line("Resolving dependencies");
        assert_eq!(fallback_line, phase_line);
    }
}
