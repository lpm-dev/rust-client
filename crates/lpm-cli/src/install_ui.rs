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
//! **Terminal trust boundary.** Short emitter names accept only static LPM text.
//! Dynamic plain text uses the explicit `*_untrusted` emitters. Styled dynamic
//! rows use [`TerminalLine`], which only combines static text with fields that
//! are sanitized before LPM-owned ANSI styling is applied.

use lpm_common::color::Painted;
use std::borrow::Cow;
use std::fmt;
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

/// A sanitized field with optional LPM-owned terminal styling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalFragment(String);

impl fmt::Display for TerminalFragment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(&self.0)
    }
}

impl AsRef<str> for TerminalFragment {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for TerminalFragment {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An LPM-owned terminal row assembled from static text and sanitized fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalLine(Cow<'static, str>);

impl TerminalLine {
    /// Starts a row with LPM-owned static text.
    pub const fn new(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// Appends LPM-owned static text.
    pub fn text(mut self, text: &'static str) -> Self {
        self.push_rendered(text);
        self
    }

    /// Appends an unstyled, externally controlled inline field.
    pub fn field(mut self, value: &str) -> Self {
        self.push_sanitized(value, |safe| safe.to_owned());
        self
    }

    /// Appends a dimmed, externally controlled inline field.
    pub fn dim(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::dimmed);
        self
    }

    /// Appends a bold, externally controlled inline field.
    pub fn bold(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::bold);
        self
    }

    /// Appends a yellow, externally controlled inline field.
    pub fn yellow(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::yellow);
        self
    }

    /// Appends a yellow bold, externally controlled inline field.
    pub fn section(mut self, value: &str) -> Self {
        self.push_sanitized(value, |safe| safe.yellow().bold());
        self
    }

    /// Appends a cyan, externally controlled inline field.
    pub fn cyan(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::cyan);
        self
    }

    /// Appends a blue URL field.
    pub fn url(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::blue);
        self
    }

    /// Appends a green, externally controlled inline field.
    pub fn green(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::green);
        self
    }

    /// Appends a red, externally controlled inline field.
    pub fn red(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::red);
        self
    }

    /// Appends a magenta, externally controlled inline field.
    pub fn magenta(mut self, value: &str) -> Self {
        self.push_sanitized(value, Painted::magenta);
        self
    }

    #[doc(hidden)]
    pub(crate) fn from_fragments(arguments: fmt::Arguments<'_>) -> Self {
        Self(Cow::Owned(arguments.to_string()))
    }

    fn push_sanitized(&mut self, value: &str, render: impl FnOnce(&str) -> String) {
        let safe = lpm_common::sanitize_terminal_inline(value);
        self.push_rendered(&render(&safe));
    }

    fn push_rendered(&mut self, fragment: &str) {
        match &mut self.0 {
            Cow::Borrowed(current) => {
                let mut rendered = String::with_capacity(current.len() + fragment.len());
                rendered.push_str(current);
                rendered.push_str(fragment);
                self.0 = Cow::Owned(rendered);
            }
            Cow::Owned(rendered) => rendered.push_str(fragment),
        }
    }

    fn into_owned(self) -> String {
        self.0.into_owned()
    }
}

#[doc(hidden)]
pub const fn assert_positional_terminal_format(format: &str) {
    let bytes = format.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'{' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'{' {
                index += 2;
                continue;
            }

            index += 1;
            while index < bytes.len() && bytes[index] != b'}' && bytes[index] != b':' {
                assert!(bytes[index].is_ascii_digit());
                index += 1;
            }
        }
        index += 1;
    }
}

#[doc(hidden)]
pub(crate) trait TerminalValue {
    fn render_terminal_fragment(&self) -> TerminalFragment;
}

impl TerminalValue for TerminalFragment {
    fn render_terminal_fragment(&self) -> TerminalFragment {
        self.clone()
    }
}

impl TerminalValue for TerminalLine {
    fn render_terminal_fragment(&self) -> TerminalFragment {
        TerminalFragment(self.0.to_string())
    }
}

impl<T: TerminalValue + ?Sized> TerminalValue for &T {
    fn render_terminal_fragment(&self) -> TerminalFragment {
        (**self).render_terminal_fragment()
    }
}

macro_rules! impl_untrusted_terminal_value {
    ($($type:ty),+ $(,)?) => {
        $(
            impl TerminalValue for $type {
                fn render_terminal_fragment(&self) -> TerminalFragment {
                    field(&self.to_string())
                }
            }
        )+
    };
}

impl_untrusted_terminal_value!(
    str,
    String,
    Cow<'_, str>,
    u8,
    u16,
    u32,
    usize,
    u64,
    u128,
    i8,
    i16,
    isize,
    i64,
    i128,
    i32,
    f32,
    f64,
    bool
);

#[doc(hidden)]
pub(crate) fn require_terminal_fragment<T: TerminalValue + ?Sized>(
    fragment: &T,
) -> TerminalFragment {
    fragment.render_terminal_fragment()
}

macro_rules! terminal_line {
    ($format:literal $(, $fragment:expr)* $(,)?) => {{
        const _: () = $crate::install_ui::assert_positional_terminal_format($format);
        $crate::install_ui::TerminalLine::from_fragments(format_args!(
            $format,
            $($crate::install_ui::require_terminal_fragment(&$fragment)),*
        ))
    }};
}

pub(crate) use terminal_line;

impl fmt::Display for TerminalLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(&self.0)
    }
}

impl AsRef<str> for TerminalLine {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for TerminalLine {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
    pub fn done(mut self, message: &'static str) {
        self.settle_as(LineKind::Done, Some(message.to_owned()));
    }

    /// Settle the spinner to `✗ {message}`.
    pub fn failed(mut self, message: &'static str) {
        self.settle_as(LineKind::Failed, Some(message.to_owned()));
    }

    /// Settle the spinner to `! {message}`.
    pub fn warn(mut self, message: &'static str) {
        self.settle_as(LineKind::Warn, Some(message.to_owned()));
    }

    /// Settle the spinner with a sanitized dynamic success message.
    pub fn done_untrusted(mut self, message: &str) {
        self.settle_as(
            LineKind::Done,
            Some(lpm_common::sanitize_terminal_inline(message).into_owned()),
        );
    }

    /// Settle the spinner with a typed success message.
    pub fn done_line(mut self, message: TerminalLine) {
        self.settle_as(LineKind::Done, Some(message.into_owned()));
    }

    /// Settle the spinner with a sanitized dynamic failure message.
    pub fn failed_untrusted(mut self, message: &str) {
        self.settle_as(
            LineKind::Failed,
            Some(lpm_common::sanitize_terminal_inline(message).into_owned()),
        );
    }

    /// Settle the spinner with a typed failure message.
    pub fn failed_line(mut self, message: TerminalLine) {
        self.settle_as(LineKind::Failed, Some(message.into_owned()));
    }

    /// Settle the spinner with a sanitized dynamic warning message.
    pub fn warn_untrusted(mut self, message: &str) {
        self.settle_as(
            LineKind::Warn,
            Some(lpm_common::sanitize_terminal_inline(message).into_owned()),
        );
    }

    /// Settle the spinner with a typed warning message.
    pub fn warn_line(mut self, message: TerminalLine) {
        self.settle_as(LineKind::Warn, Some(message.into_owned()));
    }

    fn settle_as(&mut self, kind: LineKind, replacement: Option<String>) {
        let Some(id) = self.id.take() else {
            if let Some(message) = replacement {
                emit_line(kind, &message);
            }
            return;
        };

        let message = replacement.as_deref().unwrap_or(&self.message);
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
pub fn spin(msg: &'static str) -> Spinner {
    spin_owned(msg.to_owned())
}

/// Starts a spinner with sanitized dynamic plain text.
pub fn spin_untrusted(msg: &str) -> Spinner {
    spin_owned(lpm_common::sanitize_terminal_inline(msg).into_owned())
}

/// Starts a spinner with a typed LPM-owned row.
pub fn spin_line(msg: TerminalLine) -> Spinner {
    spin_owned(msg.into_owned())
}

fn spin_owned(message: String) -> Spinner {
    settle_any_active_spinner();

    if !should_animate_spinner() {
        eprintln!("{}", static_spin_fallback_line(&message));
        return Spinner { id: None, message };
    }

    let id = NEXT_SPINNER_ID.fetch_add(1, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
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
pub fn phase(msg: &'static str) {
    emit_line(LineKind::Phase, msg);
}

/// Emits a phase row containing sanitized dynamic plain text.
pub fn phase_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    emit_line(LineKind::Phase, &safe);
}

/// Emits a typed LPM-owned phase row.
pub fn phase_line(msg: TerminalLine) {
    emit_line(LineKind::Phase, &msg.0);
}

pub fn with_firewall_badge(message: TerminalLine, active: bool) -> TerminalLine {
    if active {
        message.text(" - 🔥 LPM Firewall active")
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

pub fn safe_package_source_identity(raw: &str) -> String {
    let Ok(source) = lpm_lockfile::Source::parse(raw) else {
        return "unknown-source".to_owned();
    };
    let source_id = source.source_id();
    match source {
        lpm_lockfile::Source::Registry { url } => {
            let Ok(parsed) = reqwest::Url::parse(&url) else {
                return format!("registry:{source_id}");
            };
            let origin = parsed.origin().ascii_serialization();
            if origin == "null" {
                format!("registry:{source_id}")
            } else {
                format!("registry+{origin}")
            }
        }
        lpm_lockfile::Source::Tarball { .. } => format!("tarball:{source_id}"),
        lpm_lockfile::Source::Directory { .. } => format!("directory:{source_id}"),
        lpm_lockfile::Source::Link { .. } => format!("link:{source_id}"),
        lpm_lockfile::Source::Git { .. } => format!("git:{source_id}"),
    }
}

/// Success terminus: `✓ {msg}`.
pub fn done(msg: &'static str) {
    emit_line(LineKind::Done, msg);
}

/// Emits a success row containing sanitized dynamic plain text.
pub fn done_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    emit_line(LineKind::Done, &safe);
}

/// Emits a typed LPM-owned success row.
pub fn done_line(msg: TerminalLine) {
    emit_line(LineKind::Done, &msg.0);
}

/// Failure terminus: `✗ {msg}`.
pub fn failed(msg: &'static str) {
    emit_line(LineKind::Failed, msg);
}

/// Emits a failure row containing sanitized dynamic plain text.
pub fn failed_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    emit_line(LineKind::Failed, &safe);
}

/// Emits a typed LPM-owned failure row.
pub fn failed_line(msg: TerminalLine) {
    emit_line(LineKind::Failed, &msg.0);
}

/// Advisory / warning line: `! {msg}`.
///
/// Used for the audit summary, peer-dependency mismatch notices, and
/// any other non-fatal but operator-relevant signal.
pub fn warn(msg: &'static str) {
    emit_line(LineKind::Warn, msg);
}

/// Emits a warning row containing sanitized dynamic plain text.
pub fn warn_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    emit_line(LineKind::Warn, &safe);
}

/// Emits a typed LPM-owned warning row.
pub fn warn_line(msg: TerminalLine) {
    emit_line(LineKind::Warn, &msg.0);
}

pub fn skipped(msg: &'static str) {
    emit_line(LineKind::Skipped, msg);
}

/// Emits a skipped row containing sanitized dynamic plain text.
pub fn skipped_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    emit_line(LineKind::Skipped, &safe);
}

/// Emits a typed LPM-owned skipped row.
pub fn skipped_line(msg: TerminalLine) {
    emit_line(LineKind::Skipped, &msg.0);
}

/// Plain detail row that belongs to the slim transcript.
pub fn detail(msg: &'static str) {
    settle_any_active_spinner();
    eprintln!("{}{}", reset_prefix(), msg);
}

/// Emits a detail row containing sanitized dynamic plain text.
pub fn detail_untrusted(msg: &str) {
    let safe = lpm_common::sanitize_terminal_inline(msg);
    settle_any_active_spinner();
    eprintln!("{}{}", reset_prefix(), safe);
}

/// Emits a typed LPM-owned detail row.
pub fn detail_line(msg: TerminalLine) {
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

/// Unstyled helper for an externally controlled terminal field.
pub fn field(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).into_owned())
}

/// Unstyled helper for an intentionally multiline, externally controlled block.
pub fn multiline(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_multiline(text).into_owned())
}

/// Dim helper — sanitizes the field before applying LPM-owned styling.
pub fn dim(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).dimmed())
}

/// Bold helper.
pub fn bold(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).bold())
}

/// Yellow helper for the subject/tool/target role.
pub fn yellow(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).yellow())
}

/// Section-header helper: yellow + bold.
pub fn section(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).yellow().bold())
}

/// Cyan helper for path/scope/identifier/key/flag roles.
pub fn cyan(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).cyan())
}

/// URL helper: blue for `http(s)://…` values.
pub fn url(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).blue())
}

/// Green helper for success/status-value roles.
pub fn green(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).green())
}

/// Named status-value helper for grep-able call sites.
pub fn status_ok(text: &str) -> TerminalFragment {
    green(text)
}

/// Status bullet: green when active, dim when inactive.
pub fn bullet(active: bool) -> TerminalFragment {
    TerminalFragment(if active {
        "●".green()
    } else {
        "●".dimmed()
    })
}

/// Magenta helper for shell keywords such as `export` and `local`.
pub fn magenta(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).magenta())
}

/// Compact quota meter used by account/cache status surfaces.
pub fn usage_bar(used: u64, limit: u64, width: usize) -> TerminalFragment {
    if width == 0 || limit == 0 {
        return TerminalFragment(String::new());
    }

    let filled = usage_bar_filled_cells(used, limit, width);
    let empty = width - filled;
    let filled_segment = "█".repeat(filled);
    let empty_segment = "░".repeat(empty);

    TerminalFragment(if lpm_common::color::enabled() {
        format!(
            "{}{}",
            filled_segment.green(),
            empty_segment.green().dimmed()
        )
    } else {
        format!("{filled_segment}{empty_segment}")
    })
}

/// Yellow badge for compact role/status labels such as `admin`.
pub fn yellow_badge(text: &str) -> TerminalFragment {
    badge(text, "\x1b[1;33;48;5;236m")
}

fn badge(text: &str, open: &str) -> TerminalFragment {
    let text = lpm_common::sanitize_terminal_inline(text);
    let padded = format!(" {text} ");
    TerminalFragment(if lpm_common::color::enabled() {
        format!("{open}{padded}\x1b[0m")
    } else {
        padded
    })
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
pub fn red(text: &str) -> TerminalFragment {
    TerminalFragment(lpm_common::sanitize_terminal_inline(text).red())
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
///   * `{N} critical` is red when N > 0, otherwise plain
///   * the elapsed time is plain
///   * the trailing `— run \`lpm audit\`` hint is dimmed
///
/// Returns just the message body (no `!` prefix, no trailing newline).
pub fn format_audit_advisory(
    packages_audited: usize,
    vulnerabilities: usize,
    suspicious: usize,
    critical: usize,
    elapsed_ms: u128,
) -> TerminalLine {
    let pkg_word = packages_word(packages_audited);
    let vuln_word = if vulnerabilities == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let vuln_segment = if vulnerabilities > 0 {
        red(&format!("{vulnerabilities} {vuln_word}"))
    } else {
        field(&format!("{vulnerabilities} {vuln_word}"))
    };
    let critical_segment = if critical > 0 {
        red(&format!("{critical} critical"))
    } else {
        field("0 critical")
    };
    terminal_line!(
        "Audited {} {}, {}, {} suspicious, {} in {}ms {}",
        packages_audited,
        pkg_word,
        vuln_segment,
        suspicious,
        critical_segment,
        elapsed_ms,
        dim("— run `lpm audit`"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        LineKind, TerminalLine, assert_positional_terminal_format, format_line,
        safe_package_source_identity, spinner_animation_enabled, static_spin_fallback_line,
        usage_bar_filled_cells,
    };
    use std::borrow::Cow;

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

    #[test]
    fn terminal_line_static_text_stays_borrowed() {
        let line = TerminalLine::new("Resolving dependencies");
        assert!(matches!(line.0, Cow::Borrowed("Resolving dependencies")));
    }

    #[test]
    fn terminal_line_sanitizes_fields_without_removing_lpm_ansi() {
        let hostile = "safe\nFORGED\rrewritten\u{8}\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";
        let line = TerminalLine::new("\u{1b}[1mLPM\u{1b}[22m ").field(hostile);
        let rendered = line.to_string();

        assert_eq!(rendered, "\u{1b}[1mLPM\u{1b}[22m safe?FORGED?rewritten?end");
        assert!(!rendered.contains("\u{1b}]52"));
        assert!(!rendered.contains("hidden"));
    }

    #[test]
    fn terminal_line_macro_sanitizes_raw_positional_fragments() {
        let hostile = "safe\nFORGED\u{1b}[2Jend";
        let line = terminal_line!("\u{1b}[36mtrusted\u{1b}[39m [{}]", hostile);

        assert_eq!(
            line.to_string(),
            "\u{1b}[36mtrusted\u{1b}[39m [safe?FORGEDend]"
        );
    }

    #[test]
    fn terminal_fragments_honor_format_alignment() {
        let line = terminal_line!("|{:<8}|", super::field("safe"));
        assert_eq!(line.to_string(), "|safe    |");
    }

    #[test]
    fn terminal_line_format_rejects_implicit_named_capture() {
        let result = std::panic::catch_unwind(|| assert_positional_terminal_format("{field}"));
        assert!(result.is_err());
    }

    #[test]
    fn package_source_identity_keeps_only_registry_origin() {
        let identity = safe_package_source_identity(
            "registry+https://user:password@example.test/private?token=secret#fragment",
        );

        assert_eq!(identity, "registry+https://example.test");
    }

    #[test]
    fn package_source_identity_uses_opaque_id_for_non_registry_source() {
        let identity =
            safe_package_source_identity("git+https://user:password@example.test/private.git");

        assert!(identity.starts_with("git:g-"));
        assert!(!identity.contains("example.test"));
    }
}
