//! Slim terminal renderer for the install pipeline.
//!
//! Distinct from `crate::output`, which wraps cliclack's bordered-gutter
//! style. The install pipeline is non-interactive: it emits status lines
//! that complete and stay on screen, never prompts. cliclack's box gutter
//! adds visual noise (`│`, `┌`, `◇`, `●`, `◆`) for a flow that doesn't
//! need it, so this module bypasses cliclack entirely and prints plain
//! lines with single-glyph prefixes.
//!
//! Color palette (consistent across the install surface):
//!   * `›` blue   — phase / progress line
//!   * `✓` green  — success terminus or per-package verified
//!   * `✗` red    — failure terminus
//!   * `!` yellow — warning / advisory line (e.g. audit summary)
//!   * `+` plain  — direct-dep change in the post-install diff list
//!   * `-` plain  — removed entry in an uninstall / prune diff list
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

use lpm_common::color::Painted;

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

/// Phase / progress line: `› {msg}`.
///
/// Persistent (stays on screen after the next phase fires). Use one
/// `phase` line per logical step so the transcript narrates what the
/// install is doing without spinners.
pub fn phase(msg: &str) {
    eprintln!("{}{} {msg}", reset_prefix(), "›".blue());
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
    eprintln!("{}{} {msg}", reset_prefix(), "✓".green());
}

/// Failure terminus: `✗ {msg}`.
pub fn failed(msg: &str) {
    eprintln!("{}{} {msg}", reset_prefix(), "✗".red());
}

/// Advisory / warning line: `! {msg}`.
///
/// Used for the audit summary, peer-dependency mismatch notices, and
/// any other non-fatal but operator-relevant signal.
pub fn warn(msg: &str) {
    eprintln!("{}{} {msg}", reset_prefix(), "!".yellow());
}

fn diff_entry(glyph: &str, name: &str, version: Option<&str>, hint: Option<&str>) {
    let mut suffix = String::new();
    if let Some(version) = version {
        suffix.push('@');
        suffix.push_str(version);
    }
    if let Some(hint) = hint {
        suffix.push(' ');
        suffix.push_str(hint);
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
    diff_entry("+", name, Some(version), hint);
}

/// Removal diff entry: `- {name}{?@version}{?hint}`.
///
/// Used by uninstall / prune style flows. `name` renders unstyled; the
/// optional `@{version}` and optional `hint` render dimmed so the removed
/// thing remains the visual anchor of the line.
pub fn minus(name: &str, version: Option<&str>, hint: Option<&str>) {
    diff_entry("-", name, version, hint);
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
    text.dimmed()
}

/// Bold helper.
pub fn bold(text: &str) -> String {
    text.bold()
}

/// Green helper (for the timing in the "Done" line).
pub fn green(text: &str) -> String {
    text.green()
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
    text.red()
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
    use super::usage_bar_filled_cells;

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
}
