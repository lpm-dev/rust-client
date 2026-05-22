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
//!
//! Caller is responsible for `if json_output { … } else { install_ui::… }`
//! gating; this module never inspects `--json`.
//!
//! **Stream.** Every line goes to **stderr** (`eprintln!`). Matches the
//! cliclack code path that this module replaces — install progress is
//! progress, not the "answer" of the command. Keeps stdout reserved for
//! `--json` envelopes and for output piped to another tool.

use lpm_common::color::Painted;

/// Phase / progress line: `› {msg}`.
///
/// Persistent (stays on screen after the next phase fires). Use one
/// `phase` line per logical step so the transcript narrates what the
/// install is doing without spinners.
pub fn phase(msg: &str) {
    eprintln!("{} {msg}", "›".blue());
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
    eprintln!("{} {msg}", "✓".green());
}

/// Failure terminus: `✗ {msg}`.
pub fn failed(msg: &str) {
    eprintln!("{} {msg}", "✗".red());
}

/// Advisory / warning line: `! {msg}`.
///
/// Used for the audit summary, peer-dependency mismatch notices, and
/// any other non-fatal but operator-relevant signal.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", "!".yellow());
}

/// Direct-dependency diff entry: `+ {name}@{version}{?hint}`.
///
/// `name` renders unstyled; `@{version}` and the optional `hint` render
/// dimmed so the package name is the visual anchor of the line.
/// `hint` is for "(v6.0.3 available)" / "(deprecated)" / "(offline)" —
/// caller passes the parenthesized suffix verbatim.
pub fn plus(name: &str, version: &str, hint: Option<&str>) {
    let suffix = match hint {
        Some(h) => format!("@{version} {h}").dimmed(),
        None => format!("@{version}").dimmed(),
    };
    eprintln!("+ {name}{suffix}");
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
