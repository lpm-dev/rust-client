use indicatif::{ProgressBar, ProgressStyle};

pub(crate) const REGISTRY_BASE: &str = "https://registry.npmjs.org";
pub(crate) const USER_AGENT: &str = "lpm-audit-corpus/0.1 (+https://lpm.dev)";

pub(crate) fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    now.format(&Rfc3339).unwrap_or_else(|_| String::new())
}

pub(crate) fn encode_pkg(name: &str) -> String {
    // Scoped packages (`@scope/name`) need the `@` and `/` URL-encoded for the
    // registry path. Everything else can be passed verbatim — registry names
    // are restricted to a small ASCII subset.
    if let Some(rest) = name.strip_prefix('@') {
        format!("@{}", rest.replace('/', "%2F"))
    } else {
        name.to_string()
    }
}

pub(crate) fn progress_style(prefix: &str) -> ProgressStyle {
    ProgressStyle::with_template(&format!(
        "{prefix} [{{elapsed_precise}}] [{{wide_bar:.cyan/blue}}] {{pos}}/{{len}} ({{eta}})"
    ))
    .unwrap()
    .progress_chars("█▉▊▋▌▍▎▏ ")
}

/// Emit a milestone progress line to stderr every `every` items.
///
/// indicatif's `ProgressBar` auto-disables visual updates when
/// stderr is not a TTY (e.g. when the audit is piped through
/// `tee` for log capture or run from CI). Without this helper,
/// a multi-thousand-package live audit appears completely silent
/// for ~10-30 minutes between the "fetching top-N" line at the
/// start and the "L1: green=… amber=… red=…" summary at the end.
///
/// The milestone line is a plain newline-terminated string so it
/// survives `tee`, `grep --line-buffered`, and other pipe stages.
/// Format: `<phase>: 1000/5000 (20.0%) elapsed=2m30s eta=8m12s`.
/// One line every `every` steps + one at completion.
pub(crate) fn emit_progress_milestone(phase: &str, pb: &ProgressBar, every: u64) {
    let pos = pb.position();
    let len = pb.length().unwrap_or(0);
    if pos == 0 || (!pos.is_multiple_of(every) && pos != len) {
        return;
    }
    let pct = if len > 0 {
        (pos as f64 / len as f64) * 100.0
    } else {
        0.0
    };
    let elapsed = pb.elapsed();
    let elapsed_s = elapsed.as_secs();
    let eta_s = if pos > 0 && pos < len {
        // Linear-projection ETA. ProgressBar has its own eta() but
        // we want a stable string for log scrapers — `format_duration`
        // here is a simple secs→m/s formatter that doesn't depend on
        // indicatif's internal style strings.
        let per_item_secs = elapsed_s as f64 / pos as f64;
        let remaining = (len - pos) as f64 * per_item_secs;
        remaining as u64
    } else {
        0
    };
    eprintln!(
        "{phase}: {pos}/{len} ({pct:.1}%) elapsed={} eta={}",
        format_short_duration(elapsed_s),
        format_short_duration(eta_s),
    );
}

pub(crate) fn format_short_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_pkg_escapes_scoped_names_for_registry_paths() {
        assert_eq!(encode_pkg("@scope/name"), "@scope%2Fname");
    }

    #[test]
    fn encode_pkg_leaves_unscoped_names_unchanged() {
        assert_eq!(encode_pkg("left-pad"), "left-pad");
    }

    #[test]
    fn format_short_duration_uses_seconds_minutes_and_hours() {
        assert_eq!(format_short_duration(42), "42s");
        assert_eq!(format_short_duration(125), "2m5s");
        assert_eq!(format_short_duration(7_260), "2h1m");
    }
}
