//! Phase 46 P3 release-age cooldown config loader.
//!
//! Resolves the effective `minimumReleaseAge` (in seconds) for a project
//! install by walking, highest precedence first:
//!
//! 1. **CLI flag**: `lpm install --min-release-age=<dur>`. Parsed via
//!    [`parse_duration`] — accepts `h` / `d` suffixes and plain seconds.
//! 2. **Per-project**: `package.json > lpm > minimumReleaseAge`. Read
//!    via [`lpm_workspace::read_package_json`]; tolerant of missing /
//!    malformed manifest (matches [`lpm_security::SecurityPolicy::from_package_json`]).
//! 3. **Global**: `~/.lpm/config.toml` key `minimum-release-age-secs`.
//!    Read with a path-aware fallible loader (mirrors Phase 33's
//!    [`crate::save_config::SaveConfigLoader`] — malformed TOML or a
//!    garbage value surfaces a file-pathed error rather than being
//!    silently ignored as [`crate::commands::config::GlobalConfig::load`]
//!    would do).
//! 4. **Default**: 86400 (24h). Matches pnpm v10 and the Phase 46 plan §8.1.
//!
//! `./lpm.toml` is deliberately NOT in this chain: per D14 the project-
//! local TOML is scoped to save-policy keys, and the general project-
//! config loader is a separate follow-up (§16).
//!
//! The resolver returns `Result<u64, LpmError>`. Only the global-TOML
//! layer can raise (file read, parse, or value-shape errors). The CLI
//! input is validated upstream by the clap parser hook; the package.json
//! layer is deliberately tolerant, preserving today's cooldown behaviour
//! under D20 (P3 changes gating, not execution semantics).
//!
//! The effective seconds value is then passed to
//! [`lpm_security::SecurityPolicy::with_resolved_min_age`], which couples
//! it with the `trustedDependencies` read from the same manifest.
//!
//! The install-time call site for the resolver lives in
//! [`crate::commands::install::run_with_options`] just before the
//! `minimumReleaseAge` gate; the clap layer parses `--min-release-age`
//! via [`parse_duration`] and fans the resulting `Option<u64>` through
//! the install entry points alongside `allow_new`.

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Default cooldown window when nothing else is configured (matches
/// [`lpm_security::SecurityPolicy::DEFAULT_MIN_RELEASE_AGE`]; copied
/// here to keep this module self-contained and to avoid poking at
/// lpm-security's private constant).
const DEFAULT_MIN_RELEASE_AGE_SECS: u64 = 86400;

/// TOML key in `~/.lpm/config.toml` holding the global override.
const GLOBAL_KEY: &str = "minimum-release-age-secs";

/// Parse the `--min-release-age=<dur>` CLI argument into a seconds count.
///
/// Accepted forms:
/// - `<N>h` — hours (e.g. `72h` → 259_200)
/// - `<N>d` — days (e.g. `3d` → 259_200)
/// - `<N>` — plain seconds (e.g. `86400`)
///
/// Rejected:
/// - Empty string
/// - Surrounding whitespace (`" 72h "`)
/// - Bare suffix without a number (`h`, `d`)
/// - Unsupported suffixes (`72m`, `1w`, `1y`)
/// - Negative values (`-5h`, `-1`)
/// - Non-integer scalars (`0.5h`, `1.5d`)
/// - Overflow when multiplying hours/days into seconds
///
/// Errors are descriptive and include the offending input verbatim so
/// clap surfaces them directly to the user.
pub fn parse_duration(input: &str) -> Result<u64, LpmError> {
    if input.is_empty() {
        return Err(LpmError::Registry(
            "release-age duration must not be empty (expected `<N>h`, `<N>d`, or `<N>` seconds)"
                .into(),
        ));
    }
    if input.trim() != input {
        return Err(LpmError::Registry(format!(
            "release-age duration `{input}` must not contain surrounding whitespace"
        )));
    }

    if let Some(hours_str) = input.strip_suffix('h') {
        let hours = parse_scalar(hours_str, input)?;
        hours
            .checked_mul(3600)
            .ok_or_else(|| overflow_err(input, "hours"))
    } else if let Some(days_str) = input.strip_suffix('d') {
        let days = parse_scalar(days_str, input)?;
        days.checked_mul(86400)
            .ok_or_else(|| overflow_err(input, "days"))
    } else if input
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        Err(LpmError::Registry(format!(
            "release-age duration `{input}` has an unsupported unit (expected `h`, `d`, or plain seconds)"
        )))
    } else {
        parse_scalar(input, input)
    }
}

fn parse_scalar(scalar: &str, original: &str) -> Result<u64, LpmError> {
    if scalar.is_empty() {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` has no numeric value (expected `<N>h`, `<N>d`, or `<N>` seconds)"
        )));
    }
    if scalar.starts_with('-') {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` must be non-negative"
        )));
    }
    // `u64::from_str` silently accepts a leading `+` (e.g. `"+5".parse::<u64>()`
    // returns `Ok(5)`). Reject it explicitly so `+5h` doesn't quietly mean `5h`.
    if scalar.starts_with('+') {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` is not a valid non-negative integer (expected `<N>h`, `<N>d`, or `<N>` seconds)"
        )));
    }
    scalar.parse::<u64>().map_err(|_| {
        LpmError::Registry(format!(
            "release-age duration `{original}` is not a valid non-negative integer (expected `<N>h`, `<N>d`, or `<N>` seconds)"
        ))
    })
}

fn overflow_err(input: &str, unit: &str) -> LpmError {
    LpmError::Registry(format!(
        "release-age duration `{input}` overflows when converting {unit} to seconds"
    ))
}

/// Parse a string as a non-negative `u64`, rejecting explicit sign
/// prefixes (`+` or `-`).
///
/// `u64::from_str` silently accepts a leading `+` (`"+5".parse::<u64>()`
/// returns `Ok(5)`), which would let values like `"+259200"` slip
/// through the string-coercion paths in the global config reader and
/// [`crate::commands::config::GlobalConfig::get_u64`]. Since the CLI
/// parser rejects `+5h` by contract, every string-coercion site that
/// interprets a value as seconds MUST apply the same rule — otherwise
/// the persistent config surface silently accepts inputs the CLI
/// rejects, breaking the least-surprise property across the precedence
/// chain.
///
/// This helper is the single source of truth for string-to-seconds
/// coercion. Callers render error messages as appropriate for their
/// context (file-pathed for the global loader, `Option<u64>` for the
/// `GlobalConfig` convenience reader).
pub(crate) fn parse_strict_u64_string(s: &str) -> Option<u64> {
    if s.starts_with('-') || s.starts_with('+') {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Resolve the effective `minimumReleaseAge` for a project install.
///
/// See module docs for the precedence chain. The caller is responsible
/// for validating `cli_override` upstream (typically by routing
/// `--min-release-age=<dur>` through [`parse_duration`] in the clap
/// layer). This function treats `cli_override` as already-validated.
pub struct ReleaseAgeResolver;

impl ReleaseAgeResolver {
    /// Walk the precedence chain and return the effective seconds value.
    ///
    /// Returns an error only if the global `~/.lpm/config.toml` exists
    /// and is unreadable / malformed / has a garbage
    /// `minimum-release-age-secs` value. A missing global file is fine
    /// (falls through to default).
    pub fn resolve(project_dir: &Path, cli_override: Option<u64>) -> Result<u64, LpmError> {
        if let Some(secs) = cli_override {
            return Ok(secs);
        }
        if let Some(secs) = read_package_json_min_age(&project_dir.join("package.json")) {
            return Ok(secs);
        }
        if let Some(path) = global_config_path()
            && let Some(secs) = read_global_min_age_from_file(&path)?
        {
            return Ok(secs);
        }
        Ok(DEFAULT_MIN_RELEASE_AGE_SECS)
    }
}

/// Locate `~/.lpm/config.toml`. Returns `None` only when `HOME` is
/// unset — in that case the global layer is silently skipped
/// (matches [`crate::commands::config::GlobalConfig::load`]).
fn global_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join("config.toml"))
}

/// Read `lpm.minimumReleaseAge` from a project's `package.json`.
///
/// Tolerant by design: missing / unreadable / malformed manifest
/// returns `None` and the resolver falls through to the next layer.
/// This preserves the existing cooldown behaviour where the 24h default
/// still fires on projects without an `"lpm"` block (D20).
fn read_package_json_min_age(pkg_json_path: &Path) -> Option<u64> {
    let pkg = lpm_workspace::read_package_json(pkg_json_path).ok()?;
    pkg.lpm?.minimum_release_age
}

/// Read `minimum-release-age-secs` from a `~/.lpm/config.toml` at `path`.
///
/// Missing file → `Ok(None)`. Malformed TOML, non-table top level, or a
/// `minimum-release-age-secs` value that isn't a non-negative integer
/// (native or string-coerced) → `Err` with the file path baked in,
/// mirroring Phase 33's save-config loader error style.
///
/// String coercion accepts values like `"86400"` because the generic
/// `lpm config set <key> <value>` command writes every value as a TOML
/// string (Finding A in [`crate::save_config`]) — the documented
/// persistent-config path must actually work.
fn read_global_min_age_from_file(path: &Path) -> Result<Option<u64>, LpmError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Registry(format!("failed to read {}: {e}", path.display())))?;
    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;
    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => {
            return Err(LpmError::Registry(format!(
                "{} must be a TOML table at the top level",
                path.display()
            )));
        }
    };
    let Some(value) = table.get(GLOBAL_KEY) else {
        return Ok(None);
    };
    match value {
        toml::Value::Integer(i) => u64::try_from(*i).map(Some).map_err(|_| {
            LpmError::Registry(format!(
                "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds), got {i}",
                path.display()
            ))
        }),
        toml::Value::String(s) => parse_strict_u64_string(s).map(Some).ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds) or a string \
                 parseable as one (e.g. \"86400\"), got \"{s}\"",
                path.display()
            ))
        }),
        other => Err(LpmError::Registry(format!(
            "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds), got {other}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── parse_duration ───────────────────────────────────────────

    #[test]
    fn parse_hours_suffix() {
        assert_eq!(parse_duration("72h").unwrap(), 72 * 3600);
    }

    #[test]
    fn parse_one_hour() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_zero_hours() {
        assert_eq!(parse_duration("0h").unwrap(), 0);
    }

    #[test]
    fn parse_days_suffix() {
        assert_eq!(parse_duration("3d").unwrap(), 3 * 86400);
    }

    #[test]
    fn parse_zero_days() {
        assert_eq!(parse_duration("0d").unwrap(), 0);
    }

    #[test]
    fn parse_plain_seconds() {
        assert_eq!(parse_duration("86400").unwrap(), 86400);
    }

    #[test]
    fn parse_zero_plain() {
        assert_eq!(parse_duration("0").unwrap(), 0);
    }

    #[test]
    fn parse_leading_zeros_allowed() {
        // `u64::from_str` accepts leading zeros; no need to be fussier.
        assert_eq!(parse_duration("01h").unwrap(), 3600);
    }

    #[test]
    fn reject_empty() {
        let err = parse_duration("").unwrap_err().to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn reject_leading_whitespace() {
        let err = parse_duration(" 72h").unwrap_err().to_string();
        assert!(err.contains("whitespace"), "got: {err}");
    }

    #[test]
    fn reject_trailing_whitespace() {
        let err = parse_duration("72h ").unwrap_err().to_string();
        assert!(err.contains("whitespace"), "got: {err}");
    }

    #[test]
    fn reject_lone_hours_suffix() {
        let err = parse_duration("h").unwrap_err().to_string();
        assert!(err.contains("no numeric value"), "got: {err}");
    }

    #[test]
    fn reject_lone_days_suffix() {
        let err = parse_duration("d").unwrap_err().to_string();
        assert!(err.contains("no numeric value"), "got: {err}");
    }

    #[test]
    fn reject_minutes_suffix() {
        let err = parse_duration("72m").unwrap_err().to_string();
        assert!(err.contains("unsupported unit"), "got: {err}");
    }

    #[test]
    fn reject_weeks_suffix() {
        let err = parse_duration("1w").unwrap_err().to_string();
        assert!(err.contains("unsupported unit"), "got: {err}");
    }

    #[test]
    fn reject_negative_hours() {
        let err = parse_duration("-5h").unwrap_err().to_string();
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn reject_negative_plain() {
        let err = parse_duration("-5").unwrap_err().to_string();
        // The plain-seconds path hits `parse_scalar` which catches the
        // leading `-` first.
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn reject_garbage() {
        let err = parse_duration("abc").unwrap_err().to_string();
        // `abc` ends in `c` (alphabetic) → the unsupported-unit branch fires.
        assert!(err.contains("unsupported unit"), "got: {err}");
    }

    #[test]
    fn reject_fractional_hours() {
        let err = parse_duration("0.5h").unwrap_err().to_string();
        assert!(
            err.contains("not a valid non-negative integer"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_plus_sign() {
        // `u64::from_str` rejects `+5` — the hours path surfaces the
        // "not a valid integer" branch (not the `-` branch).
        let err = parse_duration("+5h").unwrap_err().to_string();
        assert!(
            err.contains("not a valid non-negative integer"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_hours_overflow() {
        // u64::MAX / 3600 = ~5.1e15. Anything bigger overflows.
        let input = format!("{}h", u64::MAX);
        let err = parse_duration(&input).unwrap_err().to_string();
        assert!(err.contains("overflows"), "got: {err}");
        assert!(err.contains("hours"), "got: {err}");
    }

    #[test]
    fn reject_days_overflow() {
        let input = format!("{}d", u64::MAX);
        let err = parse_duration(&input).unwrap_err().to_string();
        assert!(err.contains("overflows"), "got: {err}");
        assert!(err.contains("days"), "got: {err}");
    }

    // ── read_global_min_age_from_file ────────────────────────────

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn global_file_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_global_min_age_from_file(&dir.path().join("config.toml")).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_empty_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_key_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "some-other-key = 42\n");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_integer_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = 259200\n");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, Some(259200));
    }

    /// `lpm config set minimum-release-age-secs 259200` writes a TOML
    /// string (Finding A). The loader MUST accept that form or the
    /// documented persistent-config path is unusable.
    #[test]
    fn global_file_string_value_for_config_set_compat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "259200""#);
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, Some(259200));
    }

    #[test]
    fn global_file_negative_integer_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = -1\n");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    /// Reviewer finding (Chunk 1): `u64::from_str("+5")` returns `Ok(5)`,
    /// so without an explicit sign-prefix rejection the global-TOML
    /// string path would silently accept `"+259200"` even though the
    /// CLI flag rejects `+5h`. Both string-coercion sites now route
    /// through [`parse_strict_u64_string`] for uniform behaviour; this
    /// test is the regression guard against drift.
    #[test]
    fn global_file_plus_prefixed_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "+259200""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    /// Symmetric regression: the `-` prefix must also surface a
    /// file-pathed error, not silently parse. `u64::from_str("-5")`
    /// already returns `Err`, so the string path's behaviour here
    /// matches the CLI parser's "must be non-negative" branch —
    /// [`parse_strict_u64_string`] makes that guarantee explicit rather
    /// than implicit.
    #[test]
    fn global_file_minus_prefixed_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "-1""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    #[test]
    fn global_file_garbage_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "forever""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    #[test]
    fn global_file_wrong_type_rejected() {
        // A TOML array isn't coercible. Must surface a clear error,
        // not silently ignore.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = [1, 2, 3]\n");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("minimum-release-age-secs"), "got: {err}");
    }

    #[test]
    fn global_file_malformed_toml_rejected_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "not valid toml === [[[");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
    }

    // ── ReleaseAgeResolver::resolve ──────────────────────────────

    /// Redirect HOME so `dirs::home_dir()` points at a per-test temp
    /// directory — otherwise the resolver would pick up the developer's
    /// actual `~/.lpm/config.toml`. Mirrors the `scoped_home_dir` helper
    /// in [`crate::save_config`].
    fn scoped_home_dir() -> ScopedHomeDir {
        let dir = tempfile::tempdir().unwrap();
        let env = crate::test_env::ScopedEnv::set([("HOME", dir.path().as_os_str().to_owned())]);
        ScopedHomeDir { dir, _env: env }
    }

    struct ScopedHomeDir {
        dir: tempfile::TempDir,
        _env: crate::test_env::ScopedEnv,
    }

    impl ScopedHomeDir {
        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn write_package_json_with_min_age(project: &Path, secs: Option<u64>) {
        let body = match secs {
            Some(n) => format!(
                r#"{{ "name": "p", "version": "0.0.0", "lpm": {{ "minimumReleaseAge": {n} }} }}"#
            ),
            None => r#"{ "name": "p", "version": "0.0.0" }"#.to_string(),
        };
        write_file(&project.join("package.json"), &body);
    }

    fn write_global_config(home: &Path, contents: &str) {
        write_file(&home.join(".lpm").join("config.toml"), contents);
    }

    #[test]
    fn resolve_cli_override_wins_over_everything() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(500)).unwrap();
        assert_eq!(result, 500, "CLI override must beat package.json + global");
    }

    #[test]
    fn resolve_cli_override_zero_is_honored() {
        // `--min-release-age=0` disables cooldown for this invocation,
        // even when package.json / global set a non-zero value.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(0)).unwrap();
        assert_eq!(result, 0, "CLI --min-release-age=0 must force zero");
    }

    #[test]
    fn resolve_package_json_beats_global() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, 1000, "package.json must beat global config");
    }

    #[test]
    fn resolve_global_beats_default_when_package_json_silent() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, 2000, "global config must override 24h default");
    }

    #[test]
    fn resolve_default_when_nothing_set() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);

        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_default_when_package_json_missing() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        // No package.json written.
        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_default_when_package_json_malformed() {
        // Tolerant: malformed manifest doesn't error, falls through.
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_file(&project.path().join("package.json"), "{ not json ===");
        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_surfaces_global_config_error() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), r#"minimum-release-age-secs = "garbage""#);

        let err = ReleaseAgeResolver::resolve(project.path(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name global file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name key: {err}"
        );
    }

    #[test]
    fn resolve_cli_override_skips_global_errors() {
        // When the user explicitly passes --min-release-age=<n>, a
        // broken global config must not block the install. The CLI
        // flag short-circuits the chain.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), "not valid toml === [[[");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(0)).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn resolve_package_json_skips_global_errors() {
        // Similarly, an explicit `"lpm": { "minimumReleaseAge": N }`
        // in package.json short-circuits the global layer.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), Some(500));
        write_global_config(home.path(), "not valid toml === [[[");

        let result = ReleaseAgeResolver::resolve(project.path(), None).unwrap();
        assert_eq!(result, 500);
    }

    // ── GlobalConfig::get_u64 (spot-check in this module) ────────

    /// Minimal sanity check for the new `GlobalConfig::get_u64` helper.
    /// The deep coverage for the global-TOML layer lives in the path-
    /// aware tests above; this confirms the convenience accessor works
    /// for callers that don't need file-pathed errors.
    #[test]
    fn global_config_get_u64_accepts_integer_and_string() {
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "native-int = 123\nstring-form = \"456\"\nnegative = -1\nboolean = true\n",
        );
        let cfg = crate::commands::config::GlobalConfig::load();
        assert_eq!(cfg.get_u64("native-int"), Some(123));
        assert_eq!(cfg.get_u64("string-form"), Some(456));
        assert_eq!(cfg.get_u64("negative"), None);
        assert_eq!(cfg.get_u64("boolean"), None);
        assert_eq!(cfg.get_u64("absent"), None);
    }

    /// Reviewer regression: the convenience reader must reject
    /// sign-prefixed strings too, not just the path-aware loader.
    /// Without this, a user who runs
    /// `lpm config set some-key +5` would have `GlobalConfig::get_u64`
    /// silently return `Some(5)` while `--some-flag=+5` would be
    /// rejected by any CLI parser routed through
    /// [`parse_strict_u64_string`].
    #[test]
    fn global_config_get_u64_rejects_sign_prefixed_strings() {
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "plus-prefixed = \"+5\"\nminus-prefixed = \"-5\"\n",
        );
        let cfg = crate::commands::config::GlobalConfig::load();
        assert_eq!(cfg.get_u64("plus-prefixed"), None);
        assert_eq!(cfg.get_u64("minus-prefixed"), None);
    }

    // ── parse_strict_u64_string (shared helper) ──────────────────

    #[test]
    fn strict_u64_accepts_plain_digits() {
        assert_eq!(parse_strict_u64_string("0"), Some(0));
        assert_eq!(parse_strict_u64_string("86400"), Some(86400));
    }

    #[test]
    fn strict_u64_rejects_plus_prefix() {
        assert_eq!(parse_strict_u64_string("+5"), None);
    }

    #[test]
    fn strict_u64_rejects_minus_prefix() {
        assert_eq!(parse_strict_u64_string("-5"), None);
    }

    #[test]
    fn strict_u64_rejects_whitespace() {
        assert_eq!(parse_strict_u64_string(" 5"), None);
        assert_eq!(parse_strict_u64_string("5 "), None);
    }

    #[test]
    fn strict_u64_rejects_non_digit() {
        assert_eq!(parse_strict_u64_string("abc"), None);
        assert_eq!(parse_strict_u64_string("0x10"), None);
    }
}
