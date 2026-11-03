use std::num::NonZeroUsize;

use lpm_semver::VersionBump;

use crate::workspace_concurrency_config;

pub(super) fn parse_version_bump(raw: &str) -> Result<VersionBump, String> {
    raw.parse::<VersionBump>()
        .map_err(|error| error.to_string())
}

/// clap `value_parser` for `--advisor`. Rejects unknown slugs at parse
/// time so a typo never produces a portable-only install while the
/// user thinks they configured an uplift.
///
/// Accepts `none` plus every slug `Provider::from_slug` knows.
/// `Provider::from_slug` is the source of truth for the live set; the
/// error message hard-codes the v1 slugs for legibility but a future
/// provider addition is a one-line touch (add the slug here).
pub(super) fn parse_advisor_slug(s: &str) -> Result<String, String> {
    if s == "none" || lpm_triage_advisor::Provider::from_slug(s).is_some() {
        Ok(s.to_string())
    } else {
        Err(format!(
            "invalid --advisor '{s}'; must be one of: none, claude-cli, codex, ollama"
        ))
    }
}

pub(super) fn parse_workspace_concurrency(s: &str) -> Result<NonZeroUsize, String> {
    workspace_concurrency_config::parse_workspace_concurrency(s)
}

/// clap `value_parser` for an exact release version. Only the canonical
/// form is accepted (`0.84.0`, not `v0.84.0`) because the version is
/// interpolated verbatim into signed Git refs such as `refs/tags/v0.84.0`.
pub(super) fn parse_canonical_release_version(raw: &str) -> Result<String, String> {
    let parsed = lpm_semver::Version::parse(raw).map_err(|error| error.to_string())?;
    let canonical = parsed.to_string();
    if canonical != raw {
        return Err(format!("expected the canonical version `{canonical}`"));
    }
    Ok(canonical)
}

pub(super) fn parse_rfc3339_utc(raw: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|error| format!("expected an RFC 3339 timestamp: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_release_version_accepts_stable_and_nightly_versions() {
        for version in ["0.84.0", "0.75.0-nightly.20260817.1.1e98fb8"] {
            assert_eq!(
                parse_canonical_release_version(version).as_deref(),
                Ok(version)
            );
        }
    }

    #[test]
    fn canonical_release_version_rejects_tag_prefix() {
        assert!(parse_canonical_release_version("v0.84.0").is_err());
    }

    #[test]
    fn canonical_release_version_names_the_canonical_form_for_leading_zeros_and_whitespace() {
        for raw in ["00.84.0", " 0.84.0"] {
            assert_eq!(
                parse_canonical_release_version(raw),
                Err("expected the canonical version `0.84.0`".to_owned()),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn canonical_release_version_rejects_incomplete_versions() {
        assert!(parse_canonical_release_version("0.84").is_err());
    }

    #[test]
    fn rfc3339_utc_normalizes_offsets_to_utc() {
        let parsed = parse_rfc3339_utc("2026-11-02T07:06:07+03:00").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-11-02T04:06:07+00:00");
    }

    #[test]
    fn rfc3339_utc_rejects_dates_without_a_time() {
        let error = parse_rfc3339_utc("2026-11-02").unwrap_err();
        assert!(
            error.starts_with("expected an RFC 3339 timestamp"),
            "{error}"
        );
    }
}
