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
