use super::types::PublishTarget;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::collections::HashSet;

/// Resolve the target registries from CLI flags and lpm.json config.
///
/// CLI flags take precedence. If no flags, read from lpm.json.
/// If no config, default to LPM only.
///
/// Returns an error if the config contains unknown registry entries or if the
/// resolved target list is empty.
pub fn resolve_targets(
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    config: Option<&lpm_json::PublishConfig>,
) -> Result<Vec<PublishTarget>, LpmError> {
    let has_cli_flags = cli_npm || cli_lpm || cli_github || cli_gitlab || cli_registry.is_some();

    if has_cli_flags {
        let mut targets = Vec::new();
        if cli_lpm {
            targets.push(PublishTarget::Lpm);
        }
        if cli_npm {
            targets.push(PublishTarget::Npm);
        }
        if cli_github {
            targets.push(PublishTarget::GitHub);
        }
        if cli_gitlab {
            targets.push(PublishTarget::GitLab);
        }
        if let Some(url) = cli_registry {
            validate_custom_publish_registry_url(url, "--publish-registry")?;
            targets.push(PublishTarget::Custom(url.to_string()));
        }
        return Ok(deduplicate_targets(targets));
    }

    if let Some(publish_config) = config
        && !publish_config.registries.is_empty()
    {
        let mut targets = Vec::new();
        let mut unknown = Vec::new();

        for r in &publish_config.registries {
            match r.as_str() {
                "lpm" => targets.push(PublishTarget::Lpm),
                "npm" => targets.push(PublishTarget::Npm),
                "github" => targets.push(PublishTarget::GitHub),
                "gitlab" => targets.push(PublishTarget::GitLab),
                url if url.starts_with("https://") => {
                    validate_custom_publish_registry_url(url, "publish.registries")?;
                    targets.push(PublishTarget::Custom(url.to_string()));
                }
                url if url.starts_with("http://") => {
                    validate_custom_publish_registry_url(url, "publish.registries")?;
                }
                other => unknown.push(other.to_string()),
            }
        }

        if !unknown.is_empty() {
            return Err(LpmError::Registry(format!(
                "unknown publish registries in lpm.json: {}. \
                 Valid values: lpm, npm, github, gitlab, or an https:// URL",
                unknown.join(", ")
            )));
        }

        if targets.is_empty() {
            return Err(LpmError::Registry(
                "publish.registries in lpm.json resolved to no targets".into(),
            ));
        }

        return Ok(deduplicate_targets(targets));
    }

    // Default: LPM only
    Ok(vec![PublishTarget::Lpm])
}

pub(super) fn validate_custom_publish_registry_url(
    url: &str,
    source: &str,
) -> Result<(), LpmError> {
    if url.starts_with("https://") {
        warn_on_unfamiliar_publish_host(url);
        return Ok(());
    }

    if url.starts_with("http://") {
        return Err(LpmError::Registry(format!(
            "{source}: refusing HTTP URL \"{url}\" — publish requires HTTPS"
        )));
    }

    Err(LpmError::Registry(format!(
        "{source}: custom publish registry must be an https:// URL, got \"{url}\""
    )))
}

pub(super) fn warn_on_unfamiliar_publish_host(url: &str) {
    let host = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| url.to_string());
    if !is_known_publish_host(&host) {
        tracing::warn!(
            target_url = %url,
            host = %host,
            "custom publish registry routes to a non-default host; confirm this is intentional",
        );
    }
}

/// Hosts considered "default" / first-party publish destinations.
/// A custom URL pointing at any of these is NOT noisy; everything
/// else triggers a `tracing::warn` so an unexpected target is
/// visible in operator logs before the publish bearer is sent.
pub(super) fn is_known_publish_host(host: &str) -> bool {
    matches!(
        host,
        "lpm.dev" | "registry.npmjs.org" | "npm.pkg.github.com" | "registry.gitlab.com"
    ) || host.ends_with(".lpm.dev")
        || host.ends_with(".lpm.fyi")
}

/// Deduplicate targets while preserving order.
pub(super) fn deduplicate_targets(targets: Vec<PublishTarget>) -> Vec<PublishTarget> {
    let mut seen = HashSet::new();
    targets
        .into_iter()
        .filter(|t| seen.insert(t.key()))
        .collect()
}
