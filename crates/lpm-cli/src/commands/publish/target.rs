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
                url if url.starts_with("https://") || url.starts_with("http://") => {
                    validate_custom_publish_registry_url(url, "publish.registries")?;
                    targets.push(PublishTarget::Custom(url.to_string()));
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
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        LpmError::Registry(format!(
            "{source}: custom publish registry must be an https:// URL, got \"remote-url\""
        ))
    })?;
    let safe_url = parsed.origin().ascii_serialization();
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Registry(format!(
            "{source}: custom publish registry URL must not contain credentials: \"{safe_url}\""
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Registry(format!(
            "{source}: custom publish registry URL must not contain a query or fragment: \"{safe_url}\""
        )));
    }
    let is_loopback_http =
        parsed.scheme() == "http" && parsed.host_str().is_some_and(lpm_common::is_loopback_host);
    if parsed.scheme() != "https" && !is_loopback_http {
        return Err(LpmError::Registry(format!(
            "{source}: refusing non-HTTPS URL \"{safe_url}\" — publish requires HTTPS"
        )));
    }
    warn_on_unfamiliar_publish_host(&parsed);
    Ok(())
}

fn warn_on_unfamiliar_publish_host(url: &reqwest::Url) {
    let host = url.host_str().unwrap_or_default();
    if !is_known_publish_host(host) {
        tracing::warn!(
            target_url = %url.origin().ascii_serialization(),
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
        .filter(|target| seen.insert(publish_target_identity(target)))
        .collect()
}

fn publish_target_identity(target: &PublishTarget) -> String {
    let PublishTarget::Custom(registry_url) = target else {
        return target.key();
    };
    normalized_custom_publish_endpoint(registry_url).unwrap_or_else(|| registry_url.clone())
}

fn normalized_custom_publish_endpoint(registry_url: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(registry_url).ok()?;
    let path = canonicalize_publish_endpoint_path(parsed.path());
    let path = path.trim_end_matches('/');
    parsed.set_path(if path.is_empty() { "/" } else { path });
    Some(parsed.as_str().trim_end_matches('/').to_string())
}

fn canonicalize_publish_endpoint_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut normalized = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (
                publish_endpoint_hex_value(bytes[index + 1]),
                publish_endpoint_hex_value(bytes[index + 2]),
            )
        {
            let decoded = (high << 4) | low;
            if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                normalized.push(char::from(decoded));
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                normalized.push('%');
                normalized.push(char::from(HEX[usize::from(high)]));
                normalized.push(char::from(HEX[usize::from(low)]));
            }
            index += 3;
            continue;
        }
        normalized.push(char::from(bytes[index]));
        index += 1;
    }
    normalized
}

fn publish_endpoint_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
