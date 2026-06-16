use lpm_common::LpmError;
use lpm_registry::PackageMetadata;
use lpm_resolver::{ReleaseTimeStatus, ResolverPolicy, TrustPolicyMode};
use lpm_semver::{Version, VersionReq};
use std::path::Path;

pub(crate) fn resolver_policy_for_project(
    project_dir: &Path,
    min_release_age_override: Option<u64>,
    allow_new: bool,
    json_output: bool,
) -> Result<ResolverPolicy, LpmError> {
    let effective_min_age_secs = crate::release_age_config::ReleaseAgeResolver::resolve(
        project_dir,
        min_release_age_override,
        json_output,
    )?;
    let minimum_release_age_secs = if allow_new { 0 } else { effective_min_age_secs };
    Ok(ResolverPolicy::new(
        minimum_release_age_secs,
        TrustPolicyMode::Off,
    ))
}

pub(crate) fn latest_allowed_version(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Option<String> {
    if let Some(latest) = metadata.latest_version_tag()
        && version_allowed_by_policy(metadata, latest, policy)
        && Version::parse(latest).is_ok()
    {
        return Some(latest.to_string());
    }

    let mut versions = parse_versions(metadata);
    versions.sort();
    versions
        .into_iter()
        .rev()
        .map(|version| version.to_string())
        .find(|version| version_allowed_by_policy(metadata, version, policy))
}

pub(crate) fn latest_allowed_version_or_policy_error(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Result<String, LpmError> {
    if let Some(version) = latest_allowed_version(metadata, policy) {
        return Ok(version);
    }

    let Some(candidate) = parse_versions(metadata).into_iter().max() else {
        return Err(LpmError::Script(format!(
            "registry returned no parseable versions for '{}'",
            metadata.name
        )));
    };
    let candidate = candidate.to_string();
    Err(policy_blocked_error(metadata, &candidate, policy))
}

pub(crate) fn allowed_version_strings(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Vec<String> {
    metadata
        .versions
        .keys()
        .filter(|version| version_allowed_by_policy(metadata, version, policy))
        .cloned()
        .collect()
}

pub(crate) fn resolve_version_spec_with_policy(
    metadata: &PackageMetadata,
    spec: &str,
    policy: &ResolverPolicy,
) -> Result<String, LpmError> {
    if let Some(version) = metadata.dist_tags.get(spec) {
        return if version_allowed_by_policy(metadata, version, policy) {
            Ok(version.clone())
        } else {
            Err(policy_blocked_error(metadata, version, policy))
        };
    }

    if metadata.versions.contains_key(spec) {
        return if version_allowed_by_policy(metadata, spec, policy) {
            Ok(spec.to_string())
        } else {
            Err(policy_blocked_error(metadata, spec, policy))
        };
    }

    let req = VersionReq::parse(spec)
        .map_err(|e| LpmError::Script(format!("could not parse version token '{spec}': {e}")))?;
    let mut versions = parse_versions(metadata);
    if versions.is_empty() {
        return Err(LpmError::Script(format!(
            "registry returned no parseable versions for '{}'",
            metadata.name
        )));
    }
    versions.retain(|version| {
        req.matches(version) && version_allowed_by_policy(metadata, &version.to_string(), policy)
    });
    if let Some(version) = versions.into_iter().max() {
        return Ok(version.to_string());
    }

    let mut available = parse_versions(metadata);
    available.sort();
    Err(LpmError::Script(format!(
        "no version of '{}' satisfies '{}'. Available: {}",
        metadata.name,
        spec,
        available
            .iter()
            .rev()
            .take(5)
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn parse_versions(metadata: &PackageMetadata) -> Vec<Version> {
    metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .collect()
}

fn version_allowed_by_policy(
    metadata: &PackageMetadata,
    version: &str,
    policy: &ResolverPolicy,
) -> bool {
    matches!(
        policy.release_time_status(metadata.time.get(version).map(String::as_str)),
        ReleaseTimeStatus::Allowed
    )
}

fn policy_blocked_error(
    metadata: &PackageMetadata,
    version: &str,
    policy: &ResolverPolicy,
) -> LpmError {
    let detail = match policy.release_time_status(metadata.time.get(version).map(String::as_str)) {
        ReleaseTimeStatus::Allowed => "allowed by policy".to_string(),
        ReleaseTimeStatus::Missing => format!(
            "missing publish time for minimumReleaseAge={}s",
            policy.minimum_release_age_secs()
        ),
        ReleaseTimeStatus::TooNew { remaining_secs } => format!(
            "published too recently for minimumReleaseAge; {remaining_secs}s remaining (minimumReleaseAge={}s)",
            policy.minimum_release_age_secs()
        ),
    };
    LpmError::Script(format!("{}@{version} is blocked: {detail}", metadata.name))
}
