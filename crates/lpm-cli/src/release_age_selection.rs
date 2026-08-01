use lpm_common::LpmError;
use lpm_registry::PackageMetadata;
use lpm_resolver::{CanonicalKey, ReleaseTimeStatus, ResolverPolicy, TrustPolicyMode};
use lpm_semver::{Version, VersionReq};
use std::path::Path;

pub(crate) fn resolver_policy_for_project(
    project_dir: &Path,
    min_release_age_override: Option<u64>,
    allow_new: bool,
    json_output: bool,
) -> Result<ResolverPolicy, LpmError> {
    resolver_policy_for_project_with_excludes(
        project_dir,
        min_release_age_override,
        &[],
        allow_new,
        json_output,
    )
}

pub(crate) fn resolver_policy_for_project_with_excludes(
    project_dir: &Path,
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    allow_new: bool,
    json_output: bool,
) -> Result<ResolverPolicy, LpmError> {
    let config = crate::release_age_config::ReleaseAgeResolver::resolve_config(
        project_dir,
        min_release_age_override,
        min_release_age_exclude,
        json_output,
    )?;
    let minimum_release_age_secs = if allow_new {
        0
    } else {
        config.minimum_release_age_secs
    };
    let excludes = crate::release_age_config::parse_release_age_exclusions(
        "resolved minimum-release-age exclusions",
        &config.minimum_release_age_exclude,
    )?;
    Ok(ResolverPolicy::new_with_release_age_excludes(
        minimum_release_age_secs,
        TrustPolicyMode::Off,
        excludes,
    ))
}

pub(crate) fn latest_allowed_version(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Option<String> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    let latest_tag = metadata.latest_version_tag();
    let latest = latest_tag.and_then(|version| Version::parse(version).ok());
    if let Some(latest_tag) = latest_tag
        && latest.is_some()
        && version_allowed_by_policy(&canonical, metadata, latest_tag, policy)
    {
        return Some(latest_tag.to_string());
    }

    let mut versions = parse_versions(metadata);
    versions.sort();
    versions
        .into_iter()
        .rev()
        .filter(|version| latest.as_ref().is_none_or(|latest| version <= latest))
        .map(|version| version.to_string())
        .find(|version| version_allowed_by_policy(&canonical, metadata, version, policy))
}

pub(crate) fn latest_allowed_version_or_policy_error(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Result<String, LpmError> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    if let Some(version) = latest_allowed_version(metadata, policy) {
        return Ok(version);
    }

    let candidate = metadata
        .latest_version_tag()
        .and_then(|version| Version::parse(version).ok())
        .or_else(|| parse_versions(metadata).into_iter().max());
    let Some(candidate) = candidate else {
        return Err(LpmError::Script(format!(
            "registry returned no parseable versions for '{}'",
            metadata.name
        )));
    };
    let candidate = candidate.to_string();
    Err(policy_blocked_error(
        &canonical, metadata, &candidate, policy,
    ))
}

pub(crate) fn allowed_version_strings(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Vec<String> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    metadata
        .versions
        .keys()
        .filter(|version| version_allowed_by_policy(&canonical, metadata, version, policy))
        .cloned()
        .collect()
}

pub(crate) fn resolve_version_spec_with_policy(
    metadata: &PackageMetadata,
    spec: &str,
    policy: &ResolverPolicy,
) -> Result<String, LpmError> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    if let Some(version) = metadata.dist_tags.get(spec) {
        return if version_allowed_by_policy(&canonical, metadata, version, policy) {
            Ok(version.clone())
        } else {
            Err(policy_blocked_error(&canonical, metadata, version, policy))
        };
    }

    if metadata.versions.contains_key(spec) {
        return if version_allowed_by_policy(&canonical, metadata, spec, policy) {
            Ok(spec.to_string())
        } else {
            Err(policy_blocked_error(&canonical, metadata, spec, policy))
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
        req.matches(version)
            && version_allowed_by_policy(&canonical, metadata, &version.to_string(), policy)
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
    canonical: &CanonicalKey,
    metadata: &PackageMetadata,
    version: &str,
    policy: &ResolverPolicy,
) -> bool {
    let Ok(parsed_version) = lpm_resolver::NpmVersion::parse(version) else {
        return false;
    };
    matches!(
        policy.release_time_status_for_package_version(
            canonical,
            &parsed_version,
            metadata.time.get(version).map(String::as_str)
        ),
        ReleaseTimeStatus::Allowed
    )
}

fn policy_blocked_error(
    canonical: &CanonicalKey,
    metadata: &PackageMetadata,
    version: &str,
    policy: &ResolverPolicy,
) -> LpmError {
    let status = lpm_resolver::NpmVersion::parse(version).map_or_else(
        |_| {
            policy.release_time_status_for_package(
                canonical,
                metadata.time.get(version).map(String::as_str),
            )
        },
        |parsed_version| {
            policy.release_time_status_for_package_version(
                canonical,
                &parsed_version,
                metadata.time.get(version).map(String::as_str),
            )
        },
    );
    let detail = match status {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_allowed_version_fallback_never_exceeds_dist_tag_target() {
        let metadata: PackageMetadata = serde_json::from_value(serde_json::json!({
            "name": "rolled-back-latest",
            "dist-tags": { "latest": "3.1.0" },
            "versions": {
                "3.0.0": { "name": "rolled-back-latest", "version": "3.0.0" },
                "3.1.0": { "name": "rolled-back-latest", "version": "3.1.0" },
                "4.0.0": { "name": "rolled-back-latest", "version": "4.0.0" }
            },
            "time": {
                "3.0.0": "2025-01-01T00:00:00.000Z",
                "3.1.0": "9999-01-01T00:00:00.000Z",
                "4.0.0": "2025-01-01T00:00:00.000Z"
            }
        }))
        .unwrap();
        let policy = ResolverPolicy::new(86_400, TrustPolicyMode::Off);

        assert_eq!(
            latest_allowed_version(&metadata, &policy),
            Some("3.0.0".to_string())
        );
    }
}
