use lpm_common::LpmError;
use lpm_registry::PackageMetadata;
use lpm_resolver::{CanonicalKey, ReleaseTimeStatus, ResolverPolicy, TrustPolicyMode};
use lpm_semver::{Version, VersionReq};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReleaseTimeMetadataSource {
    NpmDirect,
    WorkerOnly,
}

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

#[cfg(test)]
pub(crate) fn latest_allowed_version(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Option<String> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    let latest_tag = metadata.latest_version_tag();
    let latest = latest_tag.and_then(|version| Version::parse(version).ok());
    if let Some(latest_tag) = latest_tag
        && latest.is_some()
        && metadata.versions.contains_key(latest_tag)
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
    Ok(allowed_version_index(metadata, policy)?.latest)
}

pub(crate) struct AllowedVersionIndex {
    pub(crate) latest: String,
    pub(crate) versions: Vec<Version>,
}

impl AllowedVersionIndex {
    pub(crate) fn resolve_spec(
        &self,
        metadata: &PackageMetadata,
        spec: &str,
        policy: &ResolverPolicy,
    ) -> Result<String, LpmError> {
        let canonical = CanonicalKey::from_dep_name(&metadata.name);
        if let Some(version) = metadata.dist_tags.get(spec) {
            return if metadata.versions.contains_key(version)
                && version_allowed_by_policy(&canonical, metadata, version, policy)
            {
                Ok(version.clone())
            } else if !metadata.versions.contains_key(version) {
                Err(LpmError::Script(format!(
                    "registry tag '{spec}' for '{}' points to missing version '{version}'",
                    metadata.name
                )))
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

        let req = VersionReq::parse(spec).map_err(|e| {
            LpmError::Script(format!("could not parse version token '{spec}': {e}"))
        })?;
        if let Some(version) = self
            .versions
            .iter()
            .rev()
            .find(|version| req.matches(version))
        {
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
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
}

pub(crate) fn allowed_version_index(
    metadata: &PackageMetadata,
    policy: &ResolverPolicy,
) -> Result<AllowedVersionIndex, LpmError> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    let parsed_latest = if let Some(latest) = metadata.latest_version_tag() {
        if !metadata.versions.contains_key(latest) {
            return Err(LpmError::Script(format!(
                "registry tag 'latest' for '{}' points to missing version '{latest}'",
                metadata.name
            )));
        }
        Some(Version::parse(latest).map_err(|error| {
            LpmError::Script(format!(
                "registry tag 'latest' for '{}' contains invalid version '{latest}': {error}",
                metadata.name
            ))
        })?)
    } else {
        None
    };

    let mut versions = Vec::with_capacity(metadata.versions.len());
    for version in metadata.versions.keys() {
        let Ok(parsed) = Version::parse(version) else {
            continue;
        };
        if version_allowed_by_policy(&canonical, metadata, version, policy) {
            versions.push(parsed);
        }
    }
    versions.sort();

    let latest = metadata
        .latest_version_tag()
        .filter(|version| version_allowed_by_policy(&canonical, metadata, version, policy))
        .map(str::to_string)
        .or_else(|| {
            versions
                .iter()
                .rev()
                .find(|version| {
                    parsed_latest
                        .as_ref()
                        .is_none_or(|latest| *version <= latest)
                })
                .map(ToString::to_string)
        });
    if let Some(latest) = latest {
        return Ok(AllowedVersionIndex { latest, versions });
    }

    let candidate = metadata
        .latest_version_tag()
        .filter(|version| metadata.versions.contains_key(*version))
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

pub(crate) async fn hydrate_release_times_if_needed(
    client: &lpm_registry::RegistryClient,
    metadata: &mut PackageMetadata,
    policy: &ResolverPolicy,
    source: ReleaseTimeMetadataSource,
) -> Result<(), LpmError> {
    let canonical = CanonicalKey::from_dep_name(&metadata.name);
    let missing_release_times = metadata
        .versions
        .keys()
        .any(|version| !metadata.time.contains_key(version));
    if !missing_release_times
        || !policy.metadata_may_need_release_times(&canonical, metadata.modified.as_deref())
    {
        return Ok(());
    }

    let release_times = match source {
        ReleaseTimeMetadataSource::NpmDirect => {
            client
                .get_npm_release_times_routed_full(
                    &metadata.name,
                    lpm_registry::UpstreamRoute::NpmDirect,
                )
                .await?
        }
        ReleaseTimeMetadataSource::WorkerOnly => {
            client
                .get_npm_release_times_proxy_only(&metadata.name)
                .await?
        }
    };
    metadata.time.extend(release_times.time);

    if let Some(version) = metadata
        .versions
        .keys()
        .find(|version| !metadata.time.contains_key(*version))
    {
        return Err(LpmError::Registry(format!(
            "registry returned incomplete release-time metadata for '{}@{version}'",
            metadata.name
        )));
    }
    Ok(())
}

pub(crate) fn resolve_version_spec_with_policy(
    metadata: &PackageMetadata,
    spec: &str,
    policy: &ResolverPolicy,
) -> Result<String, LpmError> {
    if let Some(version) = metadata.dist_tags.get(spec) {
        let canonical = CanonicalKey::from_dep_name(&metadata.name);
        return if version_allowed_by_policy(&canonical, metadata, version, policy) {
            Ok(version.clone())
        } else {
            Err(policy_blocked_error(&canonical, metadata, version, policy))
        };
    }
    allowed_version_index(metadata, policy)?.resolve_spec(metadata, spec, policy)
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

    #[test]
    fn latest_allowed_version_rejects_a_dangling_latest_tag() {
        let metadata: PackageMetadata = serde_json::from_value(serde_json::json!({
            "name": "dangling-latest",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": { "name": "dangling-latest", "version": "1.0.0" }
            }
        }))
        .unwrap();

        assert_eq!(
            latest_allowed_version(&metadata, &ResolverPolicy::default()),
            Some("1.0.0".to_string())
        );
    }

    #[test]
    fn allowed_version_index_rejects_metadata_without_parseable_versions() {
        let metadata: PackageMetadata = serde_json::from_value(serde_json::json!({
            "name": "invalid-versions",
            "versions": {
                "not-semver": { "name": "invalid-versions", "version": "not-semver" }
            }
        }))
        .unwrap();

        let error = match allowed_version_index(&metadata, &ResolverPolicy::default()) {
            Ok(_) => panic!("metadata without a semantic version must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("no parseable versions"));
    }
}
