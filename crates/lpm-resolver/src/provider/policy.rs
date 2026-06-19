use super::prelude::*;

pub(crate) fn release_age_status_for_version(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> ReleaseTimeStatus {
    let start = std::time::Instant::now();
    let status = release_age_status_for_version_inner(package, info, version, policy);
    crate::profile::record_release_age_check(
        start.elapsed(),
        !matches!(status, ReleaseTimeStatus::Allowed),
        matches!(status, ReleaseTimeStatus::Missing),
    );
    status
}

fn release_age_status_for_version_inner(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> ReleaseTimeStatus {
    let published_unix = info
        .dist
        .get(&version.to_string())
        .and_then(|dist| dist.published_at_unix);
    if published_unix.is_none()
        && policy.metadata_modified_before_or_at_cutoff_for_package(
            package,
            info.modified.as_deref(),
            info.modified_unix,
        )
    {
        return ReleaseTimeStatus::Allowed;
    }
    policy.release_time_status_unix_for_package(package, published_unix)
}

pub(crate) fn trust_downgrade_violation(
    info: &CachedPackageInfo,
    version: &NpmVersion,
) -> Option<String> {
    let start = std::time::Instant::now();
    let violation = trust_downgrade_violation_inner(info, version);
    crate::profile::record_trust_policy_check(start.elapsed(), violation.is_some());
    violation
}

fn trust_downgrade_violation_inner(
    info: &CachedPackageInfo,
    version: &NpmVersion,
) -> Option<String> {
    let version_str = version.to_string();
    let current = info.dist.get(&version_str)?;
    let published_unix = current.published_at_unix?;
    let current_evidence = current.trust_evidence;
    let exclude_prerelease = !version.is_prerelease();

    let mut strongest_prior: Option<TrustEvidence> = None;
    for candidate in &info.versions {
        if exclude_prerelease && candidate.is_prerelease() {
            continue;
        }
        let candidate_str = candidate.to_string();
        if candidate_str == version_str {
            continue;
        }
        let Some(dist) = info.dist.get(&candidate_str) else {
            continue;
        };
        let Some(candidate_published) = dist.published_at_unix else {
            continue;
        };
        if candidate_published >= published_unix {
            continue;
        }
        let Some(evidence) = dist.trust_evidence else {
            continue;
        };
        if strongest_prior.is_none_or(|prior| evidence > prior) {
            strongest_prior = Some(evidence);
            if evidence == TrustEvidence::StagedPublish {
                break;
            }
        }
    }

    let prior = strongest_prior?;
    if current_evidence.is_some_and(|current| current >= prior) {
        return None;
    }
    let current_label = current_evidence.map_or("no trust evidence", TrustEvidence::label);
    Some(format!(
        "{version_str} has {current_label}; an earlier published version had {}",
        prior.label()
    ))
}

pub(super) fn version_allowed_by_policy(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> bool {
    matches!(
        release_age_status_for_version(package, info, version, policy),
        ReleaseTimeStatus::Allowed
    ) && (!policy.trust_policy().is_no_downgrade()
        || trust_downgrade_violation(info, version).is_none())
}
