use super::prelude::*;

pub(crate) fn release_age_status_for_version(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> ReleaseTimeStatus {
    info.dist
        .get(&version.to_string())
        .and_then(|dist| dist.published_at.as_deref())
        .map_or_else(
            || policy.release_time_status_for_package(package, None),
            |published_at| policy.release_time_status_for_package(package, Some(published_at)),
        )
}

pub(crate) fn trust_downgrade_violation(
    info: &CachedPackageInfo,
    version: &NpmVersion,
) -> Option<String> {
    let version_str = version.to_string();
    let current = info.dist.get(&version_str)?;
    let published_at = current.published_at.as_deref()?;
    let published_unix = parse_npm_time_unix(published_at)?;
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
        let Some(candidate_published) = dist.published_at.as_deref().and_then(parse_npm_time_unix)
        else {
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
