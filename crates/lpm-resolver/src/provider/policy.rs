use super::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OverrideTargetRejection {
    NotPublished,
    ReleaseAge {
        remaining_secs: u64,
        minimum_secs: u64,
    },
    MissingReleaseTime,
    TrustPolicy(String),
    PlatformIncompatible,
}

impl std::fmt::Display for OverrideTargetRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublished => formatter.write_str("no published version matches the target"),
            Self::ReleaseAge {
                remaining_secs,
                minimum_secs,
            } => write!(
                formatter,
                "blocked by minimumReleaseAge; {remaining_secs}s remaining (minimumReleaseAge={minimum_secs}s)"
            ),
            Self::MissingReleaseTime => formatter.write_str(
                "blocked because strict minimumReleaseAge policy requires publish-time metadata",
            ),
            Self::TrustPolicy(reason) => {
                write!(formatter, "blocked by trust-policy no-downgrade: {reason}")
            }
            Self::PlatformIncompatible => {
                formatter.write_str("incompatible with the current OS/CPU/libc")
            }
        }
    }
}

pub(crate) fn release_age_status_for_version(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> ReleaseTimeStatus {
    if !policy.release_age_applies_to_package(package) {
        return ReleaseTimeStatus::Allowed;
    }
    let start = std::time::Instant::now();
    let status = release_age_status_for_version_unprofiled(package, info, version, policy);
    crate::profile::record_release_age_check(
        start.elapsed(),
        !matches!(status, ReleaseTimeStatus::Allowed),
        matches!(status, ReleaseTimeStatus::Missing),
    );
    status
}

pub(crate) fn release_age_status_for_version_unprofiled(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> ReleaseTimeStatus {
    if !policy.release_age_applies_to_package(package)
        || policy.release_age_version_excluded(package, version)
    {
        return ReleaseTimeStatus::Allowed;
    }
    let published_unix = if info.release_records_empty() {
        None
    } else {
        info.published_at_unix_for(version)
    };
    if published_unix.is_none()
        && policy.metadata_modified_before_or_at_cutoff_for_package(
            package,
            info.modified.as_deref(),
            info.modified_unix,
        )
    {
        return ReleaseTimeStatus::Allowed;
    }
    policy.release_time_status_unix_for_package_version(package, version, published_unix)
}

pub(crate) fn trust_downgrade_violation(
    info: &CachedPackageInfo,
    version: &NpmVersion,
) -> Option<String> {
    let start = std::time::Instant::now();
    let violation = trust_downgrade_violation_unprofiled(info, version);
    crate::profile::record_trust_policy_check(start.elapsed(), violation.is_some());
    violation
}

pub(crate) fn trust_downgrade_violation_unprofiled(
    info: &CachedPackageInfo,
    version: &NpmVersion,
) -> Option<String> {
    if info.trust_is_empty() {
        return None;
    }
    let published_unix = info.published_at_unix_for(version)?;
    let current_evidence = info.trust_evidence_for(version);
    if current_evidence == Some(TrustEvidence::StagedPublish) {
        return None;
    }

    let timeline = info.trust_timeline();
    let (earliest_staged, earliest_trusted) = if version.is_prerelease() {
        (timeline.earliest_staged_any, timeline.earliest_trusted_any)
    } else {
        (
            timeline.earliest_staged_stable,
            timeline.earliest_trusted_stable,
        )
    };
    let strongest_prior = if earliest_staged.is_some_and(|ts| ts < published_unix) {
        Some(TrustEvidence::StagedPublish)
    } else if earliest_trusted.is_some_and(|ts| ts < published_unix) {
        Some(TrustEvidence::TrustedPublisher)
    } else {
        None
    };

    let prior = strongest_prior?;
    if current_evidence.is_some_and(|current| current >= prior) {
        return None;
    }
    let current_label = current_evidence.map_or("no trust evidence", TrustEvidence::label);
    Some(format!(
        "{version} has {current_label}; an earlier published version had {}",
        prior.label()
    ))
}

pub(crate) fn version_allowed_by_policy(
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

pub(crate) fn select_override_target(
    package: &CanonicalKey,
    info: &CachedPackageInfo,
    target: &OverrideTarget,
    policy: &ResolverPolicy,
) -> Result<NpmVersion, OverrideTargetRejection> {
    let candidate_rejection = |version: &NpmVersion| {
        match release_age_status_for_version(package, info, version, policy) {
            ReleaseTimeStatus::Allowed => {}
            ReleaseTimeStatus::TooNew { remaining_secs } => {
                return Some(OverrideTargetRejection::ReleaseAge {
                    remaining_secs,
                    minimum_secs: policy.minimum_release_age_secs(),
                });
            }
            ReleaseTimeStatus::Missing => {
                return Some(OverrideTargetRejection::MissingReleaseTime);
            }
        }
        if policy.trust_policy().is_no_downgrade()
            && let Some(reason) = trust_downgrade_violation(info, version)
        {
            return Some(OverrideTargetRejection::TrustPolicy(reason));
        }
        if info.has_platform_metadata()
            && info
                .platform_is_compatible_for(version)
                .is_some_and(|compatible| !compatible)
        {
            return Some(OverrideTargetRejection::PlatformIncompatible);
        }
        None
    };

    match target {
        OverrideTarget::PinnedVersion { version, .. } => {
            if !info.versions.contains(version) {
                return Err(OverrideTargetRejection::NotPublished);
            }
            if let Some(rejection) = candidate_rejection(version) {
                return Err(rejection);
            }
            Ok(version.clone())
        }
        OverrideTarget::Range {
            range: target_range,
            ..
        } => {
            let mut first_rejection = None;
            for version in info.versions.iter() {
                if !target_range.satisfies(version) {
                    continue;
                }
                if let Some(rejection) = candidate_rejection(version) {
                    first_rejection.get_or_insert(rejection);
                    continue;
                }
                return Ok(version.clone());
            }
            Err(first_rejection.unwrap_or(OverrideTargetRejection::NotPublished))
        }
    }
}
