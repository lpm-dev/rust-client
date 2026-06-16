use super::prelude::*;

/// Outcome of `find_best_version`. Distinguishes "no version exists
/// satisfying the range" from "a satisfying version exists but the
/// current platform isn't compatible" so callers can increment
/// `platform_skipped` precisely.
pub(super) enum VersionPick {
    /// A satisfying version was found.
    Picked(NpmVersion),
    /// No version satisfies the range.
    NoSatisfying,
    /// A satisfying version exists but is blocked by release-age.
    BlockedByReleaseAge {
        version: NpmVersion,
        remaining_secs: u64,
        minimum_secs: u64,
    },
    /// The selected candidate would reduce publisher/provenance trust.
    BlockedByTrustPolicy { version: NpmVersion, reason: String },
}

/// Detect a leaked `workspace:` specifier before [`NpmRange::parse`] gets
/// to it. The implementation lives in [`crate::ranges::is_workspace_specifier`]
/// so both resolver arms consult the same predicate; this thin re-export
/// keeps the local callsite readable.
pub(super) fn is_workspace_specifier(range_str: &str) -> bool {
    crate::ranges::is_workspace_specifier(range_str)
}

/// Greedy first-match version pick. Iterates `info.versions` (sorted
/// descending by semver in
/// [`crate::provider::parse_metadata_to_cache_info`]) and returns the
/// first version satisfying the range. Platform compatibility is applied
/// after resolution so lockfiles remain portable across hosts.
#[cfg(test)]
pub(super) fn find_best_version(info: &CachedPackageInfo, range: &NpmRange) -> VersionPick {
    find_best_version_with_policy(&CanonicalKey::Root, info, range, &ResolverPolicy::default())
}

pub(super) fn find_best_version_with_policy(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    range: &NpmRange,
    policy: &ResolverPolicy,
) -> VersionPick {
    let mut first_policy_block: Option<VersionPick> = None;
    for v in &info.versions {
        if !range.satisfies(v) {
            continue;
        }
        match release_age_status_for_version(canonical, info, v, policy) {
            ReleaseTimeStatus::Allowed => {}
            ReleaseTimeStatus::Missing => {
                return VersionPick::BlockedByReleaseAge {
                    version: v.clone(),
                    remaining_secs: policy.minimum_release_age_secs(),
                    minimum_secs: policy.minimum_release_age_secs(),
                };
            }
            ReleaseTimeStatus::TooNew { remaining_secs } => {
                if first_policy_block.is_none() {
                    first_policy_block = Some(VersionPick::BlockedByReleaseAge {
                        version: v.clone(),
                        remaining_secs,
                        minimum_secs: policy.minimum_release_age_secs(),
                    });
                }
                continue;
            }
        }
        if policy.trust_policy().is_no_downgrade()
            && let Some(reason) = trust_downgrade_violation(info, v)
        {
            if first_policy_block.is_none() {
                first_policy_block = Some(VersionPick::BlockedByTrustPolicy {
                    version: v.clone(),
                    reason,
                });
            }
            continue;
        }
        return VersionPick::Picked(v.clone());
    }
    first_policy_block.unwrap_or(VersionPick::NoSatisfying)
}
