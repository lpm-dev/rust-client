use super::prelude::*;
use super::state::ResolveState;
use super::types::Edge;

/// Apply an [`OverrideTarget`] against the consumer's range, walking THIS
/// canonical's cached versions to produce a final forced version. Mirrors
/// [`crate::provider::LpmDependencyProvider::apply_override_target`]'s
/// pubgrub-arm semantics:
///
/// - `PinnedVersion` returns the pinned version verbatim, but ONLY if it
///   satisfies the consumer's declared range. Out-of-range targets return
///   `None` so the caller can fall through to the natural pick.
/// - `Range` intersects the override range with the consumer range (over
///   the cache's available versions list for THIS package) and picks the
///   newest match. Platform-incompatible candidates are skipped; this can
///   return `None` even when an in-range version exists if every candidate
///   is filtered out.
pub(super) fn apply_override_target_greedy(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    target: &OverrideTarget,
    range: &NpmRange,
    policy: &ResolverPolicy,
) -> Option<NpmVersion> {
    match target {
        OverrideTarget::PinnedVersion { version, .. } => {
            if range.satisfies(version)
                && matches!(
                    release_age_status_for_version(canonical, info, version, policy),
                    ReleaseTimeStatus::Allowed
                )
                && (!policy.trust_policy().is_no_downgrade()
                    || trust_downgrade_violation(info, version).is_none())
            {
                Some(version.clone())
            } else {
                None
            }
        }
        OverrideTarget::Range {
            range: target_range,
            ..
        } => {
            // Versions are sorted newest-first by
            // `parse_metadata_to_cache_info`, so the first match is
            // the newest match — same contract as `find_best_version`.
            for v in &info.versions {
                if !range.satisfies(v) {
                    continue;
                }
                if !target_range.satisfies(v) {
                    continue;
                }
                if !matches!(
                    release_age_status_for_version(canonical, info, v, policy),
                    ReleaseTimeStatus::Allowed
                ) {
                    continue;
                }
                if policy.trust_policy().is_no_downgrade()
                    && trust_downgrade_violation(info, v).is_some()
                {
                    continue;
                }
                let platform_ok = info.platform.is_empty()
                    || info
                        .platform
                        .get(&v.to_string())
                        .is_none_or(crate::provider::is_platform_compatible);
                if !platform_ok {
                    continue;
                }
                return Some(v.clone());
            }
            None
        }
    }
}

pub(super) enum PolicyBlock {
    ReleaseAge {
        version: NpmVersion,
        remaining_secs: u64,
        minimum_secs: u64,
    },
    TrustPolicy {
        version: NpmVersion,
        reason: String,
    },
}

pub(super) fn handle_policy_blocked(
    edge: &Edge,
    block: PolicyBlock,
    state: &ResolveState,
) -> Result<(), ResolveError> {
    if edge.behavior.optional {
        tracing::debug!(
            "optional dep {} skipped by resolver policy (range={})",
            edge.canonical,
            edge.range,
        );
        return Ok(());
    }
    let detail = match block {
        PolicyBlock::ReleaseAge {
            version,
            remaining_secs,
            minimum_secs,
        } => format!(
            "{version} published too recently for minimumReleaseAge; {remaining_secs}s remaining (minimumReleaseAge={minimum_secs}s)"
        ),
        PolicyBlock::TrustPolicy { version, reason } => {
            format!("{version} blocked by trust-policy no-downgrade: {reason}")
        }
    };
    Err(ResolveError::Resolution(Box::new(
        state.edge_resolution_context(
            edge,
            ResolutionFailureKind::PolicyBlocked,
            detail,
            None,
            None,
        ),
    )))
}

pub(super) fn handle_no_version(
    edge: &Edge,
    info: &CachedPackageInfo,
    platform_filtered: bool,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    if edge.behavior.optional {
        // Optional dep with no satisfying or platform-compatible
        // version: skip silently. Matches bun's behavior
        // (`PackageManagerEnqueue.zig:77-78` warning path) minus the
        // warning itself.
        if platform_filtered {
            state.platform_skipped += 1;
        }
        tracing::debug!(
            "optional dep {} skipped (range={}, platform_filtered={})",
            edge.canonical,
            edge.range,
            platform_filtered
        );
        return Ok(());
    }
    if edge.behavior.peer {
        // Peer deps are handled by the peer-drain pass or by the
        // post-resolve `check_unmet_peers` warning path if they stay
        // unresolved.
        tracing::debug!(
            "peer dep {} (range {}) not eagerly installed by miss handler",
            edge.canonical,
            edge.range,
        );
        return Ok(());
    }
    let available_versions = Some(info.versions.len());
    let newest_version = info.versions.first().map(ToString::to_string);
    let (kind, detail) = if platform_filtered {
        (
            ResolutionFailureKind::PlatformIncompatible,
            format!(
                "published versions matching {} are incompatible with this OS/CPU",
                edge.range
            ),
        )
    } else {
        (
            ResolutionFailureKind::NoMatchingVersion,
            format!("no published version satisfies {}", edge.range),
        )
    };
    Err(ResolveError::Resolution(Box::new(
        state.edge_resolution_context(edge, kind, detail, available_versions, newest_version),
    )))
}
