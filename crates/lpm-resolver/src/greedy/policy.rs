use super::prelude::*;
use super::state::ResolveState;
use super::types::Edge;

/// Apply an [`OverrideTarget`] against this canonical's cached versions to
/// produce a final forced version. Mirrors
/// [`crate::provider::LpmDependencyProvider::apply_override_target`]'s
/// pubgrub-arm semantics:
///
/// - `PinnedVersion` selects the exact published version.
/// - `Range` selects the newest published version in the override range.
///
/// Resolver security and platform policies still apply. The dependency's
/// declared range does not: replacing that range is the purpose of an
/// override.
pub(super) fn apply_override_target_greedy(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    target: &OverrideTarget,
    policy: &ResolverPolicy,
) -> Option<NpmVersion> {
    select_override_target(canonical, info, target, policy).ok()
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
        // version: skip silently.
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
