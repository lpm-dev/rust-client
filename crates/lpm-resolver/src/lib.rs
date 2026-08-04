//! PubGrub-based dependency resolution for LPM.
//!
//! Adapts the PubGrub algorithm for npm's package ecosystem:
//! - npm semver range syntax (^, ~, ||, *, x, hyphen ranges)
//! - Multiple versions of the same package (iterative split-retry approach)
//! - peerDependencies, optionalDependencies
//! - overrides/resolutions for forcing versions

mod greedy;
mod npm_version;
mod overrides;
mod package;
mod policy;
pub mod profile;
mod provider;
pub mod ranges;
mod resolve;
pub mod specifier;
mod speculation;
mod walker;

#[cfg(test)]
pub(crate) fn metadata_fetch_detail_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub use greedy::PeerConflictReport;
pub use greedy::WorkspaceResolveOutcome;
pub use greedy::{
    ExperimentalMetadataFetchTimings, ExperimentalVersionSelection, SharedMetadataConcurrency,
    experimental_fetch_cached_package_info_with_policy,
    experimental_fetch_cached_package_info_with_policy_and_timings,
    experimental_fetch_exact_cached_package_info_with_policy_and_timings,
    experimental_select_version_with_policy, experimental_select_version_with_policy_and_overrides,
    resolve_greedy_fused, resolve_greedy_fused_with_cache, resolve_greedy_fused_with_cache_options,
    resolve_greedy_fused_with_cache_options_and_policy,
    resolve_greedy_fused_with_cache_options_and_policy_roots,
    resolve_greedy_fused_with_cache_options_policy_and_selected_events,
    resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots,
    resolve_greedy_fused_workspace_with_cache_options_and_policy,
};
pub use npm_version::NpmVersion;
pub use overrides::{
    NpmRangeMatcher, OverrideEntry, OverrideError, OverrideHit, OverrideSelector, OverrideSet,
    OverrideSource, OverrideTarget, override_selector_target_name,
};
pub use package::{CanonicalKey, ResolverPackage};
pub use policy::{
    ReleaseAgeExclusion, ReleaseTimeStatus, ResolverPolicy, TrustEvidence, TrustPolicyMode,
};
pub use provider::{CachedDistInfo, CachedPackageInfo, PlatformMeta, is_platform_compatible};
pub use provider::{NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone};
pub use ranges::NpmRange;
pub use resolve::{
    CompiledPeerRules, PeerStageTiming, PeerWarning, ResolveError, ResolveResult, ResolvedPackage,
    RootDependencies, RootResolution, SelectedPackageEvent, StageTiming, WorkspaceUnionStageTiming,
    check_unmet_peers, resolve_dependencies, resolve_dependencies_routed,
    resolve_dependencies_with_overrides, resolve_with_shared_cache,
    resolve_with_shared_cache_options, resolve_with_shared_cache_options_and_policy,
    resolve_with_shared_cache_options_and_policy_roots, validate_allowed_versions_range,
    validate_allowed_versions_selector,
};
pub use specifier::{Specifier, SpecifierParseError, normalize_jsr_dependency};
pub use speculation::SpeculativePackageMetadata;
pub use walker::{BfsWalker, DEFAULT_NPM_FANOUT, LevelTiming, WalkerError, WalkerSummary};

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn benchmark_parse_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    provider::parse_metadata_to_cache_info(metadata)
}

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn benchmark_parse_full_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    provider::parse_full_metadata_to_cache_info(metadata)
}
