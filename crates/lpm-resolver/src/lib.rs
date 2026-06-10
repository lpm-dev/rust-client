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
pub mod profile;
mod provider;
pub mod ranges;
mod resolve;
pub mod specifier;
mod walker;

pub use greedy::PeerConflictReport;
pub use greedy::{
    resolve_greedy_fused, resolve_greedy_fused_with_cache, resolve_greedy_fused_with_cache_options,
};
pub use npm_version::NpmVersion;
pub use overrides::{
    NpmRangeMatcher, OverrideEntry, OverrideError, OverrideHit, OverrideSelector, OverrideSet,
    OverrideSource, OverrideTarget, override_selector_target_name,
};
pub use package::{CanonicalKey, ResolverPackage};
pub use provider::{CachedDistInfo, CachedPackageInfo, PlatformMeta, is_platform_compatible};
pub use provider::{NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone};
pub use ranges::NpmRange;
pub use resolve::{
    CompiledPeerRules, PeerWarning, ResolveError, ResolveResult, ResolvedPackage, StageTiming,
    check_unmet_peers, resolve_dependencies, resolve_dependencies_routed,
    resolve_dependencies_with_overrides, resolve_with_shared_cache,
    resolve_with_shared_cache_options, validate_allowed_versions_range,
    validate_allowed_versions_selector,
};
pub use specifier::{Specifier, SpecifierParseError};
pub use walker::{BfsWalker, DEFAULT_NPM_FANOUT, LevelTiming, WalkerError, WalkerSummary};
