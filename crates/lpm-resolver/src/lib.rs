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
mod walker;

pub use npm_version::NpmVersion;
pub use overrides::{
    NpmRangeMatcher, OverrideEntry, OverrideError, OverrideHit, OverrideSelector, OverrideSet,
    OverrideSource, OverrideTarget,
};
pub use package::{CanonicalKey, ResolverPackage};
pub use provider::{CachedDistInfo, CachedPackageInfo, PlatformMeta};
pub use provider::{NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone};
pub use ranges::NpmRange;
pub use resolve::{
    PeerWarning, ResolveError, ResolveResult, ResolvedPackage, StageTiming, check_unmet_peers,
    resolve_dependencies, resolve_dependencies_with_overrides, resolve_with_shared_cache,
};
pub use walker::{BfsWalker, DEFAULT_NPM_FANOUT, LevelTiming, WalkerError, WalkerSummary};
