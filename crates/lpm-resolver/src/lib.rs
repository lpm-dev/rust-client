//! PubGrub-based dependency resolution for LPM.
//!
//! Adapts the PubGrub algorithm for npm's package ecosystem:
//! - npm semver range syntax (^, ~, ||, *, x, hyphen ranges)
//! - Multiple versions of the same package (two-phase approach)
//! - peerDependencies, optionalDependencies
//! - overrides/resolutions for forcing versions

mod npm_version;
mod overrides;
mod package;
pub mod profile;
mod provider;
pub mod ranges;
mod resolve;
pub mod streaming;

pub use npm_version::NpmVersion;
pub use overrides::{
    NpmRangeMatcher, OverrideEntry, OverrideError, OverrideHit, OverrideSelector, OverrideSet,
    OverrideSource, OverrideTarget,
};
pub use package::ResolverPackage;
pub use provider::{CachedDistInfo, CachedPackageInfo, PlatformMeta, parse_metadata_to_cache_info};
pub use ranges::NpmRange;
pub use resolve::{
    PeerWarning, ResolveError, ResolveResult, ResolvedPackage, check_unmet_peers,
    resolve_dependencies, resolve_dependencies_with_overrides, resolve_with_prefetch,
};
pub use streaming::StreamingPrefetch;
