//! PubGrub-based dependency resolution for LPM.
//!
//! Adapts the PubGrub algorithm for npm's package ecosystem:
//! - npm semver range syntax (^, ~, ||, *, x, hyphen ranges)
//! - Multiple versions of the same package (two-phase approach)
//! - peerDependencies, optionalDependencies
//! - overrides/resolutions for forcing versions

mod npm_version;
mod package;
mod provider;
pub mod ranges;
mod resolve;

pub use npm_version::NpmVersion;
pub use package::ResolverPackage;
pub use provider::{CachedDistInfo, CachedPackageInfo, PlatformMeta};
pub use ranges::NpmRange;
pub use resolve::{
    ResolveError, ResolvedPackage, resolve_dependencies, resolve_dependencies_with_overrides,
};
