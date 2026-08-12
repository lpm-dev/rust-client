//! PubGrub DependencyProvider implementation for LPM.
//!
//! Bridges PubGrub's resolution algorithm with the LPM/npm registries.
//!
//! Resolver compatibility: peerDeps, optionalDeps, overrides, workspace:*, platform filtering.

mod cache;
mod config;
mod error;
mod fetch;
mod parse;
mod platform;
mod policy;
mod pubgrub_impl;
mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub(crate) use parse::is_valid_dep_name;
pub(crate) use parse::{
    merge_release_times_into_cache_info, parse_full_metadata_to_cache_info,
    parse_metadata_to_cache_info, parse_partial_metadata_to_cache_info,
};
#[cfg(test)]
pub(crate) use platform::Platform;
pub use platform::is_platform_compatible;
pub(crate) use policy::{
    release_age_status_for_version, release_age_status_for_version_unprofiled,
    select_override_target, trust_downgrade_violation, trust_downgrade_violation_unprofiled,
    version_allowed_by_policy,
};
pub(crate) use types::LpmDependencyProvider;
pub(crate) use types::SkippedDependency;
#[cfg(test)]
pub(crate) use types::SkippedDependencyReason;
pub use types::{
    CachedDistInfo, CachedPackageInfo, NotifyMap, PlatformMeta, SharedCache, StreamingBfsMetrics,
    WalkerDone,
};

mod prelude {
    #[allow(unused_imports)]
    pub(super) use super::cache::activate_workspace_fallback;
    #[allow(unused_imports)]
    pub(super) use super::error::{ProviderError, classify_registry_error};
    #[allow(unused_imports)]
    pub(super) use super::parse::{
        is_valid_dep_name, is_valid_version_string, merge_release_times_into_cache_info,
        parse_full_metadata_to_cache_info, parse_metadata_to_cache_info,
        parse_partial_metadata_to_cache_info,
    };
    #[allow(unused_imports)]
    pub(super) use super::platform::{
        Platform, check_platform_filter, is_platform_compatible, is_platform_compatible_for,
    };
    #[allow(unused_imports)]
    pub(super) use super::policy::{
        OverrideTargetRejection, release_age_status_for_version,
        release_age_status_for_version_unprofiled, select_override_target,
        trust_downgrade_violation, trust_downgrade_violation_unprofiled, version_allowed_by_policy,
    };
    #[allow(unused_imports)]
    pub(super) use super::pubgrub_impl::deep_followup_enabled;
    #[allow(unused_imports)]
    pub(super) use super::types::{
        CachedDistInfo, CachedPackageInfo, LpmDependencyProvider, NotifyMap, PlatformMeta,
        SharedCache, SkippedDependency, SkippedDependencyReason, StreamingBfsMetrics, WalkerDone,
    };
    #[allow(unused_imports)]
    pub(super) use crate::npm_version::NpmVersion;
    #[allow(unused_imports)]
    pub(super) use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
    #[allow(unused_imports)]
    pub(super) use crate::package::{CanonicalKey, ResolverPackage};
    #[allow(unused_imports)]
    pub(super) use crate::policy::{
        ReleaseTimeStatus, ResolverPolicy, TrustEvidence, TrustPolicyMode, parse_npm_time_unix,
    };
    #[allow(unused_imports)]
    pub(super) use crate::ranges::NpmRange;
    #[allow(unused_imports)]
    pub(super) use crate::resolve::RootDependencies;
    #[allow(unused_imports)]
    pub(super) use dashmap::DashMap;
    #[allow(unused_imports)]
    pub(super) use lpm_registry::{RegistryClient, RouteMode, RouteTable, UpstreamRoute};
    #[allow(unused_imports)]
    pub(super) use parking_lot::Mutex;
    #[allow(unused_imports)]
    pub(super) use pubgrub::{Dependencies, DependencyProvider, PackageResolutionStatistics};
    #[allow(unused_imports)]
    pub(super) use std::collections::{HashMap, HashSet};
    #[allow(unused_imports)]
    pub(super) use std::sync::Arc;
    #[allow(unused_imports)]
    pub(super) use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    #[allow(unused_imports)]
    pub(super) use std::time::{Duration, Instant};
    #[allow(unused_imports)]
    pub(super) use tokio::runtime::Handle;
    #[allow(unused_imports)]
    pub(super) use tokio::sync::Notify;
    #[allow(unused_imports)]
    pub(super) use version_ranges::Ranges;
}

pub(crate) use cache::{activate_workspace_fallback, insert_or_merge_cached_package_info};
