//! High-level resolution entry point.
//!
//! Iterative split-retry approach:
//! 1. Try flat resolution (one version per package) — works for ~90% of real trees
//! 2. On conflict, identify packages needing multiple versions and retry with splits
//! 3. Keep adding new split candidates until resolution succeeds or no new candidates remain

mod dispatch;
mod error;
mod format;
mod peers;
mod types;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use dispatch::{
    resolve_dependencies, resolve_dependencies_routed, resolve_dependencies_with_overrides,
    resolve_with_shared_cache, resolve_with_shared_cache_options,
    resolve_with_shared_cache_options_and_policy,
    resolve_with_shared_cache_options_and_policy_roots,
};
#[allow(unused_imports)]
pub use error::ResolveError;
pub(crate) use format::{dedupe_peer_superset_packages, mark_optional_reachability};
pub(crate) use peers::resolve_peer_binding_version;
#[allow(unused_imports)]
pub use peers::{
    CompiledPeerRules, PeerWarning, check_unmet_peers, validate_allowed_versions_range,
    validate_allowed_versions_selector,
};
#[allow(unused_imports)]
pub use types::{
    PeerStageTiming, ResolveResult, ResolvedPackage, RootDependencies, RootResolution,
    SelectedPackageEvent, StageTiming,
};

mod prelude {
    #[allow(unused_imports)]
    pub(super) use super::dispatch::{
        resolve_dependencies, resolve_dependencies_routed, resolve_dependencies_with_overrides,
        resolve_with_shared_cache, resolve_with_shared_cache_options,
        resolve_with_shared_cache_options_and_policy,
        resolve_with_shared_cache_options_and_policy_roots,
    };
    #[allow(unused_imports)]
    pub(super) use super::error::{
        ResolveError, extract_conflicting_packages, extract_conflicts_fallback,
        extract_conflicts_primary, map_pubgrub_error, no_solution_error,
    };
    #[allow(unused_imports)]
    pub(super) use super::format::{
        aliases_are_superset, dedupe_peer_superset_packages, entries_are_superset, format_solution,
        mark_optional_reachability, resolved_package_can_replace, resolved_package_identity_key,
        resolved_package_is_strict_superset, root_resolutions_from_solution,
    };
    #[allow(unused_imports)]
    pub(super) use super::peers::{
        AllowedVersionsSelector, CompiledPeerRules, GlobPattern, ParentSelector, PeerWarning,
        check_unmet_peers, compute_resolved_peers, peer_version_satisfies,
        resolve_peer_binding_version, select_peer_candidate, validate_allowed_versions_range,
        validate_allowed_versions_selector,
    };
    #[allow(unused_imports)]
    pub(super) use super::types::{
        PubGrubResult, ResolveResult, ResolvedPackage, RootDependencies, RootResolution,
        SelectedPackageEvent, StageTiming,
    };
    #[allow(unused_imports)]
    pub(super) use crate::npm_version::NpmVersion;
    #[allow(unused_imports)]
    pub(super) use crate::overrides::{OverrideHit, OverrideSet};
    #[allow(unused_imports)]
    pub(super) use crate::package::{CanonicalKey, ResolverPackage};
    #[allow(unused_imports)]
    pub(super) use crate::policy::ResolverPolicy;
    #[allow(unused_imports)]
    pub(super) use crate::provider::{
        CachedPackageInfo, LpmDependencyProvider, NotifyMap, PlatformMeta, SharedCache,
        SkippedDependency, StreamingBfsMetrics,
    };
    #[allow(unused_imports)]
    pub(super) use crate::ranges::NpmRange;
    #[allow(unused_imports)]
    pub(super) use lpm_registry::{RegistryClient, RouteMode, RouteTable};
    #[allow(unused_imports)]
    pub(super) use pubgrub::{DefaultStringReporter, Reporter};
    #[allow(unused_imports)]
    pub(super) use std::collections::{HashMap, HashSet, VecDeque};
    #[allow(unused_imports)]
    pub(super) use std::sync::Arc;
    #[allow(unused_imports)]
    pub(super) use std::time::Duration;
    #[allow(unused_imports)]
    pub(super) use tokio::runtime::Handle;
}
