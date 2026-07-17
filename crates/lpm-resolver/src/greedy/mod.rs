//! Greedy multi-version resolver.
//!
//! Replaces PubGrub-with-split-retry with a greedy enqueue + first-match
//! version pick that doubles as the fetch dispatcher.
//!
//! ## Scope
//!
//! - **Multi-version-per-canonical via reuse-on-compatible / allocate-on-
//!   incompatible.** When edge A picks `lodash@4.17.21` and edge B
//!   wants `lodash@^4`, edge B reuses A's node — first-version-wins
//!   inside any single satisfying range bucket. When edge B's range is
//!   `^3` and 4.17.21 doesn't satisfy
//!   it, the resolver allocates a new node for `lodash@3.10.1` (or
//!   whatever the best match is); both versions live independently in
//!   the resolved tree, keyed by `(canonical, version)`.
//! - **Required + optional deps.** Peer deps are recorded but not
//!   eagerly installed; the existing post-resolve [`crate::check_unmet_peers`]
//!   pass continues to surface peer warnings.
//! - **Overrides** are applied at version-pick time inside
//!   [`process_edge`]. Mirrors [`crate::provider::LpmDependencyProvider::choose_version`]'s
//!   pubgrub-arm semantics: compute the natural version, look up
//!   `OverrideSet::find_match` against (canonical, natural, parent_ctx),
//!   apply the [`OverrideTarget`] against the consumer range, record an
//!   [`OverrideHit`] on success, fall through to the natural version on
//!   target/range mismatch (legacy "irreconcilable override" debug warn).
//!   `OverrideSet::split_targets` informs reuse-vs-allocate so two parents
//!   forcing distinct versions split into independent nodes.
//! - **npm-aliases** are passed through from the cache (the `aliases` map
//!   on each `CachedPackageInfo` is already populated by
//!   [`crate::provider::parse_metadata_to_cache_info`]) and surfaced in the
//!   resolved tree.
//!
//! ## Dispatch model
//!
//! The loop is single-threaded; parallelism comes from the I/O fan-out
//! (the BfsWalker's 50-permit batch fetch + the existing 24-permit download
//! pool). Each iteration:
//!
//! 1. Pop an [`Edge`] off `task_queue`.
//! 2. Resolve its canonical's manifest via [`ensure_manifest`] — fast path
//!    is the [`crate::provider::SharedCache`] hit (the walker has been
//!    prefetching concurrently); slow path waits on the per-canonical
//!    [`tokio::sync::Notify`] up to `fetch_wait_timeout`, then falls
//!    through to a direct registry fetch.
//! 3. Pick a version with [`find_best_version`] (reverse-iterate sorted
//!    versions; first satisfying match wins).
//! 4. Either reuse an existing node for `canonical` when the selected
//!    version is compatible, or allocate a new one and enqueue its deps as fresh
//!    edges.
//! 5. Repeat until `task_queue` is empty.
//!
//! No backtracking. No split-retry. The cost model is O(edges × log
//! versions) — measured at ~600-1000 `find_best_version` calls per cold
//! install on `bench/fixture-large`, each ~µs.

mod deps;
mod edge;
mod entry;
mod fused;
mod manifest;
mod metrics;
mod peer;
mod policy;
mod state;
#[cfg(test)]
mod tests;
mod tree_policy;
mod types;
mod version;

use std::sync::Arc;

use lpm_registry::{RegistryClient, RouteTable};

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet};
use crate::package::CanonicalKey;
use crate::policy::ResolverPolicy;
use crate::provider::CachedPackageInfo;
use crate::ranges::NpmRange;
use crate::resolve::ResolveError;

pub use entry::resolve_greedy_with_root_dependencies_options_and_policy;
pub use fused::{
    resolve_greedy_fused, resolve_greedy_fused_with_cache, resolve_greedy_fused_with_cache_options,
    resolve_greedy_fused_with_cache_options_and_policy,
    resolve_greedy_fused_with_cache_options_and_policy_roots,
    resolve_greedy_fused_with_cache_options_policy_and_selected_events,
    resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots,
};
pub use types::PeerConflictReport;

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExperimentalVersionSelection {
    Picked(NpmVersion),
    NoSatisfying,
    BlockedByReleaseAge {
        version: NpmVersion,
        remaining_secs: u64,
        minimum_secs: u64,
    },
    BlockedByTrustPolicy {
        version: NpmVersion,
        reason: String,
    },
}

#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct ExperimentalMetadataFetchTimings {
    pub package: String,
    pub route: &'static str,
    pub total_ms: u128,
    pub raw_fetch_ms: u128,
    pub cache_read_ms: u128,
    pub validator_read_ms: u128,
    pub http_ms: u128,
    pub body_read_ms: u128,
    pub json_decode_ms: u128,
    pub cache_after_304_ms: u128,
    pub cache_write_dispatch_ms: u128,
    pub cache_info_parse_ms: u128,
    pub policy_release_time_ms: u128,
    pub policy_release_time_fetch_ms: u128,
    pub policy_release_time_fetch: Option<lpm_registry::PackageMetadataFetchTimings>,
    pub policy_release_time_version_count: u64,
    pub policy_full_metadata_ms: u128,
    pub body_bytes: u64,
    pub version_count: u64,
    pub cache_hit: bool,
    pub not_modified: bool,
}

impl From<version::VersionPick> for ExperimentalVersionSelection {
    fn from(value: version::VersionPick) -> Self {
        match value {
            version::VersionPick::Picked(version) => Self::Picked(version),
            version::VersionPick::NoSatisfying => Self::NoSatisfying,
            version::VersionPick::BlockedByReleaseAge {
                version,
                remaining_secs,
                minimum_secs,
            } => Self::BlockedByReleaseAge {
                version,
                remaining_secs,
                minimum_secs,
            },
            version::VersionPick::BlockedByTrustPolicy { version, reason } => {
                Self::BlockedByTrustPolicy { version, reason }
            }
        }
    }
}

#[doc(hidden)]
pub fn experimental_select_version_with_policy(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    range: &NpmRange,
    policy: &ResolverPolicy,
) -> ExperimentalVersionSelection {
    version::find_best_version_with_policy(canonical, info, range, policy).into()
}

#[doc(hidden)]
pub fn experimental_select_version_with_policy_and_overrides(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    range: &NpmRange,
    policy: &ResolverPolicy,
    overrides: &OverrideSet,
    parent_canonical: Option<&str>,
) -> (ExperimentalVersionSelection, Option<OverrideHit>) {
    let natural_pick = version::find_best_version_with_policy(canonical, info, range, policy);
    if overrides.is_empty() {
        return (natural_pick.into(), None);
    }

    let natural = match &natural_pick {
        version::VersionPick::Picked(version) => version.clone(),
        version::VersionPick::NoSatisfying
        | version::VersionPick::BlockedByReleaseAge { .. }
        | version::VersionPick::BlockedByTrustPolicy { .. } => return (natural_pick.into(), None),
    };

    let canonical_name = canonical.to_string();
    let Some(entry) = overrides.find_match(&canonical_name, &natural, parent_canonical) else {
        return (ExperimentalVersionSelection::Picked(natural), None);
    };
    let Some(forced) =
        policy::apply_override_target_greedy(canonical, info, &entry.target, range, policy)
    else {
        return (ExperimentalVersionSelection::Picked(natural), None);
    };
    let hit = OverrideHit {
        raw_key: entry.raw_key.clone(),
        source: entry.source,
        package: canonical_name,
        from_version: natural.to_string(),
        to_version: forced.to_string(),
        via_parent: parent_canonical.map(str::to_string),
    };
    (ExperimentalVersionSelection::Picked(forced), Some(hit))
}

#[doc(hidden)]
pub async fn experimental_fetch_cached_package_info_with_policy(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    manifest::fetch_metadata_for_resolver(client, route_table, canonical, policy, false)
        .await
        .map(|fetched| fetched.info)
}

#[doc(hidden)]
pub async fn experimental_fetch_cached_package_info_with_policy_and_timings(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
) -> Result<(Arc<CachedPackageInfo>, ExperimentalMetadataFetchTimings), ResolveError> {
    manifest::fetch_metadata_for_resolver_with_timings(
        client,
        route_table,
        canonical,
        policy,
        false,
    )
    .await
    .map(|(fetched, timings)| (fetched.info, timings))
}

#[doc(hidden)]
pub async fn experimental_fetch_exact_cached_package_info_with_policy_and_timings(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    version: &str,
    policy: &ResolverPolicy,
) -> Result<(Arc<CachedPackageInfo>, ExperimentalMetadataFetchTimings), ResolveError> {
    manifest::fetch_exact_metadata_for_resolver_with_timings(
        client,
        route_table,
        canonical,
        version,
        policy,
        false,
    )
    .await
    .map(|(fetched, timings)| (fetched.info, timings))
}

mod prelude {
    pub(super) use crate::npm_version::NpmVersion;
    pub(super) use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
    pub(super) use crate::package::{CanonicalKey, ResolverPackage};
    pub(super) use crate::policy::{ReleaseTimeStatus, ResolverPolicy};
    pub(super) use crate::provider::{
        CachedPackageInfo, NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone,
        merge_release_times_into_cache_info, parse_full_metadata_to_cache_info,
        parse_metadata_to_cache_info, parse_partial_metadata_to_cache_info,
        release_age_status_for_version, release_age_status_for_version_unprofiled,
        trust_downgrade_violation, trust_downgrade_violation_unprofiled,
    };
    pub(super) use crate::ranges::NpmRange;
    pub(super) use crate::resolve::{
        ResolveError, ResolveResult, ResolvedPackage, StageTiming, resolve_peer_binding_version,
    };
    pub(super) use crate::speculation::SpeculativePackageMetadata;
    pub(super) use ahash::{AHashMap, AHashSet};
    pub(super) use lpm_common::{ResolutionErrorContext, ResolutionFailureKind};
    #[cfg(test)]
    pub(super) use lpm_registry::RouteMode;
    pub(super) use lpm_registry::{RegistryClient, RouteTable, UpstreamRoute};
    pub(super) use sha2::{Digest, Sha256};
    pub(super) use std::collections::{HashMap, HashSet, VecDeque};
    pub(super) use std::sync::Arc;
    pub(super) use std::sync::atomic::Ordering;
    pub(super) use std::time::{Duration, Instant};
    pub(super) use tokio::sync::Notify;
}
