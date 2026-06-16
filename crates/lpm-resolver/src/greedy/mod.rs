//! Greedy multi-version resolver, bun-recipe port.
//!
//! Replaces PubGrub-with-split-retry with a greedy enqueue + first-match
//! version pick that doubles as the fetch dispatcher. Mirrors bun's
//! `enqueueDependencyWithMain` shape (`src/install/PackageManagerEnqueue.zig`
//! + `runTasks.zig::flushDependencyQueue`).
//!
//! ## Scope
//!
//! - **Multi-version-per-canonical via reuse-on-compatible / allocate-on-
//!   incompatible.** When edge A picks `lodash@4.17.21` and edge B
//!   wants `lodash@^4`, edge B reuses A's node — first-version-wins
//!   inside any single satisfying range bucket (matches bun + npm + pnpm
//!   semantics). When edge B's range is `^3` and 4.17.21 doesn't satisfy
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
//! The loop is single-threaded — bun's PackageManager event loop runs on
//! one thread, and parallelism comes from the I/O fan-out (the BfsWalker's
//! 50-permit batch fetch + the existing 24-permit download pool). Each
//! iteration:
//!
//! 1. Pop an [`Edge`] off `task_queue`.
//! 2. Resolve its canonical's manifest via [`ensure_manifest`] — fast path
//!    is the [`crate::provider::SharedCache`] hit (the walker has been
//!    prefetching concurrently); slow path waits on the per-canonical
//!    [`tokio::sync::Notify`] up to `fetch_wait_timeout`, then falls
//!    through to a direct registry fetch.
//! 3. Pick a version with [`find_best_version`] (reverse-iterate sorted
//!    versions; first satisfying match wins — matches bun's `npm.zig:
//!    1808-1819`).
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

pub use entry::resolve_greedy_with_options_and_policy;
pub use fused::{
    resolve_greedy_fused, resolve_greedy_fused_with_cache, resolve_greedy_fused_with_cache_options,
    resolve_greedy_fused_with_cache_options_and_policy,
};
pub use types::PeerConflictReport;

mod prelude {
    pub(super) use crate::npm_version::NpmVersion;
    pub(super) use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
    pub(super) use crate::package::{CanonicalKey, ResolverPackage};
    pub(super) use crate::policy::{ReleaseTimeStatus, ResolverPolicy};
    pub(super) use crate::provider::{
        CachedPackageInfo, NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone,
        parse_full_metadata_to_cache_info, parse_metadata_to_cache_info,
        release_age_status_for_version, trust_downgrade_violation,
    };
    pub(super) use crate::ranges::NpmRange;
    pub(super) use crate::resolve::{
        ResolveError, ResolveResult, ResolvedPackage, StageTiming, resolve_peer_binding_version,
    };
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
