use super::prelude::*;

impl StreamingBfsMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cache_waits(&self) -> u64 {
        self.cache_waits.load(Ordering::Relaxed)
    }

    pub fn cache_wait_timeouts(&self) -> u64 {
        self.cache_wait_timeouts.load(Ordering::Relaxed)
    }

    pub fn escape_hatch_fetches(&self) -> u64 {
        self.escape_hatch_fetches.load(Ordering::Relaxed)
    }

    pub fn cache_wait_walker_done_shortcuts(&self) -> u64 {
        self.cache_wait_walker_done_shortcuts
            .load(Ordering::Relaxed)
    }

    pub(super) fn incr_cache_wait(&self) {
        self.cache_waits.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn incr_cache_wait_timeout(&self) {
        self.cache_wait_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn incr_escape_hatch_fetch(&self) {
        self.escape_hatch_fetches.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn incr_cache_wait_walker_done_shortcut(&self) {
        self.cache_wait_walker_done_shortcuts
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl LpmDependencyProvider {
    /// Ensure package metadata is cached. Fetches from registry on miss.
    ///
    /// 1. **Canonicalize first.** `ResolverPackage` carries a `context`
    ///    field in its `Hash + Eq` (split-retry identities); the cache is
    ///    keyed by [`CanonicalKey`] which strips that context. Every cache
    ///    interaction MUST go through canonicalization or split retries
    ///    silently miss walker-inserted entries and fall through to
    ///    escape-hatch fetches — a silent perf cliff rather than a
    ///    correctness bug. Do not change the order of operations here.
    ///
    /// 2. **Fast path:** cache hit → return immediately.
    ///
    /// 3. **Wait-loop** (only when `fetch_wait_timeout > 0`): pin the
    ///    key's per-canonical [`Notify`] subscription with
    ///    `Notified::enable()` so any subsequent `notify_waiters()` is
    ///    captured even before the first poll, then re-check the cache
    ///    *and* the [`WalkerDone`] flag under that subscription. If the
    ///    walker has finished without inserting this key (newest-only
    ///    expansion gap, broadcast notify fired before we got here, etc.)
    ///    we increment `cache_wait_walker_done_shortcuts` and break to
    ///    step 4 in microseconds. Otherwise `block_on(timeout(notified))`;
    ///    each wake re-runs the loop's checks. On timeout, fall to step 4.
    ///
    /// 4. **Escape-hatch fetch:** direct fetch via
    ///    [`Self::direct_fetch_and_cache`], which honors the same
    ///    `route_for_package` policy the walker uses. LPM packages stay
    ///    on the Worker; npm packages go direct in
    ///    [`RouteMode::Direct`], proxy in [`RouteMode::Proxy`].
    ///
    /// Callers with no walker attached get `fetch_wait_timeout ==
    /// Duration::ZERO`, so step 3 falls immediately through to step 4 —
    /// behavior indistinguishable from today's fetch-on-miss path.
    pub(super) fn ensure_cached(&self, package: &ResolverPackage) -> Result<(), ProviderError> {
        if package.is_root() {
            return Ok(());
        }
        let key = CanonicalKey::from(package);
        // Fast path (step 2).
        if self.cache.contains_key(&key) {
            return self.ensure_policy_metadata(package, &key);
        }

        let _span = tracing::debug_span!("ensure_cached", pkg = %package).entered();
        let _prof = crate::profile::ensure_cached::start();

        // Wait-loop (step 3). Only active when a walker is attached and
        // the caller has set a non-zero fetch_wait_timeout; otherwise
        // the loop's first iteration falls straight to step 4.
        if !self.fetch_wait_timeout.is_zero() {
            // Count every PubGrub callback that hit the wait-loop on a
            // cache miss — healthy cold-install has cache_waits ≈ total_packages
            // (every miss served by the walker's insert, no fetches).
            self.metrics.incr_cache_wait();
            let notify = self
                .notify_map
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone();
            let start = Instant::now();
            loop {
                // Pin + enable the Notified BEFORE re-checking cache and
                // walker_done. `enable()` commits the subscription
                // synchronously, so any `notify_waiters()` issued *after*
                // this point is guaranteed to wake this future even if
                // we never re-poll. That defense is what makes the
                // walker-done broadcast race-free: walker stores the
                // flag (Release) then iterates `notify_map` calling
                // `notify_waiters()` on every entry. Either we observe
                // the flag in the check below, or we observe the wake.
                let mut notified = Box::pin(notify.notified());
                notified.as_mut().enable();
                if self.cache.contains_key(&key) {
                    return self.ensure_policy_metadata(package, &key);
                }
                if self.walker_done.load(Ordering::Acquire) {
                    // Walker has terminated and confirmed this key was
                    // never inserted. No point burning the rest of the
                    // timeout — the wait-loop's optimistic "walker will
                    // get there" assumption no longer holds.
                    self.metrics.incr_cache_wait_walker_done_shortcut();
                    break; // escape to step 4
                }
                let remaining = self.fetch_wait_timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    self.metrics.incr_cache_wait_timeout();
                    break; // escape to step 4
                }
                match self
                    .rt
                    .block_on(async { tokio::time::timeout(remaining, notified).await })
                {
                    Ok(_) => continue, // walker inserted our key OR shut down; recheck
                    Err(_) => {
                        self.metrics.incr_cache_wait_timeout();
                        break; // timed out; escape to step 4
                    }
                }
            }
        }

        // Escape-hatch fetch (step 4).
        self.direct_fetch_and_cache(package)
    }

    fn ensure_policy_metadata(
        &self,
        package: &ResolverPackage,
        key: &CanonicalKey,
    ) -> Result<(), ProviderError> {
        let needs_upgrade = self
            .cache
            .get(key)
            .is_some_and(|info| info.needs_policy_metadata(key, &self.policy));
        if !needs_upgrade {
            return Ok(());
        }
        let ResolverPackage::Npm { name, .. } = package else {
            return Ok(());
        };
        let route = self.route_table.route_for_package(name);
        let metadata = self
            .rt
            .block_on(self.client.get_npm_metadata_routed_full(name, route))
            .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
        self.insert_and_notify(key.clone(), parse_full_metadata_to_cache_info(&metadata));
        Ok(())
    }

    /// Insert a freshly-parsed `CachedPackageInfo` and fire any waiters on
    /// its canonical key. Ordering is load-bearing: insert → notify. Do NOT
    /// reorder — notifying before inserting races the provider's re-check
    /// and causes spurious wait-loop iterations.
    pub(super) fn insert_and_notify(&self, key: CanonicalKey, info: CachedPackageInfo) {
        self.cache.insert(key.clone(), Arc::new(info));
        if let Some(n) = self.notify_map.get(&key) {
            n.notify_waiters();
        }
    }

    /// Get the list of versions for a package. Platform compatibility is
    /// applied after resolution so lockfiles stay portable across hosts.
    ///
    /// Canonicalizes before cache lookup — split-retry identities of the
    /// same canonical package share one cache entry.
    pub(super) fn available_versions(&self, package: &ResolverPackage) -> Vec<NpmVersion> {
        let _span = tracing::debug_span!("available_versions", pkg = %package).entered();
        let _prof = crate::profile::available_versions::start();
        let key = CanonicalKey::from(package);
        self.cache
            .get(&key)
            .map(|c| {
                let info = c.value();
                info.versions
                    .iter()
                    .filter(|version| version_allowed_by_policy(&key, info, version, &self.policy))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Memoized wrapper around [`NpmRange::to_pubgrub_ranges`]. First call
    /// for a given
    /// `(package, raw_range)` pair computes the O(N-versions)
    /// conversion and caches the result; subsequent calls return a
    /// clone of the cached `Ranges`. See the doc on
    /// [`Self::range_cache`] for the correctness argument.
    ///
    /// Callers MUST pass the same `available` slice they'd have passed
    /// to the uncached call (i.e. the output of
    /// `available_versions(pkg)` at the moment of the call). The cache
    /// doesn't re-derive `available` on hits — it just returns what it
    /// recorded. Because `available_versions(pkg)` is fixed for the
    /// lifetime of one provider (metadata cache is append-only per
    /// pass), this is safe; calling with a stale `available` is a
    /// caller bug that would be wrong uncached too.
    pub(super) fn to_pubgrub_ranges_cached(
        &self,
        pkg: &ResolverPackage,
        npm_range: &NpmRange,
        available: &[NpmVersion],
    ) -> Ranges<NpmVersion> {
        let key = (pkg.clone(), npm_range.raw().to_string());
        if let Some(cached) = self.range_cache.borrow().get(&key) {
            return cached.clone();
        }
        let computed = npm_range.to_pubgrub_ranges(available);
        self.range_cache.borrow_mut().insert(key, computed.clone());
        computed
    }

    /// Extract the override hits AND the metadata cache in one shot. The
    /// two-stage `take_override_hits()` / `into_cache()` API is also
    /// available for callers that need only one of the two. Surfaces
    /// `platform_skipped`, `root_aliases`, and `root_deps` so the resolver can
    /// accumulate pass-local state without separate borrows.
    // Keep this tuple at the extraction boundary: the single caller
    // destructures it immediately, and a one-use struct would not clarify
    // ownership.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
        Vec<OverrideHit>,
        usize,
        HashMap<String, String>,
        HashMap<String, String>,
    ) {
        let hits = self.overrides.take_hits();
        let platform_skipped = *self.platform_skipped.borrow();
        let root_aliases = self.root_aliases.into_inner();
        let root_deps = self.root_deps;
        // Surface Arc<CachedPackageInfo> directly — deep-cloning each
        // entry's seven nested HashMaps moved ~7 MB per cold resolve on
        // `bench/fixture-large` (hidden inside `pubgrub_ms`). Arc::clone is
        // a refcount bump.
        let cache: HashMap<CanonicalKey, Arc<CachedPackageInfo>> = match Arc::try_unwrap(self.cache)
        {
            Ok(dm) => dm.into_iter().collect(),
            Err(arc) => arc
                .iter()
                .map(|e| (e.key().clone(), Arc::clone(e.value())))
                .collect(),
        };
        (cache, hits, platform_skipped, root_aliases, root_deps)
    }
}
