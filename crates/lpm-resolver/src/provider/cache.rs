use super::prelude::*;

pub(crate) fn insert_or_merge_cached_package_info(
    shared_cache: &SharedCache,
    canonical: CanonicalKey,
    incoming: Arc<CachedPackageInfo>,
) -> Arc<CachedPackageInfo> {
    match shared_cache.entry(canonical) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&incoming));
            incoming
        }
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let existing = Arc::clone(entry.get());
            if Arc::ptr_eq(&existing, &incoming) {
                return existing;
            }

            if incoming.workspace_versions.is_empty() && !existing.workspace_versions.is_empty() {
                entry.insert(Arc::clone(&incoming));
                return incoming;
            }

            if incoming.versions_complete
                && !existing.versions_complete
                && existing.workspace_versions.is_empty()
            {
                entry.insert(Arc::clone(&incoming));
                return incoming;
            }

            let merged = Arc::new(merge_cached_package_info(&existing, &incoming));
            entry.insert(Arc::clone(&merged));
            merged
        }
    }
}

pub(crate) fn activate_workspace_fallback(
    shared_cache: &SharedCache,
    canonical: &CanonicalKey,
) -> Option<Arc<CachedPackageInfo>> {
    let existing = shared_cache
        .get(canonical)
        .map(|entry| Arc::clone(entry.value()))?;
    if existing.workspace_versions.is_empty() {
        return None;
    }

    let mut fallback = (*existing).clone();
    fallback.versions_complete = true;
    let fallback = Arc::new(fallback);
    shared_cache.insert(canonical.clone(), fallback.clone());
    Some(fallback)
}

fn merge_cached_package_info(
    existing: &CachedPackageInfo,
    incoming: &CachedPackageInfo,
) -> CachedPackageInfo {
    let mut versions = Vec::with_capacity(existing.versions.len() + incoming.versions.len());
    versions.extend(existing.versions.iter().cloned());
    versions.extend(incoming.versions.iter().cloned());
    versions.sort_by(|a, b| b.cmp(a));
    versions.dedup();

    let mut dist = existing.dist.clone();
    for (version, incoming_dist) in &incoming.dist {
        dist.entry(version.clone())
            .and_modify(|existing_dist| {
                *existing_dist = merge_cached_dist_info(existing_dist, incoming_dist);
            })
            .or_insert_with(|| incoming_dist.clone());
    }

    let mut deps = existing.deps.clone();
    deps.extend(incoming.deps.clone());
    let mut peer_deps = existing.peer_deps.clone();
    peer_deps.extend(incoming.peer_deps.clone());
    let mut optional_dep_names = existing.optional_dep_names.clone();
    optional_dep_names.extend(incoming.optional_dep_names.clone());
    let mut optional_peer_names = existing.optional_peer_names.clone();
    optional_peer_names.extend(incoming.optional_peer_names.clone());
    let mut node_engines = existing.node_engines.clone();
    node_engines.extend(incoming.node_engines.clone());
    let mut bundled_dep_names = existing.bundled_dep_names.clone();
    bundled_dep_names.extend(incoming.bundled_dep_names.clone());
    let mut platform = existing.platform.clone();
    platform.extend(incoming.platform.clone());
    let mut aliases = existing.aliases.clone();
    aliases.extend(incoming.aliases.clone());
    let mut covered_ranges = existing.covered_ranges.clone();
    covered_ranges.extend(incoming.covered_ranges.iter().cloned());
    let mut workspace_versions = existing.workspace_versions.clone();
    workspace_versions.extend(incoming.workspace_versions.iter().cloned());

    for workspace_version in &workspace_versions {
        let version = workspace_version.to_string();
        preserve_workspace_entry(&mut deps, &existing.deps, &version);
        preserve_workspace_entry(&mut peer_deps, &existing.peer_deps, &version);
        preserve_workspace_entry(
            &mut optional_dep_names,
            &existing.optional_dep_names,
            &version,
        );
        preserve_workspace_entry(
            &mut optional_peer_names,
            &existing.optional_peer_names,
            &version,
        );
        preserve_workspace_entry(&mut node_engines, &existing.node_engines, &version);
        preserve_workspace_entry(
            &mut bundled_dep_names,
            &existing.bundled_dep_names,
            &version,
        );
        preserve_workspace_entry(&mut platform, &existing.platform, &version);
        preserve_workspace_entry(&mut dist, &existing.dist, &version);
        preserve_workspace_entry(&mut aliases, &existing.aliases, &version);
    }

    let incoming_adds_versions = incoming
        .versions
        .iter()
        .any(|version| !existing.versions.contains(version));
    let existing_adds_versions = existing
        .versions
        .iter()
        .any(|version| !incoming.versions.contains(version));
    let versions_complete =
        incoming.versions_complete || (existing.versions_complete && !incoming_adds_versions);
    let trust_metadata_complete = (existing.trust_metadata_complete
        && (incoming.trust_metadata_complete || !incoming_adds_versions))
        || (incoming.trust_metadata_complete && !existing_adds_versions);
    let platform_metadata_complete = (existing.platform_metadata_complete
        && (incoming.platform_metadata_complete || !incoming_adds_versions))
        || (incoming.platform_metadata_complete && !existing_adds_versions);

    let mut merged = CachedPackageInfo {
        modified: incoming
            .modified
            .clone()
            .or_else(|| existing.modified.clone()),
        modified_unix: incoming.modified_unix.or(existing.modified_unix),
        trust_metadata_complete,
        versions_complete,
        covered_ranges,
        workspace_versions,
        platform_metadata_complete,
        latest_version: incoming
            .latest_version
            .clone()
            .or_else(|| existing.latest_version.clone()),
        versions,
        deps,
        peer_deps,
        optional_dep_names,
        optional_peer_names,
        node_engines,
        bundled_dep_names,
        platform,
        dist,
        aliases,
    };
    merged.remove_shadowed_peer_requirements();
    merged
}

fn preserve_workspace_entry<T: Clone>(
    merged: &mut HashMap<String, T>,
    workspace: &HashMap<String, T>,
    version: &str,
) {
    if let Some(value) = workspace.get(version) {
        merged.insert(version.to_string(), value.clone());
    } else {
        merged.remove(version);
    }
}

fn merge_cached_dist_info(existing: &CachedDistInfo, incoming: &CachedDistInfo) -> CachedDistInfo {
    CachedDistInfo {
        tarball_url: incoming
            .tarball_url
            .clone()
            .or_else(|| existing.tarball_url.clone()),
        integrity: incoming
            .integrity
            .clone()
            .or_else(|| existing.integrity.clone()),
        signatures: if incoming.signatures.is_empty() {
            existing.signatures.clone()
        } else {
            incoming.signatures.clone()
        },
        published_at: incoming
            .published_at
            .clone()
            .or_else(|| existing.published_at.clone()),
        published_at_unix: incoming.published_at_unix.or(existing.published_at_unix),
        trust_evidence: incoming.trust_evidence.or(existing.trust_evidence),
    }
}

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

    pub(super) fn ensure_cached_for_range(
        &self,
        package: &ResolverPackage,
        range: &NpmRange,
    ) -> Result<(), ProviderError> {
        if package.is_root() {
            return Ok(());
        }
        let key = CanonicalKey::from(package);
        let needs_registry_metadata = self
            .cache
            .get(&key)
            .is_some_and(|info| info.needs_metadata_for_range(range));
        if needs_registry_metadata {
            return self.direct_fetch_and_cache(package);
        }
        self.ensure_cached(package)
    }

    fn ensure_policy_metadata(
        &self,
        package: &ResolverPackage,
        key: &CanonicalKey,
    ) -> Result<(), ProviderError> {
        self.ensure_policy_metadata_with_trace(
            package,
            key,
            lpm_registry::timing::metadata_fetch_detail_enabled(),
        )
    }

    pub(super) fn ensure_policy_metadata_with_trace(
        &self,
        package: &ResolverPackage,
        key: &CanonicalKey,
        trace_metadata_fetches: bool,
    ) -> Result<(), ProviderError> {
        let needs_upgrade = self
            .cache
            .get(key)
            .is_some_and(|info| info.needs_supplemental_metadata(key, &self.policy));
        if !needs_upgrade {
            return Ok(());
        }
        let ResolverPackage::Npm { name, .. } = package else {
            return Ok(());
        };
        let route = self.route_table.route_for_package(name);
        let policy_start = trace_metadata_fetches.then(Instant::now);
        let info = self
            .cache
            .get(key)
            .map(|info| (**info).clone())
            .ok_or_else(|| ProviderError::Registry(format!("npm:{name}: metadata cache miss")))?;
        let fetched_full_policy_metadata = info.needs_trust_metadata(&self.policy);
        let mut info = if fetched_full_policy_metadata {
            self.fetch_full_policy_info(name, route.clone(), key)?
        } else {
            info
        };
        let mut release_time_detail = None;
        let release_time_start = trace_metadata_fetches.then(Instant::now);
        if info.needs_release_time_metadata(key, &self.policy) {
            release_time_detail =
                Some(self.fetch_release_time_policy_info(name, route.clone(), key, &mut info)?);
        }
        if info.needs_platform_metadata() {
            self.fetch_platform_info(name, route.clone(), key, &mut info)?;
        }
        if let Some(start) = policy_start {
            let elapsed = start.elapsed().as_millis();
            let mut record = lpm_registry::timing::MetadataFetchDetailRecord {
                package: key.to_string(),
                route: match route {
                    UpstreamRoute::NpmDirect => "npm_direct",
                    UpstreamRoute::LpmWorker => "lpm_worker",
                    UpstreamRoute::Custom { .. } => "custom",
                },
                total_ms: elapsed,
                policy_release_time_ms: release_time_start
                    .filter(|_| release_time_detail.is_some())
                    .map_or(0, |start| start.elapsed().as_millis()),
                policy_full_metadata_ms: if fetched_full_policy_metadata {
                    elapsed
                } else {
                    0
                },
                version_count: info.versions.len() as u64,
                ..lpm_registry::timing::MetadataFetchDetailRecord::default()
            };
            if let Some(detail) = &release_time_detail {
                detail.apply_to(&mut record);
            }
            lpm_registry::timing::record_metadata_fetch_detail(record);
        }
        self.insert_and_notify(key.clone(), info);
        Ok(())
    }

    /// Insert a freshly-parsed `CachedPackageInfo` and fire any waiters on
    /// its canonical key. Ordering is load-bearing: insert → notify. Do NOT
    /// reorder — notifying before inserting races the provider's re-check
    /// and causes spurious wait-loop iterations.
    pub(super) fn insert_and_notify(&self, key: CanonicalKey, info: CachedPackageInfo) {
        insert_or_merge_cached_package_info(&self.cache, key.clone(), Arc::new(info));
        self.available_versions_cache
            .lock()
            .retain(|package, _| CanonicalKey::from(package) != key);
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
        if let Some(cached) = self.available_versions_cache.lock().get(package) {
            return cached.clone();
        }
        let key = CanonicalKey::from(package);
        let Some(info) = self.cache.get(&key) else {
            return Vec::new();
        };
        let info = info.value();
        let versions =
            if !self.policy.release_age_active() && !self.policy.trust_policy().is_no_downgrade() {
                info.versions.clone()
            } else {
                info.versions
                    .iter()
                    .filter(|version| version_allowed_by_policy(&key, info, version, &self.policy))
                    .cloned()
                    .collect()
            };
        self.available_versions_cache
            .lock()
            .insert(package.clone(), versions.clone());
        versions
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
        if let Some(cached) = self.range_cache.lock().get(&key) {
            return cached.clone();
        }
        let latest_version = if npm_range.is_latest_tag() {
            let canonical = CanonicalKey::from(pkg);
            self.cache
                .get(&canonical)
                .and_then(|info| info.latest_version.clone())
        } else {
            None
        };
        let computed =
            npm_range.to_pubgrub_ranges_with_latest_bound(available, latest_version.as_ref());
        self.range_cache.lock().insert(key, computed.clone());
        computed
    }

    /// Extract the override hits AND the metadata cache in one shot. The
    /// two-stage `take_override_hits()` / `into_cache()` API is also
    /// available for callers that need only one of the two. Surfaces skipped
    /// dependency candidates, root aliases, and root deps so the resolver can
    /// validate the final selected graph without separate borrows.
    // Keep this tuple at the extraction boundary: the single caller
    // destructures it immediately, and a one-use struct would not clarify
    // ownership.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
        Vec<OverrideHit>,
        Vec<SkippedDependency>,
        HashMap<String, String>,
        RootDependencies,
    ) {
        let hits = self.overrides.take_hits();
        let mut skipped_dependencies: Vec<_> = self
            .skipped_dependencies
            .into_inner()
            .into_values()
            .collect();
        skipped_dependencies.sort_by_cached_key(|skipped| {
            (
                skipped.parent.to_string(),
                skipped.parent_version.clone(),
                skipped.local_name.clone(),
            )
        });
        let root_aliases = self.root_aliases.into_inner();
        let root_dependencies = self.root_dependencies;
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
        (
            cache,
            hits,
            skipped_dependencies,
            root_aliases,
            root_dependencies,
        )
    }
}
