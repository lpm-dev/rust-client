use super::manifest_core::ManifestVersion;
use super::prelude::*;
use super::types::{CachedAvailableVersions, CachedRange};

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

pub(crate) fn merge_cached_package_info(
    existing: &CachedPackageInfo,
    incoming: &CachedPackageInfo,
) -> CachedPackageInfo {
    let mut covered_ranges = existing.covered_ranges.clone();
    covered_ranges.extend(incoming.covered_ranges.iter().cloned());
    let mut workspace_versions = existing.workspace_versions.clone();
    workspace_versions.extend(incoming.workspace_versions.iter().cloned());

    let incoming_adds_versions = incoming.versions.iter().any(|version| {
        existing
            .versions
            .binary_search_by(|candidate| version.cmp(candidate))
            .is_err()
    });
    let existing_adds_versions = existing.versions.iter().any(|version| {
        incoming
            .versions
            .binary_search_by(|candidate| version.cmp(candidate))
            .is_err()
    });
    let versions_complete =
        incoming.versions_complete || (existing.versions_complete && !incoming_adds_versions);
    let trust_metadata_complete = (existing.trust_metadata_complete
        && (incoming.trust_metadata_complete || !incoming_adds_versions))
        || (incoming.trust_metadata_complete && !existing_adds_versions);
    let platform_metadata_complete = (existing.platform_metadata_complete
        && (incoming.platform_metadata_complete || !incoming_adds_versions))
        || (incoming.platform_metadata_complete && !existing_adds_versions);

    if !incoming_adds_versions
        && incoming
            .modified
            .as_ref()
            .is_none_or(|value| existing.modified.as_ref() == Some(value))
        && incoming
            .latest_version
            .as_ref()
            .is_none_or(|value| existing.latest_version.as_ref() == Some(value))
        && incoming
            .dist_tags()
            .iter()
            .all(|(tag, version)| existing.dist_tags().get(tag) == Some(version))
        && incoming.versions.iter().all(|version| {
            let current = existing.manifest_version_owned_for(version);
            let updated = merge_manifest_version(
                current.as_ref(),
                incoming.manifest_version_owned_for(version),
                existing.workspace_versions.contains(version),
            );
            current == updated
        })
    {
        let mut merged = existing.clone();
        merged.covered_ranges = covered_ranges;
        merged.workspace_versions = workspace_versions;
        merged.versions_complete = versions_complete;
        merged.trust_metadata_complete = trust_metadata_complete;
        merged.platform_metadata_complete = platform_metadata_complete;
        merged.preferred_latest = merged_preferred_latest(existing, incoming, &merged);
        return merged;
    }

    let modified = incoming
        .modified
        .clone()
        .or_else(|| existing.modified.clone());
    let latest_version = incoming
        .latest_version
        .clone()
        .or_else(|| existing.latest_version.clone());
    let mut dist_tags = existing.dist_tags().clone();
    dist_tags.extend(
        incoming
            .dist_tags()
            .iter()
            .map(|(tag, version)| (tag.clone(), version.clone())),
    );
    let mut versions = Vec::with_capacity(existing.versions.len() + incoming.versions.len());
    versions.extend(existing.versions.iter().cloned());
    versions.extend(incoming.versions.iter().cloned());
    versions.sort_unstable_by(|left, right| right.cmp(left));
    versions.dedup();
    let mut builder = CachedPackageInfo::builder(
        modified,
        trust_metadata_complete,
        versions_complete,
        covered_ranges,
        workspace_versions,
        platform_metadata_complete,
        latest_version,
        versions.len(),
    );
    builder.set_dist_tags(dist_tags);
    for version in versions {
        let existing_manifest = existing.manifest_version_owned_for(&version);
        let incoming_manifest = incoming.manifest_version_owned_for(&version);
        let manifest =
            if existing.workspace_versions.contains(&version) || incoming_manifest.is_none() {
                existing_manifest
            } else {
                merge_manifest_version(existing_manifest.as_ref(), incoming_manifest, false)
            };
        if let Some(manifest) = manifest {
            builder.push(manifest);
        }
    }
    let mut merged = builder.finish();
    merged.preferred_latest = merged_preferred_latest(existing, incoming, &merged);
    merged
}

fn merged_preferred_latest(
    existing: &CachedPackageInfo,
    incoming: &CachedPackageInfo,
    merged: &CachedPackageInfo,
) -> Option<NpmVersion> {
    if !merged.workspace_versions.is_empty() || merged.versions_complete {
        return None;
    }
    incoming
        .preferred_latest
        .as_ref()
        .or(existing.preferred_latest.as_ref())
        .filter(|latest| Some(*latest) == merged.latest_version.as_ref())
        .cloned()
}

fn merge_manifest_version(
    existing: Option<&ManifestVersion>,
    incoming: Option<ManifestVersion>,
    preserve_existing: bool,
) -> Option<ManifestVersion> {
    if preserve_existing {
        return existing.cloned();
    }
    match (existing, incoming) {
        (Some(existing), Some(mut incoming)) => {
            if incoming.dependencies.is_empty() {
                incoming.dependencies.clone_from(&existing.dependencies);
            }
            if incoming.peer_dependencies.is_empty() {
                incoming
                    .peer_dependencies
                    .clone_from(&existing.peer_dependencies);
            }
            if incoming.node_engine.is_none() {
                incoming.node_engine.clone_from(&existing.node_engine);
            }
            if incoming.platform.is_none() {
                incoming.platform.clone_from(&existing.platform);
            }
            incoming.dist = merge_cached_dist_info(&existing.dist, &incoming.dist);
            Some(incoming)
        }
        (Some(existing), None) => Some(existing.clone()),
        (None, incoming) => incoming,
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
        unpacked_size: incoming.unpacked_size.or(existing.unpacked_size),
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
            self.direct_fetch_and_cache(package)?;
        } else {
            self.ensure_cached(package)?;
        }
        let missing = self.cache.get(&key).is_some_and(|info| {
            info.workspace_versions.is_empty()
                && !info
                    .versions
                    .iter()
                    .any(|version| info.range_satisfies(range, version))
        });
        if missing && self.refreshed_metadata.lock().insert(key.clone()) {
            let metadata = self
                .rt
                .block_on(super::fetch::revalidate_metadata(
                    &self.client,
                    &self.route_table,
                    &key,
                ))
                .map_err(classify_registry_error)?;
            self.cache.insert(
                key.clone(),
                Arc::new(parse_owned_metadata_to_cache_info(metadata)),
            );
            self.available_versions_cache
                .lock()
                .retain(|package, _| CanonicalKey::from(package) != key);
            self.ensure_policy_metadata(package, &key)?;
        }
        Ok(())
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
    pub(super) fn available_versions(&self, package: &ResolverPackage) -> Arc<[NpmVersion]> {
        let _span = tracing::debug_span!("available_versions", pkg = %package).entered();
        let _prof = crate::profile::available_versions::start();
        let key = CanonicalKey::from(package);
        let Some(info) = self.cache.get(&key) else {
            return Arc::from([]);
        };
        let info = info.value();
        if let Some(cached) = self.available_versions_cache.lock().get(package)
            && Arc::ptr_eq(&cached.metadata, info)
        {
            return Arc::clone(&cached.versions);
        }

        let versions = if !self.policy.release_age_active()
            && !self.policy.trust_policy().is_no_downgrade()
        {
            Arc::clone(&info.versions)
        } else {
            Arc::from(
                info.versions
                    .iter()
                    .filter(|version| version_allowed_by_policy(&key, info, version, &self.policy))
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        self.available_versions_cache.lock().insert(
            package.clone(),
            CachedAvailableVersions {
                metadata: Arc::clone(info),
                versions: Arc::clone(&versions),
            },
        );
        versions
    }

    /// Reuse a conversion only while its available versions and tag are unchanged.
    pub(super) fn to_pubgrub_ranges_cached(
        &self,
        pkg: &ResolverPackage,
        npm_range: &NpmRange,
        available: &Arc<[NpmVersion]>,
    ) -> Ranges<NpmVersion> {
        let key = (pkg.clone(), npm_range.raw().to_string());
        let tagged_version = npm_range.dist_tag().and_then(|tag| {
            let canonical = CanonicalKey::from(pkg);
            self.cache
                .get(&canonical)
                .and_then(|info| info.dist_tag_version(tag).cloned())
        });
        if let Some(cached) = self.range_cache.lock().get(&key)
            && Arc::ptr_eq(&cached.available, available)
            && cached.tagged_version == tagged_version
        {
            return cached.range.clone();
        }
        let computed =
            npm_range.to_pubgrub_ranges_with_dist_tag(available, tagged_version.as_ref());
        self.range_cache.lock().insert(
            key,
            CachedRange {
                available: Arc::clone(available),
                tagged_version,
                range: computed.clone(),
            },
        );
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
        solution: &pubgrub::SelectedDependencies<Self>,
    ) -> (
        HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
        Vec<OverrideHit>,
        Vec<SkippedDependency>,
        HashMap<String, String>,
        RootDependencies,
    ) {
        let hits = self.selected_override_hits(solution);
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

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn history() -> lpm_registry::PackageMetadata {
        serde_json::from_value(serde_json::json!({
            "name": "shared",
            "dist-tags": {"latest": "3.0.0"},
            "versions": {
                "1.0.0": {"name": "shared", "version": "1.0.0"},
                "2.0.0": {"name": "shared", "version": "2.0.0", "dependencies": {"child": "^1"},
                    "dist": {"tarball": "https://example.invalid/old.tgz", "integrity": "sha512-old"}},
                "3.0.0": {"name": "shared", "version": "3.0.0"}
            }
        })).unwrap()
    }

    #[test]
    fn equivalent_partial_and_full_snapshots_keep_the_shared_version_history() {
        let full = parse_owned_metadata_to_cache_info(history());
        let mut partial_raw = history();
        partial_raw.versions.retain(|version, _| version == "2.0.0");
        partial_raw.dist_tags.clear();
        let mut partial = parse_owned_partial_metadata_to_cache_info(partial_raw);
        partial.covered_ranges.insert("2.0.0".into());

        let merged_partial = merge_cached_package_info(&full, &partial);
        assert!(Arc::ptr_eq(&full.versions, &merged_partial.versions));
        assert!(merged_partial.covered_ranges.contains("2.0.0"));
        let merged_full = merge_cached_package_info(&merged_partial, &full);
        assert!(Arc::ptr_eq(&full.versions, &merged_full.versions));
        assert_eq!(
            merged_full.manifest_versions_owned(),
            full.manifest_versions_owned()
        );
    }

    #[test]
    fn partial_snapshots_preserve_changed_dependencies_distribution_and_platform() {
        let full = parse_owned_metadata_to_cache_info(history());
        let partial_raw = serde_json::from_value(serde_json::json!({
            "name": "shared", "versions": {"2.0.0": {
                "name": "shared", "version": "2.0.0", "dependencies": {"child": "^2"},
                "os": ["linux"], "cpu": ["x64"], "libc": ["musl"],
                "dist": {"tarball": "https://example.invalid/new.tgz", "integrity": "sha512-new"}
            }}
        }))
        .unwrap();
        let partial = parse_owned_partial_metadata_to_cache_info(partial_raw);
        let merged = merge_cached_package_info(&full, &partial);

        assert_eq!(
            merged.tarball_url("2.0.0"),
            Some("https://example.invalid/new.tgz")
        );
        assert_eq!(merged.integrity("2.0.0"), Some("sha512-new"));
        assert_eq!(merged.dependency("2.0.0", "child").unwrap().range, "^2");
        assert_eq!(merged.platform("2.0.0").unwrap().libc, ["musl"]);
        assert_eq!(merged.versions.len(), 3);
    }

    #[test]
    fn equivalent_manifests_preserve_updated_coverage_and_provenance_flags() {
        let full = parse_owned_metadata_to_cache_info(history());
        let mut incoming = full.clone();
        incoming.versions_complete = false;
        incoming.platform_metadata_complete = true;
        incoming.trust_metadata_complete = true;
        incoming.covered_ranges.insert("^2".into());

        let merged = merge_cached_package_info(&full, &incoming);

        assert!(Arc::ptr_eq(&full.versions, &merged.versions));
        assert!(merged.versions_complete);
        assert!(merged.platform_metadata_complete);
        assert!(merged.trust_metadata_complete);
        assert!(merged.covered_ranges.contains("^2"));
    }

    #[test]
    fn later_snapshots_preserve_updated_tags_and_release_times() {
        let full = parse_owned_metadata_to_cache_info(history());
        let mut incoming_raw = history();
        incoming_raw.modified = Some("2026-01-02T00:00:00Z".into());
        incoming_raw.dist_tags.insert("beta".into(), "2.0.0".into());
        incoming_raw
            .time
            .insert("2.0.0".into(), "2026-01-01T00:00:00Z".into());
        let incoming = parse_owned_partial_metadata_to_cache_info(incoming_raw);

        let merged = merge_cached_package_info(&full, &incoming);

        assert_eq!(merged.modified.as_deref(), Some("2026-01-02T00:00:00Z"));
        assert_eq!(
            merged.dist_tag_version("beta").unwrap().to_string(),
            "2.0.0"
        );
        assert_eq!(merged.published_at("2.0.0"), Some("2026-01-01T00:00:00Z"));
    }
}

#[cfg(test)]
mod preferred_provenance_tests {
    use super::*;

    fn partial(latest: &str) -> CachedPackageInfo {
        let metadata = serde_json::from_value(serde_json::json!({
            "name":"pkg", "dist-tags":{"latest":latest}, "versions":{
                "1.0.0":{"name":"pkg","version":"1.0.0"},
                "2.0.0":{"name":"pkg","version":"2.0.0"}
            }
        }))
        .unwrap();
        super::super::parse::parse_owned_partial_metadata_to_cache_info(metadata)
    }

    #[test]
    fn generic_partial_metadata_has_no_preferred_provenance() {
        let info = partial("1.0.0");
        assert!(info.preferred_latest.is_none());
        assert!(info.needs_metadata_for_range(&NpmRange::parse("*").unwrap()));
    }

    #[test]
    fn preferred_range_proof_rejects_unknown_tags_stale_identity_and_workspace_data() {
        let range = NpmRange::parse("^1").unwrap();
        let mut info = partial("1.0.0");
        assert!(!info.preferred_latest_satisfies(&range));
        info.preferred_latest = info.latest_version.clone();
        assert!(info.preferred_latest_satisfies(&range));
        assert!(info.needs_metadata_for_range(&range));
        assert!(!info.preferred_latest_satisfies(&NpmRange::parse("^2").unwrap()));
        assert!(!info.preferred_latest_satisfies(&NpmRange::parse_registry_spec("beta").unwrap()));
        let mut workspace = info.clone();
        workspace
            .workspace_versions
            .insert(NpmVersion::parse("1.0.0").unwrap());
        assert!(!workspace.preferred_latest_satisfies(&range));
        let mut stale = info.clone();
        stale.latest_version = Some(NpmVersion::parse("2.0.0").unwrap());
        assert!(!stale.preferred_latest_satisfies(&range));
        info.versions = Arc::from([NpmVersion::parse("2.0.0").unwrap()]);
        assert!(!info.preferred_latest_satisfies(&range));
    }

    #[test]
    fn merge_preserves_preferred_provenance_only_for_the_current_registry_latest() {
        let mut original = partial("1.0.0");
        original.preferred_latest = original.latest_version.clone();
        let unchanged = merge_cached_package_info(&original, &partial("1.0.0"));
        assert_eq!(unchanged.preferred_latest, original.preferred_latest);
        let changed = merge_cached_package_info(&original, &partial("2.0.0"));
        assert!(changed.preferred_latest.is_none());
        let mut workspace = partial("1.0.0");
        workspace
            .workspace_versions
            .insert(NpmVersion::parse("1.0.0").unwrap());
        assert!(
            merge_cached_package_info(&original, &workspace)
                .preferred_latest
                .is_none()
        );
    }
}
