use super::prelude::*;

impl LpmDependencyProvider {
    /// Pick the version the resolver would choose without any override applied.
    /// Returns the newest version in the consumer's declared range.
    ///
    /// Factored out of [`Self::choose_version`] so the override path can
    /// compute `from_version` for the apply trace AND fall back to this same
    /// value when no override matches.
    pub(super) fn pick_natural_version(
        &self,
        package: &ResolverPackage,
        range: &Ranges<NpmVersion>,
    ) -> Option<NpmVersion> {
        let key = CanonicalKey::from(package);
        let info = self.cache.get(&key)?;
        let info = info.value();

        // Versions are sorted newest-first; first match wins.
        for version in &info.versions {
            if !range.contains(version) {
                continue;
            }
            if !version_allowed_by_policy(&key, info, version, &self.policy) {
                continue;
            }

            return Some(version.clone());
        }
        None
    }

    /// Apply an [`OverrideTarget`] against the consumer's PubGrub `range`
    /// to produce a final forced version.
    ///
    /// - `PinnedVersion` returns the pinned version verbatim, but ONLY if it
    ///   satisfies the consumer's declared range — never picking a version the
    ///   consumer didn't ask for and silently pretending it works. Out-of-range
    ///   pinned targets return `None` so [`Self::choose_version`] surfaces them
    ///   as a debug-level warning.
    /// - `Range` intersects the override range with the consumer range
    ///   (via the cache's available versions list for THIS package)
    ///   and picks the newest match. A `^2.0.0` override means "use the
    ///   newest 2.x", not "force `2.0.0`".
    pub(super) fn apply_override_target(
        &self,
        package: &ResolverPackage,
        target: &OverrideTarget,
        range: &Ranges<NpmVersion>,
    ) -> Option<NpmVersion> {
        match target {
            OverrideTarget::PinnedVersion { version, .. } => {
                let key = CanonicalKey::from(package);
                let allowed = self.cache.get(&key).is_some_and(|info| {
                    version_allowed_by_policy(&key, info.value(), version, &self.policy)
                });
                if range.contains(version) && allowed {
                    Some(version.clone())
                } else {
                    None
                }
            }
            OverrideTarget::Range {
                range: target_range,
                ..
            } => {
                // Walk THIS package's cached versions only — cache is
                // canonical-keyed, so split-context variants of the same
                // canonical package share one entry — the override check
                // is over the canonical version list.
                let key = CanonicalKey::from(package);
                let info = self.cache.get(&key)?;
                let info = info.value();
                for v in &info.versions {
                    // versions are sorted newest-first, so the first
                    // match is the newest match.
                    if !range.contains(v) {
                        continue;
                    }
                    if !target_range.satisfies(v) {
                        continue;
                    }
                    if !version_allowed_by_policy(&key, info, v, &self.policy) {
                        continue;
                    }
                    return Some(v.clone());
                }
                None
            }
        }
    }
}

/// Should the resolver's follow-up batch calls use the deep variant
/// (worker recursively resolves transitives) rather than the shallow
/// variant (just the named packages)?
///
/// Default ON. `LPM_DEEP_FOLLOWUP=0` (or any value starting with `0`)
/// flips it off. Any other value — including empty — keeps it on, so
/// `LPM_DEEP_FOLLOWUP=1`, `=true`, `=yes`, unset all behave the same.
///
/// Measured win on cold installs:
/// - 58-dep fixture: −24.4 s resolve_ms (−39 %)
/// - 280-pkg fixture: −3.5 s resolve_ms (−28 %)
///
/// The escape hatch is for bisecting future regressions, not
/// operational use.
pub(super) fn deep_followup_enabled() -> bool {
    match std::env::var("LPM_DEEP_FOLLOWUP") {
        Ok(v) => !v.starts_with('0'),
        Err(_) => true,
    }
}

/// Priority for the resolver. Higher = resolved first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverPriority {
    conflict_count: u32,
    inverse_version_count: u32,
}

impl Ord for ResolverPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.conflict_count
            .cmp(&other.conflict_count)
            .then(self.inverse_version_count.cmp(&other.inverse_version_count))
    }
}

impl PartialOrd for ResolverPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl DependencyProvider for LpmDependencyProvider {
    type P = ResolverPackage;
    type V = NpmVersion;
    type VS = Ranges<NpmVersion>;
    type Priority = ResolverPriority;
    type M = String;
    type Err = ProviderError;

    fn prioritize(
        &self,
        package: &Self::P,
        _range: &Self::VS,
        stats: &PackageResolutionStatistics,
    ) -> Self::Priority {
        let conflict_count = stats.conflict_count();
        let key = CanonicalKey::from(package);
        let version_count = self.cache.get(&key).map_or(100, |c| c.versions.len()) as u32;

        ResolverPriority {
            conflict_count,
            inverse_version_count: u32::MAX - version_count,
        }
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        if package.is_root() {
            return Ok(Some(NpmVersion::new(0, 0, 0)));
        }

        let _span = tracing::debug_span!("choose_version", pkg = %package).entered();
        let _prof = crate::profile::choose_version::start();
        self.ensure_cached(package)?;

        let canonical = package.canonical_name();

        // Step 1 — compute the *natural* version: the newest version
        // satisfying the consumer's declared range, ignoring overrides.
        // The natural version is what the resolver WOULD pick without
        // any override; we capture it so the override summary can show
        // `from → to` (e.g. `foo 1.5.3 → 2.1.0`).
        let natural = self.pick_natural_version(package, range);

        // Step 2 — override lookup. We need a natural version to evaluate
        // the NameRange and Path range filters against. If there's no
        // natural match (range satisfies nothing in the cache), the
        // override can't apply — fall through to the unconstrained
        // newest-in-range pass below for whatever the resolver wants to
        // do (usually return None and surface a NoSolution).
        if let Some(natural_ver) = natural.as_ref() {
            let parent_ctx = package.context();
            if let Some(entry) = self
                .overrides
                .find_match(&canonical, natural_ver, parent_ctx)
            {
                // Apply the override target to produce the forced version.
                if let Some(forced) = self.apply_override_target(package, &entry.target, range) {
                    let hit = OverrideHit {
                        raw_key: entry.raw_key.clone(),
                        source: entry.source,
                        package: canonical.clone(),
                        from_version: natural_ver.to_string(),
                        to_version: forced.to_string(),
                        via_parent: parent_ctx.map(str::to_string),
                    };
                    tracing::debug!(
                        "override applied: {} {} → {} (via {})",
                        hit.package,
                        hit.from_version,
                        hit.to_version,
                        hit.source_display()
                    );
                    self.overrides.record_hit(hit);
                    return Ok(Some(forced));
                } else {
                    // The override target didn't satisfy the consumer's
                    // declared range — "irreconcilable override" case.
                    // Leave the consumer's natural version in place and
                    // let any downstream peer/SAT checks surface the
                    // situation. We do NOT silently pretend the override
                    // applied.
                    tracing::warn!(
                        "override {} could not be satisfied: target {} is outside consumer range for {}",
                        entry.raw_key,
                        entry.target.raw(),
                        canonical
                    );
                }
            }
        }

        // Step 3 — no override applied. Return the natural version
        // (computed above so we don't re-traverse the cache).
        Ok(natural)
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        let _span =
            tracing::debug_span!("get_dependencies", pkg = %package, ver = %version).entered();
        let _prof = crate::profile::get_dependencies::start();
        if package.is_root() {
            // Batch-prefetch root deps missing from BOTH in-memory and disk cache.
            // The initial batch_metadata_deep in install.rs covers most deps, so
            // this only fires when there are genuine cache misses (e.g., initial
            // batch failed or was incomplete).
            //
            // The prefetch list uses TARGET names for aliased root deps;
            // keeping the alias syntax would cause a failed metadata
            // fetch for a bogus name. When a walker is attached
            // (`fetch_wait_timeout > 0`), it IS the metadata producer —
            // firing the deep batch follow-up from inside
            // `get_dependencies` races ahead of the walker and pays the
            // full Worker RPC latency for manifests the walker is about
            // to insert anyway. On a cold-cache express install this
            // inflated `pubgrub_ms` from 7 ms to 21 s. Keep the
            // follow-up only when there is no walker attached
            // (`fetch_wait_timeout == ZERO`) so they retain their fast-
            // path behavior.
            if self.fetch_wait_timeout.is_zero() {
                let uncached: Vec<String> = self
                    .root_deps
                    .iter()
                    .map(|(local, range)| {
                        crate::ranges::parse_npm_alias(range)
                            .map_or_else(|| local.clone(), |a| a.target)
                    })
                    .filter(|target| {
                        let key = CanonicalKey::from_dep_name(target);
                        !self.cache.contains_key(&key) && !self.client.is_metadata_fresh(target)
                    })
                    .collect();

                if uncached.len() > 1 && !*self.batch_disabled.borrow() {
                    // Root-level follow-up (only fires when the pre-resolve
                    // batch was absent or incomplete) also uses the deep
                    // variant so the first pubgrub walk starts with a
                    // pre-populated transitive cache instead of serially
                    // fetching dep-of-deps inside the tree walk. Same
                    // `LPM_DEEP_FOLLOWUP` escape hatch as the per-package
                    // path below.
                    let deep_followup = deep_followup_enabled();
                    let fetch = async {
                        if deep_followup {
                            self.client.batch_metadata_deep(&uncached).await
                        } else {
                            self.client.batch_metadata(&uncached).await
                        }
                    };
                    match self.rt.block_on(fetch) {
                        Ok(batch) => {
                            tracing::debug!(
                                "root batch prefetch (deep={}): {} uncached → {} fetched",
                                deep_followup,
                                uncached.len(),
                                batch.len()
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                "root batch prefetch failed, disabling batching for this run: {e}"
                            );
                            *self.batch_disabled.borrow_mut() = true;
                        }
                    }
                }
            }

            let mut constraints = pubgrub::Map::default();
            for (dep_name, dep_range_str) in &self.root_deps {
                // Root-level alias rewrite: if the consumer's package.json
                // declares `"local": "npm:target@range"`, the resolver
                // must key the PubGrub constraint on `target` (the real
                // registry identity) while the install pipeline remembers
                // `local → target` for the linker to build
                // `node_modules/<local>/`. The alias is recorded in
                // `self.root_aliases` (RefCell, accumulated as we walk
                // each root dep).
                let (target_name, range_str) = match crate::ranges::parse_npm_alias(dep_range_str) {
                    Some(alias) => {
                        self.root_aliases
                            .borrow_mut()
                            .insert(dep_name.clone(), alias.target.clone());
                        (alias.target, alias.range)
                    }
                    None => (dep_name.clone(), dep_range_str.clone()),
                };

                let pkg = ResolverPackage::from_dep_name(&target_name);

                // Ensure dep is cached so we know its versions
                self.ensure_cached(&pkg)?;
                let available = self.available_versions(&pkg);

                // **Defense-in-depth.** `workspace:<rest>` must
                // be rewritten upstream by `lpm-workspace` before
                // reaching the resolver. If it slips through (future
                // refactor drops the upstream layer, hand-edited
                // manifest, malformed cache), `NpmRange::parse` would
                // fail with an opaque semver error. Surface the actual
                // diagnosis to the maintainer. Mirrors the greedy arm's
                // root-seed guard at `greedy::seed_root_edges`.
                if crate::ranges::is_workspace_specifier(&range_str) {
                    return Err(ProviderError::InvalidRange(format!(
                        "root dep {dep_name}: range '{range_str}' uses the \
                         `workspace:` protocol, which must be resolved by \
                         `lpm-workspace` before reaching the resolver. This is \
                         an internal bug — please file an issue at \
                         https://github.com/lpm-dev/rust-client/issues"
                    )));
                }

                let npm_range = NpmRange::parse(&range_str).map_err(ProviderError::InvalidRange)?;

                let range = if available.is_empty() {
                    npm_range.to_pubgrub_ranges_heuristic()
                } else {
                    self.to_pubgrub_ranges_cached(&pkg, &npm_range, &available)
                };

                constraints.insert(pkg, range);
            }
            return Ok(Dependencies::Available(constraints));
        }

        self.ensure_cached(package)?;

        let ver_str = version.to_string();
        let key = CanonicalKey::from(package);
        let (ver_deps, optional_names, ver_aliases, bundled_names) = {
            let info = match self.cache.get(&key) {
                Some(info) => info,
                None => {
                    return Ok(Dependencies::Unavailable(format!(
                        "no metadata for {package}"
                    )));
                }
            };
            let mut deps = match info.deps.get(&ver_str) {
                Some(deps) => deps.clone(),
                None => return Ok(Dependencies::Available(pubgrub::Map::default())),
            };
            let mut opt = info
                .optional_dep_names
                .get(&ver_str)
                .cloned()
                .unwrap_or_default();
            // local_name → target_name alias map. Empty for most packages (bare-identity deps).
            let aliases = info.aliases.get(&ver_str).cloned().unwrap_or_default();
            // Collect bundled dep names for this version. Used
            // below to drop them from `deps` BEFORE the prefetch +
            // pubgrub-constraint loop runs — pubgrub never sees the
            // bundled names so it doesn't try to resolve them as
            // separate registry packages.
            let bundled = info
                .bundled_dep_names
                .get(&ver_str)
                .cloned()
                .unwrap_or_default();
            // Strip bundled deps from the constraint set up front.
            // Done here rather than per-loop-iteration so the prefetch
            // batch below also skips them (they're not in the registry
            // under their bundled identity, so prefetching is wasted
            // work + a likely 404).
            if !bundled.is_empty() {
                let before = deps.len();
                deps.retain(|name, _| !bundled.contains(name));
                let dropped = before - deps.len();
                if dropped > 0 {
                    tracing::debug!(
                        "skipping {dropped} bundled dep(s) of {package}@{ver_str} \
                         — provided by parent's tarball"
                    );
                }
            }
            if !self.include_optional_dependencies && !opt.is_empty() {
                deps.retain(|name, _| !opt.contains(name));
                opt.clear();
            }
            (deps, opt, aliases, bundled)
        };
        let _ = bundled_names; // currently consumed up front; kept for future use

        // Scope key for a child of a split parent must include the parent's
        // OWN split context, not just its canonical name. Otherwise,
        // grandchildren of two already-split parents (e.g. `ajv[<root>]@8`
        // and `ajv[eslint]@6`, both children of different node_modules
        // branches) collapse back into a single pubgrub identity when they
        // each declare a dep on, say, `json-schema-traverse`. Using the
        // parent's full Display form propagates the split downward:
        // grandchildren get `[ajv[<root>]]` vs `[ajv[eslint]]` and resolve
        // independently, preserving the nested node_modules shape.
        let parent_name = package.to_string();
        let mut constraints = pubgrub::Map::default();

        // Batch-prefetch deps missing from BOTH in-memory and disk cache.
        // Checks disk freshness via stat() (microseconds) to avoid redundant HTTP
        // requests for packages the initial batch_metadata_deep already cached.
        // Only fires when 2+ deps are genuine network misses.
        //
        // The follow-up batch is issued with `deep=true` so the worker
        // recurses from each uncached name and returns its transitives in
        // the same RPC — every parent in the walk that hits the follow-up
        // path pre-populates the disk cache for its descendants, collapsing
        // what would otherwise be N serial round-trips into 1. Gated by
        // `LPM_DEEP_FOLLOWUP` (default on). Setting `=0` reverts to shallow
        // `batch_metadata` for bisection.
        //
        // When a walker is attached (`fetch_wait_timeout > 0`), it IS the
        // metadata producer and the wait-loop in `ensure_cached` handles
        // per-name misses cheaply via the `walker_done` shortcut. Firing
        // this batch from inside `get_dependencies` races ahead of the walker
        // and pays the full Worker RPC latency for manifests the walker is
        // about to insert. On a cold-cache 60-dep install this inflated
        // `pubgrub_ms` from 7 ms to 21 s. Skip wholesale when a walker is
        // attached.
        let deep_followup = deep_followup_enabled();
        if self.fetch_wait_timeout.is_zero() {
            let uncached: Vec<String> = ver_deps
                .keys()
                .filter(|name| {
                    let k = CanonicalKey::from_dep_name(name);
                    !self.cache.contains_key(&k) && !self.client.is_metadata_fresh(name)
                })
                .cloned()
                .collect();

            if uncached.len() > 1 && !*self.batch_disabled.borrow() {
                let fetch = async {
                    if deep_followup {
                        self.client.batch_metadata_deep(&uncached).await
                    } else {
                        self.client.batch_metadata(&uncached).await
                    }
                };
                match self.rt.block_on(fetch) {
                    Ok(batch) => {
                        tracing::debug!(
                            "dep batch prefetch for {parent_name} (deep={}): {} uncached → {} fetched",
                            deep_followup,
                            uncached.len(),
                            batch.len()
                        );
                    }
                    Err(e) => {
                        // Non-fatal: loop below falls back to individual ensure_cached() calls
                        tracing::debug!(
                            "dep batch prefetch failed, disabling batching for this run: {e}"
                        );
                        *self.batch_disabled.borrow_mut() = true;
                    }
                }
            }
        }

        for (dep_name, dep_range_str) in &ver_deps {
            // **Defense-in-depth.** Detect a leaked
            // `workspace:` specifier BEFORE the alias rewrite +
            // ensure_cached path runs — otherwise we'd try to fetch
            // a registry package named after the workspace local
            // identity (e.g., `internal`), waste a network round-trip,
            // and surface an opaque 404 instead of the actual cause.
            // Mirrors `greedy::enqueue_child_deps`. Registry-published
            // packages should never declare `workspace:` deps (npm
            // rejects at publish time); landing one in the constraint
            // loop signals a malformed cache or upstream bypass.
            if crate::ranges::is_workspace_specifier(dep_range_str) {
                tracing::warn!(
                    "ignoring transitive `workspace:` dep '{}' from {}@{} → {} \
                     (workspace: must be resolved upstream by lpm-workspace; \
                     a registry-published package should not declare it)",
                    dep_range_str,
                    package,
                    version,
                    dep_name,
                );
                continue;
            }

            // Resolve alias edges under the TARGET identity. For non-aliased
            // deps the local name == target name, so `target_name` is simply
            // `dep_name`. For aliases declared as `"local": "npm:target@range"`
            // (e.g., Radix UI's `strip-ansi-cjs → npm:strip-ansi@^6.0.1`),
            // we key the ResolverPackage on `target_name` so PubGrub dedup +
            // metadata fetch target the real registry identity. `dep_name` (the
            // local) is still used everywhere that records "how did the parent
            // refer to this dep" (split set, is_optional flag), and in
            // `format_solution` it becomes the edge key on
            // `ResolvedPackage.dependencies`.
            let target_name: &str = ver_aliases
                .get(dep_name)
                .map_or(dep_name.as_str(), String::as_str);
            let base_pkg = ResolverPackage::from_dep_name(target_name);

            // If this dep is in the split set, create a scoped identity
            // so PubGrub treats each consumer's version independently.
            // Match against the TARGET name — split decisions are about
            // the canonical registry identity, not the parent-specific
            // alias label.
            let pkg = if self.split_packages.contains(target_name) {
                base_pkg.with_context(&parent_name)
            } else {
                base_pkg
            };

            let is_optional = optional_names.contains(dep_name);

            // Ensure dep is cached — skip optional deps that fail to fetch.
            //
            // An optional `@lpm.dev` dep that hits an auth/entitlement error
            // must surface as a user-visible warning, not a silent debug skip.
            // Without this distinction, gated-dep omission is
            // indistinguishable from the legitimate "fsevents on linux"
            // platform-skip pattern.
            //
            // Other failure shapes (network blips, npm registry 5xx,
            // platform-incompatible) keep the silent debug behavior —
            // they're expected and noisy.
            match self.ensure_cached(&pkg) {
                Ok(()) => {}
                Err(e) => {
                    if is_optional {
                        let is_lpm = matches!(pkg, ResolverPackage::Lpm { .. });
                        let is_auth = matches!(e, ProviderError::AuthRequired(_));
                        if is_lpm && is_auth {
                            tracing::warn!(
                                "optional dep {dep_name} skipped: requires LPM authentication \
                                 (run `lpm login` to install this package)"
                            );
                        } else {
                            tracing::debug!("skipping optional dep {dep_name}: {e}");
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
            let available = self.available_versions(&pkg);

            // Optional dependencies with no semver-satisfying candidate are
            // omitted, while platform metadata on satisfying candidates is
            // preserved for install-time filtering.
            let npm_range = match NpmRange::parse(dep_range_str) {
                Ok(r) => r,
                Err(e) => {
                    if is_optional {
                        tracing::debug!("skipping optional dep {dep_name}@{dep_range_str}: {e}");
                    } else {
                        tracing::warn!("skipping dep {dep_name}@{dep_range_str}: {e}");
                    }
                    continue;
                }
            };

            let range = if available.is_empty() {
                npm_range.to_pubgrub_ranges_heuristic()
            } else {
                self.to_pubgrub_ranges_cached(&pkg, &npm_range, &available)
            };

            if is_optional {
                let any_satisfies = available.iter().any(|version| range.contains(version));
                if !any_satisfies {
                    let host = Platform::current();
                    tracing::debug!(
                        "skipping optional dep {dep_name}@{dep_range_str}: \
                         no available version satisfies range \
                         (available={}, os={}, cpu={}, libc={})",
                        available.len(),
                        host.os,
                        host.cpu,
                        host.libc.unwrap_or("none"),
                    );
                    *self.platform_skipped.borrow_mut() += 1;
                    continue;
                }
            }
            constraints.insert(pkg, range);
        }

        // Peer dependencies are NOT propagated as constraints during resolution.
        // Instead, they are checked post-resolution against the actual resolved tree.
        // This avoids the over-constraint problem where union-across-all-versions
        // peer deps could force incompatible requirements (e.g., styled-components@5
        // peers react@^16 but styled-components@6 peers react@^18 — union would
        // force react@^18, breaking projects using v5).
        //
        // See check_unmet_peers() for the post-resolution check.

        Ok(Dependencies::Available(constraints))
    }
}
