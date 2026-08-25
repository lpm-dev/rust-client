use super::prelude::*;

pub(super) struct ReleaseTimePolicyFetchDetail {
    pub(super) total_ms: u128,
    pub(super) timings: lpm_registry::PackageMetadataFetchTimings,
    pub(super) version_count: u64,
}

impl ReleaseTimePolicyFetchDetail {
    pub(super) fn apply_to(&self, record: &mut lpm_registry::timing::MetadataFetchDetailRecord) {
        record.policy_release_time_fetch_ms = self.total_ms;
        record.policy_release_time_cache_read_ms = self.timings.cache_read_ms;
        record.policy_release_time_validator_read_ms = self.timings.validator_read_ms;
        record.policy_release_time_http_ms = self.timings.http_ms;
        record.policy_release_time_body_read_ms = self.timings.body_read_ms;
        record.policy_release_time_json_decode_ms = self.timings.json_decode_ms;
        record.policy_release_time_cache_after_304_ms = self.timings.cache_after_304_ms;
        record.policy_release_time_cache_write_dispatch_ms = self.timings.cache_write_dispatch_ms;
        record.policy_release_time_body_bytes = self.timings.body_bytes;
        record.policy_release_time_version_count = self.version_count;
        record.policy_release_time_cache_hit = self.timings.cache_hit;
        record.policy_release_time_not_modified = self.timings.not_modified;
    }
}

impl LpmDependencyProvider {
    /// Synchronous fetch of a single package, keyed + cached under its
    /// canonical form. LPM → Worker unconditionally; npm → per `RouteMode`.
    ///
    /// Called by [`Self::ensure_cached`] as the escape-hatch when the
    /// walker either isn't attached or didn't reach this package within
    /// `fetch_wait_timeout`.
    pub(super) fn direct_fetch_and_cache(
        &self,
        package: &ResolverPackage,
    ) -> Result<(), ProviderError> {
        let key = CanonicalKey::from(package);
        // Count every fetch that falls through to the escape hatch.
        // Root returns early without triggering a registry fetch.
        if !package.is_root() {
            self.metrics.incr_escape_hatch_fetch();
        }
        match package {
            ResolverPackage::Root => Ok(()),
            ResolverPackage::Lpm { owner, name, .. } => {
                let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                    .map_err(|e| ProviderError::Registry(e.to_string()))?;

                let trace_metadata_fetches = lpm_registry::timing::metadata_fetch_detail_enabled();
                let total_start = trace_metadata_fetches.then(Instant::now);
                let raw_start = trace_metadata_fetches.then(Instant::now);
                let metadata = self
                    .rt
                    .block_on(self.client.get_package_metadata(&pkg_name))
                    .map_err(classify_registry_error)?;
                let detail =
                    raw_start.map(|start| lpm_registry::timing::MetadataFetchDetailRecord {
                        package: key.to_string(),
                        route: "lpm",
                        raw_fetch_ms: start.elapsed().as_millis(),
                        version_count: metadata.versions.len() as u64,
                        ..lpm_registry::timing::MetadataFetchDetailRecord::default()
                    });

                // Use shared parser. Prereleases included
                // (range matcher handles npm prerelease semantics).
                let parse_start = trace_metadata_fetches.then(Instant::now);
                let info = parse_owned_metadata_to_cache_info(metadata);
                if let Some(mut record) = detail {
                    if let Some(start) = parse_start {
                        record.cache_info_parse_ms = start.elapsed().as_millis();
                    }
                    if let Some(start) = total_start {
                        record.total_ms = start.elapsed().as_millis();
                    }
                    lpm_registry::timing::record_metadata_fetch_detail(record);
                }
                self.insert_and_notify(key, info);
                Ok(())
            }
            ResolverPackage::Npm { name, .. } => {
                let route = self.route_table.route_for_package(name);
                let trace_metadata_fetches = lpm_registry::timing::metadata_fetch_detail_enabled();
                let total_start = trace_metadata_fetches.then(Instant::now);
                let raw_start = trace_metadata_fetches.then(Instant::now);
                let mut detail: Option<lpm_registry::timing::MetadataFetchDetailRecord> = None;
                let metadata_result = match &route {
                    UpstreamRoute::LpmWorker => self
                        .rt
                        .block_on(self.client.get_npm_package_metadata(name))
                        .inspect(|metadata| {
                            if let Some(start) = raw_start {
                                detail = Some(lpm_registry::timing::MetadataFetchDetailRecord {
                                    package: key.to_string(),
                                    route: "lpm_worker",
                                    raw_fetch_ms: start.elapsed().as_millis(),
                                    version_count: metadata.versions.len() as u64,
                                    ..lpm_registry::timing::MetadataFetchDetailRecord::default()
                                });
                            }
                        }),
                    UpstreamRoute::NpmDirect => {
                        if trace_metadata_fetches {
                            self.rt
                                .block_on(self.client.get_npm_metadata_direct_with_timings(name))
                                .map(|timed| {
                                    let registry = timed.timings;
                                    detail = Some(
                                        lpm_registry::timing::MetadataFetchDetailRecord {
                                            package: key.to_string(),
                                            route: "npm_direct",
                                            raw_fetch_ms: raw_start
                                                .map_or(0, |start| start.elapsed().as_millis()),
                                            cache_read_ms: registry.cache_read_ms,
                                            validator_read_ms: registry.validator_read_ms,
                                            http_ms: registry.http_ms,
                                            body_read_ms: registry.body_read_ms,
                                            json_decode_ms: registry.json_decode_ms,
                                            cache_after_304_ms: registry.cache_after_304_ms,
                                            cache_write_dispatch_ms: registry.cache_write_dispatch_ms,
                                            body_bytes: registry.body_bytes,
                                            version_count: timed.metadata.versions.len() as u64,
                                            cache_hit: registry.cache_hit,
                                            not_modified: registry.not_modified,
                                            ..lpm_registry::timing::MetadataFetchDetailRecord::default()
                                        },
                                    );
                                    timed.metadata
                                })
                        } else {
                            self.rt.block_on(self.client.get_npm_metadata_direct(name))
                        }
                    }
                    UpstreamRoute::Custom { target, auth } => {
                        // Auth is origin-scoped and re-verified inside
                        // `get_npm_metadata_from` before attaching the header.
                        self.rt
                            .block_on(self.client.get_npm_metadata_from(
                                &target.base_url,
                                name,
                                auth.as_deref(),
                            ))
                            .inspect(|metadata| {
                                if let Some(start) = raw_start {
                                    detail =
                                        Some(lpm_registry::timing::MetadataFetchDetailRecord {
                                            package: key.to_string(),
                                            route: "custom",
                                            raw_fetch_ms: start.elapsed().as_millis(),
                                            version_count: metadata.versions.len() as u64,
                                            ..lpm_registry::timing::MetadataFetchDetailRecord::default()
                                        });
                                }
                            })
                    }
                };
                let metadata = match metadata_result {
                    Ok(metadata) => metadata,
                    Err(lpm_common::LpmError::NotFound(_))
                        if activate_workspace_fallback(&self.cache, &key).is_some() =>
                    {
                        self.available_versions_cache
                            .lock()
                            .retain(|package, _| CanonicalKey::from(package) != key);
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(ProviderError::Registry(format!("npm:{name}: {error}")));
                    }
                };

                let parse_start = trace_metadata_fetches.then(Instant::now);
                let mut info = parse_owned_metadata_to_cache_info(metadata);
                if let Some(record) = &mut detail
                    && let Some(start) = parse_start
                {
                    record.cache_info_parse_ms = start.elapsed().as_millis();
                }
                if info.needs_trust_metadata(&self.policy) {
                    let policy_start = trace_metadata_fetches.then(Instant::now);
                    info = self.fetch_full_policy_info(name, route, &key)?;
                    if let Some(record) = &mut detail
                        && let Some(start) = policy_start
                    {
                        record.policy_full_metadata_ms = start.elapsed().as_millis();
                    }
                } else {
                    if info.needs_release_time_metadata(&key, &self.policy) {
                        let policy_start = trace_metadata_fetches.then(Instant::now);
                        let release_time_detail = self.fetch_release_time_policy_info(
                            name,
                            route.clone(),
                            &key,
                            &mut info,
                        )?;
                        if let Some(record) = &mut detail
                            && let Some(start) = policy_start
                        {
                            record.policy_release_time_ms = start.elapsed().as_millis();
                            release_time_detail.apply_to(record);
                        }
                    }
                    if info.needs_platform_metadata() {
                        self.fetch_platform_info(name, route, &key, &mut info)?;
                    }
                }
                if let Some(mut record) = detail {
                    if let Some(start) = total_start {
                        record.total_ms = start.elapsed().as_millis();
                    }
                    lpm_registry::timing::record_metadata_fetch_detail(record);
                }
                tracing::debug!("npm package {name}: {} versions", info.versions.len());
                self.insert_and_notify(key, info);
                Ok(())
            }
        }
    }

    pub(super) fn fetch_full_policy_info(
        &self,
        name: &str,
        route: UpstreamRoute,
        key: &CanonicalKey,
    ) -> Result<CachedPackageInfo, ProviderError> {
        let full = self
            .rt
            .block_on(
                self.client
                    .get_npm_metadata_routed_full(name, route.clone()),
            )
            .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
        let info = parse_owned_full_metadata_to_cache_info(full);
        if !info.needs_supplemental_metadata(key, &self.policy) {
            return Ok(info);
        }
        if !matches!(route, UpstreamRoute::LpmWorker) {
            return Ok(info);
        }

        tracing::debug!(
            "Worker full metadata for {name} omitted policy fields; falling back to direct npm full metadata"
        );
        let direct_full = self
            .rt
            .block_on(self.client.refetch_npm_metadata_direct_full(name))
            .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
        Ok(parse_owned_full_metadata_to_cache_info(direct_full))
    }

    pub(super) fn fetch_release_time_policy_info(
        &self,
        name: &str,
        route: UpstreamRoute,
        key: &CanonicalKey,
        info: &mut CachedPackageInfo,
    ) -> Result<ReleaseTimePolicyFetchDetail, ProviderError> {
        let fetch_start = Instant::now();
        let release_times = self
            .rt
            .block_on(
                self.client
                    .get_npm_release_times_routed_full_with_timings(name, route.clone()),
            )
            .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
        let mut timings = release_times.timings;
        let mut version_count = release_times.metadata.time.len() as u64;
        merge_release_times_into_cache_info(info, &release_times.metadata);
        if !info.needs_policy_metadata(key, &self.policy) {
            return Ok(ReleaseTimePolicyFetchDetail {
                total_ms: fetch_start.elapsed().as_millis(),
                timings,
                version_count,
            });
        }
        if !matches!(route, UpstreamRoute::LpmWorker) {
            return Ok(ReleaseTimePolicyFetchDetail {
                total_ms: fetch_start.elapsed().as_millis(),
                timings,
                version_count,
            });
        }

        let direct_release_times = self
            .rt
            .block_on(
                self.client
                    .get_npm_release_times_routed_full_with_timings(name, UpstreamRoute::NpmDirect),
            )
            .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
        timings = direct_release_times.timings;
        version_count = direct_release_times.metadata.time.len() as u64;
        merge_release_times_into_cache_info(info, &direct_release_times.metadata);
        Ok(ReleaseTimePolicyFetchDetail {
            total_ms: fetch_start.elapsed().as_millis(),
            timings,
            version_count,
        })
    }

    pub(super) fn fetch_platform_info(
        &self,
        name: &str,
        route: UpstreamRoute,
        key: &CanonicalKey,
        info: &mut CachedPackageInfo,
    ) -> Result<(), ProviderError> {
        let platform_metadata = self
            .rt
            .block_on(lpm_registry::timing::with_metadata_purpose(
                lpm_registry::timing::MetadataPurpose::PlatformHydration,
                self.client
                    .get_npm_platform_metadata_routed_full(name, route.clone()),
            ))
            .map_err(|error| ProviderError::Registry(format!("npm:{name}: {error}")))?;
        merge_release_times_into_cache_info(info, &platform_metadata);
        if !info.needs_platform_metadata() {
            return Ok(());
        }
        if matches!(route, UpstreamRoute::LpmWorker) {
            let direct_platform_metadata = self
                .rt
                .block_on(lpm_registry::timing::with_metadata_purpose(
                    lpm_registry::timing::MetadataPurpose::PlatformHydration,
                    self.client
                        .get_npm_platform_metadata_routed_full(name, UpstreamRoute::NpmDirect),
                ))
                .map_err(|error| ProviderError::Registry(format!("npm:{name}: {error}")))?;
            merge_release_times_into_cache_info(info, &direct_platform_metadata);
        }
        if info.needs_platform_metadata() {
            return Err(ProviderError::Registry(format!(
                "npm:{key}: full registry metadata omitted the versions map required to recover platform restrictions"
            )));
        }
        Ok(())
    }
}
