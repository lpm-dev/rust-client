use super::prelude::*;

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

                let metadata = self
                    .rt
                    .block_on(self.client.get_package_metadata(&pkg_name))
                    .map_err(classify_registry_error)?;

                // Use shared parser. Prereleases included
                // (range matcher handles npm prerelease semantics).
                let info = parse_metadata_to_cache_info(&metadata);
                self.insert_and_notify(key, info);
                Ok(())
            }
            ResolverPackage::Npm { name, .. } => {
                let route = self.route_table.route_for_package(name);
                let metadata = match &route {
                    UpstreamRoute::LpmWorker => {
                        self.rt.block_on(self.client.get_npm_package_metadata(name))
                    }
                    UpstreamRoute::NpmDirect => {
                        self.rt.block_on(self.client.get_npm_metadata_direct(name))
                    }
                    UpstreamRoute::Custom { target, auth } => {
                        // Auth is origin-scoped and re-verified inside
                        // `get_npm_metadata_from` before attaching the header.
                        self.rt.block_on(self.client.get_npm_metadata_from(
                            &target.base_url,
                            name,
                            auth.as_ref(),
                        ))
                    }
                }
                .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;

                let mut info = parse_metadata_to_cache_info(&metadata);
                if info.needs_policy_metadata(&key, &self.policy) {
                    let full = self
                        .rt
                        .block_on(self.client.get_npm_metadata_routed_full(name, route))
                        .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;
                    info = parse_full_metadata_to_cache_info(&full);
                }
                tracing::debug!("npm package {name}: {} versions", info.versions.len());
                self.insert_and_notify(key, info);
                Ok(())
            }
        }
    }
}
