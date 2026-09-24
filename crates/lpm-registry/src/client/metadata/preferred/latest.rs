use super::*;
use crate::TimedPreferredMetadata;

enum Preference {
    History(Box<PreferredMetadata>),
    Latest(Box<VersionMetadata>),
}

fn valid_latest(name: &str, manifest: &VersionMetadata) -> bool {
    if manifest.name != name || lpm_semver::Version::parse(&manifest.version).is_err() {
        return false;
    }
    let Some(dist) = &manifest.dist else {
        return false;
    };
    let valid_url = dist.tarball.as_deref().is_some_and(|value| {
        reqwest::Url::parse(value)
            .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
    });
    let valid_integrity = match dist.integrity.as_deref() {
        Some(value) => lpm_common::Integrity::parse(value).is_ok(),
        None => dist.shasum.as_deref().is_some_and(|value| {
            value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
    };
    valid_url && valid_integrity
}

impl RegistryClient {
    pub(in crate::client) fn npm_latest_metadata_cache_key(&self, name: &str) -> String {
        self.metadata_cache_key_for_origin("npm-direct-latest", &self.npm_registry_url, name, None)
    }

    /// Prefer a full latest-version document when it satisfies the range.
    /// Fresh history caches take precedence; partial documents never populate
    /// complete-history caches or provide publication-time authority.
    pub async fn get_npm_preferred_resolution_metadata_with_timings<F>(
        &self,
        name: &str,
        accepts: F,
    ) -> Result<TimedPreferredMetadata, LpmError>
    where
        F: Fn(&str) -> bool + Send + 'static,
    {
        crate::timing::record_metadata_request(name);
        let mut timings = PackageMetadataFetchTimings::default();
        let preference = self.fetch_latest_preference(name, &mut timings).await;
        let force_complete = match preference {
            Ok(Preference::History(selected)) if selected.covers(&accepts) => {
                return Ok(TimedPreferredMetadata {
                    fetched: TimedPackageMetadata {
                        metadata: selected.metadata,
                        timings,
                    },
                    versions_complete: selected.versions_complete,
                    platform_metadata_complete: false,
                });
            }
            Ok(Preference::History(_)) => true,
            Ok(Preference::Latest(manifest)) if accepts(&manifest.version) => {
                let version = manifest.version.clone();
                let mut metadata = package_metadata_from_version_doc(name, &version, *manifest)?;
                metadata.dist_tags.insert("latest".to_owned(), version);
                return Ok(TimedPreferredMetadata {
                    fetched: TimedPackageMetadata { metadata, timings },
                    versions_complete: false,
                    platform_metadata_complete: true,
                });
            }
            Ok(Preference::Latest(_)) | Err(_) => false,
        };
        // The latest flight ends before entering either history flight.
        let (mut fetched, versions_complete) = if force_complete {
            let fetched = self.get_npm_metadata_direct_with_timings(name).await?;
            self.invalidate_metadata_cache_key(&self.npm_preferred_metadata_cache_key(name));
            (fetched, true)
        } else {
            self.get_npm_preferred_metadata_with_cache_fields::<_, true>(name, accepts)
                .await?
        };
        fetched.timings.add_attempt(&timings);
        Ok(TimedPreferredMetadata {
            fetched,
            versions_complete,
            platform_metadata_complete: false,
        })
    }

    async fn read_preference_cache(&self, name: &str, latest_key: &str) -> Option<Preference> {
        let key = self.npm_preferred_metadata_cache_key(name);
        if let Some(cached) = self.read_preferred_cache_for_use::<true>(&key).await
            && cached.value.is_valid(name)
        {
            return Some(Preference::History(Box::new(cached.value)));
        }
        let key = self.npm_direct_metadata_cache_key(name);
        if let Some((metadata, _)) = self.read_complete_cache_for_use::<true>(&key).await
            && batch_metadata_entry_matches_name(name, &metadata)
        {
            return Some(Preference::History(Box::new(PreferredMetadata {
                metadata,
                versions_complete: true,
            })));
        }
        if let Some(cached) = self.history_cache.lookup(latest_key).1 {
            let body = Arc::clone(&cached.body);
            let parse = move || {
                serde_json::from_slice::<VersionMetadata>(lpm_common::strip_utf8_bom_bytes(
                    body.bytes(),
                ))
            };
            let manifest = if cached.body.bytes().len()
                < crate::client::body::BLOCKING_METADATA_PARSE_THRESHOLD
            {
                parse().ok()
            } else {
                tokio::task::spawn_blocking(parse)
                    .await
                    .ok()
                    .and_then(Result::ok)
            };
            if let Some(manifest) = manifest.filter(|manifest| valid_latest(name, manifest)) {
                return Some(Preference::Latest(Box::new(manifest)));
            }
        }
        let cached = self
            .read_metadata_cache_entry_as_async::<VersionMetadata>(latest_key)
            .await?;
        valid_latest(name, &cached.value).then_some(Preference::Latest(Box::new(cached.value)))
    }

    async fn fetch_latest_preference(
        &self,
        name: &str,
        timings: &mut PackageMetadataFetchTimings,
    ) -> Result<Preference, LpmError> {
        let key = self.npm_latest_metadata_cache_key(name);
        let started = std::time::Instant::now();
        let cached = self.read_preference_cache(name, &key).await;
        timings.cache_read_ms += started.elapsed().as_millis();
        if let Some(cached) = cached {
            timings.cache_hit = true;
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();
        let _flight = self.history_cache.flight(&key).await;
        let (generation, _) = self.history_cache.lookup(&key);
        let started = std::time::Instant::now();
        let cached = self.read_preference_cache(name, &key).await;
        timings.cache_read_ms += started.elapsed().as_millis();
        if let Some(cached) = cached {
            timings.cache_hit = true;
            return Ok(cached);
        }
        let rpc_start = std::time::Instant::now();
        let result = self
            .fetch_latest_document(name, &key, generation, timings)
            .await;
        crate::timing::record_rpc(rpc_start.elapsed());
        result.map(|manifest| Preference::Latest(Box::new(manifest)))
    }

    async fn fetch_latest_document(
        &self,
        name: &str,
        key: &str,
        generation: u64,
        timings: &mut PackageMetadataFetchTimings,
    ) -> Result<VersionMetadata, LpmError> {
        let started = std::time::Instant::now();
        let validator = self.read_cache_validator(key);
        timings.validator_read_ms += started.elapsed().as_millis();
        let url = format!("{}/{name}/latest", self.npm_registry_url);
        let request = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/json");
        let request = Self::apply_cached_etag(request, validator.as_ref());
        let started = std::time::Instant::now();
        let result = self.send_package_metadata_request(request).await;
        timings.http_ms += started.elapsed().as_millis();
        let mut response = result?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let started = std::time::Instant::now();
            let cached = self
                .cached_metadata_after_304_at_generation::<VersionMetadata, _>(
                    key,
                    &response,
                    validator.as_ref(),
                    |manifest| valid_latest(name, manifest),
                    Some(generation),
                )
                .await;
            timings.cache_after_304_ms += started.elapsed().as_millis();
            if let Some(cached) = cached {
                timings.not_modified = true;
                let expires_at = std::time::Instant::now() + cached.remaining_freshness;
                if !cached.remaining_freshness.is_zero() {
                    let history_cache = Arc::clone(&self.history_cache);
                    let (cached, body) = tokio::task::spawn_blocking(move || {
                        let body = history_cache.retain_json(&cached.value);
                        (cached, body)
                    })
                    .await
                    .map_err(|error| {
                        LpmError::Registry(format!("latest revalidation task failed: {error}"))
                    })?;
                    if let Some(body) = body {
                        self.history_cache.insert(
                            key.to_owned(),
                            generation,
                            crate::client::history_cache::HistoryEntry {
                                body,
                                expires_at,
                                etag: None,
                            },
                        );
                    }
                    return Ok(cached.value);
                }
                return Ok(cached.value);
            }
            let request = self
                .http
                .for_url(&url)
                .await?
                .get(&url)
                .header("Accept", "application/json");
            let started = std::time::Instant::now();
            let result = self.send_package_metadata_request(request).await;
            timings.http_ms += started.elapsed().as_millis();
            response = result?;
        }
        let etag = Self::response_etag(&response);
        let directive = Self::metadata_cache_directive(response.headers());
        let expires_at = directive
            .local_freshness()
            .filter(|fresh_for| !fresh_for.is_zero())
            .map(|fresh_for| std::time::Instant::now() + fresh_for);
        let history_cache = expires_at.map(|_| Arc::clone(&self.history_cache));
        let (parsed, body) = crate::client::body::parse_capped_metadata_owned_attempt(
            response,
            MAX_VERSION_METADATA_BYTES,
            &format!("latest npm document {name}"),
            move |bytes| {
                let manifest = serde_json::from_slice::<VersionMetadata>(
                    lpm_common::strip_utf8_bom_bytes(&bytes),
                )?;
                let body = history_cache.and_then(|cache| cache.retain_compact(bytes));
                Ok((manifest, body))
            },
        )
        .await;
        timings.body_read_ms += body.body_read_ms;
        timings.json_decode_ms += body.json_parse_ms;
        timings.body_bytes += body.body_bytes;
        let (manifest, body) = parsed?;
        if !valid_latest(name, &manifest) {
            return Err(LpmError::Registry(format!(
                "latest npm document has an invalid package binding for {name}"
            )));
        }
        if let (Some(body), Some(expires_at)) = (body, expires_at) {
            self.history_cache.insert(
                key.to_owned(),
                generation,
                crate::client::history_cache::HistoryEntry {
                    body,
                    expires_at,
                    etag: None,
                },
            );
        }
        let started = std::time::Instant::now();
        self.history_cache.with_generation(generation, || {
            self.write_metadata_cache_with_directive(key, &manifest, etag.as_deref(), directive);
        });
        timings.cache_write_dispatch_ms += started.elapsed().as_millis();
        Ok(manifest)
    }
}
