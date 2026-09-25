use super::*;
use crate::TimedPreferredMetadata;

enum Preference {
    History(Box<PreferredMetadata>),
    Latest(Box<VersionMetadata>),
}

/// How one known preference answers a ranged request.
enum Selection {
    Ready(Box<Selected>),
    CompleteHistory,
    History,
}

struct Selected {
    metadata: PackageMetadata,
    versions_complete: bool,
    platform_metadata_complete: bool,
}

impl Selected {
    fn with_timings(self, timings: PackageMetadataFetchTimings) -> TimedPreferredMetadata {
        TimedPreferredMetadata {
            fetched: TimedPackageMetadata {
                metadata: self.metadata,
                timings,
            },
            versions_complete: self.versions_complete,
            platform_metadata_complete: self.platform_metadata_complete,
        }
    }
}

fn select_preference(
    name: &str,
    preference: Preference,
    accepts: &impl Fn(&str) -> bool,
) -> Selection {
    match preference {
        Preference::History(selected) if selected.covers(accepts) => {
            Selection::Ready(Box::new(Selected {
                metadata: selected.metadata,
                versions_complete: selected.versions_complete,
                platform_metadata_complete: false,
            }))
        }
        Preference::History(_) => Selection::CompleteHistory,
        Preference::Latest(manifest) if accepts(&manifest.version) => {
            let version = manifest.version.clone();
            match package_metadata_from_version_doc(name, &version, *manifest) {
                Ok(mut metadata) => {
                    metadata.dist_tags.insert("latest".to_owned(), version);
                    Selection::Ready(Box::new(Selected {
                        metadata,
                        versions_complete: false,
                        platform_metadata_complete: true,
                    }))
                }
                Err(_) => Selection::History,
            }
        }
        Preference::Latest(_) => Selection::History,
    }
}

fn history_result(
    (fetched, versions_complete): (TimedPackageMetadata, bool),
) -> TimedPreferredMetadata {
    TimedPreferredMetadata {
        fetched,
        versions_complete,
        platform_metadata_complete: false,
    }
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
    pub(in crate::client) fn npm_latest_metadata_cache_key(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
    ) -> String {
        self.npm_access_cache_key("npm-direct-latest", name, access)
    }

    /// Resolve a ranged request from the smallest document that can answer it.
    ///
    /// Fresh history caches take precedence over cached latest documents. Without a
    /// usable cache, the latest document and the preferred history are requested
    /// together: a latest version inside the range answers the request and cancels
    /// the history transfer, while any other outcome continues with the history
    /// already in flight, so a miss never adds a sequential round trip. Partial
    /// documents never populate complete-history caches or provide
    /// publication-time authority.
    #[tracing::instrument(
        target = "lpm_install_timeline",
        level = "trace",
        name = "preferred_metadata",
        skip_all
    )]
    pub async fn get_npm_preferred_resolution_metadata_with_timings<F>(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
        accepts: F,
    ) -> Result<TimedPreferredMetadata, LpmError>
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        crate::timing::record_metadata_request(name);
        let mut timings = PackageMetadataFetchTimings::default();
        let latest_key = self.npm_latest_metadata_cache_key(name, access);
        let started = std::time::Instant::now();
        let cached = self.read_preference_cache(name, access, &latest_key).await;
        timings.cache_read_ms += started.elapsed().as_millis();
        match cached.map(|preference| select_preference(name, preference, &accepts)) {
            Some(Selection::Ready(selected)) => {
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                Ok(selected.with_timings(timings))
            }
            Some(Selection::CompleteHistory) => {
                let mut fetched = self
                    .get_npm_metadata_direct_inner(name, MetadataCachePolicy::UseFresh, access)
                    .await?;
                self.invalidate_metadata_cache_key(
                    &self.npm_preferred_metadata_cache_key(name, access),
                );
                fetched.timings.add_attempt(&timings);
                Ok(history_result((fetched, true)))
            }
            Some(Selection::History) => {
                crate::timing::record_metadata_cache_miss();
                self.fetch_npm_preferred_history::<_, true>(name, access, accepts, timings)
                    .await
                    .map(history_result)
            }
            None => {
                crate::timing::record_metadata_cache_miss();
                self.race_latest_and_history(name, access, &latest_key, accepts, timings)
                    .await
            }
        }
    }

    async fn race_latest_and_history<F>(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
        latest_key: &str,
        accepts: F,
        timings: PackageMetadataFetchTimings,
    ) -> Result<TimedPreferredMetadata, LpmError>
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let accepts = Arc::new(accepts);
        let history_accepts = Arc::clone(&accepts);
        let history = self.fetch_npm_preferred_history::<_, true>(
            name,
            access,
            move |version: &str| history_accepts(version),
            PackageMetadataFetchTimings::default(),
        );
        let latest = self.fetch_latest_leg(name, access, latest_key);
        tokio::pin!(history, latest);
        // Poll the latest leg first: a request queued behind another request's
        // history flight then answers from the shared latest document before it
        // sends a history request of its own.
        let (latest_result, latest_timings) = tokio::select! {
            biased;
            latest_outcome = &mut latest => latest_outcome,
            history_outcome = &mut history => {
                let history_error = match history_outcome {
                    Ok((mut fetched, versions_complete)) => {
                        fetched.timings.add_attempt(&timings);
                        return Ok(history_result((fetched, versions_complete)));
                    }
                    Err(error) => error,
                };
                let (latest_result, mut latest_timings) = latest.await;
                latest_timings.add_attempt(&timings);
                return match latest_result
                    .map(|preference| select_preference(name, preference, &*accepts))
                {
                    Ok(Selection::Ready(selected)) => Ok(selected.with_timings(latest_timings)),
                    _ => Err(history_error),
                };
            }
        };
        if let Ok(preference) = latest_result
            && let Selection::Ready(selected) = select_preference(name, preference, &*accepts)
        {
            let mut answer = latest_timings;
            answer.add_attempt(&timings);
            return Ok(selected.with_timings(answer));
        }
        let (mut fetched, versions_complete) = history.await?;
        fetched.timings.add_concurrent_attempt(&latest_timings);
        fetched.timings.add_attempt(&timings);
        Ok(history_result((fetched, versions_complete)))
    }

    async fn read_preference_cache(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
        latest_key: &str,
    ) -> Option<Preference> {
        let key = self.npm_preferred_metadata_cache_key(name, access);
        if let Some(cached) = self.read_preferred_cache_for_use::<true>(&key).await
            && cached.value.is_valid(name)
        {
            return Some(Preference::History(Box::new(cached.value)));
        }
        let key = self.npm_direct_metadata_cache_key(name, access);
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

    /// Fetch the latest document after the caller found no usable cache. The flight
    /// re-checks every preference cache so concurrent requests share one response.
    async fn fetch_latest_leg(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
        key: &str,
    ) -> (Result<Preference, LpmError>, PackageMetadataFetchTimings) {
        let mut timings = PackageMetadataFetchTimings::default();
        let _flight = self.history_cache.flight(key).await;
        let (generation, _) = self.history_cache.lookup(key);
        let started = std::time::Instant::now();
        let cached = self.read_preference_cache(name, access, key).await;
        timings.cache_read_ms += started.elapsed().as_millis();
        if let Some(cached) = cached {
            timings.cache_hit = true;
            return (Ok(cached), timings);
        }
        let rpc_start = std::time::Instant::now();
        let result = self
            .fetch_latest_document(name, access, key, generation, &mut timings)
            .await;
        crate::timing::record_rpc(rpc_start.elapsed());
        (
            result.map(|manifest| Preference::Latest(Box::new(manifest))),
            timings,
        )
    }

    async fn fetch_latest_document(
        &self,
        name: &str,
        access: PublicNpmAccess<'_>,
        key: &str,
        generation: u64,
        timings: &mut PackageMetadataFetchTimings,
    ) -> Result<VersionMetadata, LpmError> {
        let started = std::time::Instant::now();
        let validator = self.read_cache_validator(key);
        timings.validator_read_ms += started.elapsed().as_millis();
        let url = format!("{}/{name}/latest", self.npm_registry_url);
        let request = self
            .npm_registry_get(&url, "application/json", access)
            .await?;
        let request = Self::apply_cached_etag(request, validator.as_ref());
        let started = std::time::Instant::now();
        let result = self
            .send_package_metadata_request_with_npmrc_auth(request, access.auth())
            .await;
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
                .npm_registry_get(&url, "application/json", access)
                .await?;
            let started = std::time::Instant::now();
            let result = self
                .send_package_metadata_request_with_npmrc_auth(request, access.auth())
                .await;
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
