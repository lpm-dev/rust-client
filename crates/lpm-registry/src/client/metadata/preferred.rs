use super::*;
use serde::de::{DeserializeSeed, Error, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::borrow::Cow;

#[derive(serde::Serialize, serde::Deserialize)]
struct PreferredMetadata {
    metadata: PackageMetadata,
    versions_complete: bool,
}

impl PreferredMetadata {
    fn is_valid(&self, name: &str) -> bool {
        batch_metadata_entry_matches_name(name, &self.metadata)
            && (self.versions_complete
                || self.metadata.dist_tags.get("latest").is_some_and(|latest| {
                    self.metadata.versions.get(latest).is_some_and(|manifest| {
                        manifest.name == name && manifest.version == *latest
                    })
                }))
    }

    fn covers(&self, accepts: &impl Fn(&str) -> bool) -> bool {
        self.versions_complete
            || self
                .metadata
                .dist_tags
                .get("latest")
                .is_some_and(|latest| accepts(latest))
    }
}

#[derive(serde::Deserialize)]
struct Catalog<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default, rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
    #[serde(borrow, default)]
    versions: Option<&'a RawValue>,
}

struct PreferredVersions<'a> {
    latest: &'a str,
}

struct SelectedRecords<'a> {
    latest: Option<&'a RawValue>,
    newest_stable: Option<(String, &'a RawValue)>,
}

impl<'de> DeserializeSeed<'de> for PreferredVersions<'_> {
    type Value = SelectedRecords<'de>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for PreferredVersions<'_> {
    type Value = SelectedRecords<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("npm version records")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut latest = None;
        let mut newest: Option<(lpm_semver::Version, Cow<'de, str>, &'de RawValue)> = None;
        while let Some(version) = map.next_key_seed(super::version_selection::StringSeed)? {
            let record = map.next_value::<&RawValue>()?;
            if version == self.latest {
                latest = Some(record);
            }
            if let Ok(parsed) = lpm_semver::Version::parse(&version)
                && !parsed.is_prerelease()
                && newest
                    .as_ref()
                    .is_none_or(|(current, _, _)| &parsed >= current)
            {
                newest = Some((parsed, version, record));
            }
        }
        Ok(SelectedRecords {
            latest,
            newest_stable: newest.map(|(_, name, record)| (name.into_owned(), record)),
        })
    }
}

fn parse_preferred(
    bytes: &[u8],
    name: &str,
    accepts: &impl Fn(&str) -> bool,
) -> Result<PreferredMetadata, serde_json::Error> {
    let catalog: Catalog<'_> = serde_json::from_slice(bytes)?;
    if catalog.name != name {
        return Err(serde_json::Error::custom(
            "package history identity does not match request",
        ));
    }
    let full = || {
        let metadata: PackageMetadata = serde_json::from_slice(bytes)?;
        if !batch_metadata_entry_matches_name(name, &metadata) {
            return Err(serde_json::Error::custom(
                "package history identity does not match request",
            ));
        }
        Ok(PreferredMetadata {
            metadata,
            versions_complete: true,
        })
    };
    let Some(latest) = catalog
        .dist_tags
        .get("latest")
        .filter(|latest| accepts(latest))
    else {
        return full();
    };
    let Some(records) = catalog.versions else {
        return full();
    };
    let mut deserializer = serde_json::Deserializer::from_str(records.get());
    let selected = PreferredVersions { latest }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    let Some(latest_record) = selected.latest else {
        return full();
    };
    let mut versions = HashMap::with_capacity(2);
    for (version, record) in std::iter::once((latest.clone(), latest_record)).chain(
        selected
            .newest_stable
            .filter(|(version, _)| version != latest),
    ) {
        let manifest: VersionMetadata = serde_json::from_str(record.get())?;
        if manifest.name != name || manifest.version != version {
            return full();
        }
        versions.insert(version, manifest);
    }
    Ok(PreferredMetadata {
        metadata: PackageMetadata {
            name: name.to_owned(),
            description: None,
            modified: catalog.modified,
            dist_tags: catalog.dist_tags,
            versions,
            time: HashMap::new(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        },
        versions_complete: false,
    })
}

impl RegistryClient {
    pub(in crate::client) fn npm_preferred_metadata_cache_key(&self, name: &str) -> String {
        self.metadata_cache_key_for_origin(
            "npm-direct-preferred",
            &self.npm_registry_url,
            name,
            None,
        )
    }

    /// Return preferred manifests with explicit completeness, or complete history when the
    /// preference cannot satisfy the caller. Complete-history consumers use the ordinary API.
    pub async fn get_npm_preferred_metadata_direct_with_timings<F>(
        &self,
        name: &str,
        accepts: F,
    ) -> Result<(TimedPackageMetadata, bool), LpmError>
    where
        F: Fn(&str) -> bool + Send + 'static,
    {
        let cache_key = self.npm_preferred_metadata_cache_key(name);
        let mut timings = PackageMetadataFetchTimings::default();
        crate::timing::record_metadata_request(name);
        let read_start = std::time::Instant::now();
        if let Some(cached) = self
            .read_metadata_cache_entry_as_async::<PreferredMetadata>(&cache_key)
            .await
            && cached.value.is_valid(name)
        {
            if cached.value.covers(&accepts) {
                timings.cache_read_ms = read_start.elapsed().as_millis();
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                return Ok((
                    TimedPackageMetadata {
                        metadata: cached.value.metadata,
                        timings,
                    },
                    cached.value.versions_complete,
                ));
            }
            let cache_read_ms = read_start.elapsed().as_millis();
            let mut complete = self.get_npm_metadata_direct_with_timings(name).await?;
            complete.timings.cache_read_ms += cache_read_ms;
            self.invalidate_metadata_cache_key(&cache_key);
            return Ok((complete, true));
        }
        let complete_key = self.npm_direct_metadata_cache_key(name);
        if let Some(cached) = self.read_metadata_cache_async(&complete_key).await
            && batch_metadata_entry_matches_name(name, &cached.0)
        {
            timings.cache_read_ms = read_start.elapsed().as_millis();
            timings.cache_hit = true;
            crate::timing::record_metadata_cache_hit();
            return Ok((
                TimedPackageMetadata {
                    metadata: cached.0,
                    timings,
                },
                true,
            ));
        }
        timings.cache_read_ms = read_start.elapsed().as_millis();
        crate::timing::record_metadata_cache_miss();
        let _flight = metadata_fetch_flight_guard(&cache_key).await;
        let coalesced_start = std::time::Instant::now();
        if let Some(cached) = self
            .read_metadata_cache_entry_as_async::<PreferredMetadata>(&cache_key)
            .await
            && cached.value.is_valid(name)
            && cached.value.covers(&accepts)
        {
            timings.cache_hit = true;
            timings.cache_read_ms += coalesced_start.elapsed().as_millis();
            return Ok((
                TimedPackageMetadata {
                    metadata: cached.value.metadata,
                    timings,
                },
                cached.value.versions_complete,
            ));
        }
        if let Some(cached) = self.read_metadata_cache_async(&complete_key).await
            && batch_metadata_entry_matches_name(name, &cached.0)
        {
            timings.cache_hit = true;
            timings.cache_read_ms += coalesced_start.elapsed().as_millis();
            return Ok((
                TimedPackageMetadata {
                    metadata: cached.0,
                    timings,
                },
                true,
            ));
        }
        timings.cache_read_ms += coalesced_start.elapsed().as_millis();
        let validator_start = std::time::Instant::now();
        let validator = self.read_cache_validator(&cache_key);
        timings.validator_read_ms = validator_start.elapsed().as_millis();
        let url = format!("{}/{name}", self.npm_registry_url);
        let rpc_start = std::time::Instant::now();
        let result = async {
            let request = self
                .http
                .for_url(&url)
                .await?
                .get(&url)
                .header("Accept", "application/vnd.npm.install-v1+json");
            let request = Self::apply_cached_etag(request, validator.as_ref());
            let http_start = std::time::Instant::now();
            let mut response = self.send_package_metadata_request(request).await?;
            timings.http_ms = http_start.elapsed().as_millis();
            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                let cache_start = std::time::Instant::now();
                if let Some(cached) = self
                    .cached_metadata_after_304_as::<PreferredMetadata, _>(
                        &cache_key,
                        &response,
                        validator.as_ref(),
                        |cached| cached.is_valid(name) && cached.covers(&accepts),
                    )
                    .await
                {
                    timings.not_modified = true;
                    timings.cache_after_304_ms = cache_start.elapsed().as_millis();
                    if Self::metadata_cache_directive(response.headers())
                        == super::super::cache::MetadataCacheDirective::NoStore
                    {
                        self.invalidate_metadata_cache_key(&complete_key);
                    }
                    return Ok((
                        TimedPackageMetadata {
                            metadata: cached.value.metadata,
                            timings,
                        },
                        cached.value.versions_complete,
                    ));
                }
                timings.cache_after_304_ms = cache_start.elapsed().as_millis();
                let request = self
                    .http
                    .for_url(&url)
                    .await?
                    .get(&url)
                    .header("Accept", "application/vnd.npm.install-v1+json");
                let http_start = std::time::Instant::now();
                response = self.send_package_metadata_request(request).await?;
                timings.http_ms += http_start.elapsed().as_millis();
            }
            let etag = Self::response_etag(&response);
            let directive = Self::metadata_cache_directive(response.headers());
            let selected_name = name.to_owned();
            let (selected, body) = super::super::body::parse_capped_metadata_with_timing_using(
                response,
                MAX_METADATA_BYTES,
                &format!("preferred npm history {name}"),
                move |bytes| parse_preferred(bytes, &selected_name, &accepts),
            )
            .await?;
            timings.body_read_ms = body.body_read_ms;
            timings.json_decode_ms = body.json_parse_ms;
            timings.body_bytes = body.body_bytes;
            let write_start = std::time::Instant::now();
            if directive == super::super::cache::MetadataCacheDirective::NoStore {
                self.write_metadata_cache_with_directive(&cache_key, &selected, None, directive);
                self.write_metadata_cache_with_directive(
                    &complete_key,
                    &selected.metadata,
                    None,
                    directive,
                );
            } else if selected.versions_complete {
                self.invalidate_metadata_cache_key(&cache_key);
                self.write_metadata_cache_with_directive(
                    &complete_key,
                    &selected.metadata,
                    etag.as_deref(),
                    directive,
                );
            } else {
                self.write_metadata_cache_with_directive(
                    &cache_key,
                    &selected,
                    etag.as_deref(),
                    directive,
                );
            }
            timings.cache_write_dispatch_ms = write_start.elapsed().as_millis();
            Ok((
                TimedPackageMetadata {
                    metadata: selected.metadata,
                    timings,
                },
                selected.versions_complete,
            ))
        }
        .await;
        crate::timing::record_rpc(rpc_start.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_projection_preserves_latest_preference_and_newest_stable_summary() {
        let body = br#"{"name":"pkg","versions":{"1.0.0":{"name":"pkg","version":"1.0.0"},"2.0.0":false,"3.0.0":{"name":"pkg","version":"3.0.0"},"4.0.0-beta.1":42},"dist-tags":{"latest":"1.0.0"}}"#;
        let selected = parse_preferred(body, "pkg", &|version| version == "1.0.0").unwrap();
        assert!(!selected.versions_complete);
        assert_eq!(selected.metadata.versions.len(), 2);
        assert!(selected.metadata.versions.contains_key("1.0.0"));
        assert!(selected.metadata.versions.contains_key("3.0.0"));
    }

    #[test]
    fn preferred_selection_preserves_order_independence_and_escaped_version_keys() {
        for records in [
            r#""1.0.0":{"name":"pkg","version":"1.0.0"},"\u0032.0.0":{"name":"pkg","version":"2.0.0"},"3.0.0":{"name":"pkg","version":"3.0.0"}"#,
            r#""3.0.0":{"name":"pkg","version":"3.0.0"},"\u0032.0.0":{"name":"pkg","version":"2.0.0"},"1.0.0":{"name":"pkg","version":"1.0.0"}"#,
        ] {
            let body = format!(
                r#"{{"name":"pkg","dist-tags":{{"latest":"2.0.0"}},"versions":{{{records}}}}}"#
            );
            let selected = parse_preferred(body.as_bytes(), "pkg", &|_| true).unwrap();
            assert!(!selected.versions_complete);
            assert_eq!(selected.metadata.versions.len(), 2);
            assert!(selected.metadata.versions.contains_key("2.0.0"));
            assert!(selected.metadata.versions.contains_key("3.0.0"));
        }
    }

    #[test]
    fn nonmatching_latest_reuses_the_body_as_complete_history() {
        let body = br#"{"name":"pkg","dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{"name":"pkg","version":"1.0.0"},"2.0.0":{"name":"pkg","version":"2.0.0"}}}"#;
        let selected = parse_preferred(body, "pkg", &|_| false).unwrap();
        assert!(selected.versions_complete);
        assert_eq!(selected.metadata.versions.len(), 2);
    }

    #[test]
    fn complete_fallback_rejects_mismatched_manifest_identity() {
        for tags in [r#"{"latest":"2.0.0"}"#, r#"{}"#] {
            let body = format!(
                r#"{{"name":"pkg","dist-tags":{tags},"versions":{{"1.0.0":{{"name":"other","version":"1.0.0"}}}}}}"#
            );
            assert!(parse_preferred(body.as_bytes(), "pkg", &|_| false).is_err());
        }
    }

    #[test]
    fn preferred_projection_accepts_empty_history_without_versions() {
        let parsed = parse_preferred(br#"{"name":"pkg"}"#, "pkg", &|_| true).unwrap();
        assert!(parsed.versions_complete);
        assert!(parsed.metadata.versions.is_empty());
    }
    async fn preferred_test_client(
        server: &wiremock::MockServer,
        cache: &std::path::Path,
    ) -> RegistryClient {
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.to_path_buf()))
            .with_synchronous_cache_writes(true)
    }

    fn history() -> serde_json::Value {
        serde_json::json!({"name":"pkg","dist-tags":{"latest":"2.0.0"},"versions":{
            "1.0.0":{"name":"pkg","version":"1.0.0"},
            "2.0.0":{"name":"pkg","version":"2.0.0"}
        }})
    }

    #[tokio::test]
    async fn complete_preference_fallback_coalesces_concurrent_requests() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(history())
                    .set_delay(std::time::Duration::from_millis(30)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let (first, second) = tokio::join!(
            client.get_npm_preferred_metadata_direct_with_timings("pkg", |_| false),
            client.get_npm_preferred_metadata_direct_with_timings("pkg", |_| false)
        );
        assert!(first.unwrap().1);
        assert!(second.unwrap().1);
        server.verify().await;
    }

    #[tokio::test]
    async fn no_store_complete_fallback_removes_the_preferred_validator() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(history())
                    .insert_header("Cache-Control", "no-store"),
            )
            .expect(2)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let key = client.npm_preferred_metadata_cache_key("pkg");
        let selected = parse_preferred(history().to_string().as_bytes(), "pkg", &|_| true).unwrap();
        client.write_metadata_cache_with_directive(
            &key,
            &selected,
            Some("\"old\""),
            super::super::super::cache::MetadataCacheDirective::Store {
                fresh_for: std::time::Duration::ZERO,
            },
        );
        assert!(client.read_cache_validator(&key).is_some());
        let (_, complete) = client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| false)
            .await
            .unwrap();
        assert!(complete);
        assert!(client.read_cache_validator(&key).is_none());
        assert!(
            client
                .read_cache_validator(&client.npm_direct_metadata_cache_key("pkg"))
                .is_none()
        );
        client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| false)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert!(!requests[1].headers.contains_key("if-none-match"));
    }

    #[tokio::test]
    async fn preferred_cache_is_private_to_partial_consumers_and_invalidated_with_package() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history()))
            .expect(3)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let (first, complete) = client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!complete);
        assert_eq!(first.metadata.versions.len(), 1);
        let (cached, _) = client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(cached.timings.cache_hit);
        assert_eq!(
            client
                .get_npm_metadata_direct("pkg")
                .await
                .unwrap()
                .versions
                .len(),
            2
        );
        client.invalidate_metadata_cache("pkg");
        let (refetched, _) = client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!refetched.timings.cache_hit);
    }

    #[tokio::test]
    async fn preferred_unusable_304_retries_without_claiming_revalidation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let calls = AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(move |_: &wiremock::Request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(304)
                } else {
                    ResponseTemplate::new(200).set_body_json(history())
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = preferred_test_client(&server, cache.path()).await;
        let (fetched, complete) = client
            .get_npm_preferred_metadata_direct_with_timings("pkg", |_| true)
            .await
            .unwrap();
        assert!(!complete);
        assert!(!fetched.timings.not_modified);
        assert!(fetched.timings.body_bytes > 0);
    }
}
