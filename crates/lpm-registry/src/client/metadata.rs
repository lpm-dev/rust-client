use super::*;

#[derive(serde::Deserialize)]
struct NdjsonBatchEntry {
    name: String,
    metadata: PackageMetadata,
}

struct NdjsonBatchEntryStream {
    response: reqwest::Response,
    cache_entries: bool,
    buffer: Vec<u8>,
    scan_from: usize,
    bytes_read: u64,
    chunks_read: u64,
    json_parse_ns: u128,
    cache_write_ns: u128,
    received: usize,
    finished: bool,
    finish_logged: bool,
}

impl NdjsonBatchEntryStream {
    fn new(response: reqwest::Response, cache_entries: bool) -> Result<Self, LpmError> {
        if let Some(declared) = response.content_length()
            && declared as usize > MAX_METADATA_BYTES
        {
            return Err(LpmError::Registry(format!(
                "NDJSON batch: declared body length {declared} exceeds cap {MAX_METADATA_BYTES}"
            )));
        }
        Ok(Self {
            response,
            cache_entries,
            buffer: Vec::new(),
            scan_from: 0,
            bytes_read: 0,
            chunks_read: 0,
            json_parse_ns: 0,
            cache_write_ns: 0,
            received: 0,
            finished: false,
            finish_logged: false,
        })
    }

    async fn next(
        &mut self,
        client: &RegistryClient,
    ) -> Result<Option<(String, PackageMetadata)>, LpmError> {
        loop {
            if let Some(entry) = self.next_buffered_entry(client)? {
                return Ok(Some(entry));
            }
            if self.finished {
                self.record_finished();
                return Ok(None);
            }
            match self.response.chunk().await {
                Ok(None) => {
                    self.finished = true;
                    self.scan_from = 0;
                }
                Ok(Some(chunk)) => {
                    self.chunks_read += 1;
                    self.bytes_read += chunk.len() as u64;
                    if (self.bytes_read as usize) > MAX_METADATA_BYTES {
                        return Err(LpmError::Registry(format!(
                            "NDJSON batch: streamed body exceeded cap {MAX_METADATA_BYTES} \
                             (after {} chunks)",
                            self.chunks_read
                        )));
                    }
                    self.buffer.extend_from_slice(&chunk);
                }
                Err(e) => {
                    let chain: Vec<String> =
                        std::iter::successors(Some(&e as &dyn std::error::Error), |e| e.source())
                            .map(|e| e.to_string())
                            .collect();
                    return Err(LpmError::Registry(format!(
                        "NDJSON read error after {} chunks / {} bytes (parse: {:.1}ms, cache_write: {:.1}ms): {} cause(s): {}",
                        self.chunks_read,
                        self.bytes_read,
                        self.json_parse_ns as f64 / 1_000_000.0,
                        self.cache_write_ns as f64 / 1_000_000.0,
                        chain.len(),
                        chain.join(" <- "),
                    )));
                }
            }
        }
    }

    fn next_buffered_entry(
        &mut self,
        client: &RegistryClient,
    ) -> Result<Option<(String, PackageMetadata)>, LpmError> {
        loop {
            if self.finished {
                if !self.buffer.iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Ok(None);
                }
                let line_bytes = std::mem::take(&mut self.buffer);
                let line = match std::str::from_utf8(&line_bytes) {
                    Ok(line) => line,
                    Err(_) => return Ok(None),
                };
                return Ok(self.parse_entry_line(client, line));
            }

            let search_slice = &self.buffer[self.scan_from..];
            let Some(rel_pos) = search_slice.iter().position(|&b| b == b'\n') else {
                self.scan_from = self.buffer.len();
                return Ok(None);
            };
            let newline_pos = self.scan_from + rel_pos;
            let line = std::str::from_utf8(&self.buffer[..newline_pos])
                .map_err(|e| LpmError::Registry(format!("NDJSON UTF-8 error: {e}")))?
                .to_string();
            self.buffer.drain(..newline_pos + 1);
            self.scan_from = 0;
            if line.is_empty() {
                continue;
            }
            if let Some(entry) = self.parse_entry_line(client, &line) {
                return Ok(Some(entry));
            }
        }
    }

    fn parse_entry_line(
        &mut self,
        client: &RegistryClient,
        line: &str,
    ) -> Option<(String, PackageMetadata)> {
        let parse_start = std::time::Instant::now();
        let parsed: Option<NdjsonBatchEntry> = serde_json::from_str(line).ok();
        let parse_elapsed = parse_start.elapsed();
        self.json_parse_ns += parse_elapsed.as_nanos();
        crate::timing::record_parse(parse_elapsed);

        let entry = parsed?;
        let name = entry.name;
        let meta = entry.metadata;
        if !batch_metadata_entry_matches_name(&name, &meta) {
            tracing::debug!(
                "skipping NDJSON metadata entry with mismatched package name: requested {name}, metadata {}",
                meta.name
            );
            return None;
        }

        if self.cache_entries {
            let cache_key = client.batch_metadata_cache_key(&name);
            let write_start = std::time::Instant::now();
            client.write_metadata_cache(&cache_key, &meta, None);
            self.cache_write_ns += write_start.elapsed().as_nanos();
        }
        self.received += 1;
        Some((name, meta))
    }

    fn record_finished(&mut self) {
        if self.finish_logged {
            return;
        }
        self.finish_logged = true;
        tracing::debug!(
            "batch metadata (NDJSON): received {} — json_parse: {:.2}ms, cache_write: {:.2}ms",
            self.received,
            self.json_parse_ns as f64 / 1_000_000.0,
            self.cache_write_ns as f64 / 1_000_000.0,
        );
    }
}

/// Incremental view over a Worker batch metadata response.
///
/// For NDJSON responses, each call to [`Self::next`] reads only as far as the
/// next complete metadata entry. JSON fallback responses are parsed eagerly and
/// then yielded from memory.
pub struct BatchMetadataEntryStream<'a> {
    client: &'a RegistryClient,
    inner: BatchMetadataEntryStreamInner,
    rpc_start: std::time::Instant,
    rpc_recorded: bool,
}

enum BatchMetadataEntryStreamInner {
    Ndjson(Box<NdjsonBatchEntryStream>),
    Json(std::vec::IntoIter<(String, PackageMetadata)>),
}

impl BatchMetadataEntryStream<'_> {
    pub async fn next(&mut self) -> Result<Option<(String, PackageMetadata)>, LpmError> {
        let client = self.client;
        let result = match &mut self.inner {
            BatchMetadataEntryStreamInner::Ndjson(stream) => stream.next(client).await,
            BatchMetadataEntryStreamInner::Json(entries) => Ok(entries.next()),
        };
        match result {
            Ok(None) => {
                self.record_rpc_once();
                Ok(None)
            }
            Ok(Some(entry)) => Ok(Some(entry)),
            Err(error) => {
                self.record_rpc_once();
                Err(error)
            }
        }
    }

    fn ndjson(
        client: &RegistryClient,
        response: reqwest::Response,
        rpc_start: std::time::Instant,
        cache_entries: bool,
    ) -> Result<BatchMetadataEntryStream<'_>, LpmError> {
        Ok(BatchMetadataEntryStream {
            client,
            inner: BatchMetadataEntryStreamInner::Ndjson(Box::new(NdjsonBatchEntryStream::new(
                response,
                cache_entries,
            )?)),
            rpc_start,
            rpc_recorded: false,
        })
    }

    fn json(
        client: &RegistryClient,
        entries: std::vec::IntoIter<(String, PackageMetadata)>,
        rpc_start: std::time::Instant,
    ) -> BatchMetadataEntryStream<'_> {
        BatchMetadataEntryStream {
            client,
            inner: BatchMetadataEntryStreamInner::Json(entries),
            rpc_start,
            rpc_recorded: false,
        }
    }

    fn record_rpc_once(&mut self) {
        if self.rpc_recorded {
            return;
        }
        crate::timing::record_rpc(self.rpc_start.elapsed());
        self.rpc_recorded = true;
    }
}

impl Drop for BatchMetadataEntryStream<'_> {
    fn drop(&mut self) {
        self.record_rpc_once();
    }
}

fn batch_metadata_entry_matches_name(name: &str, meta: &PackageMetadata) -> bool {
    meta.name == name || meta.versions.values().any(|version| version.name == name)
}

fn merge_batch_package_metadata(existing: &mut PackageMetadata, incoming: PackageMetadata) {
    let incoming_latest_version = incoming.latest_version;
    existing.description = incoming.description.or_else(|| existing.description.take());
    existing.modified = incoming.modified.or_else(|| existing.modified.take());
    existing.downloads = incoming.downloads.or(existing.downloads);
    existing.distribution_mode = incoming
        .distribution_mode
        .or_else(|| existing.distribution_mode.take());
    existing.package_type = incoming
        .package_type
        .or_else(|| existing.package_type.take());
    existing.ecosystem = incoming.ecosystem.or_else(|| existing.ecosystem.take());
    existing.dist_tags.extend(incoming.dist_tags);
    existing.versions.extend(incoming.versions);
    existing.time.extend(incoming.time);

    if let Some(latest) = highest_metadata_version(&existing.versions) {
        existing
            .dist_tags
            .insert("latest".to_string(), latest.clone());
        existing.latest_version = Some(latest);
    } else if existing.latest_version.is_none() {
        existing.latest_version = incoming_latest_version;
    }
}

fn highest_metadata_version(
    versions: &std::collections::HashMap<String, VersionMetadata>,
) -> Option<String> {
    versions
        .keys()
        .filter_map(|version| {
            lpm_semver::Version::parse(version)
                .ok()
                .map(|parsed| (parsed, version))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, version)| version.clone())
}

impl RegistryClient {
    fn batch_metadata_cache_key(&self, name: &str) -> String {
        if name.starts_with("@lpm.dev/") {
            self.lpm_metadata_cache_key(name)
        } else {
            self.npm_worker_metadata_cache_key(name)
        }
    }

    pub(super) fn apply_worker_metadata_http_version(
        &self,
        req: reqwest::RequestBuilder,
        url: &str,
    ) -> reqwest::RequestBuilder {
        if !self.should_try_worker_metadata_http3(url) {
            return req;
        }
        Self::apply_http3_request_version(req)
    }

    fn should_try_worker_metadata_http3(&self, url: &str) -> bool {
        if !self.worker_metadata_http3_enabled {
            return false;
        }
        if self.base_url_origin != DEFAULT_REGISTRY_URL {
            return false;
        }
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        parsed.scheme() == "https" && parsed.origin().ascii_serialization() == DEFAULT_REGISTRY_URL
    }

    async fn worker_metadata_http3_client_for(
        &self,
        url: &str,
    ) -> Result<Option<reqwest::Client>, LpmError> {
        if !self.should_try_worker_metadata_http3(url) {
            return Ok(None);
        }
        #[cfg(feature = "experimental-http3")]
        {
            let mut guard = self.worker_metadata_http3_client.lock().await;
            if let Some(client) = guard.as_ref() {
                return Ok(Some(client.clone()));
            }
            let client =
                Self::build_worker_metadata_http3_client_with_tls(&self.http.tls_overrides)?;
            *guard = Some(client.clone());
            Ok(Some(client))
        }
        #[cfg(not(feature = "experimental-http3"))]
        {
            Ok(None)
        }
    }

    #[cfg(feature = "experimental-http3")]
    fn apply_http3_request_version(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.version(reqwest::Version::HTTP_3)
    }

    #[cfg(not(feature = "experimental-http3"))]
    fn apply_http3_request_version(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req
    }

    pub(super) async fn build_worker_metadata_get(
        &self,
        url: &str,
    ) -> Result<reqwest::RequestBuilder, LpmError> {
        if let Some(client) = self.worker_metadata_http3_client_for(url).await? {
            let mut req = client.get(url);
            if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
                req = req.bearer_auth(bearer);
            }
            return Ok(Self::apply_http3_request_version(req));
        }
        let req = self.build_get(url).await?;
        Ok(self.apply_worker_metadata_http_version(req, url))
    }

    async fn build_worker_metadata_post(
        &self,
        url: &str,
    ) -> Result<reqwest::RequestBuilder, LpmError> {
        if let Some(client) = self.worker_metadata_http3_client_for(url).await? {
            return Ok(Self::apply_http3_request_version(client.post(url)));
        }
        Ok(self.http.for_url(url).await?.post(url))
    }

    fn apply_cached_etag(
        req: reqwest::RequestBuilder,
        cache_validator: Option<&CacheValidator>,
    ) -> reqwest::RequestBuilder {
        if let Some(etag) = cache_validator.and_then(|validator| validator.etag.as_deref()) {
            req.header("If-None-Match", etag)
        } else {
            req
        }
    }

    fn response_etag(response: &reqwest::Response) -> Option<String> {
        response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    fn validate_release_time_metadata(
        name: &str,
        metadata: ReleaseTimeMetadata,
    ) -> Result<ReleaseTimeMetadata, LpmError> {
        if metadata.matches_package(name) {
            return Ok(metadata);
        }
        Err(LpmError::Registry(format!(
            "registry returned release times for unexpected package '{}' when requesting '{name}'",
            metadata.name.as_deref().unwrap_or("<missing>")
        )))
    }

    async fn cached_release_times_from_metadata_cache(
        &self,
        name: &str,
        metadata_cache_key: &str,
    ) -> Option<ReleaseTimeMetadata> {
        let (cached, _etag) = self
            .read_metadata_cache_as_async::<ReleaseTimeMetadata>(metadata_cache_key)
            .await?;
        (cached.matches_package(name) && !cached.time.is_empty()).then_some(cached)
    }

    async fn send_package_metadata_request(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, LpmError> {
        let request = request_builder
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build request: {e}")))?;
        let attempted_worker_http3 = request.version() == reqwest::Version::HTTP_3;
        let fallback_request = Self::worker_metadata_http3_fallback_request(&request)?;
        let client_override = if attempted_worker_http3 {
            self.worker_metadata_http3_client.lock().await.clone()
        } else {
            None
        };
        let response = match self.send_request_with_retry(request, client_override).await {
            Ok(response) => response,
            Err(error)
                if attempted_worker_http3
                    && Self::worker_metadata_http3_should_fallback(&error) =>
            {
                let Some(fallback_request) = fallback_request else {
                    return Err(error);
                };
                tracing::debug!("Worker metadata HTTP/3 failed; retrying with default transport");
                self.send_request_with_retry(fallback_request, None).await?
            }
            Err(error) => return Err(error),
        };
        crate::timing::record_metadata_http_version(response.version());
        Ok(response)
    }

    pub(super) fn worker_metadata_http3_should_fallback(error: &LpmError) -> bool {
        matches!(error, LpmError::Network(_))
    }

    pub(super) fn worker_metadata_http3_fallback_request(
        request: &reqwest::Request,
    ) -> Result<Option<reqwest::Request>, LpmError> {
        if request.version() != reqwest::Version::HTTP_3 {
            return Ok(None);
        }
        let mut fallback = request.try_clone().ok_or_else(|| {
            LpmError::Network("request body cannot be retried (not cloneable)".into())
        })?;
        *fallback.version_mut() = reqwest::Version::default();
        Ok(Some(fallback))
    }

    fn npm_proxy_can_fallback_to_direct(error: &LpmError) -> bool {
        matches!(
            error,
            LpmError::AuthRequired | LpmError::UpstreamProxyEntitlementRequired { .. }
        )
    }

    async fn cached_metadata_after_304_as<T>(&self, cache_key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        let path = self.cache_path(cache_key)?;
        tokio::task::spawn_blocking(move || {
            let content = Self::read_cache_content_path(&path)?;
            let meta = Self::deserialize_cached_metadata_as::<T>(&content.data)?;
            let _ = filetime::set_file_mtime(&path, filetime::FileTime::now());
            Some(meta)
        })
        .await
        .ok()
        .flatten()
    }

    async fn cached_metadata_after_304(&self, cache_key: &str) -> Option<PackageMetadata> {
        self.cached_metadata_after_304_as(cache_key).await
    }

    /// Fetch metadata for multiple packages in a single HTTP request.
    ///
    /// Calls: POST /api/registry/batch-metadata
    /// Returns a map of package_name → PackageMetadata.
    ///
    /// This is the key optimization for cold installs — instead of 70+
    /// individual HTTP requests, we batch everything into 1-3 requests.
    pub async fn batch_metadata(
        &self,
        package_names: &[String],
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(package_names, false, &[], false, &[], None)
            .await
    }

    /// Batch fetch with deep transitive resolution.
    /// The server recursively discovers and fetches transitive deps (up to 3 levels),
    /// returning ALL metadata in a single response. This turns 3 sequential batch
    /// calls into 1 round-trip.
    pub async fn batch_metadata_deep(
        &self,
        package_names: &[String],
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(package_names, true, &[], false, &[], None)
            .await
    }

    pub async fn batch_metadata_deep_with_release_age_packages(
        &self,
        package_names: &[String],
        release_age_package_names: &[String],
        release_age_all_packages: bool,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(
            package_names,
            true,
            release_age_package_names,
            release_age_all_packages,
            &[],
            None,
        )
        .await
    }

    pub async fn batch_metadata_deep_with_release_age_packages_and_package_specs(
        &self,
        package_names: &[String],
        release_age_package_names: &[String],
        release_age_all_packages: bool,
        package_specs: &[(String, String)],
        release_age_cutoff_unix: Option<i64>,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        self.batch_metadata_inner(
            package_names,
            true,
            release_age_package_names,
            release_age_all_packages,
            package_specs,
            release_age_cutoff_unix,
        )
        .await
    }

    pub async fn batch_metadata_deep_with_release_age_packages_and_package_specs_stream(
        &self,
        package_names: &[String],
        release_age_package_names: &[String],
        release_age_all_packages: bool,
        package_specs: &[(String, String)],
        release_age_cutoff_unix: Option<i64>,
    ) -> Result<BatchMetadataEntryStream<'_>, LpmError> {
        if package_names.is_empty() {
            return Ok(BatchMetadataEntryStream::json(
                self,
                Vec::new().into_iter(),
                std::time::Instant::now(),
            ));
        }
        self.record_batch_metadata_request_packages(package_names);
        let body = Self::batch_metadata_request_body(
            package_names,
            true,
            release_age_package_names,
            release_age_all_packages,
            package_specs,
            release_age_cutoff_unix,
        );
        let cache_batch_entries = package_specs.is_empty();
        let rpc_start = std::time::Instant::now();
        let response = match self.send_batch_metadata_response(&body).await {
            Ok(response) => response,
            Err(error) => {
                crate::timing::record_rpc(rpc_start.elapsed());
                return Err(error);
            }
        };
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.contains("application/x-ndjson") {
            BatchMetadataEntryStream::ndjson(self, response, rpc_start, cache_batch_entries)
        } else {
            let map = match self
                .parse_json_batch_with_cache(response, cache_batch_entries)
                .await
            {
                Ok(map) => map,
                Err(error) => {
                    crate::timing::record_rpc(rpc_start.elapsed());
                    return Err(error);
                }
            };
            Ok(BatchMetadataEntryStream::json(
                self,
                map.into_iter().collect::<Vec<_>>().into_iter(),
                rpc_start,
            ))
        }
    }

    pub(super) async fn batch_metadata_inner(
        &self,
        package_names: &[String],
        deep: bool,
        release_age_package_names: &[String],
        release_age_all_packages: bool,
        package_specs: &[(String, String)],
        release_age_cutoff_unix: Option<i64>,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        if package_names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        self.record_batch_metadata_request_packages(package_names);
        let body = Self::batch_metadata_request_body(
            package_names,
            deep,
            release_age_package_names,
            release_age_all_packages,
            package_specs,
            release_age_cutoff_unix,
        );

        let rpc_start = std::time::Instant::now();
        let result = async {
            let response = self.send_batch_metadata_response(&body).await?;
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if content_type.contains("application/x-ndjson") {
                self.parse_ndjson_batch_with_cache(response, package_specs.is_empty())
                    .await
            } else {
                self.parse_json_batch_with_cache(response, package_specs.is_empty())
                    .await
            }
        }
        .await;

        crate::timing::record_rpc(rpc_start.elapsed());
        result
    }

    fn record_batch_metadata_request_packages(&self, package_names: &[String]) {
        for package_name in package_names {
            crate::timing::record_metadata_request(package_name);
            crate::timing::record_metadata_cache_miss();
        }
    }

    fn batch_metadata_request_body(
        package_names: &[String],
        deep: bool,
        release_age_package_names: &[String],
        release_age_all_packages: bool,
        package_specs: &[(String, String)],
        release_age_cutoff_unix: Option<i64>,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({ "packages": package_names, "deep": deep });
        if release_age_all_packages {
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "releaseAgeAllPackages".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        } else if !release_age_package_names.is_empty()
            && let Some(object) = body.as_object_mut()
        {
            object.insert(
                "releaseAgePackages".to_string(),
                serde_json::json!(release_age_package_names),
            );
        }
        if deep
            && !package_specs.is_empty()
            && let Some(object) = body.as_object_mut()
        {
            object.insert("rangeAware".to_string(), serde_json::Value::Bool(true));
            if let Some(cutoff_unix) = release_age_cutoff_unix {
                object.insert(
                    "releaseAgeCutoffUnix".to_string(),
                    serde_json::json!(cutoff_unix),
                );
            }
            object.insert(
                "packageSpecs".to_string(),
                serde_json::Value::Array(
                    package_specs
                        .iter()
                        .map(|(name, range)| {
                            serde_json::json!({
                                "name": name,
                                "range": range,
                            })
                        })
                        .collect(),
                ),
            );
        }
        body
    }

    async fn send_batch_metadata_response(
        &self,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, LpmError> {
        let url = format!("{}/api/registry/batch-metadata", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let mut req = self
                .build_worker_metadata_post(&url)
                .await?
                .header("Accept", "application/x-ndjson")
                .json(&body);
            if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired) {
                req = req.bearer_auth(bearer);
            }
            let req = self.apply_worker_metadata_http_version(req, &url);
            self.send_package_metadata_request(req).await
        })
        .await
    }

    /// Parse an NDJSON batch response. Each line is:
    /// `{"name":"lodash","metadata":{...}}\n`. Returns the
    /// fully-populated map.
    async fn parse_ndjson_batch_with_cache(
        &self,
        response: reqwest::Response,
        cache_entries: bool,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let mut map = std::collections::HashMap::new();
        let mut entries = NdjsonBatchEntryStream::new(response, cache_entries)?;
        while let Some((name, meta)) = entries.next(self).await? {
            match map.entry(name) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    merge_batch_package_metadata(entry.get_mut(), meta);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(meta);
                }
            }
        }
        Ok(map)
    }

    /// Parse a legacy JSON batch response: `{ "packages": { "name": {...} } }`
    async fn parse_json_batch_with_cache(
        &self,
        response: reqwest::Response,
        cache_entries: bool,
    ) -> Result<std::collections::HashMap<String, PackageMetadata>, LpmError> {
        let result: serde_json::Value = parse_capped_metadata(response, "batch metadata").await?;

        let packages_obj = result
            .get("packages")
            .and_then(|p| p.as_object())
            .ok_or_else(|| LpmError::Registry("batch response missing packages".into()))?;

        let mut map = std::collections::HashMap::new();
        for (name, meta_value) in packages_obj {
            if let Ok(meta) = serde_json::from_value::<PackageMetadata>(meta_value.clone()) {
                if !batch_metadata_entry_matches_name(name, &meta) {
                    continue;
                }

                if cache_entries {
                    let cache_key = self.batch_metadata_cache_key(name);
                    self.write_metadata_cache(&cache_key, &meta, None);
                }
                map.insert(name.clone(), meta);
            }
        }

        tracing::debug!(
            "batch metadata (JSON): requested {}, received {}",
            packages_obj.len(),
            map.len()
        );
        Ok(map)
    }

    // ─── Package Endpoints ──────────────────────────────────────────

    /// Fetch full metadata for an LPM package.
    ///
    /// Calls: GET /api/registry/@lpm.dev/owner.package-name
    ///
    /// Uses a two-tier caching strategy:
    /// 1. **TTL hit** — If cache is fresh (< 5 min), return immediately without HTTP.
    /// 2. **Conditional request** — If cache is stale but has an ETag, send
    ///    `If-None-Match`. A 304 response revalidates the cache without transferring data.
    /// 3. **Full fetch** — Otherwise fetch fresh data and cache it with the server's ETag.
    pub async fn get_package_metadata(
        &self,
        name: &PackageName,
    ) -> Result<PackageMetadata, LpmError> {
        self.get_package_metadata_inner(name, true).await
    }

    /// Fetch full metadata for an LPM package without reading or validating
    /// the existing packument cache.
    pub async fn refetch_package_metadata(
        &self,
        name: &PackageName,
    ) -> Result<PackageMetadata, LpmError> {
        self.get_package_metadata_inner(name, false).await
    }

    async fn get_package_metadata_inner(
        &self,
        name: &PackageName,
        use_cache: bool,
    ) -> Result<PackageMetadata, LpmError> {
        let scoped = name.scoped();
        crate::timing::record_metadata_request(&scoped);
        let cache_key = self.lpm_metadata_cache_key(&scoped);

        if use_cache && let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await
        {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit: {scoped}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        // npm registries expect raw scoped names in the path:
        // /api/registry/@lpm.dev/owner.package (NOT percent-encoded)
        let url = format!("{}/api/registry/{scoped}", self.base_url);

        // Time the network portion only. TTL cache hits above return
        // before this point, so the RPC counter never double-counts them.
        let rpc_start = std::time::Instant::now();

        // Posture: AuthRequired. `@lpm.dev` package metadata may be
        // gated; on 401 the recovery wrapper performs one silent
        // refresh + retry. The closure re-reads ETag + bearer each
        // attempt so the rotated token is used on retry.
        let result = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let cache_key = self.lpm_metadata_cache_key(&scoped);
                let cache_validator = use_cache
                    .then(|| self.read_cache_validator(&cache_key))
                    .flatten();
                let mut req = self.build_worker_metadata_get(&url).await?;
                if let Some(etag) = cache_validator.as_ref().and_then(|c| c.etag.as_deref()) {
                    req = req.header("If-None-Match", etag);
                }

                let mut response = self.send_package_metadata_request(req).await?;

                if use_cache && response.status() == reqwest::StatusCode::NOT_MODIFIED {
                    if let Some(meta) = self.cached_metadata_after_304(&cache_key).await {
                        tracing::debug!("metadata cache revalidated (304): {}", name.scoped());
                        return Ok(meta);
                    }
                    response = self
                        .send_package_metadata_request(self.build_worker_metadata_get(&url).await?)
                        .await?;
                }

                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let metadata: PackageMetadata =
                    parse_capped_metadata(response, &format!("get_package_metadata {url}")).await?;

                self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                Ok(metadata)
            })
            .await;

        crate::timing::record_rpc(rpc_start.elapsed());
        result
    }

    /// Fetch metadata for an npm package from the upstream npm registry.
    ///
    /// First tries via LPM's upstream proxy (if enabled), then falls back
    /// to the public npm registry at registry.npmjs.org when the proxy misses.
    ///
    /// Supports ETag conditional requests for both proxy and direct npm paths.
    pub async fn get_npm_package_metadata(&self, name: &str) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_worker_metadata_cache_key(name);

        // Tier 1: TTL-based cache hit
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit: npm:{name}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        // Past this point the call WILL hit a registry (proxy or upstream).
        // `record_rpc` fires in each tier's exit path (success or error)
        // so the counter captures real network time, not cache fast-paths.
        let rpc_start = std::time::Instant::now();
        // Macro closing over `rpc_start` so every exit path bumps the
        // counter exactly once before returning. Mirrors the existing
        // `execute_with_recovery` wrap on `get_package_metadata`.
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        // Tier 2: Try LPM upstream proxy with conditional request
        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let cache_validator = self.read_cache_validator(&cache_key);

        let req = Self::apply_cached_etag(
            self.build_worker_metadata_get(&proxy_url).await?,
            cache_validator.as_ref(),
        );

        match self.send_package_metadata_request(req).await {
            Ok(mut response) => {
                if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                    if let Some(meta) = self.cached_metadata_after_304(&cache_key).await {
                        tracing::debug!("metadata cache revalidated (304): npm:{name}");
                        return finish!(Ok(meta));
                    }
                    response = self
                        .send_package_metadata_request(
                            self.build_worker_metadata_get(&proxy_url).await?,
                        )
                        .await?;
                }

                if response.status().is_success() {
                    let etag = Self::response_etag(&response);

                    if let Ok(metadata) = parse_capped_metadata::<PackageMetadata>(
                        response,
                        &format!("get_npm_package_metadata (proxy) {name}"),
                    )
                    .await
                    {
                        // Verify we got the right package (not a routing error)
                        if metadata.name == name
                            || metadata.versions.values().any(|v| v.name == name)
                        {
                            tracing::debug!("fetched {name} via LPM upstream proxy");
                            self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                            return finish!(Ok(metadata));
                        }

                        return finish!(Err(LpmError::Registry(format!(
                            "proxy returned metadata for unexpected package '{}' when requesting '{name}'",
                            metadata.name
                        ))));
                    }
                }
            }
            Err(LpmError::NotFound(_)) => {
                tracing::debug!("npm metadata miss via LPM upstream proxy: {name}");
            }
            Err(error) if Self::npm_proxy_can_fallback_to_direct(&error) => {
                // Proxy access can be unavailable for standalone npm packages.
                // Direct npm remains the compatibility fallback; firewall
                // block errors use a distinct variant and are not swallowed here.
                tracing::debug!(
                    "npm proxy unavailable for {name}: {error}; falling back to public registry"
                );
            }
            Err(error) => return finish!(Err(error)),
        }

        // Tier 3: Fall back to public npm registry (no auth needed)
        // Use abbreviated packument to reduce payload by 50-90%
        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        tracing::debug!("fetching {name} from npm registry");
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/vnd.npm.install-v1+json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (direct fallback 304): npm:{name}");
                return finish!(Ok(metadata));
            }
            response = match self
                .send_package_metadata_request(
                    self.http
                        .for_url(&npm_url)
                        .await?
                        .get(&npm_url)
                        .header("Accept", "application/vnd.npm.install-v1+json"),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata_res = parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_package_metadata (direct) {name}"),
        )
        .await;
        let metadata = match metadata_res {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    /// Fetch npm package metadata direct from `registry.npmjs.org`,
    /// skipping the LPM Worker proxy tier entirely.
    ///
    /// Used when running in [`RouteMode::Direct`](crate::RouteMode::Direct):
    /// bypassing the Worker is the whole point, so we must NOT fall back
    /// to it on a miss. The TTL cache is preserved so warm installs and
    /// previously-seen packages stay cache-fast.
    pub async fn get_npm_metadata_direct(&self, name: &str) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_direct_metadata_cache_key(name);

        // Tier 1: TTL+HMAC cache hit (same as `get_npm_package_metadata`).
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (direct): npm:{name}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let cache_validator = self.read_cache_validator(&cache_key);

        // Go straight to the public npm registry. Abbreviated packument
        // format reduces payload by 50-90%, matching what the proxy-fallback
        // tier in `get_npm_package_metadata` uses.
        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        tracing::debug!("fetching {name} direct from npm registry");
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/vnd.npm.install-v1+json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (direct 304): npm:{name}");
                return finish!(Ok(metadata));
            }
            response = match self
                .send_package_metadata_request(
                    self.http
                        .for_url(&npm_url)
                        .await?
                        .get(&npm_url)
                        .header("Accept", "application/vnd.npm.install-v1+json"),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_direct {name}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    pub async fn get_npm_metadata_direct_with_timings(
        &self,
        name: &str,
    ) -> Result<TimedPackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_direct_metadata_cache_key(name);
        let mut timings = PackageMetadataFetchTimings::default();

        let cache_read_start = std::time::Instant::now();
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            timings.cache_read_ms = cache_read_start.elapsed().as_millis();
            timings.cache_hit = true;
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (direct): npm:{name}");
            return Ok(TimedPackageMetadata {
                metadata: cached,
                timings,
            });
        }
        timings.cache_read_ms = cache_read_start.elapsed().as_millis();
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let validator_start = std::time::Instant::now();
        let cache_validator = self.read_cache_validator(&cache_key);
        timings.validator_read_ms = validator_start.elapsed().as_millis();

        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        tracing::debug!("fetching {name} direct from npm registry");
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/vnd.npm.install-v1+json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let http_start = std::time::Instant::now();
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => {
                timings.http_ms = timings
                    .http_ms
                    .saturating_add(http_start.elapsed().as_millis());
                r
            }
            Err(e) => {
                return finish!(Err(e));
            }
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            timings.not_modified = true;
            let cache_304_start = std::time::Instant::now();
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
                tracing::debug!("metadata cache revalidated (direct 304): npm:{name}");
                return finish!(Ok(TimedPackageMetadata { metadata, timings }));
            }
            timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
            let req = self
                .http
                .for_url(&npm_url)
                .await?
                .get(&npm_url)
                .header("Accept", "application/vnd.npm.install-v1+json");
            let retry_http_start = std::time::Instant::now();
            response = match self.send_package_metadata_request(req).await {
                Ok(r) => {
                    timings.http_ms = timings
                        .http_ms
                        .saturating_add(retry_http_start.elapsed().as_millis());
                    r
                }
                Err(e) => {
                    return finish!(Err(e));
                }
            };
        }
        let etag = Self::response_etag(&response);
        let (metadata, body_timings) = match parse_capped_metadata_with_timing::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_direct {name}"),
        )
        .await
        {
            Ok(parsed) => parsed,
            Err(e) => return finish!(Err(e)),
        };
        timings.body_read_ms = body_timings.body_read_ms;
        timings.json_decode_ms = body_timings.json_parse_ms;
        timings.body_bytes = body_timings.body_bytes;
        let cache_write_start = std::time::Instant::now();
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        timings.cache_write_dispatch_ms = cache_write_start.elapsed().as_millis();
        finish!(Ok(TimedPackageMetadata { metadata, timings }))
    }

    pub async fn get_npm_version_metadata_direct_with_timings(
        &self,
        name: &str,
        version: &str,
    ) -> Result<TimedPackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_direct_version_metadata_cache_key(name, version);
        let mut timings = PackageMetadataFetchTimings::default();

        let cache_read_start = std::time::Instant::now();
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            timings.cache_read_ms = cache_read_start.elapsed().as_millis();
            if package_metadata_matches_version_doc(name, version, &cached) {
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                tracing::debug!("metadata cache hit (direct version): npm:{name}@{version}");
                return Ok(TimedPackageMetadata {
                    metadata: cached,
                    timings,
                });
            }
            tracing::debug!(
                "metadata cache mismatch (direct version): npm:{name}@{version}; refetching"
            );
        }
        timings.cache_read_ms = cache_read_start.elapsed().as_millis();
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let validator_start = std::time::Instant::now();
        let cache_validator = self.read_cache_validator(&cache_key);
        timings.validator_read_ms = validator_start.elapsed().as_millis();

        let npm_url = format!("{}/{}/{}", self.npm_registry_url, name, version);
        tracing::debug!("fetching {name}@{version} direct from npm registry");
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let http_start = std::time::Instant::now();
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => {
                timings.http_ms = timings
                    .http_ms
                    .saturating_add(http_start.elapsed().as_millis());
                r
            }
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            timings.not_modified = true;
            let cache_304_start = std::time::Instant::now();
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
                if package_metadata_matches_version_doc(name, version, &metadata) {
                    tracing::debug!(
                        "metadata cache revalidated (direct version 304): npm:{name}@{version}"
                    );
                    return finish!(Ok(TimedPackageMetadata { metadata, timings }));
                }
                tracing::debug!(
                    "metadata cache mismatch after direct version 304: npm:{name}@{version}; refetching"
                );
            }
            timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
            let req = self
                .http
                .for_url(&npm_url)
                .await?
                .get(&npm_url)
                .header("Accept", "application/json");
            let retry_http_start = std::time::Instant::now();
            response = match self.send_package_metadata_request(req).await {
                Ok(r) => {
                    timings.http_ms = timings
                        .http_ms
                        .saturating_add(retry_http_start.elapsed().as_millis());
                    r
                }
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let (version_metadata, body_timings) =
            match parse_capped_metadata_with_timing::<VersionMetadata>(
                response,
                &format!("get_npm_version_metadata_direct {name}@{version}"),
            )
            .await
            {
                Ok(parsed) => parsed,
                Err(e) => return finish!(Err(e)),
            };
        timings.body_read_ms = body_timings.body_read_ms;
        timings.json_decode_ms = body_timings.json_parse_ms;
        timings.body_bytes = body_timings.body_bytes;
        let metadata = match package_metadata_from_version_doc(name, version, version_metadata) {
            Ok(metadata) => metadata,
            Err(e) => return finish!(Err(e)),
        };
        let cache_write_start = std::time::Instant::now();
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        timings.cache_write_dispatch_ms = cache_write_start.elapsed().as_millis();
        finish!(Ok(TimedPackageMetadata { metadata, timings }))
    }

    /// Fetch a full npm packument through the proxy/direct fallback chain.
    ///
    /// Kept separate from [`Self::get_npm_package_metadata`] so installs that
    /// need release-age or trust-policy metadata do not poison the default
    /// abbreviated cache with a much larger document.
    pub async fn get_npm_package_metadata_full(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_worker_full_metadata_cache_key(name);
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit: npm-full:{name}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let cache_validator = self.read_cache_validator(&cache_key);
        let req = Self::apply_cached_etag(
            self.build_worker_metadata_get(&proxy_url)
                .await?
                .header("Accept", "application/json"),
            cache_validator.as_ref(),
        );

        match self.send_package_metadata_request(req).await {
            Ok(mut response) if response.status() == reqwest::StatusCode::NOT_MODIFIED => {
                if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                    tracing::debug!("metadata cache revalidated (full proxy 304): npm:{name}");
                    return finish!(Ok(metadata));
                }
                response = self
                    .send_package_metadata_request(
                        self.build_worker_metadata_get(&proxy_url)
                            .await?
                            .header("Accept", "application/json"),
                    )
                    .await
                    .inspect_err(|_error| {
                        crate::timing::record_rpc(rpc_start.elapsed());
                    })?;
                if response.status().is_success() {
                    let etag = Self::response_etag(&response);
                    if let Ok(metadata) = parse_capped_metadata::<PackageMetadata>(
                        response,
                        &format!("get_npm_package_metadata_full (proxy) {name}"),
                    )
                    .await
                    {
                        if metadata.name == name
                            || metadata.versions.values().any(|v| v.name == name)
                        {
                            self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                            return finish!(Ok(metadata));
                        }
                        return finish!(Err(LpmError::Registry(format!(
                            "proxy returned metadata for unexpected package '{}' when requesting '{name}'",
                            metadata.name
                        ))));
                    }
                }
            }
            Ok(response) if response.status().is_success() => {
                let etag = Self::response_etag(&response);
                if let Ok(metadata) = parse_capped_metadata::<PackageMetadata>(
                    response,
                    &format!("get_npm_package_metadata_full (proxy) {name}"),
                )
                .await
                {
                    if metadata.name == name || metadata.versions.values().any(|v| v.name == name) {
                        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                        return finish!(Ok(metadata));
                    }
                    return finish!(Err(LpmError::Registry(format!(
                        "proxy returned metadata for unexpected package '{}' when requesting '{name}'",
                        metadata.name
                    ))));
                }
            }
            Ok(_) | Err(LpmError::NotFound(_)) => {}
            Err(error) if Self::npm_proxy_can_fallback_to_direct(&error) => {}
            Err(error) => return finish!(Err(error)),
        }

        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!(
                    "metadata cache revalidated (full direct fallback 304): npm:{name}"
                );
                return finish!(Ok(metadata));
            }
            response = match self
                .send_package_metadata_request(
                    self.http
                        .for_url(&npm_url)
                        .await?
                        .get(&npm_url)
                        .header("Accept", "application/json"),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_package_metadata_full (direct) {name}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    /// Fetch a full npm packument directly from `registry.npmjs.org`.
    pub async fn get_npm_metadata_direct_full(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, LpmError> {
        self.get_npm_metadata_direct_full_inner(name, true).await
    }

    /// Fetch a full npm packument directly from `registry.npmjs.org`
    /// without reading the existing full-metadata cache first.
    ///
    /// Used when a routed full-metadata source populated `npm-full:*`
    /// with incomplete policy fields and the caller needs a fresh direct
    /// response to repair that cache entry.
    pub async fn refetch_npm_metadata_direct_full(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, LpmError> {
        self.get_npm_metadata_direct_full_inner(name, false).await
    }

    async fn get_npm_metadata_direct_full_inner(
        &self,
        name: &str,
        use_cache: bool,
    ) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_direct_full_metadata_cache_key(name);
        if use_cache && let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await
        {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (direct): npm-full:{name}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let cache_validator = use_cache
            .then(|| self.read_cache_validator(&cache_key))
            .flatten();
        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if use_cache && response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (direct full 304): npm:{name}");
                return finish!(Ok(metadata));
            }
            response = match self
                .send_package_metadata_request(
                    self.http
                        .for_url(&npm_url)
                        .await?
                        .get(&npm_url)
                        .header("Accept", "application/json"),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_direct_full {name}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    /// Fetch npm package metadata from the configured LPM Worker proxy
    /// without falling back to public npm.
    ///
    /// Diagnostic commands use this when the lockfile already records
    /// the configured LPM registry as the package source. Re-querying
    /// that same origin is not a new disclosure, but falling back to
    /// `registry.npmjs.org` on a proxy miss would be.
    pub async fn get_npm_package_metadata_proxy_only(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_proxy_only_metadata_cache_key(name);
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (proxy-only): npm:{name}");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let proxy_url = format!("{}/api/registry/{}", self.base_url, name);
        let cache_validator = self.read_cache_validator(&cache_key);
        let mut req = self.build_worker_metadata_get(&proxy_url).await?;
        if let Some(etag) = cache_validator
            .as_ref()
            .and_then(|validator| validator.etag.as_deref())
        {
            req = req.header("If-None-Match", etag);
        }

        let mut response = match self.send_package_metadata_request(req).await {
            Ok(response) => response,
            Err(err) => return finish!(Err(err)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(meta) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (proxy-only 304): npm:{name}");
                return finish!(Ok(meta));
            }
            response = match self
                .send_package_metadata_request(self.build_worker_metadata_get(&proxy_url).await?)
                .await
            {
                Ok(response) => response,
                Err(err) => return finish!(Err(err)),
            };
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_package_metadata_proxy_only {name}"),
        )
        .await
        {
            Ok(metadata) => metadata,
            Err(err) => return finish!(Err(err)),
        };
        if metadata.name == name
            || metadata
                .versions
                .values()
                .any(|version| version.name == name)
        {
            self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
            return finish!(Ok(metadata));
        }
        finish!(Err(LpmError::Registry(format!(
            "proxy returned metadata for unexpected package '{}' when requesting '{name}'",
            metadata.name
        ))))
    }

    /// Fetch npm metadata honoring an explicit upstream route.
    ///
    /// [`UpstreamRoute::LpmWorker`] → full three-tier chain via
    /// [`Self::get_npm_package_metadata`] (cache → proxy → direct
    /// fallback).
    /// [`UpstreamRoute::NpmDirect`] → cache + direct npm only, skipping
    /// the Worker hop.
    /// [`UpstreamRoute::Custom`] → fetch from a `.npmrc`-declared registry
    /// via [`Self::get_npm_metadata_from`].
    ///
    /// Single entry point for the BFS walker and the provider's
    /// escape-hatch path so routing policy lives in one place.
    pub async fn get_npm_metadata_routed(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<PackageMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.get_npm_package_metadata(name).await,
            crate::UpstreamRoute::NpmDirect => self.get_npm_metadata_direct(name).await,
            crate::UpstreamRoute::Custom { target, auth } => {
                self.get_npm_metadata_from(&target.base_url, name, auth.as_ref())
                    .await
            }
        }
    }

    /// Fetch full npm metadata honoring the same routing policy as
    /// [`Self::get_npm_metadata_routed`].
    pub async fn get_npm_metadata_routed_full(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<PackageMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.get_npm_package_metadata_full(name).await,
            crate::UpstreamRoute::NpmDirect => self.get_npm_metadata_direct_full(name).await,
            crate::UpstreamRoute::Custom { target, auth } => {
                self.get_npm_metadata_from_full(&target.base_url, name, auth.as_ref())
                    .await
            }
        }
    }

    pub async fn get_npm_release_times_routed_full(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<ReleaseTimeMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.get_npm_package_release_times_full(name).await,
            crate::UpstreamRoute::NpmDirect => {
                self.get_npm_release_times_direct_full_inner(name, true)
                    .await
            }
            crate::UpstreamRoute::Custom { target, auth } => {
                self.get_npm_release_times_from_full(&target.base_url, name, auth.as_ref())
                    .await
            }
        }
    }

    pub async fn get_npm_release_times_routed_full_with_timings(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Result<TimedReleaseTimeMetadata, LpmError> {
        match route {
            crate::UpstreamRoute::NpmDirect => {
                self.get_npm_release_times_direct_full_inner_with_timings(name, true)
                    .await
            }
            route => {
                let metadata = self.get_npm_release_times_routed_full(name, route).await?;
                Ok(TimedReleaseTimeMetadata {
                    metadata,
                    timings: PackageMetadataFetchTimings::default(),
                })
            }
        }
    }

    async fn get_npm_package_release_times_full(
        &self,
        name: &str,
    ) -> Result<ReleaseTimeMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_worker_release_times_cache_key(name);
        if let Some((cached, _etag)) = self
            .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&cache_key)
            .await
            && cached.matches_package(name)
        {
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        let full_cache_key = self.npm_worker_full_metadata_cache_key(name);
        if let Some((cached, _etag)) = self
            .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&full_cache_key)
            .await
            && cached.matches_package(name)
            && !cached.time.is_empty()
        {
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        let metadata_cache_key = self.npm_worker_metadata_cache_key(name);
        if let Some(cached) = self
            .cached_release_times_from_metadata_cache(name, &metadata_cache_key)
            .await
        {
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let proxy_url = format!("{}/api/registry/{}?release_times=1", self.base_url, name);
        let cache_validator = self.read_cache_validator(&cache_key);
        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let req = Self::apply_cached_etag(
            self.build_worker_metadata_get(&proxy_url)
                .await?
                .header("Accept", "application/json"),
            cache_validator.as_ref(),
        );

        match self.send_package_metadata_request(req).await {
            Ok(mut response) => {
                if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                    if let Some(metadata) = self
                        .cached_metadata_after_304_as::<ReleaseTimeMetadata>(&cache_key)
                        .await
                        && metadata.matches_package(name)
                    {
                        return finish!(Ok(metadata));
                    }
                    response = self
                        .send_package_metadata_request(
                            self.build_worker_metadata_get(&proxy_url)
                                .await?
                                .header("Accept", "application/json"),
                        )
                        .await?;
                }

                if response.status().is_success() {
                    let etag = Self::response_etag(&response);
                    if let Ok(metadata) = parse_capped_metadata::<ReleaseTimeMetadata>(
                        response,
                        &format!("get_npm_package_release_times_full (proxy) {name}"),
                    )
                    .await
                    {
                        let metadata = Self::validate_release_time_metadata(name, metadata)?;
                        if !metadata.time.is_empty() {
                            self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
                            return finish!(Ok(metadata));
                        }
                    }
                }
            }
            Err(LpmError::NotFound(_)) => {}
            Err(error) if Self::npm_proxy_can_fallback_to_direct(&error) => {}
            Err(error) => return finish!(Err(error)),
        }

        crate::timing::record_rpc(rpc_start.elapsed());
        self.get_npm_release_times_direct_full_inner(name, false)
            .await
    }

    async fn get_npm_release_times_direct_full_inner(
        &self,
        name: &str,
        use_cache: bool,
    ) -> Result<ReleaseTimeMetadata, LpmError> {
        Ok(self
            .get_npm_release_times_direct_full_inner_with_timings(name, use_cache)
            .await?
            .metadata)
    }

    async fn get_npm_release_times_direct_full_inner_with_timings(
        &self,
        name: &str,
        use_cache: bool,
    ) -> Result<TimedReleaseTimeMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let cache_key = self.npm_direct_release_times_cache_key(name);
        let mut timings = PackageMetadataFetchTimings::default();
        if use_cache {
            let cache_read_start = std::time::Instant::now();
            if let Some((cached, _etag)) = self
                .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&cache_key)
                .await
                && cached.matches_package(name)
            {
                timings.cache_read_ms = cache_read_start.elapsed().as_millis();
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                return Ok(TimedReleaseTimeMetadata {
                    metadata: cached,
                    timings,
                });
            }
            let full_cache_key = self.npm_direct_full_metadata_cache_key(name);
            if let Some((cached, _etag)) = self
                .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&full_cache_key)
                .await
                && cached.matches_package(name)
                && !cached.time.is_empty()
            {
                timings.cache_read_ms = cache_read_start.elapsed().as_millis();
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                return Ok(TimedReleaseTimeMetadata {
                    metadata: cached,
                    timings,
                });
            }
            let metadata_cache_key = self.npm_direct_metadata_cache_key(name);
            if let Some(cached) = self
                .cached_release_times_from_metadata_cache(name, &metadata_cache_key)
                .await
            {
                timings.cache_read_ms = cache_read_start.elapsed().as_millis();
                timings.cache_hit = true;
                crate::timing::record_metadata_cache_hit();
                return Ok(TimedReleaseTimeMetadata {
                    metadata: cached,
                    timings,
                });
            }
            timings.cache_read_ms = cache_read_start.elapsed().as_millis();
        }
        crate::timing::record_metadata_cache_miss();

        let validator_start = std::time::Instant::now();
        let cache_validator = use_cache
            .then(|| self.read_cache_validator(&cache_key))
            .flatten();
        timings.validator_read_ms = validator_start.elapsed().as_millis();
        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let npm_url = format!("{}/{}", self.npm_registry_url, name);
        let req = self
            .http
            .for_url(&npm_url)
            .await?
            .get(&npm_url)
            .header("Accept", "application/json");
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let http_start = std::time::Instant::now();
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(response) => {
                timings.http_ms = timings
                    .http_ms
                    .saturating_add(http_start.elapsed().as_millis());
                response
            }
            Err(err) => return finish!(Err(err)),
        };
        if use_cache && response.status() == reqwest::StatusCode::NOT_MODIFIED {
            timings.not_modified = true;
            let cache_304_start = std::time::Instant::now();
            if let Some(metadata) = self
                .cached_metadata_after_304_as::<ReleaseTimeMetadata>(&cache_key)
                .await
                && metadata.matches_package(name)
            {
                timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
                return finish!(Ok(TimedReleaseTimeMetadata { metadata, timings }));
            }
            timings.cache_after_304_ms = cache_304_start.elapsed().as_millis();
            let retry_http_start = std::time::Instant::now();
            response = match self
                .send_package_metadata_request(
                    self.http
                        .for_url(&npm_url)
                        .await?
                        .get(&npm_url)
                        .header("Accept", "application/json"),
                )
                .await
            {
                Ok(response) => {
                    timings.http_ms = timings
                        .http_ms
                        .saturating_add(retry_http_start.elapsed().as_millis());
                    response
                }
                Err(err) => return finish!(Err(err)),
            };
        }
        let etag = Self::response_etag(&response);
        let (metadata, body_timings) =
            match parse_capped_metadata_with_timing::<ReleaseTimeMetadata>(
                response,
                &format!("get_npm_release_times_direct_full {name}"),
            )
            .await
            {
                Ok(parsed) => parsed,
                Err(err) => return finish!(Err(err)),
            };
        timings.body_read_ms = body_timings.body_read_ms;
        timings.json_decode_ms = body_timings.json_parse_ms;
        timings.body_bytes = body_timings.body_bytes;
        let metadata = match Self::validate_release_time_metadata(name, metadata) {
            Ok(metadata) => metadata,
            Err(err) => return finish!(Err(err)),
        };
        let cache_write_start = std::time::Instant::now();
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        timings.cache_write_dispatch_ms = cache_write_start.elapsed().as_millis();
        finish!(Ok(TimedReleaseTimeMetadata { metadata, timings }))
    }

    pub async fn get_npm_release_times_from_full(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<ReleaseTimeMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let url = format!("{base_url}/{name}");
        let dest_origin = crate::npmrc::OriginKey::from_request_url(&url).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid registry URL '{url}' — must be http(s) with a host"
            ))
        })?;
        let _ = &dest_origin;
        let cache_key = format!(
            "npm-release-times:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );

        if let Some((cached, _etag)) = self
            .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&cache_key)
            .await
            && cached.matches_package(name)
        {
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        let full_cache_key = format!(
            "npm-full:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );
        if let Some((cached, _etag)) = self
            .read_metadata_cache_as_async::<ReleaseTimeMetadata>(&full_cache_key)
            .await
            && cached.matches_package(name)
            && !cached.time.is_empty()
        {
            crate::timing::record_metadata_cache_hit();
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let cache_validator = self.read_cache_validator(&cache_key);
        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let req = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/json");
        let req = apply_npmrc_auth(req, &url, auth)?;
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(response) => response,
            Err(err) => return finish!(Err(err)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self
                .cached_metadata_after_304_as::<ReleaseTimeMetadata>(&cache_key)
                .await
                && metadata.matches_package(name)
            {
                return finish!(Ok(metadata));
            }
            let req = self
                .http
                .for_url(&url)
                .await?
                .get(&url)
                .header("Accept", "application/json");
            let req = apply_npmrc_auth(req, &url, auth)?;
            response = match self.send_package_metadata_request(req).await {
                Ok(response) => response,
                Err(err) => return finish!(Err(err)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<ReleaseTimeMetadata>(
            response,
            &format!("get_npm_release_times_from_full {name} @ {base_url}"),
        )
        .await
        {
            Ok(metadata) => metadata,
            Err(err) => return finish!(Err(err)),
        };
        let metadata = match Self::validate_release_time_metadata(name, metadata) {
            Ok(metadata) => metadata,
            Err(err) => return finish!(Err(err)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    /// Fetch only the fields required for install-time blocked-set metadata
    /// capture: `time[version]` (→ `published_at`) and
    /// `versions[v]._behavioralTags` (→ `behavioral_tags{,_hash}`).
    ///
    /// **On cache hit** the registry blob is deserialized into the minimal
    /// [`BlockedSetPackageMeta`] struct, skipping allocation of all other
    /// `VersionMetadata` fields (deps, devDeps, readme, etc.). For a 51-package
    /// install this eliminates ~90% of the rmp_serde string allocations that
    /// [`get_npm_metadata_routed`] would otherwise produce.
    ///
    /// **On cache miss** this falls back to [`get_npm_metadata_routed`] (full
    /// fetch + cache write), then projects the result down to the minimal type
    /// without a second deserialization pass.
    ///
    /// **Custom routes** (`UpstreamRoute::Custom`) use a principal-fingerprint
    /// cache key that is computed inside [`get_npm_metadata_from`] and is not
    /// reproducible here — those routes skip the fast path and go straight to
    /// the full fetch + projection.
    pub async fn get_npm_blocked_set_meta(
        &self,
        name: &str,
        route: crate::UpstreamRoute,
    ) -> Option<crate::types::BlockedSetPackageMeta> {
        crate::timing::record_metadata_request(name);
        // Custom routes use a principal-fingerprint key we can't reproduce here.
        let cache_key = match &route {
            crate::UpstreamRoute::LpmWorker => Some(self.npm_worker_metadata_cache_key(name)),
            crate::UpstreamRoute::NpmDirect => Some(self.npm_direct_metadata_cache_key(name)),
            crate::UpstreamRoute::Custom { .. } => None,
        };
        if let Some(cache_key) = cache_key
            && let Some((meta, _)) =
                self.read_metadata_cache_as::<crate::types::BlockedSetPackageMeta>(&cache_key)
        {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("blocked-set meta cache hit (minimal): {name}");
            return Some(meta);
        }
        crate::timing::record_metadata_cache_miss();

        // Cache miss or custom route: fetch full metadata (writes cache),
        // then project to the minimal type without re-deserializing.
        let full = self.get_npm_metadata_routed(name, route).await.ok()?;
        Some(crate::types::BlockedSetPackageMeta {
            time: full.time,
            versions: full
                .versions
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        crate::types::BlockedSetVersionMeta {
                            behavioral_tags: v.behavioral_tags,
                        },
                    )
                })
                .collect(),
        })
    }

    /// Fetch npm-style abbreviated metadata from an arbitrary registry,
    /// optionally attaching origin-scoped auth.
    ///
    /// Generalizes [`Self::get_npm_metadata_direct`] so `.npmrc`-
    /// declared private/internal registries are first-class fetch
    /// targets. The same connection pool is reused (reqwest keys its
    /// pool by origin, so multiple destinations don't multiply TLS
    /// handshakes).
    ///
    /// ## Auth attachment
    ///
    /// When `auth` is `Some`, the request bears `Authorization: Bearer`
    /// or `Authorization: Basic` per the credential's variant. The
    /// caller (`RouteTable::route_for_package`) is responsible for
    /// pairing auth with the right `target`. Defense-in-depth: this
    /// method **re-verifies** that the auth's origin matches the
    /// destination URL's origin via `OriginKey::from_request_url`
    /// before sending, returning `LpmError::Registry` on mismatch
    /// (which should never trigger in correctly-built calls but
    /// hard-fails rather than leaking a token if it does).
    ///
    /// ## Cache key
    ///
    /// `npm:<principal-fingerprint>:<full-url>`. Standard Worker and direct
    /// routes are source-scoped separately. Custom registries also partition
    /// by auth and mTLS principal because the same URL can return different
    /// content to different credentials.
    ///
    /// ## What this does NOT do
    ///
    /// - HTTP→HTTPS upgrade or `--insecure` enforcement: the existing
    ///   `is_https_url` / `is_localhost_url` logic governs that
    ///   elsewhere; callers passing an `http://` URL must satisfy that
    ///   gate themselves.
    /// - Tier 2 (Worker) fallback: custom registries are by definition
    ///   not the LPM Worker; falling back would leak a private package
    ///   name to a public registry. Cache miss → direct fetch only.
    pub async fn get_npm_metadata_from(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let url = format!("{base_url}/{name}");

        // Parse destination origin once; used for both the cache key
        // and the auth-origin defensive check.
        let dest_origin = crate::npmrc::OriginKey::from_request_url(&url).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid registry URL '{url}' — must be http(s) with a host"
            ))
        })?;

        // Origin-mismatch defense lives in `apply_npmrc_auth` below;
        // we still parse `dest_origin` here because we need
        // `host_lower` for the cache key namespace.
        let _ = &dest_origin;

        // Cache key namespace: `npm:<auth_fingerprint>:<url>`.
        //
        // Earlier drafts keyed on (host) only, then (host, port), then
        // full URL. Each step closed a real collision class but the
        // last left a worse hole: the cache was **auth-blind**. A
        // successful fetch under credential A populated the cache, and
        // a later fetch for the same URL under credential B (or none)
        // read A's response without proving its own access. For
        // private registries that vary packument content per token
        // that's a direct auth-bypass; even for token-gated registries
        // that serve identical content per token, it still leaks the
        // existence of private versions to other principals on the
        // same machine.
        //
        // Including the auth fingerprint partitions the cache per
        // principal. Identical credentials → identical fingerprint →
        // warm hits across calls. Different credentials → distinct
        // namespaces. `anon` is the canonical no-auth namespace.
        // The fingerprint is a SHA-256 truncation, so debug logs of
        // the cache key never expose raw tokens. Re-issued client certs
        // invalidate cache cleanly even when URL + auth are unchanged.
        let cache_key = format!(
            "npm:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );

        // Tier 1: TTL+magic cache hit.
        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (custom)");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let cache_validator = self.read_cache_validator(&cache_key);
        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        tracing::debug!("fetching {name} from custom registry {base_url}");
        let req = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/vnd.npm.install-v1+json");
        // `apply_npmrc_auth` does the origin-mismatch defensive check
        // and attaches Bearer/Basic. Anonymous = no-op.
        let req = apply_npmrc_auth(req, &url, auth)?;
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());

        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (custom 304)");
                return finish!(Ok(metadata));
            }
            let req = self
                .http
                .for_url(&url)
                .await?
                .get(&url)
                .header("Accept", "application/vnd.npm.install-v1+json");
            let req = apply_npmrc_auth(req, &url, auth)?;
            response = match self.send_package_metadata_request(req).await {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_from {name} @ {base_url}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    /// Fetch a full packument from a configured custom registry.
    pub async fn get_npm_metadata_from_full(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<PackageMetadata, LpmError> {
        crate::timing::record_metadata_request(name);
        let url = format!("{base_url}/{name}");
        let dest_origin = crate::npmrc::OriginKey::from_request_url(&url).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid registry URL '{url}' — must be http(s) with a host"
            ))
        })?;
        let _ = &dest_origin;
        let cache_key = format!(
            "npm-full:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );

        if let Some((cached, _etag)) = self.read_metadata_cache_async(&cache_key).await {
            crate::timing::record_metadata_cache_hit();
            tracing::debug!("metadata cache hit (custom full)");
            return Ok(cached);
        }
        crate::timing::record_metadata_cache_miss();

        let cache_validator = self.read_cache_validator(&cache_key);
        let rpc_start = std::time::Instant::now();
        macro_rules! finish {
            ($expr:expr) => {{
                let r = $expr;
                crate::timing::record_rpc(rpc_start.elapsed());
                r
            }};
        }

        let req = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/json");
        let req = apply_npmrc_auth(req, &url, auth)?;
        let req = Self::apply_cached_etag(req, cache_validator.as_ref());
        let mut response = match self.send_package_metadata_request(req).await {
            Ok(r) => r,
            Err(e) => return finish!(Err(e)),
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some(metadata) = self.cached_metadata_after_304(&cache_key).await {
                tracing::debug!("metadata cache revalidated (custom full 304)");
                return finish!(Ok(metadata));
            }
            let req = self
                .http
                .for_url(&url)
                .await?
                .get(&url)
                .header("Accept", "application/json");
            let req = apply_npmrc_auth(req, &url, auth)?;
            response = match self.send_package_metadata_request(req).await {
                Ok(r) => r,
                Err(e) => return finish!(Err(e)),
            };
        }
        let etag = Self::response_etag(&response);
        let metadata = match parse_capped_metadata::<PackageMetadata>(
            response,
            &format!("get_npm_metadata_from_full {name} @ {base_url}"),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => return finish!(Err(e)),
        };
        self.write_metadata_cache(&cache_key, &metadata, etag.as_deref());
        finish!(Ok(metadata))
    }

    pub async fn get_registry_signing_keys(
        &self,
        base_url: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<Vec<RegistrySigningKey>, LpmError> {
        #[derive(serde::Deserialize)]
        struct KeysResponse {
            #[serde(default)]
            keys: Vec<RegistrySigningKey>,
        }

        let url = format!("{}/-/npm/v1/keys", base_url.trim_end_matches('/'));
        let cache_key = format!(
            "registry-signing-keys:{}:{url}",
            principal_fingerprint(auth, self.http.identity_fp_for_url(&url))
        );
        let mut cache = self.registry_signing_keys_cache.lock().await;
        if let Some(keys) = cache.get(&cache_key) {
            return Ok(keys.clone());
        }

        let req = self
            .http
            .for_url(&url)
            .await?
            .get(&url)
            .header("Accept", "application/json");
        let req = apply_npmrc_auth(req, &url, auth)?;
        let response = match self.send_with_retry(req).await {
            Ok(response) => response,
            Err(LpmError::NotFound(_)) => {
                cache.insert(cache_key, Vec::new());
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let keys =
            parse_capped_metadata::<KeysResponse>(response, "get_registry_signing_keys").await?;
        cache.insert(cache_key, keys.keys.clone());
        Ok(keys.keys)
    }

    /// Fan-out npm metadata fetches at `max_concurrency`, direct to
    /// `registry.npmjs.org`, with **halve-on-429** adaptive back-pressure.
    ///
    /// Returned vector is in input order; each entry is a per-package
    /// `Result`. Per-package failures do NOT abort the batch, which lets
    /// the walker log + continue.
    ///
    /// ## Halve-on-429
    ///
    /// If any in-flight request surfaces [`LpmError::RateLimited`], the
    /// effective concurrency is halved for the remainder of this call.
    /// Floor is 4. This is a one-way ratchet per call; the next
    /// `parallel_fetch_npm_manifests` invocation starts fresh.
    ///
    /// Implementation: halving combines two mechanisms to handle both
    /// partial and full saturation:
    ///
    /// 1. **Immediate forget** — the 429-observing task synchronously
    ///    `forget()`s as many permits as are currently free in the
    ///    semaphore. If the pool is fully saturated, this forgets zero.
    /// 2. **Deferred forget** — any shortfall is recorded in a shared
    ///    `forget_debt` counter. Every task, as it completes, checks the
    ///    debt and — if non-zero — forgets its own permit (returning
    ///    nothing to the pool) and decrements the debt. Over the next
    ///    few task completions the pool shrinks to the halved size.
    ///
    /// This fixes the silent-no-op under full saturation: when every
    /// permit is checked out, `try_acquire_owned` returns zero, so the
    /// old code registered a halve event without actually halving. The
    /// debt-on-completion path ensures the ceiling genuinely moves.
    ///
    /// `halve_events` counts only calls that registered debt + forgets
    /// — it is only incremented when either an immediate forget or a
    /// debt-add actually happened, so stats cannot claim halving when
    /// no effective reduction occurred.
    ///
    /// Rationale: `send_with_retry` already handles per-request 429s
    /// with `Retry-After`. What `send_with_retry` can't do is reduce
    /// the batch's aggregate pressure on npm — that needs batch-level
    /// knowledge.
    ///
    /// Returned [`FanOutStats`] surfaces the halve events so callers
    /// can record them in observability without interpreting errors.
    pub async fn parallel_fetch_npm_manifests(
        self: &Arc<Self>,
        names: &[String],
        max_concurrency: usize,
    ) -> (
        Vec<(String, Result<PackageMetadata, LpmError>)>,
        FanOutStats,
    ) {
        self.parallel_fetch_npm_manifests_inner(
            names,
            max_concurrency,
            crate::timing::metadata_fetch_detail_enabled(),
        )
        .await
    }

    pub(super) async fn parallel_fetch_npm_manifests_inner(
        self: &Arc<Self>,
        names: &[String],
        max_concurrency: usize,
        trace_metadata_fetches: bool,
    ) -> (
        Vec<(String, Result<PackageMetadata, LpmError>)>,
        FanOutStats,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Semaphore;

        const CONCURRENCY_FLOOR: usize = 4;

        let initial = max_concurrency.max(CONCURRENCY_FLOOR);
        let semaphore = Arc::new(Semaphore::new(initial));
        // Tracks the current effective ceiling (initial minus forgotten
        // permits, whether forgotten immediately or via debt).
        let current_ceiling = Arc::new(AtomicUsize::new(initial));
        // Permits still owed to the halving mechanism. Task completions
        // consume debt before returning their permit to the pool.
        let forget_debt = Arc::new(AtomicUsize::new(0));
        let halve_events = Arc::new(AtomicUsize::new(0));

        let mut futures = Vec::with_capacity(names.len());
        for (idx, name) in names.iter().enumerate() {
            let sem = semaphore.clone();
            let ceiling = current_ceiling.clone();
            let debt = forget_debt.clone();
            let halves = halve_events.clone();
            let client = self.clone();
            let name = name.clone();
            futures.push(tokio::spawn(async move {
                // `acquire_owned` returns a permit that auto-releases on
                // drop UNLESS we call `forget()` (used for halve-on-429).
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            idx,
                            name,
                            Err(LpmError::Network(
                                "fanout semaphore closed before fetch".into(),
                            )),
                        );
                    }
                };

                let result = if trace_metadata_fetches {
                    let total_start = std::time::Instant::now();
                    client
                        .get_npm_metadata_direct_with_timings(&name)
                        .await
                        .map(|timed| {
                            let timings = timed.timings;
                            let version_count = timed.metadata.versions.len() as u64;
                            let total_ms = total_start.elapsed().as_millis();
                            crate::timing::record_metadata_fetch_detail(
                                crate::timing::MetadataFetchDetailRecord {
                                    package: name.clone(),
                                    route: "npm_direct",
                                    total_ms,
                                    raw_fetch_ms: total_ms,
                                    cache_read_ms: timings.cache_read_ms,
                                    validator_read_ms: timings.validator_read_ms,
                                    http_ms: timings.http_ms,
                                    body_read_ms: timings.body_read_ms,
                                    json_decode_ms: timings.json_decode_ms,
                                    cache_after_304_ms: timings.cache_after_304_ms,
                                    cache_write_dispatch_ms: timings.cache_write_dispatch_ms,
                                    body_bytes: timings.body_bytes,
                                    version_count,
                                    cache_hit: timings.cache_hit,
                                    not_modified: timings.not_modified,
                                    ..crate::timing::MetadataFetchDetailRecord::default()
                                },
                            );
                            timed.metadata
                        })
                } else {
                    client.get_npm_metadata_direct(&name).await
                };

                if matches!(result, Err(LpmError::RateLimited { .. })) {
                    // Atomically claim a halving step against `ceiling`
                    // via a CAS loop. Without this, two concurrent 429s
                    // can both read `current=8` before either decrements,
                    // both enqueue `want_forget=4` of debt, and the 8
                    // subsequent completions drive effective pool to 0 —
                    // below the floor. CAS on the ceiling is the only
                    // way to make "decide how much to halve" atomic WRT
                    // other 429-handlers; a CAS on debt alone can't help
                    // because each handler's `want_forget` is computed
                    // from a stale ceiling.
                    //
                    // Loop ends in one of two states:
                    //   - We committed the decrement: ceiling is now
                    //     `current - want_forget`. We own `want_forget`
                    //     permits to forget (via immediate `try_acquire`
                    //     + deferred debt); the pool physical size
                    //     catches up as completions pay debt.
                    //   - Ceiling dropped to/below floor before we won
                    //     the CAS: nothing more to halve. Exit without
                    //     adding debt (another handler did our work).
                    loop {
                        let current = ceiling.load(Ordering::SeqCst);
                        if current <= CONCURRENCY_FLOOR {
                            break; // at floor; nothing more to halve
                        }
                        let want_forget = (current / 2).min(current - CONCURRENCY_FLOOR);
                        let new_ceiling = current - want_forget;
                        if ceiling
                            .compare_exchange(
                                current,
                                new_ceiling,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_err()
                        {
                            continue; // another handler moved ceiling; retry
                        }

                        // We own `want_forget` permits to remove. Split
                        // between immediate forgets (pool has free
                        // permits right now) and deferred debt (saturated;
                        // next task completions forget their permits).
                        let mut forgot_now = 0usize;
                        while forgot_now < want_forget {
                            match sem.clone().try_acquire_owned() {
                                Ok(p) => {
                                    p.forget();
                                    forgot_now += 1;
                                }
                                Err(_) => break,
                            }
                        }
                        let shortfall = want_forget - forgot_now;
                        if shortfall > 0 {
                            debt.fetch_add(shortfall, Ordering::SeqCst);
                        }
                        halves.fetch_add(1, Ordering::SeqCst);
                        tracing::debug!(
                            "parallel_fetch_npm_manifests: halving after 429 on {name} \
                             (immediate={forgot_now}, deferred_debt={shortfall}, \
                             ceiling {current}→{new_ceiling})"
                        );
                        break;
                    }
                }

                // Task completion: pay down any outstanding forget debt
                // by forgetting our own permit instead of returning it.
                // CAS loop avoids double-decrement races when several
                // completions race on the same debt.
                let mut paid_debt = false;
                loop {
                    let d = debt.load(Ordering::SeqCst);
                    if d == 0 {
                        break;
                    }
                    match debt.compare_exchange(d, d - 1, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => {
                            paid_debt = true;
                            break;
                        }
                        Err(_) => continue, // raced; retry
                    }
                }
                if paid_debt {
                    // Forget our own permit to satisfy the debt. Ceiling
                    // was already decremented at CAS time in the
                    // halve-step above — do NOT decrement again here or
                    // the ceiling lags behind reality by (debt paid).
                    permit.forget();
                } else {
                    drop(permit);
                }

                (idx, name, result)
            }));
        }

        let mut results: Vec<(usize, String, Result<PackageMetadata, LpmError>)> =
            Vec::with_capacity(names.len());
        for fut in futures {
            match fut.await {
                Ok(entry) => results.push(entry),
                Err(join_err) => {
                    results.push((
                        0,
                        String::new(),
                        Err(LpmError::Network(format!(
                            "fanout task panicked: {join_err}"
                        ))),
                    ));
                }
            }
        }
        results.sort_by_key(|(idx, _, _)| *idx);
        let out: Vec<(String, Result<PackageMetadata, LpmError>)> =
            results.into_iter().map(|(_, n, r)| (n, r)).collect();

        let stats = FanOutStats {
            initial_concurrency: initial,
            final_concurrency: current_ceiling.load(Ordering::SeqCst),
            halve_events: halve_events.load(Ordering::SeqCst),
        };
        (out, stats)
    }
}

fn package_metadata_from_version_doc(
    expected_name: &str,
    expected_version: &str,
    version_metadata: VersionMetadata,
) -> Result<PackageMetadata, LpmError> {
    if version_metadata.name != expected_name || version_metadata.version != expected_version {
        return Err(LpmError::Registry(format!(
            "npm version metadata returned {}@{} when requesting {expected_name}@{expected_version}",
            version_metadata.name, version_metadata.version
        )));
    }

    let mut versions = std::collections::HashMap::with_capacity(1);
    versions.insert(expected_version.to_string(), version_metadata);
    Ok(PackageMetadata {
        name: expected_name.to_string(),
        description: None,
        modified: None,
        dist_tags: std::collections::HashMap::new(),
        versions,
        time: std::collections::HashMap::new(),
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: None,
        ecosystem: None,
    })
}

fn package_metadata_matches_version_doc(
    expected_name: &str,
    expected_version: &str,
    metadata: &PackageMetadata,
) -> bool {
    if metadata.name != expected_name || metadata.versions.len() != 1 {
        return false;
    }
    metadata
        .versions
        .get(expected_version)
        .is_some_and(|version| version.name == expected_name && version.version == expected_version)
}
