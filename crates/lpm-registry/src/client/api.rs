use super::transport::{
    Answered, FailedResponse, MAX_RETRIES, backoff_delay, version_exists_error,
};
use super::*;

/// The longest a tarball upload may take: a minute, and ten seconds a MiB,
/// about 100 KiB/s, up to half an hour.
fn tarball_upload_timeout(size: usize) -> Duration {
    let mebibytes = (size as u64).div_ceil(1024 * 1024);
    Duration::from_secs((60 + mebibytes * 10).min(30 * 60))
}

/// Headers an upload URL may ask for: its content's type, a write-once
/// condition, and storage's own. Never a credential or a framing header.
fn tarball_upload_header_is_allowed(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "content-type" || name == "if-none-match" || name.starts_with("x-amz-")
}

/// A tarball, shared with its publish, as a request body that isn't copied
/// for each try.
struct SharedTarball(Arc<Vec<u8>>);

impl AsRef<[u8]> for SharedTarball {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The longest a tarball upload may go without the connection taking any
/// of its body or its answer arriving before it's given up as stalled.
const TARBALL_UPLOAD_STALL: Duration = Duration::from_secs(60);

/// The pieces a tarball upload sends its body in, each of which counts as
/// progress when the connection takes it.
const TARBALL_UPLOAD_CHUNK: usize = 256 * 1024;

/// When a tarball upload last made progress.
pub(super) struct UploadProgress {
    started: tokio::time::Instant,
    last_millis: std::sync::atomic::AtomicU64,
}

impl UploadProgress {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            started: tokio::time::Instant::now(),
            last_millis: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn mark(&self) {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis
            .store(millis, std::sync::atomic::Ordering::Relaxed);
    }

    /// Resolves once `limit` passes without progress.
    pub(super) async fn stalled(&self, limit: Duration) {
        loop {
            let last =
                Duration::from_millis(self.last_millis.load(std::sync::atomic::Ordering::Relaxed));
            let deadline = self.started + last + limit;
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// `tarball` as a request body in pieces, each marking `progress` as the
/// connection takes it.
pub(super) fn tarball_upload_chunks(
    tarball: bytes::Bytes,
    progress: Arc<UploadProgress>,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::convert::Infallible>> + Send + 'static {
    let len = tarball.len();
    futures::stream::iter((0..len).step_by(TARBALL_UPLOAD_CHUNK).map(move |start| {
        progress.mark();
        Ok(tarball.slice(start..(start + TARBALL_UPLOAD_CHUNK).min(len)))
    }))
}

/// Whether `body` is one of the Registry's refusals, which name their
/// `code`, rather than a server's answer for a route it doesn't have.
fn is_coded_refusal(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|json| json.get("code").is_some_and(serde_json::Value::is_string))
}

/// The error a refusal of a publish's upload is, as the publish's own would
/// read: `VERSION_EXISTS` as the version existing, anything else with its
/// status, message and code.
fn publish_upload_refusal(status: u16, body: &str, version: &str) -> LpmError {
    let json = serde_json::from_str::<serde_json::Value>(body).ok();
    let text = |field: &str| {
        json.as_ref()
            .and_then(|json| json.get(field))
            .and_then(serde_json::Value::as_str)
    };
    let code = text("code");
    if code == Some("VERSION_EXISTS") {
        return version_exists_error(version);
    }
    let status_text = reqwest::StatusCode::from_u16(status)
        .map_or_else(|_| status.to_string(), |status| status.to_string());
    let error = text("error").map_or_else(
        || format!("HTTP {status_text}"),
        |error| lpm_common::sanitize_terminal_inline(error).into_owned(),
    );
    LpmError::Registry(match code {
        Some(code) => format!("publish failed ({status_text}): {error} [{code}]"),
        None => format!("publish failed ({status_text}): {error}"),
    })
}

/// The error a tarball upload that got no answer is, without its URL: a
/// presigned URL's query is a credential for the upload.
pub(super) fn tarball_upload_network_error(error: reqwest::Error) -> LpmError {
    LpmError::Network(format!(
        "tarball upload failed: {}",
        lpm_http::error_chain(&error.without_url())
    ))
}

/// The error storage's refusal of a tarball upload is, with the code and
/// message of its XML error where it gives one.
async fn tarball_upload_refusal(status: u16, response: reqwest::Response) -> LpmError {
    let body = read_capped_error_text(response).await;
    let element = |name: &str| {
        let open = format!("<{name}>");
        let start = body.find(&open)? + open.len();
        let end = body[start..].find(&format!("</{name}>"))? + start;
        Some(lpm_common::sanitize_terminal_inline(&body[start..end]).into_owned())
    };
    let detail = match (element("Code"), element("Message")) {
        (Some(code), Some(message)) => format!(": {code}: {message}"),
        (Some(code), None) => format!(": {code}"),
        _ => String::new(),
    };
    LpmError::Http {
        status,
        message: format!("tarball upload failed{detail}"),
    }
}

impl RegistryClient {
    // ─── Discovery Endpoints ────────────────────────────────────────

    /// Search packages.
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint, no
    /// bearer attached even when stored.
    ///
    /// Calls: GET /api/search/packages?q=...&limit=...&mode=semantic
    pub async fn search_packages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SearchResponse, LpmError> {
        validate_search_registry_base(&self.base_url)?;
        let url = format!(
            "{}/api/search/packages?q={}&limit={}&mode=semantic",
            self.base_url,
            urlencoding::encode(query),
            limit.min(20)
        );
        let mut results: SearchResponse = self
            .get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await?;
        results.packages.truncate(limit.min(20) as usize);
        Ok(results)
    }

    pub async fn search_npm_packages_routed(
        &self,
        query: &str,
        limit: u32,
        route: crate::UpstreamRoute,
    ) -> Result<SearchResponse, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.search_packages(query, limit).await,
            crate::UpstreamRoute::NpmDirect => self.search_npm_packages(query, limit).await,
            crate::UpstreamRoute::Custom { target, auth } => {
                self.search_npm_packages_from(&target.base_url, query, limit, auth.as_deref())
                    .await
            }
        }
    }

    pub async fn search_npm_packages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SearchResponse, LpmError> {
        self.search_npm_packages_from(&self.npm_registry_url, query, limit, None)
            .await
    }

    pub async fn search_npm_packages_from(
        &self,
        base_url: &str,
        query: &str,
        limit: u32,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<SearchResponse, LpmError> {
        #[derive(serde::Deserialize)]
        struct NpmSearchEnvelope {
            objects: Vec<NpmSearchObject>,
        }

        #[derive(serde::Deserialize)]
        struct NpmSearchObject {
            package: NpmSearchPackage,
        }

        #[derive(serde::Deserialize)]
        struct NpmSearchPackage {
            name: String,
            #[serde(default)]
            description: Option<String>,
            version: String,
        }

        validate_search_registry_base(base_url)?;
        let destination = RequestDestination::parse(&format!(
            "{base_url}/-/v1/search?text={}&size={}",
            urlencoding::encode(query),
            limit.min(20)
        ))?;
        let req = self
            .http
            .for_destination(&destination)
            .await?
            .get(destination.as_url().clone())
            .header("Accept", "application/json");
        let req = apply_npmrc_auth_to_destination(req, &destination, auth)?;
        let response = self.send_with_retry_with_npmrc_auth(req, auth).await.map_err(|error| {
            match error {
                LpmError::AuthRequired => LpmError::Registry(
                    "search authentication failed. Configure credentials in .npmrc for the selected npm-compatible registry.".into(),
                ),
                error => error,
            }
        })?;
        let envelope: NpmSearchEnvelope =
            parse_capped_api_json(response, &format!("response from {}", destination.as_str()))
                .await?;

        Ok(SearchResponse {
            packages: envelope
                .objects
                .into_iter()
                .take(limit.min(20) as usize)
                .map(|object| SearchPackage {
                    id: None,
                    name: object.package.name,
                    owner: None,
                    description: object.package.description,
                    distribution_mode: Some("npm".to_string()),
                    download_count: None,
                    latest_version: Some(object.package.version),
                    ecosystem: Some("js".to_string()),
                    quality_score: None,
                    category: None,
                    avatar_url: None,
                    is_org: None,
                    archived: None,
                })
                .collect(),
        })
    }

    /// Search owners (users and organizations).
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint.
    ///
    /// Calls: GET /api/search/owners?q=...&limit=...
    pub async fn search_owners(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<OwnerSearchResponse, LpmError> {
        let url = format!(
            "{}/api/search/owners?q={}&limit={}",
            self.base_url,
            urlencoding::encode(query),
            limit.min(10)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Check if a package name is available.
    ///
    /// Posture: `AuthRequired` — the original docstring noted "prevents
    /// enumeration", which means the server gates this endpoint.
    /// Wrapped in `execute_with_recovery` so a stale stored session
    /// self-heals.
    ///
    /// Calls: GET /api/registry/check-name?name=owner.package-name
    pub async fn check_name(&self, name: &str) -> Result<CheckNameResponse, LpmError> {
        let url = format!(
            "{}/api/registry/check-name?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Auth Endpoints ─────────────────────────────────────────────

    /// Get current user info.
    ///
    /// Posture: `AuthRequired`. On 401 with a refresh-backed session,
    /// `execute_with_recovery` performs one silent refresh + retry.
    ///
    /// Calls: GET /api/registry/-/whoami
    pub async fn whoami(&self) -> Result<WhoamiResponse, LpmError> {
        const MAX_ORGANIZATION_PAGES: usize = 100;

        #[derive(serde::Deserialize)]
        struct WhoamiOrganizationsPage {
            #[serde(default)]
            organizations: Vec<WhoamiOrg>,
            #[serde(default, rename = "organizations_next_cursor")]
            organizations_next_cursor: Option<String>,
        }

        let url = format!("{}/api/registry/-/whoami", self.base_url);
        let mut response: WhoamiResponse = self
            .execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await?;
        let mut next_cursor = response.organizations_next_cursor.take();
        let mut seen_cursors = std::collections::HashSet::new();
        let mut seen_scopes: std::collections::HashSet<String> =
            response.available_scopes.iter().cloned().collect();

        for _ in 0..MAX_ORGANIZATION_PAGES {
            let Some(cursor) = next_cursor.take() else {
                return Ok(response);
            };
            if !seen_cursors.insert(cursor.clone()) {
                return Err(LpmError::Registry(
                    "registry returned a repeated whoami organization cursor".to_string(),
                ));
            }

            let continuation_url = format!(
                "{}/api/registry/-/whoami/organizations?cursor={}",
                self.base_url,
                urlencoding::encode(&cursor)
            );
            let page: WhoamiOrganizationsPage = self
                .execute_with_recovery(AuthPosture::AuthRequired, || {
                    self.get_json(&continuation_url)
                })
                .await?;

            for organization in page.organizations {
                let scope = format!("@{}", organization.slug);
                if seen_scopes.insert(scope.clone()) {
                    response.available_scopes.push(scope);
                }
                response.organizations.push(organization);
            }
            next_cursor = page.organizations_next_cursor;
        }

        Err(LpmError::Registry(
            "registry returned too many whoami organization pages".to_string(),
        ))
    }

    /// Validate the current token.
    ///
    /// Posture: `AuthRequired`.
    ///
    /// Calls: GET /api/registry/cli/check
    pub async fn check_token(&self) -> Result<TokenCheckResponse, LpmError> {
        let url = format!("{}/api/registry/cli/check", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Asks the publish preflight whether the Registry would take
    /// `name@version`: the token's publish authorization and the version's
    /// availability, and given the `size` of the tarball it would be sent,
    /// the size cap and the account's storage. It creates no Registry state.
    /// A refusal comes back with its status and code; a timeout, a rate
    /// limit, a server error or a network failure is retried first.
    pub async fn publish_preflight(
        &self,
        name: &str,
        version: &str,
        size: Option<u64>,
    ) -> Result<PublishPreflightVerdict, LpmError> {
        let mut url = format!(
            "{}/api/registry/-/package/publish-preflight?name={}&version={}",
            self.base_url,
            urlencoding::encode(name),
            urlencoding::encode(version)
        );
        if let Some(size) = size {
            url.push_str(&format!("&size={size}"));
        }
        let answer = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                match self
                    .send_with_retry_keeping_status(self.build_get(&url).await?)
                    .await?
                {
                    Answered::Failed(FailedResponse { status: 401, .. }) => {
                        Err(LpmError::AuthRequired)
                    }
                    answer => Ok(answer),
                }
            })
            .await?;
        let response = match answer {
            Answered::Success(response) => response,
            Answered::Failed(FailedResponse {
                status,
                retry_after_secs,
                body,
            }) => {
                let json = serde_json::from_str::<serde_json::Value>(&body).ok();
                let text = |field: &str| {
                    json.as_ref()
                        .and_then(|json| json.get(field))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                };
                let error = text("error").unwrap_or_else(|| {
                    let status = reqwest::StatusCode::from_u16(status)
                        .map_or_else(|_| status.to_string(), |status| status.to_string());
                    format!("HTTP {status}")
                });
                return Ok(PublishPreflightVerdict::Refused {
                    status,
                    code: text("code"),
                    error,
                    body,
                    retry_after_secs,
                });
            }
        };
        let response: PublishPreflightResponse =
            parse_capped_api_json(response, "publish preflight response").await?;
        if !response.success {
            return Err(LpmError::Registry(format!(
                "publish preflight was denied for {name}@{version}"
            )));
        }
        if response.name != name || response.version != version {
            return Err(LpmError::Registry(format!(
                "publish preflight returned a mismatched package identity (expected {name}@{version}, received {}@{})",
                response.name, response.version
            )));
        }
        Ok(PublishPreflightVerdict::Accepted(response))
    }

    /// Opens an upload of the tarball a publish of `name@version` sends,
    /// which the publish then names in place of the tarball, so a tarball
    /// isn't bound by the Registry's limit on a request's body. The Registry
    /// runs the publish preflight's checks with the tarball's `size` first.
    /// A refusal is the error the publish would give; a timeout, a rate
    /// limit, a server error or a network failure is retried first. None
    /// from a Registry that takes no uploads, which answers 404 or 405
    /// without a refusal's code.
    ///
    /// Calls: POST /api/registry/-/package/uploads
    pub async fn create_publish_upload(
        &self,
        name: &str,
        version: &str,
        size: u64,
        integrity: &str,
    ) -> Result<Option<PublishUpload>, LpmError> {
        let url = format!("{}/api/registry/-/package/uploads", self.base_url);
        let body = serde_json::json!({
            "name": name,
            "version": version,
            "size": size,
            "integrity": integrity,
        });
        let answer = self
            .execute_with_recovery(AuthPosture::AuthRequired, || async {
                let mut request = self.http.for_url(&url).await?.post(&url).json(&body);
                if let Some(bearer) = self.current_bearer(AuthPosture::AuthRequired)? {
                    request = request.bearer_auth(bearer);
                }
                match self.send_with_retry_keeping_status(request).await? {
                    Answered::Failed(FailedResponse { status: 401, .. }) => {
                        Err(LpmError::AuthRequired)
                    }
                    answer => Ok(answer),
                }
            })
            .await?;
        let response = match answer {
            Answered::Success(response) => response,
            Answered::Failed(FailedResponse {
                status: 404 | 405,
                body,
                ..
            }) if !is_coded_refusal(&body) => return Ok(None),
            Answered::Failed(FailedResponse { status, body, .. }) => {
                return Err(publish_upload_refusal(status, &body, version));
            }
        };
        let upload: PublishUpload =
            parse_capped_api_json(response, "publish upload response").await?;
        if upload.id.is_empty() {
            return Err(LpmError::Registry(
                "the Registry opened a tarball upload without an id".into(),
            ));
        }
        Ok(Some(upload))
    }

    /// Sends a publish's tarball to the URL `upload` was given, with its
    /// headers and no credential of the Registry's. The URL takes one write,
    /// so storage answering that it has the tarball already (412) means an
    /// earlier try stored it; the publish checks the bytes either way. A
    /// timeout, a rate limit, a server error or a network failure is
    /// retried.
    pub async fn upload_publish_tarball(
        &self,
        upload: &PublishUpload,
        tarball: &Arc<Vec<u8>>,
    ) -> Result<(), LpmError> {
        let url = reqwest::Url::parse(&upload.upload_url).map_err(|_| {
            LpmError::Registry("the Registry gave a tarball upload URL that isn't valid".into())
        })?;
        self.validate_request_url(&url)?;
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &upload.upload_headers {
            let header = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .ok()
                .filter(|_| tarball_upload_header_is_allowed(name))
                .ok_or_else(|| {
                    LpmError::Registry(format!(
                        "the Registry asked for a tarball upload header LPM doesn't send: {}",
                        lpm_common::sanitize_terminal_inline(name)
                    ))
                })?;
            let value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                LpmError::Registry(format!(
                    "the Registry gave a tarball upload header that isn't valid: {name}"
                ))
            })?;
            headers.insert(header, value);
        }
        let client = self.http.for_transfer_url(url.as_str()).await?;
        let timeout = tarball_upload_timeout(tarball.len());
        let body = bytes::Bytes::from_owner(SharedTarball(Arc::clone(tarball)));

        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            let progress = UploadProgress::new();
            let request = client
                .put(url.clone())
                .headers(headers.clone())
                .header(reqwest::header::CONTENT_LENGTH, body.len())
                .timeout(timeout)
                .body(reqwest::Body::wrap_stream(tarball_upload_chunks(
                    body.clone(),
                    Arc::clone(&progress),
                )));
            let sent = tokio::select! {
                sent = request.send() => sent.map_err(tarball_upload_network_error),
                () = progress.stalled(TARBALL_UPLOAD_STALL) => Err(LpmError::Network(format!(
                    "tarball upload stalled: nothing was sent or answered for {} s",
                    TARBALL_UPLOAD_STALL.as_secs()
                ))),
            };
            match sent {
                Ok(response) => match response.status().as_u16() {
                    200..=299 | 412 => return Ok(()),
                    status @ (408 | 429 | 500 | 502 | 503 | 504) => {
                        last_error = Some(tarball_upload_refusal(status, response).await);
                    }
                    status => return Err(tarball_upload_refusal(status, response).await),
                },
                Err(error) => last_error = Some(error),
            }
            if attempt < MAX_RETRIES {
                tokio::time::sleep(backoff_delay(attempt)).await;
            }
        }
        Err(last_error
            .unwrap_or_else(|| LpmError::Network("tarball upload failed after retries".into())))
    }

    /// Read the current publication lifecycle state for an uploaded LPM version.
    pub async fn get_publication_status(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PublicationStatusResponse, LpmError> {
        let url = format!(
            "{}/api/registry/-/package/publication-status?name={}&version={}",
            self.base_url,
            urlencoding::encode(name),
            urlencoding::encode(version)
        );
        let response: PublicationStatusResponse = self
            .execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await?;
        if response.name != name || response.version != version {
            return Err(LpmError::Registry(format!(
                "publication status returned a mismatched package identity (expected {name}@{version}, received {}@{})",
                response.name, response.version
            )));
        }
        Ok(response)
    }

    /// Revoke the current refresh-backed CLI session on the server.
    ///
    /// Posture: `SessionRequired`. The bearer is re-resolved inside the
    /// recovery closure so that, on a 401 → refresh → retry, the
    /// rotated token is sent on the second attempt.
    ///
    /// Calls: POST /api/cli/revoke
    pub async fn revoke_session(&self) -> Result<(), LpmError> {
        let url = format!("{}/api/cli/revoke", self.base_url);

        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let bearer = self
                .current_bearer(AuthPosture::SessionRequired)?
                .ok_or(LpmError::SessionExpired)?;
            let req = self
                .http
                .for_url(&url)
                .await?
                .post(&url)
                .bearer_auth(&bearer);
            let response = self.send_with_retry(req).await?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(LpmError::Registry(format!(
                    "session revocation failed: {}",
                    response.status()
                )))
            }
        })
        .await
    }

    /// Publish a package to the registry.
    ///
    /// Posture: `AuthRequired`. Wrapped in `execute_with_recovery`
    /// so a stale access token on a refresh-backed session triggers
    /// one silent refresh + retry of the entire publish. The bespoke
    /// 500-handling inside `send_publish_safe` is preserved because it
    /// lives inside the closure and runs on each attempt.
    ///
    /// Calls: PUT /api/registry/{encoded_name}
    /// Optional `otp` header for 2FA-enabled users. When the registry asks
    /// for the second factor as a browser approval instead, this returns
    /// `LpmError::BrowserApprovalRequired`; publish again with the token the
    /// approval gives through `publish_approved_package`.
    ///
    /// Uses publish-safe retry logic (S4): does NOT retry on HTTP 500
    /// (the server may have stored the version before crashing). Only retries
    /// on gateway errors (502/503/504) and network-level failures.
    ///
    /// Timeout is scaled based on tarball size (S3): 60s + 2s per MB, cap 600s.
    pub async fn publish_package(
        &self,
        encoded_name: &str,
        published_version: &str,
        published_integrity: &str,
        payload: &lpm_http::ReplayableRequestBody,
        otp: Option<&str>,
        tarball_size_bytes: usize,
    ) -> Result<serde_json::Value, LpmError> {
        self.send_publish(
            encoded_name,
            published_version,
            published_integrity,
            payload,
            otp.map(SecondFactorProof::Code),
            tarball_size_bytes,
        )
        .await
    }

    /// Publish a package whose second factor the user approved in the
    /// browser, carrying the approval's one-time token. Otherwise as
    /// `publish_package`.
    pub async fn publish_approved_package(
        &self,
        encoded_name: &str,
        published_version: &str,
        published_integrity: &str,
        payload: &lpm_http::ReplayableRequestBody,
        approval_token: &str,
        tarball_size_bytes: usize,
    ) -> Result<serde_json::Value, LpmError> {
        self.send_publish(
            encoded_name,
            published_version,
            published_integrity,
            payload,
            Some(SecondFactorProof::Approval(approval_token)),
            tarball_size_bytes,
        )
        .await
    }

    async fn send_publish(
        &self,
        encoded_name: &str,
        published_version: &str,
        published_integrity: &str,
        payload: &lpm_http::ReplayableRequestBody,
        second_factor: Option<SecondFactorProof<'_>>,
        tarball_size_bytes: usize,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/registry/{}", self.base_url, encoded_name);

        // S3: Scale timeout based on tarball size
        let tarball_mb = tarball_size_bytes as u64 / (1024 * 1024);
        let timeout_secs = std::cmp::min(60 + tarball_mb * 2, 600);
        let timeout = Duration::from_secs(timeout_secs);
        let publish_client = self.http.for_url_no_build(&url).clone();

        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let bearer = self.current_bearer(AuthPosture::AuthRequired)?;

            // S4: Publish-safe send — no retry on 500, only on gateway errors
            let response = self
                .send_publish_safe(
                    || {
                        let body = payload.body();
                        let mut request = publish_client
                            .put(&url)
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .header(reqwest::header::CONTENT_LENGTH, payload.len())
                            .header(super::second_factor::BROWSER_APPROVAL_SUPPORT_HEADER, "1")
                            .timeout(timeout)
                            .body(body);
                        if let Some(bearer) = bearer.as_ref() {
                            request = request.bearer_auth(bearer);
                        }
                        if let Some(proof) = second_factor {
                            let (header, value) = proof.header();
                            request = request.header(header, value);
                        }
                        Ok(request)
                    },
                    payload,
                    bearer.as_deref(),
                    encoded_name,
                    published_version,
                    published_integrity,
                )
                .await?;
            let (status, body) = match response {
                PublishSafeResponse::Response(response) => {
                    let status = response.status();
                    let body = parse_capped_api_json(response, "publish response").await?;
                    (status, body)
                }
                PublishSafeResponse::Recovered(body) => (reqwest::StatusCode::OK, body),
            };

            if status.is_success() {
                return Ok(body);
            }
            let error_msg = body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error");
            let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("");

            Err(LpmError::Registry(format!(
                "publish failed ({}): {} {}",
                status,
                error_msg,
                if code.is_empty() {
                    String::new()
                } else {
                    format!("[{code}]")
                }
            )))
        })
        .await
    }

    // ─── Intelligence Endpoints ─────────────────────────────────────

    /// Get quality report for a package.
    ///
    /// Public reports allow anonymous reads; private reports require publisher access.
    ///
    /// Calls: GET /api/registry/quality?name=owner.package-name
    pub async fn get_quality(&self, name: &str) -> Result<QualityResponse, LpmError> {
        let url = format!(
            "{}/api/registry/quality?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.execute_with_package_access_recovery(|| self.get_json(&url))
            .await
    }

    /// Read an optional install report using available credentials without refreshing a session.
    pub async fn get_quality_for_install(&self, name: &str) -> Result<QualityResponse, LpmError> {
        let url = format!(
            "{}/api/registry/quality?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.get_json(&url).await
    }

    /// Get Agent Skills for a package.
    ///
    /// Private package skills and publisher-only
    /// pending versions must follow the same principal as package metadata
    /// and tarball access.
    ///
    /// Calls: GET /api/registry/skills?name=owner.package-name
    pub async fn get_skills(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SkillsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/skills?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.execute_with_package_access_recovery(|| self.get_json(&url))
            .await
    }

    /// Get API documentation for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/api-docs?name=owner.package-name
    pub async fn get_api_docs(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<ApiDocsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/api-docs?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get LLM context for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/llm-context?name=owner.package-name
    pub async fn get_llm_context(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<LlmContextResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/llm-context?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    // ─── Revenue Endpoints ──────────────────────────────────────────

    /// Get Pool revenue stats for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Wrapped in
    /// `execute_with_recovery` so a stale stored session self-heals.
    ///
    /// Calls: GET /api/registry/pool/stats
    pub async fn get_pool_stats(&self) -> Result<PoolStatsResponse, LpmError> {
        let url = format!("{}/api/registry/pool/stats", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Get Marketplace earnings for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Same recovery
    /// contract as `get_pool_stats`.
    ///
    /// Calls: GET /api/registry/marketplace/earnings
    pub async fn get_marketplace_earnings(&self) -> Result<MarketplaceEarningsResponse, LpmError> {
        let url = format!("{}/api/registry/marketplace/earnings", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Health ─────────────────────────────────────────────────────

    /// Check registry health.
    ///
    /// Posture: `AnonymousOnly` — health endpoint is universally
    /// public and must never carry a bearer.
    ///
    /// Calls: GET /api/registry/health
    pub async fn health_check(&self) -> Result<bool, LpmError> {
        let url = format!("{}/api/registry/health", self.base_url);
        let response = self
            .send_with_retry(
                self.build_get_with_posture(&url, AuthPosture::AnonymousOnly)
                    .await?,
            )
            .await?;
        Ok(response.status().is_success())
    }

    // ─── Tunnel Endpoints ──────────────────────────────────────────

    /// List claimed tunnel domains.
    ///
    /// Posture: `SessionRequired`. Wrapped in `execute_with_recovery`
    /// so stale-access-token cases still self-heal for refresh-backed
    /// sessions.
    ///
    /// Calls: GET /api/tunnel/domains or GET /api/tunnel/domains?org=slug
    pub async fn tunnel_list(&self, org_slug: Option<&str>) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains?org={}",
                self.base_url,
                urlencoding::encode(slug)
            )
        } else {
            format!("{}/api/tunnel/domains", self.base_url)
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }

    /// Claim a tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list`.
    ///
    /// Calls: POST /api/tunnel/domains
    /// Body: { domain: "acme-api.lpm.llc", org?: "acmecorp" }
    pub async fn tunnel_claim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains", self.base_url);
        let mut body = serde_json::json!({ "domain": domain });
        if let Some(slug) = org_slug {
            body["org"] = serde_json::Value::String(slug.to_string());
        }
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let response = self.post_json_raw(&url, &body).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel claim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// Release a claimed tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list`.
    ///
    /// Calls: DELETE /api/tunnel/domains/{domain}
    pub async fn tunnel_unclaim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains/{}?org={}",
                self.base_url,
                urlencoding::encode(domain),
                urlencoding::encode(slug)
            )
        } else {
            format!(
                "{}/api/tunnel/domains/{}",
                self.base_url,
                urlencoding::encode(domain)
            )
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let mut req = self.http.for_url(&url).await?.delete(&url);
            if let Some(bearer) = self.current_bearer(AuthPosture::SessionRequired)? {
                req = req.bearer_auth(bearer);
            }
            let response = self.send_with_retry(req).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel unclaim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// List available tunnel base domains.
    ///
    /// Posture: `AnonymousPreferred` — endpoint is documented public.
    /// No bearer attached, no recovery on 401.
    ///
    /// Calls: GET /api/tunnel/domains/available
    pub async fn tunnel_available_domains(&self) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains/available", self.base_url);
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Look up a specific tunnel domain claim.
    ///
    /// Posture: `SessionRequired` (the response includes
    /// `ownedByYou` which depends on the caller's identity). Same
    /// recovery contract as `tunnel_list`.
    ///
    /// Calls: GET /api/tunnel/domains/{domain}
    pub async fn tunnel_domain_lookup(&self, domain: &str) -> Result<serde_json::Value, LpmError> {
        let url = format!(
            "{}/api/tunnel/domains/{}",
            self.base_url,
            urlencoding::encode(domain)
        );
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }

    /// Issue one authenticated tunnel ownership lookup without install-grade retries.
    /// Diagnostic callers apply the whole-operation deadline.
    pub async fn diagnostic_tunnel_domain_lookup_once(
        &self,
        domain: &str,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!(
            "{}/api/tunnel/domains/{}",
            self.base_url,
            urlencoding::encode(domain)
        );
        let request = self
            .build_get_with_posture(&url, AuthPosture::SessionRequired)
            .await?;
        let response = self.send_once_preserving_status(request).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(LpmError::Http {
                status: status.as_u16(),
                message: "tunnel diagnostic lookup failed".into(),
            });
        }
        parse_capped_api_json(response, "tunnel diagnostic lookup response").await
    }
}

fn validate_search_registry_base(base_url: &str) -> Result<(), LpmError> {
    let base = RequestDestination::parse(base_url)?;
    if base.as_url().query().is_some() || base.as_url().fragment().is_some() {
        return Err(LpmError::Registry(
            "search registry URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

impl PublishPreflightVerdict {
    /// The accepted answer, or the refusal as the error any other request's
    /// failure is (see [`super::transport::failed_answer_error`]), with the
    /// Registry's message where its body gives one, and the body otherwise.
    pub fn into_result(self) -> Result<PublishPreflightResponse, LpmError> {
        match self {
            Self::Accepted(response) => Ok(response),
            Self::Refused {
                status,
                body,
                retry_after_secs,
                ..
            } => {
                let message = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|json| json.get("error")?.as_str().map(str::to_owned))
                    .unwrap_or_else(|| body.clone());
                Err(super::transport::failed_answer_error(
                    status,
                    &body,
                    message,
                    retry_after_secs,
                ))
            }
        }
    }
}
