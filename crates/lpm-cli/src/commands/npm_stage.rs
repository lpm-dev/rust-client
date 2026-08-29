use crate::commands::publish_common::{
    NpmPayloadOptions, NpmProvenanceAttachment, TarballRef, build_npm_payload,
};
use crate::commands::publish_npm::NPM_REGISTRY_URL;
use crate::commands::web_auth;
use crate::output;
use flate2::read::GzDecoder;
use lpm_common::LpmError;
use lpm_runner::lpm_json::NpmPublishConfig;
use reqwest::Method;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const NPM_COMMAND_STAGE: &str = "stage";
const STAGE_LIST_PER_PAGE: u32 = 100;
const MAX_STAGE_LIST_ITEMS: usize = 10_000;
const MAX_STAGE_LIST_PAGES: usize = 100;
const MAX_STAGE_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STAGE_PACKUMENT_RESPONSE_BYTES: usize = 100 * 1024 * 1024;
const MAX_STAGE_UNCOMPRESSED_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STAGE_UNCOMPRESSED_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct StagePublishResult {
    pub(crate) stage_id: String,
    pub(crate) data: serde_json::Value,
    pub(crate) duration: Duration,
}

#[derive(Debug)]
pub(crate) struct StageListResult {
    pub(crate) items: Vec<serde_json::Value>,
    pub(crate) total: usize,
}

#[derive(Debug)]
pub(crate) struct StageDownloadResult {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
    pub(crate) manifest: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NpmStageRegistrySource {
    Default,
    Cli,
    Config,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NpmStageRegistry {
    url: String,
    source: NpmStageRegistrySource,
}

impl NpmStageRegistry {
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn source(&self) -> NpmStageRegistrySource {
        self.source
    }
}

#[derive(Clone, Copy)]
struct NpmStageRuntime {
    open_browser: bool,
    web_auth_timeout: Duration,
    web_auth_poll_interval: Duration,
}

impl NpmStageRuntime {
    fn production() -> Self {
        Self {
            open_browser: true,
            web_auth_timeout: Duration::from_secs(5 * 60),
            web_auth_poll_interval: Duration::from_secs(1),
        }
    }
}

pub(crate) fn resolve_npm_stage_registry_with_source(
    npm_config: Option<&NpmPublishConfig>,
    cli_registry: Option<&str>,
) -> Result<NpmStageRegistry, LpmError> {
    let (registry, source) = match cli_registry {
        Some(raw) if raw.trim().is_empty() => {
            return Err(LpmError::Registry(
                "--npm-registry must not be empty".into(),
            ));
        }
        Some(raw) => (
            raw.trim_end_matches('/').to_string(),
            NpmStageRegistrySource::Cli,
        ),
        None => match npm_config.and_then(|config| config.registry.as_deref()) {
            Some(raw) => (
                raw.trim_end_matches('/').to_string(),
                NpmStageRegistrySource::Config,
            ),
            None => (
                NPM_REGISTRY_URL.to_string(),
                NpmStageRegistrySource::Default,
            ),
        },
    };

    validate_npm_stage_registry(&registry)?;
    if registry != NPM_REGISTRY_URL {
        tracing::warn!(
            target_url = %lpm_common::safe_url_origin(&registry),
            default_url = NPM_REGISTRY_URL,
            "npm staged publish registry overridden; confirm the target and credentials are intentional",
        );
    }
    Ok(NpmStageRegistry {
        url: registry,
        source,
    })
}

pub(crate) fn validate_npm_stage_registry(registry_url: &str) -> Result<(), LpmError> {
    let safe_origin = lpm_common::safe_url_origin(registry_url);
    let parsed = reqwest::Url::parse(registry_url).map_err(|_| {
        LpmError::Registry(format!(
            "refusing invalid npm staged publish registry {safe_origin:?}"
        ))
    })?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Registry(format!(
            "refusing npm staged publish registry {safe_origin:?}: query and fragment components are not allowed"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Registry(format!(
            "refusing npm staged publish registry {safe_origin:?}: embedded credentials are not allowed"
        )));
    }
    if lpm_common::lpm_registry_url_is_accepted(registry_url) {
        return Ok(());
    }

    Err(LpmError::Registry(format!(
        "refusing npm staged publish registry {safe_origin:?}: use HTTPS, or HTTP loopback for local testing"
    )))
}

pub(crate) fn validate_stage_id(stage_id: &str) -> Result<(), LpmError> {
    let bytes = stage_id.as_bytes();
    if bytes.len() != 36 {
        return Err(invalid_stage_id(stage_id));
    }

    for (index, byte) in bytes.iter().copied().enumerate() {
        let valid = matches!(index, 8 | 13 | 18 | 23)
            .then_some(byte == b'-')
            .unwrap_or_else(|| byte.is_ascii_hexdigit());
        if !valid {
            return Err(invalid_stage_id(stage_id));
        }
    }

    Ok(())
}

fn invalid_stage_id(stage_id: &str) -> LpmError {
    LpmError::Registry(format!("invalid stage id {stage_id:?}: expected a UUID"))
}

pub(crate) fn parse_stage_list_filter(package: Option<&str>) -> Result<Option<String>, LpmError> {
    let Some(raw) = package.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let name = raw.strip_suffix("@*").unwrap_or(raw);
    let version_delimiter = if name.starts_with('@') {
        name.rfind('@').filter(|index| *index > 0)
    } else {
        name.find('@')
    };
    if version_delimiter.is_some() {
        return Err(LpmError::Registry(
            "version specifiers are not supported for listing staged packages".into(),
        ));
    }

    validate_package_filter_name(name)?;
    Ok(Some(name.to_string()))
}

fn validate_package_filter_name(name: &str) -> Result<(), LpmError> {
    if name.contains(char::is_whitespace) {
        return Err(LpmError::Registry(format!(
            "invalid package filter {name:?}: package names cannot contain whitespace"
        )));
    }

    if name.starts_with('@') && !name.contains('/') {
        return Err(LpmError::Registry(format!(
            "invalid package filter {name:?}: scoped package names must include /"
        )));
    }

    Ok(())
}

pub(crate) async fn fetch_package_metadata(
    token: &str,
    npm_name: &str,
    registry_url: &str,
) -> Result<crate::commands::publish_npm::NpmVersionPolicyMetadata, LpmError> {
    let client = stage_http_client(Duration::from_secs(60))?;
    let url = endpoint_url(registry_url, &urlencoding::encode(npm_name));
    let response = web_auth::add_npm_web_auth_headers(client.get(url), NPM_COMMAND_STAGE)
        .header(
            reqwest::header::ACCEPT,
            "application/vnd.npm.install-v1+json",
        )
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            LpmError::Registry(format!(
                "npm package metadata request failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    let status = response.status();
    let bytes = read_stage_response_body_with_limit(
        response,
        "npm package metadata",
        MAX_STAGE_PACKUMENT_RESPONSE_BYTES,
    )
    .await?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|error| {
            LpmError::Registry(format!(
                "npm package metadata response was invalid: {error}"
            ))
        });
    }

    let body = parse_json_response_or_empty(&bytes);

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(LpmError::Registry(format!(
            "npm staged publish requires {npm_name} to already exist on the registry"
        )));
    }

    Err(LpmError::Registry(stage_error_message(
        "npm package metadata request",
        status,
        &body,
        token,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn stage_publish(
    token: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &std::sync::Arc<Vec<u8>>,
    tarball_hashes: &crate::commands::publish_common::TarballHashes,
    provenance_attachment: Option<&NpmProvenanceAttachment>,
    access: &str,
    tag: &str,
    registry_url: &str,
) -> Result<StagePublishResult, LpmError> {
    stage_publish_impl(
        token,
        npm_name,
        version,
        version_data,
        tarball_data,
        tarball_hashes,
        provenance_attachment,
        access,
        tag,
        registry_url,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn stage_publish_impl(
    token: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &std::sync::Arc<Vec<u8>>,
    tarball_hashes: &crate::commands::publish_common::TarballHashes,
    provenance_attachment: Option<&NpmProvenanceAttachment>,
    access: &str,
    tag: &str,
    registry_url: &str,
) -> Result<StagePublishResult, LpmError> {
    validate_npm_stage_registry(registry_url)?;
    let started_at = std::time::Instant::now();
    let payload = build_npm_payload(
        registry_url,
        npm_name,
        version,
        version_data,
        TarballRef {
            data: tarball_data,
            hashes: tarball_hashes,
        },
        access,
        NpmPayloadOptions {
            tag: Some(tag),
            provenance_attachment,
        },
    )?;
    let tarball_mb = tarball_data.len() as u64 / (1024 * 1024);
    let timeout = Duration::from_secs(std::cmp::min(60 + tarball_mb * 2, 600));
    let client = stage_manual_redirect_http_client(timeout)?;
    let url = endpoint_url(
        registry_url,
        &format!("-/stage/package/{}", urlencoding::encode(npm_name)),
    );

    let request = web_auth::add_npm_web_auth_headers(client.post(url), NPM_COMMAND_STAGE)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_LENGTH, payload.len())
        .timeout(timeout)
        .body(payload.request_body())
        .bearer_auth(token)
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to build npm stage request: {e}")))?;
    let response =
        lpm_http::send_with_replayable_redirects(&client, request, Some(payload.replayable()))
            .await
            .map_err(|e| LpmError::Registry(format!("npm stage publish request failed: {e}")))?;

    let status = response.status();
    let body = response_json_or_empty(response, "npm stage publish").await?;
    if status.is_success() {
        let stage_id = body
            .get("stageId")
            .or_else(|| body.get("stage_id"))
            .or_else(|| body.get("id"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| LpmError::Registry("npm stage publish response missing stageId".into()))?
            .to_string();

        return Ok(StagePublishResult {
            stage_id,
            data: body,
            duration: started_at.elapsed(),
        });
    }

    Err(LpmError::Registry(stage_error_message(
        "npm stage publish",
        status,
        &body,
        token,
    )))
}

pub(crate) async fn list_staged_packages(
    token: &str,
    registry_url: &str,
    package_filter: Option<&str>,
) -> Result<StageListResult, LpmError> {
    validate_npm_stage_registry(registry_url)?;
    let client = stage_http_client(Duration::from_secs(60))?;
    let mut page = 0_usize;
    let mut items = Vec::new();

    loop {
        let mut query = Vec::with_capacity(3);
        query.push(("page", page.to_string()));
        query.push(("perPage", STAGE_LIST_PER_PAGE.to_string()));
        if let Some(package) = package_filter {
            query.push(("package", package.to_string()));
        }

        let response = web_auth::add_npm_web_auth_headers(
            client.get(endpoint_url(registry_url, "-/stage")),
            NPM_COMMAND_STAGE,
        )
        .query(&query)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            LpmError::Registry(format!(
                "npm stage list request failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;

        let status = response.status();
        let body = response_json_or_empty(response, "npm stage list").await?;
        if !status.is_success() {
            return Err(LpmError::Registry(stage_error_message(
                "npm stage list",
                status,
                &body,
                token,
            )));
        }

        let page_items = body
            .get("items")
            .and_then(|value| value.as_array())
            .ok_or_else(|| LpmError::Registry("npm stage list response missing items".into()))?;
        let page_total_u64 = body
            .get("total")
            .and_then(|value| value.as_u64())
            .unwrap_or_else(|| (items.len() + page_items.len()) as u64);
        let page_total = usize::try_from(page_total_u64).map_err(|_| {
            LpmError::Registry("npm stage list total exceeds the supported item limit".into())
        })?;
        if page_total > MAX_STAGE_LIST_ITEMS {
            return Err(LpmError::Registry(format!(
                "npm stage list total exceeds the {MAX_STAGE_LIST_ITEMS}-item limit"
            )));
        }
        if items.len().saturating_add(page_items.len()) > MAX_STAGE_LIST_ITEMS {
            return Err(LpmError::Registry(format!(
                "npm stage list exceeds the {MAX_STAGE_LIST_ITEMS}-item limit"
            )));
        }
        items.reserve(page_items.len());
        items.extend(page_items.iter().cloned());

        if items.len() >= page_total || page_items.len() < STAGE_LIST_PER_PAGE as usize {
            return Ok(StageListResult {
                total: page_total,
                items,
            });
        }
        page = page
            .checked_add(1)
            .ok_or_else(|| LpmError::Registry("npm stage list page overflow".into()))?;
        if page >= MAX_STAGE_LIST_PAGES {
            return Err(LpmError::Registry(format!(
                "npm stage list exceeds the {MAX_STAGE_LIST_PAGES}-page limit"
            )));
        }
    }
}

pub(crate) async fn view_staged_package(
    token: &str,
    registry_url: &str,
    stage_id: &str,
) -> Result<serde_json::Value, LpmError> {
    validate_stage_id(stage_id)?;
    stage_json_get(
        token,
        registry_url,
        &format!("-/stage/{stage_id}"),
        "npm stage view",
    )
    .await
}

pub(crate) async fn approve_staged_package(
    token: &str,
    registry_url: &str,
    stage_id: &str,
    otp: Option<&str>,
    json_output: bool,
    yes: bool,
) -> Result<serde_json::Value, LpmError> {
    validate_stage_id(stage_id)?;
    stage_otp_mutation(
        token,
        registry_url,
        &format!("-/stage/{stage_id}/approve"),
        Method::POST,
        "approve staged package",
        otp,
        json_output,
        yes,
        NpmStageRuntime::production(),
    )
    .await
}

pub(crate) async fn reject_staged_package(
    token: &str,
    registry_url: &str,
    stage_id: &str,
    otp: Option<&str>,
    json_output: bool,
    yes: bool,
) -> Result<serde_json::Value, LpmError> {
    validate_stage_id(stage_id)?;
    stage_otp_mutation(
        token,
        registry_url,
        &format!("-/stage/{stage_id}"),
        Method::DELETE,
        "reject staged package",
        otp,
        json_output,
        yes,
        NpmStageRuntime::production(),
    )
    .await
}

pub(crate) async fn download_staged_package(
    token: &str,
    registry_url: &str,
    stage_id: &str,
    output_dir: &Path,
) -> Result<StageDownloadResult, LpmError> {
    validate_stage_id(stage_id)?;
    validate_npm_stage_registry(registry_url)?;
    let client = stage_http_client(Duration::from_secs(10 * 60))?;
    let response = web_auth::add_npm_web_auth_headers(
        client.get(endpoint_url(
            registry_url,
            &format!("-/stage/{stage_id}/tarball"),
        )),
        NPM_COMMAND_STAGE,
    )
    .bearer_auth(token)
    .send()
    .await
    .map_err(|e| {
        LpmError::Registry(format!(
            "npm stage download request failed: {}",
            lpm_http::display_error(&e)
        ))
    })?;

    let status = response.status();
    if !status.is_success() {
        let body = response_json_or_empty(response, "npm stage download error").await?;
        return Err(LpmError::Registry(stage_error_message(
            "npm stage download",
            status,
            &body,
            token,
        )));
    }

    if let Some(content_length) = response.content_length()
        && content_length > lpm_registry::MAX_COMPRESSED_TARBALL_SIZE
    {
        return Err(LpmError::Registry(format!(
            "staged tarball Content-Length exceeds maximum compressed size ({content_length} bytes > {} bytes limit)",
            lpm_registry::MAX_COMPRESSED_TARBALL_SIZE
        )));
    }
    let temporary = tempfile::NamedTempFile::new_in(output_dir).map_err(LpmError::Io)?;
    let temporary_writer = temporary.reopen().map_err(LpmError::Io)?;
    let mut temporary_writer = tokio::fs::File::from_std(temporary_writer);
    let mut bytes = 0_u64;
    let mut stream = response.bytes_stream();
    use futures::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            LpmError::Registry(format!("npm stage download body failed: {error}"))
        })?;
        bytes = bytes
            .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| LpmError::Registry("staged tarball size overflow".into()))?;
        if bytes > lpm_registry::MAX_COMPRESSED_TARBALL_SIZE {
            return Err(LpmError::Registry(format!(
                "staged tarball exceeds maximum compressed size of {} bytes",
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE
            )));
        }
        temporary_writer
            .write_all(&chunk)
            .await
            .map_err(LpmError::Io)?;
    }
    temporary_writer.flush().await.map_err(LpmError::Io)?;
    temporary_writer.sync_all().await.map_err(LpmError::Io)?;
    drop(temporary_writer);
    let archive = std::fs::File::open(temporary.path()).map_err(LpmError::Io)?;
    let manifest = read_manifest_from_tarball_reader(archive, 100_000)?;
    let name = manifest
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("downloaded staged tarball missing package name".into())
        })?;
    let version = manifest
        .get("version")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("downloaded staged tarball missing package version".into())
        })?;
    crate::commands::publish_npm::validate_npm_name(name).map_err(|error| {
        LpmError::Registry(format!(
            "downloaded staged tarball has an invalid package name: {error}"
        ))
    })?;
    crate::commands::publish::validate_publish_version(version).map_err(|error| {
        LpmError::Registry(format!(
            "downloaded staged tarball has an invalid package version {version:?}: {error}"
        ))
    })?;
    let filename = format!("{}-{version}-{stage_id}.tgz", safe_tarball_name(name));
    let path = output_dir.join(filename);
    if path.parent() != Some(output_dir) {
        return Err(LpmError::Registry(
            "downloaded staged tarball identity did not produce a contained filename".into(),
        ));
    }
    temporary
        .persist_noclobber(&path)
        .map_err(|error| LpmError::Io(error.error))?;

    Ok(StageDownloadResult {
        path,
        bytes,
        manifest,
    })
}

async fn stage_json_get(
    token: &str,
    registry_url: &str,
    route: &str,
    action: &str,
) -> Result<serde_json::Value, LpmError> {
    validate_npm_stage_registry(registry_url)?;
    let client = stage_http_client(Duration::from_secs(60))?;
    let response = web_auth::add_npm_web_auth_headers(
        client.get(endpoint_url(registry_url, route)),
        NPM_COMMAND_STAGE,
    )
    .bearer_auth(token)
    .send()
    .await
    .map_err(|e| {
        LpmError::Registry(format!(
            "{action} request failed: {}",
            lpm_http::display_error(&e)
        ))
    })?;

    let status = response.status();
    let body = response_json_or_empty(response, action).await?;
    if status.is_success() {
        return Ok(body);
    }

    Err(LpmError::Registry(stage_error_message(
        action, status, &body, token,
    )))
}

#[allow(clippy::too_many_arguments)]
async fn stage_otp_mutation(
    token: &str,
    registry_url: &str,
    route: &str,
    method: Method,
    action: &str,
    otp: Option<&str>,
    json_output: bool,
    yes: bool,
    runtime: NpmStageRuntime,
) -> Result<serde_json::Value, LpmError> {
    validate_npm_stage_registry(registry_url)?;
    let timeout = Duration::from_secs(60);
    let mutation_client = stage_manual_redirect_http_client(timeout)?;
    let response = send_stage_mutation(
        &mutation_client,
        token,
        registry_url,
        route,
        method.clone(),
        otp,
        timeout,
    )
    .await
    .map_err(|e| LpmError::Registry(format!("{action} request failed: {e}")))?;
    let status = response.status();
    let headers = response.headers().clone();

    if status.is_success() {
        return response_json_or_empty(response, action).await;
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        let body = response_json_or_empty(response, action).await?;
        if let Some(challenge) = web_auth::parse_web_auth_challenge_from_body(&body, registry_url) {
            if !can_prompt(json_output, yes) {
                return Err(LpmError::Registry(format!(
                    "npm requires browser authentication to {action}, but this command is running in non-interactive mode"
                )));
            }

            let otp = web_auth::complete_web_auth_challenge(
                &challenge,
                action,
                json_output,
                runtime.open_browser,
                runtime.web_auth_timeout,
                runtime.web_auth_poll_interval,
            )
            .await?;
            let retry = send_stage_mutation(
                &mutation_client,
                token,
                registry_url,
                route,
                method,
                Some(&otp),
                timeout,
            )
            .await
            .map_err(|e| LpmError::Registry(format!("{action} retry failed: {e}")))?;
            return stage_mutation_response(action, retry, token).await;
        }

        if is_otp_required(&headers) {
            if !can_prompt(json_output, yes) {
                return Err(LpmError::Registry(format!(
                    "npm OTP required to {action}. Pass --otp <code> or rerun in an interactive TTY."
                )));
            }

            if !json_output {
                output::warn("npm requires a one-time password");
            }

            let otp = prompt_npm_otp()?;
            let retry = send_stage_mutation(
                &mutation_client,
                token,
                registry_url,
                route,
                method,
                Some(&otp),
                timeout,
            )
            .await
            .map_err(|e| LpmError::Registry(format!("{action} retry failed: {e}")))?;
            return stage_mutation_response(action, retry, token).await;
        }

        return Err(LpmError::Registry(stage_error_message(
            action, status, &body, token,
        )));
    }

    stage_mutation_response(action, response, token).await
}

async fn send_stage_mutation(
    client: &reqwest::Client,
    token: &str,
    registry_url: &str,
    route: &str,
    method: Method,
    otp: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Response, lpm_http::ReplayableRequestError<std::convert::Infallible>> {
    let mut request = web_auth::add_npm_web_auth_headers(
        client.request(method, endpoint_url(registry_url, route)),
        NPM_COMMAND_STAGE,
    )
    .bearer_auth(token);
    if let Some(code) = otp {
        request = request.header("npm-otp", code);
    }
    let request = request
        .timeout(timeout)
        .build()
        .map_err(lpm_http::ReplayableRequestError::request)?;
    lpm_http::send_with_replayable_redirects(client, request, None).await
}

async fn stage_mutation_response(
    action: &str,
    response: reqwest::Response,
    token: &str,
) -> Result<serde_json::Value, LpmError> {
    let status = response.status();
    let body = response_json_or_empty(response, action).await?;
    if status.is_success() {
        return Ok(body);
    }

    Err(LpmError::Registry(stage_error_message(
        action, status, &body, token,
    )))
}

fn stage_http_client(timeout: Duration) -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .timeout(timeout)
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))
}

fn stage_manual_redirect_http_client(timeout: Duration) -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))
}

pub(crate) fn endpoint_url(registry_url: &str, route: &str) -> String {
    format!(
        "{}/{}",
        registry_url.trim_end_matches('/'),
        route.trim_start_matches('/')
    )
}

fn can_prompt(json_output: bool, yes: bool) -> bool {
    !json_output && !yes && web_auth::terminal_is_interactive()
}

fn is_otp_required(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("otp"))
}

fn prompt_npm_otp() -> Result<String, LpmError> {
    cliclack::input("Enter npm one-time password")
        .interact()
        .map_err(|e| LpmError::Registry(e.to_string()))
}

async fn response_json_or_empty(
    response: reqwest::Response,
    label: &str,
) -> Result<serde_json::Value, LpmError> {
    let bytes = read_stage_response_body(response, label).await?;
    Ok(parse_json_response_or_empty(&bytes))
}

async fn read_stage_response_body(
    response: reqwest::Response,
    label: &str,
) -> Result<Vec<u8>, LpmError> {
    read_stage_response_body_with_limit(response, label, MAX_STAGE_JSON_RESPONSE_BYTES).await
}

async fn read_stage_response_body_with_limit(
    response: reqwest::Response,
    label: &str,
    limit: usize,
) -> Result<Vec<u8>, LpmError> {
    lpm_http::read_body_capped(response, limit)
        .await
        .map_err(|error| {
            LpmError::Registry(format!(
                "{label} response body limit exceeded or could not be read: {error}"
            ))
        })
}

fn parse_json_response_or_empty(bytes: &[u8]) -> serde_json::Value {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return serde_json::json!({});
    }
    serde_json::from_slice(bytes)
        .unwrap_or_else(|_| serde_json::json!({ "error": String::from_utf8_lossy(bytes) }))
}

fn stage_error_message(
    action: &str,
    status: reqwest::StatusCode,
    body: &serde_json::Value,
    token: &str,
) -> String {
    let error = body
        .get("error")
        .or_else(|| body.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let error = lpm_common::redact_exact_secret(error, token);
    match status.as_u16() {
        401 => format!(
            "{action} failed: authentication failed. Run `lpm login --npm` or set NPM_TOKEN."
        ),
        403 => format!(
            "{action} forbidden — token may lack npm staged-publish permission. npm says: {error}"
        ),
        404 => format!("{action} failed: staged package or endpoint not found. npm says: {error}"),
        409 => format!(
            "{action} failed: package version already exists or is already staged. npm says: {error}"
        ),
        429 => format!("{action} failed: npm rate limit exceeded. Wait and try again."),
        _ => format!("{action} failed (HTTP {status}): {error}"),
    }
}

#[cfg(test)]
fn read_manifest_from_tarball_with_entry_limit(
    data: &[u8],
    max_entries: usize,
) -> Result<serde_json::Value, LpmError> {
    read_manifest_from_tarball_reader(data, max_entries)
}

fn read_manifest_from_tarball_reader(
    reader: impl Read,
    max_entries: usize,
) -> Result<serde_json::Value, LpmError> {
    let decoder = GzDecoder::new(reader);
    let mut archive_limits = lpm_extractor::TarArchiveLimits::new(max_entries);
    archive_limits.max_entry_bytes = MAX_STAGE_UNCOMPRESSED_ENTRY_BYTES;
    archive_limits.max_total_entry_bytes = MAX_STAGE_UNCOMPRESSED_ARCHIVE_BYTES;
    let (_, manifest) = lpm_extractor::visit_tar_archive(decoder, archive_limits, |mut entry| {
        if entry.path() == Path::new("package/package.json") {
            if entry.size() > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
                return Err(LpmError::Registry(format!(
                    "staged manifest exceeds the {}-byte limit",
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES
                )));
            }
            let mut content = Vec::with_capacity(entry.size() as usize);
            entry
                .by_ref()
                .take(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES.saturating_add(1))
                .read_to_end(&mut content)
                .map_err(|e| LpmError::Registry(format!("failed to read staged manifest: {e}")))?;
            if content.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
                return Err(LpmError::Registry(format!(
                    "staged manifest exceeds the {}-byte limit",
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES
                )));
            }
            let manifest = serde_json::from_slice(&content)
                .map_err(|e| LpmError::Registry(format!("staged manifest is invalid JSON: {e}")))?;
            return Ok(std::ops::ControlFlow::Break(manifest));
        }
        Ok(std::ops::ControlFlow::Continue(()))
    })?;

    manifest.ok_or_else(|| {
        LpmError::Registry("downloaded staged tarball missing package/package.json".into())
    })
}

fn safe_tarball_name(name: &str) -> String {
    name.trim_start_matches('@').replace('/', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn staged_tarball(manifest: serde_json::Value) -> Vec<u8> {
        use std::io::Write as _;

        let manifest = serde_json::to_vec(&manifest).unwrap();
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", manifest.as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn staged_manifest_scan_enforces_its_entry_limit() {
        use std::io::Write as _;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for path in ["package/a", "package/b", "package/package.json"] {
                let content: &[u8] = if path.ends_with("package.json") {
                    b"{}"
                } else {
                    b""
                };
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, content).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        let archive = encoder.finish().unwrap();

        let error = read_manifest_from_tarball_with_entry_limit(&archive, 2)
            .expect_err("the staged manifest scan accepted too many entries");

        assert!(
            error.to_string().contains("too many"),
            "expected entry-count limit error, got: {error}"
        );
    }

    #[test]
    fn staged_manifest_scan_rejects_an_oversized_declared_uncompressed_entry() {
        use std::io::Write as _;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut manifest_header = tar::Header::new_gnu();
            manifest_header.set_size(2);
            manifest_header.set_mode(0o644);
            manifest_header.set_cksum();
            builder
                .append_data(&mut manifest_header, "package/package.json", &b"{}"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        tar_data.truncate(tar_data.len().saturating_sub(1024));
        let mut oversized_header = tar::Header::new_gnu();
        oversized_header.set_path("package/oversized.bin").unwrap();
        oversized_header.set_size(512 * 1024 * 1024 + 1);
        oversized_header.set_mode(0o644);
        oversized_header.set_cksum();
        tar_data.extend_from_slice(oversized_header.as_bytes());
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        let archive = encoder.finish().unwrap();

        let error = read_manifest_from_tarball_with_entry_limit(&archive, 100_000)
            .expect_err("an oversized declared uncompressed entry must be rejected");

        assert!(
            error.to_string().contains("per-entry cap"),
            "staged archive refusal must identify the expansion limit: {error}"
        );
    }

    #[test]
    fn endpoint_url_joins_registry_and_route_once() {
        assert_eq!(
            endpoint_url("https://registry.npmjs.org/", "/-/stage"),
            "https://registry.npmjs.org/-/stage"
        );
    }

    #[test]
    fn validate_stage_id_accepts_uuid_shape() {
        assert!(validate_stage_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
    }

    #[test]
    fn validate_stage_id_rejects_non_uuid_shape() {
        let err = validate_stage_id("not-a-stage-id").unwrap_err().to_string();
        assert!(err.contains("expected a UUID"));
    }

    #[test]
    fn parse_stage_list_filter_rejects_version_specifiers() {
        let err = parse_stage_list_filter(Some("@scope/pkg@1.0.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Version specifiers") || err.contains("version specifiers"));
    }

    #[test]
    fn parse_stage_list_filter_accepts_scoped_star_filter() {
        assert_eq!(
            parse_stage_list_filter(Some("@scope/pkg@*")).unwrap(),
            Some("@scope/pkg".to_string())
        );
    }

    #[test]
    fn resolve_npm_stage_registry_allows_loopback_http() {
        let registry =
            resolve_npm_stage_registry_with_source(None, Some("http://127.0.0.1:4873")).unwrap();

        assert_eq!(registry.url(), "http://127.0.0.1:4873");
        assert_eq!(registry.source(), NpmStageRegistrySource::Cli);
    }

    #[test]
    fn resolve_npm_stage_registry_rejects_non_loopback_http() {
        let err =
            resolve_npm_stage_registry_with_source(None, Some("http://packages.example.test"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("use HTTPS"));
    }

    #[test]
    fn resolve_npm_stage_registry_rejects_query_and_fragment_without_echoing_them() {
        let secret = "registry-query-secret";
        let error = resolve_npm_stage_registry_with_source(
            None,
            Some(&format!(
                "https://registry.example.test/npm?token={secret}#fragment"
            )),
        )
        .expect_err("registry query and fragment components must be rejected")
        .to_string();

        assert!(error.contains("query") || error.contains("fragment"));
        assert!(
            !error.contains(secret),
            "registry errors must redact URL query text"
        );
    }

    #[tokio::test]
    async fn stage_publish_attaches_explicit_sigstore_bundle() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/stage/package/plain-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "stageId": "stage-123"
            })))
            .mount(&server)
            .await;
        let provenance = NpmProvenanceAttachment {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".into(),
            data: r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2"}"#.into(),
        };

        let tarball = std::sync::Arc::new(b"fake-tarball".to_vec());
        let hashes = crate::commands::publish_common::compute_hashes(&tarball);
        let result = stage_publish_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({"name": "plain-pkg", "version": "1.0.0"}),
            &tarball,
            &hashes,
            Some(&provenance),
            "public",
            "latest",
            &server.uri(),
        )
        .await
        .expect("stage publish should succeed");

        assert_eq!(result.stage_id, "stage-123");
        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| request.method.as_str() == "POST")
            .expect("stage request should be recorded");
        let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let attachment = &payload["_attachments"]["plain-pkg-1.0.0.sigstore"];
        assert_eq!(attachment["content_type"], provenance.media_type.as_ref());
        assert_eq!(attachment["data"], provenance.data.as_ref());
        assert_eq!(attachment["length"], provenance.data.len());
    }

    #[tokio::test]
    async fn stage_metadata_ignores_irrelevant_packument_documents() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/plain-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "plain-pkg",
                "dist-tags": ["intentionally", "not", "an", "object"],
                "time": {"created": ["not", "a", "timestamp"]},
                "readme": {"unexpected": "shape"},
                "_attachments": {"ignored.tgz": {"data": [1, 2, 3]}},
                "versions": {
                    "1.0.0": {
                        "name": "plain-pkg",
                        "version": "1.0.0",
                        "dependencies": ["unexpected", "shape"],
                        "dist": "also ignored"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let metadata = fetch_package_metadata("npm-token", "plain-pkg", &server.uri())
            .await
            .expect("irrelevant packument documents must not affect stage policy metadata");

        assert!(
            crate::commands::publish_npm::enforce_npm_version_policy(
                &metadata,
                "plain-pkg",
                "1.1.0",
                false,
            )
            .is_ok(),
        );
    }

    #[tokio::test]
    async fn stage_metadata_requests_and_accepts_a_large_abbreviated_packument() {
        let server = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "plain-pkg",
            "versions": {},
            "padding": "x".repeat(17 * 1024 * 1024),
        })
        .to_string();
        Mock::given(method("GET"))
            .and(path("/plain-pkg"))
            .and(header("accept", "application/vnd.npm.install-v1+json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument))
            .expect(1)
            .mount(&server)
            .await;

        let metadata = fetch_package_metadata("npm-token", "plain-pkg", &server.uri())
            .await
            .expect("large abbreviated packuments within the npm metadata cap must be accepted");

        assert!(
            crate::commands::publish_npm::enforce_npm_version_policy(
                &metadata,
                "plain-pkg",
                "1.0.0",
                false,
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn stage_list_rejects_a_remote_total_above_the_aggregate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/stage"))
            .and(query_param("page", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": vec![serde_json::json!({"id": "stage"}); 100],
                "total": u64::MAX,
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/-/stage"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [],
                "total": u64::MAX,
            })))
            .mount(&server)
            .await;

        let error = list_staged_packages("npm-token", &server.uri(), None)
            .await
            .expect_err("an unbounded remote pagination total must be rejected");

        assert!(
            error.to_string().contains("limit"),
            "pagination refusal must name the aggregate limit: {error}"
        );
    }

    #[tokio::test]
    async fn stage_download_rejects_manifest_identity_that_can_escape_the_output_directory() {
        let stage_id = "123e4567-e89b-12d3-a456-426614174000";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/-/stage/{stage_id}/tarball")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(staged_tarball(
                serde_json::json!({
                    "name": "plain-pkg",
                    "version": "1.0.0/../../escaped",
                }),
            )))
            .expect(1)
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("downloads");
        std::fs::create_dir_all(output.join("plain-pkg-1.0.0")).unwrap();
        let escaped = root.path().join(format!("escaped-{stage_id}.tgz"));

        let error = download_staged_package("npm-token", &server.uri(), stage_id, &output)
            .await
            .expect_err("manifest identity must not influence the destination path");

        assert!(error.to_string().contains("version"));
        assert!(
            !escaped.exists(),
            "staged download escaped its output directory"
        );
    }

    #[tokio::test]
    async fn stage_list_redacts_a_registry_reflection_of_its_bearer() {
        let token = "stage-reflection-secret";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/stage"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": format!("submitted bearer was {token}"),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = list_staged_packages(token, &server.uri(), None)
            .await
            .expect_err("registry rejection must remain an error")
            .to_string();

        assert!(
            !error.contains(token),
            "reflected bearer leaked through the error: {error}"
        );
        assert!(error.contains("<redacted>"));
    }

    #[tokio::test]
    async fn stage_download_rejects_an_oversized_declared_tarball_before_reading_it() {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE + 1
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let output = tempfile::tempdir().unwrap();

        let error = download_staged_package(
            "npm-token",
            &format!("http://{address}"),
            "123e4567-e89b-12d3-a456-426614174000",
            output.path(),
        )
        .await
        .expect_err("an oversized staged tarball must be rejected");
        server.await.unwrap();

        assert!(
            error.to_string().contains("maximum compressed size"),
            "the download must fail at its declared-size boundary: {error}",
        );
        assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn stage_publish_replays_exact_post_body_across_same_origin_307() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/stage/package/plain-pkg"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/redirected-stage"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/redirected-stage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "stageId": "stage-redirected"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let tarball = std::sync::Arc::new(b"redirected-tarball".to_vec());
        let hashes = crate::commands::publish_common::compute_hashes(&tarball);
        let result = stage_publish_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({"name": "plain-pkg", "version": "1.0.0"}),
            &tarball,
            &hashes,
            None,
            "public",
            "latest",
            &server.uri(),
        )
        .await
        .expect("same-origin 307 should replay staged publish");

        assert_eq!(result.stage_id, "stage-redirected");
        let requests = server.received_requests().await.unwrap();
        let stage_requests = requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .collect::<Vec<_>>();
        assert_eq!(stage_requests.len(), 2);
        assert_eq!(stage_requests[0].body, stage_requests[1].body);
        assert_eq!(
            stage_requests[1]
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(stage_requests[1].body.len().to_string().as_str())
        );
    }

    #[tokio::test]
    async fn stage_mutation_strips_bearer_and_otp_across_cross_origin_303() {
        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/capture"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .expect(1)
            .mount(&target)
            .await;

        let redirector = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/stage/stage-id/approve"))
            .respond_with(
                ResponseTemplate::new(303)
                    .insert_header("location", format!("{}/capture", target.uri())),
            )
            .expect(1)
            .mount(&redirector)
            .await;

        let result = stage_otp_mutation(
            "npm-token",
            &redirector.uri(),
            "-/stage/stage-id/approve",
            Method::POST,
            "approve staged package",
            Some("123456"),
            false,
            false,
            NpmStageRuntime::production(),
        )
        .await
        .expect("cross-origin 303 should complete without forwarding credentials");

        assert_eq!(result["success"], true);
        let requests = target.received_requests().await.unwrap();
        let redirected = requests.first().expect("redirect target request");
        assert!(redirected.headers.get("authorization").is_none());
        assert!(redirected.headers.get("x-otp").is_none());
        assert!(redirected.headers.get("npm-otp").is_none());
    }
}
