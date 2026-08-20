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
            target_url = %registry,
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
    if lpm_common::lpm_registry_url_is_accepted(registry_url) {
        return Ok(());
    }

    Err(LpmError::Registry(format!(
        "refusing npm staged publish registry {registry_url:?}: use HTTPS, or HTTP loopback for local testing"
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
) -> Result<serde_json::Value, LpmError> {
    let client = stage_http_client(Duration::from_secs(60))?;
    let url = endpoint_url(registry_url, &urlencoding::encode(npm_name));
    let response = web_auth::add_npm_web_auth_headers(client.get(url), NPM_COMMAND_STAGE)
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
    let body = response_json_or_empty(response).await;
    if status.is_success() {
        return Ok(body);
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(LpmError::Registry(format!(
            "npm staged publish requires {npm_name} to already exist on the registry"
        )));
    }

    Err(LpmError::Registry(stage_error_message(
        "npm package metadata request",
        status,
        &body,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn stage_publish(
    token: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &[u8],
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
    tarball_data: &[u8],
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
    );
    let tarball_mb = tarball_data.len() as u64 / (1024 * 1024);
    let timeout = Duration::from_secs(std::cmp::min(60 + tarball_mb * 2, 600));
    let client = stage_http_client(timeout)?;
    let url = endpoint_url(
        registry_url,
        &format!("-/stage/package/{}", urlencoding::encode(npm_name)),
    );

    let response = web_auth::add_npm_web_auth_headers(client.post(url), NPM_COMMAND_STAGE)
        .json(&payload)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            LpmError::Registry(format!(
                "npm stage publish request failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    let status = response.status();
    let body = response_json_or_empty(response).await;
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
    )))
}

pub(crate) async fn list_staged_packages(
    token: &str,
    registry_url: &str,
    package_filter: Option<&str>,
) -> Result<StageListResult, LpmError> {
    validate_npm_stage_registry(registry_url)?;
    let client = stage_http_client(Duration::from_secs(60))?;
    let mut page = 0;
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
        let body = response_json_or_empty(response).await;
        if !status.is_success() {
            return Err(LpmError::Registry(stage_error_message(
                "npm stage list",
                status,
                &body,
            )));
        }

        let page_items = body
            .get("items")
            .and_then(|value| value.as_array())
            .ok_or_else(|| LpmError::Registry("npm stage list response missing items".into()))?;
        let page_total = body
            .get("total")
            .and_then(|value| value.as_u64())
            .map_or(items.len() + page_items.len(), |value| value as usize);
        items.reserve(page_items.len());
        items.extend(page_items.iter().cloned());

        if items.len() >= page_total || page_items.len() < STAGE_LIST_PER_PAGE as usize {
            return Ok(StageListResult {
                total: page_total,
                items,
            });
        }
        page += 1;
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
        let body = response_json_or_empty(response).await;
        return Err(LpmError::Registry(stage_error_message(
            "npm stage download",
            status,
            &body,
        )));
    }

    let data = response
        .bytes()
        .await
        .map_err(|e| LpmError::Registry(format!("npm stage download body failed: {e}")))?;
    let manifest = read_manifest_from_tarball(&data)?;
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
    let filename = format!("{}-{version}-{stage_id}.tgz", safe_tarball_name(name));
    let path = output_dir.join(filename);
    std::fs::write(&path, &data).map_err(LpmError::Io)?;

    Ok(StageDownloadResult {
        path,
        bytes: data.len() as u64,
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
    let body = response_json_or_empty(response).await;
    if status.is_success() {
        return Ok(body);
    }

    Err(LpmError::Registry(stage_error_message(
        action, status, &body,
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
    let client = stage_http_client(Duration::from_secs(60))?;
    let response = send_stage_mutation(&client, token, registry_url, route, method.clone(), otp)
        .await
        .map_err(|e| {
            LpmError::Registry(format!(
                "{action} request failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;
    let status = response.status();
    let headers = response.headers().clone();

    if status.is_success() {
        return Ok(response_json_or_empty(response).await);
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        let body = response_json_or_empty(response).await;
        if let Some(challenge) = web_auth::parse_web_auth_challenge_from_body(&body) {
            if !can_prompt(json_output, yes) {
                return Err(LpmError::Registry(format!(
                    "npm requires browser authentication to {action}, but this command is running in non-interactive mode"
                )));
            }

            let otp = web_auth::complete_web_auth_challenge(
                &client,
                &challenge,
                action,
                json_output,
                runtime.open_browser,
                runtime.web_auth_timeout,
                runtime.web_auth_poll_interval,
            )
            .await?;
            let retry =
                send_stage_mutation(&client, token, registry_url, route, method, Some(&otp))
                    .await
                    .map_err(|e| {
                        LpmError::Registry(format!(
                            "{action} retry failed: {}",
                            lpm_http::display_error(&e)
                        ))
                    })?;
            return stage_mutation_response(action, retry).await;
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
            let retry =
                send_stage_mutation(&client, token, registry_url, route, method, Some(&otp))
                    .await
                    .map_err(|e| {
                        LpmError::Registry(format!(
                            "{action} retry failed: {}",
                            lpm_http::display_error(&e)
                        ))
                    })?;
            return stage_mutation_response(action, retry).await;
        }

        return Err(LpmError::Registry(stage_error_message(
            action, status, &body,
        )));
    }

    stage_mutation_response(action, response).await
}

async fn send_stage_mutation(
    client: &reqwest::Client,
    token: &str,
    registry_url: &str,
    route: &str,
    method: Method,
    otp: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut request = web_auth::add_npm_web_auth_headers(
        client.request(method, endpoint_url(registry_url, route)),
        NPM_COMMAND_STAGE,
    )
    .bearer_auth(token);
    if let Some(code) = otp {
        request = request.header("npm-otp", code);
    }
    request.send().await
}

async fn stage_mutation_response(
    action: &str,
    response: reqwest::Response,
) -> Result<serde_json::Value, LpmError> {
    let status = response.status();
    let body = response_json_or_empty(response).await;
    if status.is_success() {
        return Ok(body);
    }

    Err(LpmError::Registry(stage_error_message(
        action, status, &body,
    )))
}

fn stage_http_client(timeout: Duration) -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
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

async fn response_json_or_empty(response: reqwest::Response) -> serde_json::Value {
    let text = response.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return serde_json::json!({});
    }
    serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "error": text }))
}

fn stage_error_message(
    action: &str,
    status: reqwest::StatusCode,
    body: &serde_json::Value,
) -> String {
    let error = body
        .get("error")
        .or_else(|| body.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
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

fn read_manifest_from_tarball(data: &[u8]) -> Result<serde_json::Value, LpmError> {
    read_manifest_from_tarball_with_entry_limit(data, 100_000)
}

fn read_manifest_from_tarball_with_entry_limit(
    data: &[u8],
    max_entries: usize,
) -> Result<serde_json::Value, LpmError> {
    let decoder = GzDecoder::new(data);
    let archive_limits = lpm_extractor::TarArchiveLimits::new(max_entries);
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

        let result = stage_publish_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({"name": "plain-pkg", "version": "1.0.0"}),
            b"fake-tarball",
            &crate::commands::publish_common::compute_hashes(b"fake-tarball"),
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
}
