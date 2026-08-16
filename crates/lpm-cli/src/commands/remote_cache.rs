use crate::install_ui;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lpm_common::{DEFAULT_REGISTRY_URL, LpmRoot, format_bytes};
use reqwest::StatusCode;
use reqwest::blocking::{Body, Client};
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{IsTerminal, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

const MAX_REMOTE_ARTIFACT_BYTES: u64 = 500 * 1024 * 1024;
const REMOTE_CACHE_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_TAG_HEADER: &str = "x-artifact-tag";
const ARTIFACT_SHA_HEADER: &str = "x-artifact-sha";
const ARTIFACT_DURATION_HEADER: &str = "x-artifact-duration";
const ARTIFACT_CLIENT_CI_HEADER: &str = "x-artifact-client-ci";
const ARTIFACT_CLIENT_INTERACTIVE_HEADER: &str = "x-artifact-client-interactive";

static REMOTE_CACHE_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct RemoteCacheClient {
    base_url: String,
    token: String,
    team: Option<String>,
    signature_key: Option<String>,
    read_only: bool,
    env_policy: lpm_runner::lpm_json::RemoteCacheEnvConfig,
}

pub struct CacheStatus {
    pub local_path: PathBuf,
    pub local_bytes: u64,
    pub remote: RemoteStatus,
}

pub struct RemoteStatus {
    pub enabled: bool,
    pub url: Option<String>,
    pub team: Option<String>,
    pub status: Option<String>,
    pub usage_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    pub error: Option<String>,
}

pub fn client_from_config(
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Option<RemoteCacheClient> {
    match resolve_client(lpm_config) {
        Ok(client) => client,
        Err(reason) => {
            warn_once(&reason);
            None
        }
    }
}

pub fn try_restore(
    client: &RemoteCacheClient,
    key: &str,
    project_dir: &Path,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, lpm_common::LpmError>,
) -> Option<lpm_task::cache::CacheHit> {
    match client.restore(key, project_dir, output_globs, validate) {
        Ok(hit) => hit,
        Err(reason) => {
            warn_once(&reason);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn try_store(
    client: &RemoteCacheClient,
    key: &str,
    project_dir: &Path,
    command: &str,
    output_globs: &[String],
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
    env_vars: &HashMap<String, String>,
    inherited_env: &HashMap<String, String>,
) {
    if client.read_only {
        return;
    }

    if let Some(reason) =
        upload_block_reason(&client.env_policy, env_vars, inherited_env, stdout, stderr)
    {
        warn_once(&reason);
        return;
    }

    if let Err(reason) = client.store(
        key,
        project_dir,
        command,
        output_globs,
        stdout,
        stderr,
        duration_ms,
    ) {
        warn_once(&reason);
    }
}

pub fn status_for_project(project_dir: &Path) -> CacheStatus {
    let root = LpmRoot::from_env().ok();
    let local_path = root
        .as_ref()
        .map_or_else(|| PathBuf::from("~/.lpm/cache/tasks"), LpmRoot::cache_tasks);
    let local_bytes = crate::commands::cache::dir_size(&local_path).unwrap_or(0);
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let remote = remote_status(lpm_config.as_ref());

    CacheStatus {
        local_path,
        local_bytes,
        remote,
    }
}

pub fn cache_status_json(status: &CacheStatus) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "local": {
            "path": status.local_path.display().to_string(),
            "bytes": status.local_bytes,
            "size": format_bytes(status.local_bytes),
        },
        "remote": {
            "enabled": status.remote.enabled,
            "url": status.remote.url,
            "team": status.remote.team,
            "status": status.remote.status,
            "usage_bytes": status.remote.usage_bytes,
            "usage": status.remote.usage_bytes.map(format_bytes),
            "limit_bytes": status.remote.limit_bytes,
            "limit": status.remote.limit_bytes.map(format_bytes),
            "error": status.remote.error,
        },
    })
}

pub fn print_cache_status_human(status: &CacheStatus) {
    println!("{}", install_ui::section("Local cache"));
    println!(
        "{}",
        crate::install_ui::terminal_line!(
            "  {} {}",
            cache_status_label("path"),
            status.local_path.display().to_string()
        )
    );
    println!(
        "{}",
        crate::install_ui::terminal_line!(
            "  {} {}",
            cache_status_label("size"),
            format_bytes(status.local_bytes)
        )
    );
    println!();

    println!("{}", install_ui::section("Remote cache"));
    let enabled_value = if status.remote.enabled {
        install_ui::status_ok("true")
    } else {
        install_ui::dim("false")
    };
    println!(
        "{}",
        crate::install_ui::terminal_line!("  {} {}", cache_status_label("enabled"), enabled_value)
    );
    if status.remote.enabled {
        let status_value = status
            .remote
            .status
            .as_deref()
            .map_or_else(|| install_ui::dim("unknown"), install_ui::status_ok);
        println!(
            "{}",
            crate::install_ui::terminal_line!(
                "  {} {}",
                cache_status_label("status"),
                status_value
            )
        );
        if let Some(url) = &status.remote.url {
            println!(
                "{}",
                crate::install_ui::terminal_line!(
                    "  {} {}",
                    cache_status_label("url"),
                    install_ui::url(url)
                )
            );
        }
        if let (Some(usage), Some(limit)) = (status.remote.usage_bytes, status.remote.limit_bytes) {
            let usage_display = format_bytes(usage);
            let limit_display = format_bytes(limit);
            let usage_bar = install_ui::usage_bar(usage, limit, 10);
            let usage_line = if usage_bar.is_empty() {
                crate::install_ui::terminal_line!(
                    "  {} {} / {}",
                    cache_status_label("usage"),
                    usage_display,
                    limit_display
                )
            } else {
                crate::install_ui::terminal_line!(
                    "  {} {} / {}  {}",
                    cache_status_label("usage"),
                    usage_display,
                    limit_display,
                    usage_bar
                )
            };
            println!("{usage_line}");
        }
    }
    println!();

    if let Some(error) = &status.remote.error {
        install_ui::warn_untrusted(&format!("Remote status unavailable: {error}"));
    }
    install_ui::done("Cache status loaded");
}

fn cache_status_label(label: &'static str) -> install_ui::TerminalFragment {
    install_ui::dim(&format!("{label:<8}"))
}

impl RemoteCacheClient {
    fn restore(
        &self,
        key: &str,
        project_dir: &Path,
        output_globs: &[String],
        validate: impl FnOnce() -> Result<bool, lpm_common::LpmError>,
    ) -> Result<Option<lpm_task::cache::CacheHit>, String> {
        run_blocking_http(|| self.restore_blocking(key, project_dir, output_globs, validate))
    }

    fn restore_blocking(
        &self,
        key: &str,
        project_dir: &Path,
        output_globs: &[String],
        validate: impl FnOnce() -> Result<bool, lpm_common::LpmError>,
    ) -> Result<Option<lpm_task::cache::CacheHit>, String> {
        let client = blocking_http_client()?;
        let url = self.artifact_url(key)?;
        let mut response = client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .map_err(|e| {
                format!(
                    "remote cache lookup failed: {}",
                    lpm_http::display_error(&e)
                )
            })?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(None),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err("remote cache authorization failed; continuing without it".into());
            }
            status => {
                return Err(format!(
                    "remote cache lookup returned HTTP {}; continuing without it",
                    status.as_u16()
                ));
            }
        }

        if let Some(length) = response.content_length()
            && length > MAX_REMOTE_ARTIFACT_BYTES
        {
            return Err(format!(
                "remote cache artifact exceeds the {} limit; treating it as a miss",
                format_bytes(MAX_REMOTE_ARTIFACT_BYTES),
            ));
        }

        let tag = response
            .headers()
            .get(ARTIFACT_TAG_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let advertised_sha = response
            .headers()
            .get(ARTIFACT_SHA_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|e| format!("failed to create remote cache temp file: {e}"))?;
        let digests =
            copy_response_to_temp(&mut response, &mut temp, self.signature_key.as_deref())?;

        // A downloaded artifact is extracted into the project tree only after
        // the advertised content hash passes. When a signing key is configured,
        // the HMAC must pass too, so a cache host without the key can't forge
        // restoreable bytes.
        let Some(advertised_sha) = &advertised_sha else {
            return Err(
                "remote cache artifact is missing a content hash; treating it as a miss".into(),
            );
        };
        verify_artifact_sha(advertised_sha, &digests.sha256_hex)?;

        if let Some(key) = &self.signature_key {
            let Some(tag) = tag else {
                return Err(
                    "remote cache artifact is missing a signature tag; treating it as a miss"
                        .into(),
                );
            };
            verify_artifact_tag(key, &tag, &digests.hmac_tag)?;
        }

        let artifact = temp
            .as_file()
            .try_clone()
            .map_err(|e| format!("failed to retain verified remote cache artifact: {e}"))?;
        lpm_task::cache::restore_remote_artifact_from_file_if(
            key,
            artifact,
            project_dir,
            output_globs,
            validate,
        )
        .map_err(|e| format!("remote cache artifact could not be restored: {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    fn store(
        &self,
        key: &str,
        project_dir: &Path,
        command: &str,
        output_globs: &[String],
        stdout: &str,
        stderr: &str,
        duration_ms: u64,
    ) -> Result<(), String> {
        run_blocking_http(|| {
            self.store_blocking(
                key,
                project_dir,
                command,
                output_globs,
                stdout,
                stderr,
                duration_ms,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn store_blocking(
        &self,
        key: &str,
        project_dir: &Path,
        command: &str,
        output_globs: &[String],
        stdout: &str,
        stderr: &str,
        duration_ms: u64,
    ) -> Result<(), String> {
        let client = blocking_http_client()?;
        let mut artifact = tempfile::NamedTempFile::new()
            .map_err(|e| format!("failed to create remote cache artifact temp file: {e}"))?;
        let artifact_path = artifact.path().to_path_buf();
        let artifact_args = lpm_task::cache::RemoteArtifactCreate {
            key,
            project_dir,
            command,
            output_globs,
            stdout,
            stderr,
            duration_ms,
            artifact_path: &artifact_path,
        };
        lpm_task::cache::create_remote_artifact_in_file(artifact_args, artifact.as_file_mut())
            .map_err(|e| format!("failed to create remote cache artifact: {e}"))?;

        let artifact_len = artifact
            .as_file()
            .metadata()
            .map_err(|e| format!("failed to stat remote cache artifact: {e}"))?
            .len();
        if artifact_len > MAX_REMOTE_ARTIFACT_BYTES {
            return Err(format!(
                "remote cache artifact exceeds the {} upload limit; skipping upload",
                format_bytes(MAX_REMOTE_ARTIFACT_BYTES),
            ));
        }

        let hash_file = artifact
            .as_file()
            .try_clone()
            .map_err(|e| format!("failed to retain remote cache artifact for hashing: {e}"))?;
        let digests = hash_artifact(hash_file, self.signature_key.as_deref())?;
        let mut body_file = artifact
            .as_file()
            .try_clone()
            .map_err(|e| format!("failed to retain remote cache artifact for upload: {e}"))?;
        body_file
            .rewind()
            .map_err(|e| format!("failed to rewind remote cache artifact for upload: {e}"))?;
        let url = self.artifact_url(key)?;

        let mut request = client
            .put(url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(CONTENT_LENGTH, artifact_len.to_string())
            .header(ARTIFACT_DURATION_HEADER, duration_ms.to_string())
            .header(ARTIFACT_SHA_HEADER, digests.sha256_hex)
            .header(
                ARTIFACT_CLIENT_CI_HEADER,
                if is_ci_environment() { "1" } else { "0" },
            )
            .header(
                ARTIFACT_CLIENT_INTERACTIVE_HEADER,
                if std::io::stdout().is_terminal() {
                    "1"
                } else {
                    "0"
                },
            )
            .body(Body::new(body_file));

        if let Some(tag) = digests.hmac_tag {
            request = request.header(ARTIFACT_TAG_HEADER, tag);
        }

        let response = request.send().map_err(|e| {
            format!(
                "remote cache upload failed: {}",
                lpm_http::display_error(&e)
            )
        })?;

        if response.status().is_success() {
            return Ok(());
        }

        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err("remote cache upload was not authorized; continuing without it".into());
        }

        Err(format!(
            "remote cache upload returned HTTP {}; continuing without it",
            response.status().as_u16()
        ))
    }

    fn artifact_url(&self, key: &str) -> Result<reqwest::Url, String> {
        let mut url = reqwest::Url::parse(&format!("{}/artifacts/{key}", self.base_url))
            .map_err(|e| format!("invalid remote cache URL: {e}"))?;
        if let Some(team) = &self.team {
            url.query_pairs_mut().append_pair("slug", team);
        }
        Ok(url)
    }

    fn status_url(&self) -> Result<reqwest::Url, String> {
        let mut url = reqwest::Url::parse(&format!("{}/artifacts/status", self.base_url))
            .map_err(|e| format!("invalid remote cache status URL: {e}"))?;
        if let Some(team) = &self.team {
            url.query_pairs_mut().append_pair("slug", team);
        }
        Ok(url)
    }
}

struct ArtifactDigests {
    sha256_hex: String,
    hmac_tag: Option<String>,
}

fn resolve_client(
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<RemoteCacheClient>, String> {
    if !remote_cache_requested(lpm_config) {
        return Ok(None);
    }

    let config = lpm_config.and_then(|cfg| cfg.remote_cache.as_ref());
    let base_url = resolve_base_url(config.and_then(|cfg| cfg.url.as_deref()))?;
    let cache_matches_registry = cache_origin_matches_registry(&base_url);
    let token = match std::env::var("LPM_REMOTE_CACHE_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
    {
        Some(token) => token,
        // The ambient registry login token (keychain / LPM_TOKEN) is only sent
        // when the cache lives on the LPM registry origin. A cache URL from a
        // checked-in lpm.json that points elsewhere must carry its own
        // LPM_REMOTE_CACHE_TOKEN, so a hostile config can't redirect the
        // registry credential to an attacker-controlled host.
        None if cache_matches_registry => {
            lpm_auth::get_token(registry_origin_for_auth(&base_url).as_str()).ok_or_else(|| {
                "remote cache is enabled but no token was found; set LPM_REMOTE_CACHE_TOKEN or run lpm login"
                    .to_string()
            })?
        }
        None => {
            return Err(
                "remote cache is configured for a host other than the LPM registry; set LPM_REMOTE_CACHE_TOKEN to authenticate (the registry login token is never sent to third-party cache hosts)"
                    .to_string(),
            );
        }
    };

    let signature_key = std::env::var("LPM_REMOTE_CACHE_SIGNATURE_KEY")
        .ok()
        .filter(|key| !key.is_empty());
    if config.is_some_and(|cfg| cfg.signature) && signature_key.is_none() {
        return Err(
            "remoteCache.signature is true but LPM_REMOTE_CACHE_SIGNATURE_KEY is not set".into(),
        );
    }
    if !cache_matches_registry && signature_key.is_none() {
        return Err(
            "remote cache is configured for a host other than the LPM registry; set LPM_REMOTE_CACHE_SIGNATURE_KEY so third-party artifacts are signed before restore"
                .into(),
        );
    }

    Ok(Some(RemoteCacheClient {
        base_url,
        token,
        team: std::env::var("LPM_REMOTE_CACHE_TEAM")
            .ok()
            .filter(|team| !team.trim().is_empty())
            .or_else(|| config.and_then(|cfg| cfg.team.clone())),
        signature_key,
        read_only: env_flag("LPM_REMOTE_CACHE_READ_ONLY").unwrap_or(false)
            || config.is_some_and(|cfg| cfg.read_only),
        env_policy: config.map(|cfg| cfg.env.clone()).unwrap_or_default(),
    }))
}

fn remote_status(lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>) -> RemoteStatus {
    let configured = remote_cache_requested(lpm_config);
    if !configured {
        return RemoteStatus {
            enabled: false,
            url: None,
            team: None,
            status: Some("disabled".into()),
            usage_bytes: None,
            limit_bytes: None,
            error: None,
        };
    }

    let client = match resolve_client(lpm_config) {
        Ok(Some(client)) => client,
        Ok(None) => {
            return RemoteStatus {
                enabled: false,
                url: None,
                team: None,
                status: Some("disabled".into()),
                usage_bytes: None,
                limit_bytes: None,
                error: None,
            };
        }
        Err(error) => {
            return RemoteStatus {
                enabled: true,
                url: None,
                team: None,
                status: None,
                usage_bytes: None,
                limit_bytes: None,
                error: Some(error),
            };
        }
    };

    let url = client.base_url.clone();
    let team = client.team.clone();
    match client.fetch_status() {
        Ok(remote) => RemoteStatus {
            enabled: true,
            url: Some(url),
            team,
            status: remote.status,
            usage_bytes: remote.usage_bytes,
            limit_bytes: remote.limit_bytes,
            error: None,
        },
        Err(error) => RemoteStatus {
            enabled: true,
            url: Some(url),
            team,
            status: None,
            usage_bytes: None,
            limit_bytes: None,
            error: Some(error),
        },
    }
}

struct FetchedRemoteStatus {
    status: Option<String>,
    usage_bytes: Option<u64>,
    limit_bytes: Option<u64>,
}

impl RemoteCacheClient {
    fn fetch_status(&self) -> Result<FetchedRemoteStatus, String> {
        run_blocking_http(|| self.fetch_status_blocking())
    }

    fn fetch_status_blocking(&self) -> Result<FetchedRemoteStatus, String> {
        let client = blocking_http_client()?;
        let url = self.status_url()?;
        let response = client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .map_err(|e| {
                format!(
                    "remote cache status failed: {}",
                    lpm_http::display_error(&e)
                )
            })?;

        if !response.status().is_success() {
            return Err(format!(
                "remote cache status returned HTTP {}",
                response.status().as_u16()
            ));
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| format!("remote cache status returned invalid JSON: {e}"))?;
        Ok(FetchedRemoteStatus {
            status: body
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            usage_bytes: body
                .get("usageBytes")
                .or_else(|| body.get("usage_bytes"))
                .and_then(serde_json::Value::as_u64),
            limit_bytes: body
                .get("limitBytes")
                .or_else(|| body.get("limit_bytes"))
                .and_then(serde_json::Value::as_u64),
        })
    }
}

fn blocking_http_client() -> Result<Client, String> {
    lpm_http::blocking_client_builder()
        .timeout(REMOTE_CACHE_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to initialize remote cache HTTP client: {e}"))
}

fn run_blocking_http<T>(f: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

fn remote_cache_requested(lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>) -> bool {
    if let Some(enabled) = env_flag("LPM_REMOTE_CACHE") {
        return enabled;
    }
    lpm_config
        .and_then(|cfg| cfg.remote_cache.as_ref())
        .is_some_and(|remote| remote.enabled)
}

fn resolve_base_url(config_url: Option<&str>) -> Result<String, String> {
    let raw = std::env::var("LPM_REMOTE_CACHE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .or_else(|| config_url.map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{}/v8", lpm_common::resolve_lpm_registry_url()));

    let trimmed = raw.trim().trim_end_matches('/');
    let with_v8 = if trimmed.ends_with("/v8") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v8")
    };
    let parsed =
        reqwest::Url::parse(&with_v8).map_err(|e| format!("invalid remote cache URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(with_v8),
        "http" if parsed.host_str().is_some_and(is_loopback_host) => Ok(with_v8),
        "http" => Err("remote cache refuses HTTP URLs unless they point at localhost".into()),
        scheme => Err(format!(
            "remote cache URL scheme '{scheme}' is not supported"
        )),
    }
}

fn cache_origin_matches_registry(base_url: &str) -> bool {
    let cache_origin = registry_origin_for_auth(base_url);
    let registry_origin = registry_origin_for_auth(&lpm_common::resolve_lpm_registry_url());
    cache_origin.eq_ignore_ascii_case(&registry_origin)
}

fn registry_origin_for_auth(base_url: &str) -> String {
    reqwest::Url::parse(base_url)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            let port = url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            Some(format!("{}://{host}{port}", url.scheme()))
        })
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn env_flag(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn copy_response_to_temp(
    response: &mut impl Read,
    temp: &mut tempfile::NamedTempFile,
    signature_key: Option<&str>,
) -> Result<ArtifactDigests, String> {
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    let mut sha = Sha256::new();
    let mut mac = signature_key.map(new_hmac).transpose()?;

    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|e| format!("failed to read remote cache artifact: {e}"))?;
        if read == 0 {
            break;
        }

        total = total.saturating_add(read as u64);
        if total > MAX_REMOTE_ARTIFACT_BYTES {
            return Err(format!(
                "remote cache artifact exceeds the {} limit; treating it as a miss",
                format_bytes(MAX_REMOTE_ARTIFACT_BYTES),
            ));
        }

        sha.update(&buffer[..read]);
        if let Some(mac) = mac.as_mut() {
            mac.update(&buffer[..read]);
        }
        temp.write_all(&buffer[..read])
            .map_err(|e| format!("failed to write remote cache artifact: {e}"))?;
    }

    temp.flush()
        .map_err(|e| format!("failed to flush remote cache artifact: {e}"))?;

    Ok(ArtifactDigests {
        sha256_hex: hex::encode(sha.finalize()),
        hmac_tag: mac.map(|mac| format_hmac_tag(&mac.finalize().into_bytes())),
    })
}

fn hash_artifact(mut file: File, signature_key: Option<&str>) -> Result<ArtifactDigests, String> {
    file.rewind()
        .map_err(|e| format!("failed to rewind remote cache artifact: {e}"))?;
    let mut sha = Sha256::new();
    let mut mac = signature_key.map(new_hmac).transpose()?;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("failed to hash remote cache artifact: {e}"))?;
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
        if let Some(mac) = mac.as_mut() {
            mac.update(&buffer[..read]);
        }
    }

    Ok(ArtifactDigests {
        sha256_hex: hex::encode(sha.finalize()),
        hmac_tag: mac.map(|mac| format_hmac_tag(&mac.finalize().into_bytes())),
    })
}

fn new_hmac(key: &str) -> Result<HmacSha256, String> {
    HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| "remote cache signature key is invalid".to_string())
}

fn format_hmac_tag(bytes: &[u8]) -> String {
    format!("sha256={}", URL_SAFE_NO_PAD.encode(bytes))
}

fn verify_artifact_sha(advertised: &str, computed: &str) -> Result<(), String> {
    if advertised.trim().eq_ignore_ascii_case(computed) {
        Ok(())
    } else {
        Err("remote cache artifact failed content-hash verification; treating it as a miss".into())
    }
}

fn verify_artifact_tag(
    _key: &str,
    received: &str,
    computed: &Option<String>,
) -> Result<(), String> {
    let Some(computed) = computed else {
        return Err("remote cache signature could not be computed".into());
    };
    let received_bytes = decode_hmac_tag(received)?;
    let computed_bytes = decode_hmac_tag(computed)?;
    if received_bytes == computed_bytes {
        Ok(())
    } else {
        Err("remote cache artifact signature is invalid; treating it as a miss".into())
    }
}

fn decode_hmac_tag(tag: &str) -> Result<Vec<u8>, String> {
    let raw = tag.strip_prefix("sha256=").unwrap_or(tag);
    URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .map_err(|_| "remote cache artifact signature tag is invalid".to_string())
}

fn upload_block_reason(
    policy: &lpm_runner::lpm_json::RemoteCacheEnvConfig,
    env_vars: &HashMap<String, String>,
    inherited_env: &HashMap<String, String>,
    stdout: &str,
    stderr: &str,
) -> Option<String> {
    for (name, value) in env_vars.iter().chain(inherited_env) {
        if !env_name_blocks_upload(policy, name) {
            continue;
        }

        if value.len() >= 8 && (stdout.contains(value) || stderr.contains(value)) {
            return Some(format!(
                "remote cache upload skipped because task output contains the value of {name}"
            ));
        }

        return Some(format!(
            "remote cache upload skipped because loaded env var {name} looks secret-like"
        ));
    }
    None
}

fn env_name_blocks_upload(policy: &lpm_runner::lpm_json::RemoteCacheEnvConfig, name: &str) -> bool {
    if policy
        .exclude
        .iter()
        .any(|pattern| pattern_matches(name, pattern))
    {
        return true;
    }
    if policy
        .include
        .iter()
        .any(|pattern| pattern_matches(name, pattern))
    {
        return false;
    }
    !policy.allow_secrets && default_secret_pattern(name)
}

fn default_secret_pattern(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "DATABASE_URL"
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("API_KEY")
        || upper.ends_with("_KEY")
}

fn pattern_matches(name: &str, pattern: &str) -> bool {
    let name = name.to_ascii_uppercase();
    let pattern = pattern.to_ascii_uppercase();
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return name == pattern;
    }

    let starts_with_star = pattern.starts_with('*');
    let ends_with_star = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let haystack = &name[cursor..];
        let Some(offset) = haystack.find(part) else {
            return false;
        };
        if idx == 0 && !starts_with_star && offset != 0 {
            return false;
        }
        cursor += offset + part.len();
    }

    ends_with_star || cursor == name.len()
}

fn is_ci_environment() -> bool {
    ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI"]
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()))
}

fn warn_once(message: &str) {
    if !REMOTE_CACHE_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
        install_ui::warn_untrusted(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_tag_roundtrips_with_expected_key() {
        let mut mac = new_hmac("secret-key").unwrap();
        mac.update(b"artifact bytes");
        let tag = format_hmac_tag(&mac.finalize().into_bytes());

        let computed = Some(tag.clone());
        verify_artifact_tag("secret-key", &tag, &computed).unwrap();
    }

    #[test]
    fn hmac_tag_rejects_mismatch() {
        let mut mac = new_hmac("secret-key").unwrap();
        mac.update(b"artifact bytes");
        let computed = Some(format_hmac_tag(&mac.finalize().into_bytes()));

        let mut other = new_hmac("other-key").unwrap();
        other.update(b"artifact bytes");
        let received = format_hmac_tag(&other.finalize().into_bytes());

        let err = verify_artifact_tag("secret-key", &received, &computed).unwrap_err();
        assert!(err.contains("invalid"));
    }

    #[test]
    fn artifact_sha_accepts_matching_hash_case_insensitively() {
        verify_artifact_sha("ABCDEF0123", "abcdef0123").unwrap();
        verify_artifact_sha("  abcdef0123  ", "abcdef0123").unwrap();
    }

    #[test]
    fn artifact_sha_rejects_mismatch() {
        let err = verify_artifact_sha(&"0".repeat(64), &"1".repeat(64)).unwrap_err();
        assert!(err.contains("content-hash"));
    }

    #[test]
    fn artifact_hash_uses_the_open_file_after_its_path_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        std::fs::write(&path, "verified").unwrap();
        let open = File::open(&path).unwrap();
        std::fs::rename(&path, directory.path().join("moved")).unwrap();
        std::fs::write(&path, "replacement").unwrap();

        let digest = hash_artifact(open, None).unwrap();

        assert_eq!(digest.sha256_hex, hex::encode(Sha256::digest(b"verified")));
    }

    #[test]
    fn upload_is_blocked_for_secret_like_env_names() {
        let mut env = HashMap::new();
        env.insert("DATABASE_URL".into(), "postgres://example".into());

        let reason = upload_block_reason(
            &lpm_runner::lpm_json::RemoteCacheEnvConfig::default(),
            &env,
            &HashMap::new(),
            "",
            "",
        )
        .expect("secret-like env must block upload");

        assert!(reason.contains("DATABASE_URL"));
    }

    #[test]
    fn upload_is_blocked_when_secret_value_reaches_logs() {
        let mut env = HashMap::new();
        env.insert("LPM_TOKEN".into(), "super-secret-token".into());

        let reason = upload_block_reason(
            &lpm_runner::lpm_json::RemoteCacheEnvConfig::default(),
            &env,
            &HashMap::new(),
            "token=super-secret-token",
            "",
        )
        .expect("secret value in logs must block upload");

        assert!(reason.contains("task output"));
    }

    #[test]
    fn include_pattern_allows_named_secret_env() {
        let mut env = HashMap::new();
        env.insert("PUBLIC_API_KEY".into(), "public-key".into());
        let policy = lpm_runner::lpm_json::RemoteCacheEnvConfig {
            include: vec!["PUBLIC_*".into()],
            ..Default::default()
        };

        assert!(upload_block_reason(&policy, &env, &HashMap::new(), "", "").is_none());
    }

    #[test]
    fn inherited_secret_like_env_blocks_remote_upload() {
        let inherited = HashMap::from([("CI_DEPLOY_PASSWORD".into(), "secret-value".into())]);

        let reason = upload_block_reason(
            &lpm_runner::lpm_json::RemoteCacheEnvConfig::default(),
            &HashMap::new(),
            &inherited,
            "",
            "",
        )
        .expect("secret-like inherited env must block upload");

        assert!(reason.contains("CI_DEPLOY_PASSWORD"));
    }

    #[test]
    fn exclude_pattern_overrides_include_pattern() {
        let policy = lpm_runner::lpm_json::RemoteCacheEnvConfig {
            include: vec!["PUBLIC_*".into()],
            exclude: vec!["*_KEY".into()],
            ..Default::default()
        };

        assert!(env_name_blocks_upload(&policy, "PUBLIC_API_KEY"));
    }
}
