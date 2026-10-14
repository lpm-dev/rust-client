use crate::install_ui;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lpm_common::{LpmError, LpmRoot, format_bytes};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_LENGTH, LOCATION};
use reqwest::{Body, Client};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::io::{IsTerminal, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

type HmacSha256 = Hmac<Sha256>;

/// The largest artifact the LPM.dev Registry stores.
const REGISTRY_MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;
/// The largest artifact uploaded to, or restored from, any other cache server.
const MAX_REMOTE_ARTIFACT_BYTES: u64 = 500 * 1024 * 1024;
const MAX_REMOTE_STATUS_BYTES: u64 = 64 * 1024;
/// How long a 429 pauses requests when it gives no `Retry-After`: a minute,
/// the Registry's shortest window.
const DEFAULT_LIMIT_PAUSE: Duration = Duration::from_secs(60);
/// The longest pause a 429 can ask for: a day, the Registry's longest window.
const MAX_LIMIT_PAUSE: Duration = Duration::from_secs(24 * 60 * 60);
/// The longest wait an upload refused with 429 sits out before going once
/// more; a longer one is a spent limit.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(5);
const REMOTE_CACHE_TIMEOUT: Duration = Duration::from_secs(30);
/// Each upload read moves to the blocking pool, so the stream's 4 KiB default
/// made a 64 MiB upload about ten times slower than 64 KiB reads.
const UPLOAD_READ_BYTES: usize = 64 * 1024;
const ARTIFACT_TAG_HEADER: &str = "x-artifact-tag";
const ARTIFACT_SHA_HEADER: &str = "x-artifact-sha";
const ARTIFACT_DURATION_HEADER: &str = "x-artifact-duration";
const ARTIFACT_CLIENT_CI_HEADER: &str = "x-artifact-client-ci";
const ARTIFACT_CLIENT_INTERACTIVE_HEADER: &str = "x-artifact-client-interactive";
/// Asks the LPM.dev Registry to answer a cache hit with a redirect to the
/// cache's download host, the artifact's headers on the redirect, rather
/// than streaming it. Other cache servers ignore it.
const DOWNLOAD_REDIRECT_HEADER: &str = "x-lpm-download-redirect";

static REMOTE_CACHE_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);
/// A cache server's base URL and the team its requests name.
type CacheTeam = (String, Option<String>);
/// Each cache server and team's request limits, shared by every task's client
/// in the run.
static REQUEST_LIMITS: Mutex<BTreeMap<CacheTeam, Arc<RequestLimits>>> = Mutex::new(BTreeMap::new());

#[derive(Clone)]
pub struct RemoteCacheClient {
    base_url: String,
    auth: RemoteCacheAuth,
    team: Option<String>,
    signature_key: Option<String>,
    read_only: bool,
    env_policy: lpm_runner::lpm_json::RemoteCacheEnvConfig,
    max_artifact_bytes: u64,
    limits: Arc<RequestLimits>,
}

#[derive(Clone, Copy)]
enum LimitedRequest {
    Lookup,
    Upload,
}

/// Until when a cache server refuses one team's lookups, and its uploads,
/// after answering one with 429, until when of that for a spent limit, and
/// whether the run has said so yet.
#[derive(Default)]
struct RequestLimits {
    lookups_until: Mutex<Option<Instant>>,
    uploads_until: Mutex<Option<Instant>>,
    lookups_limited_until: Mutex<Option<Instant>>,
    uploads_limited_until: Mutex<Option<Instant>>,
    lookup_limit_warned: AtomicBool,
    upload_limit_warned: AtomicBool,
    lookups_busy_noted: AtomicBool,
    uploads_busy_noted: AtomicBool,
    uploads_refused: AtomicBool,
    lookups_refused: AtomicBool,
}

impl RequestLimits {
    fn for_cache(base_url: &str, team: Option<&str>) -> Arc<Self> {
        REQUEST_LIMITS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((base_url.to_owned(), team.map(ToOwned::to_owned)))
            .or_default()
            .clone()
    }

    fn until(&self, request: LimitedRequest) -> &Mutex<Option<Instant>> {
        match request {
            LimitedRequest::Lookup => &self.lookups_until,
            LimitedRequest::Upload => &self.uploads_until,
        }
    }

    fn limited_until(&self, request: LimitedRequest) -> &Mutex<Option<Instant>> {
        match request {
            LimitedRequest::Lookup => &self.lookups_limited_until,
            LimitedRequest::Upload => &self.uploads_limited_until,
        }
    }

    fn paused(&self, request: LimitedRequest) -> bool {
        running(self.until(request))
    }

    fn lookups_paused(&self) -> bool {
        self.paused(LimitedRequest::Lookup)
    }

    /// Uploads also wait out a lookup limit: a task that couldn't look its
    /// artifact up would likely upload one the cache already holds.
    fn uploads_paused(&self) -> bool {
        self.paused(LimitedRequest::Upload) || self.paused(LimitedRequest::Lookup)
    }

    /// Whether this kind of request waits out a spent limit, rather than the
    /// cache server's room for requests at once.
    fn paused_by_a_limit(&self, request: LimitedRequest) -> bool {
        running(self.limited_until(request))
            || (matches!(request, LimitedRequest::Upload)
                && running(self.limited_until(LimitedRequest::Lookup)))
    }

    /// Pauses this kind of request while the cache server has no room for it.
    fn pause(&self, request: LimitedRequest, wait: Duration) {
        extend(self.until(request), Instant::now() + wait);
    }

    /// Pauses this kind of request for a spent limit, whose warning covers
    /// the requests it skips.
    fn spend(&self, request: LimitedRequest, wait: Duration) {
        let resume = Instant::now() + wait;
        extend(self.until(request), resume);
        extend(self.limited_until(request), resume);
    }

    /// Stops uploads for the rest of the run once the cache server refuses
    /// one: the token can't write there, and every later upload would be
    /// refused too, each counting against the server's limit for refused
    /// requests. True when this call stopped them, so the run says so once.
    fn refuse_uploads(&self) -> bool {
        !self.uploads_refused.swap(true, Ordering::Relaxed)
    }

    fn uploads_refused(&self) -> bool {
        self.uploads_refused.load(Ordering::Relaxed)
    }

    /// Stops lookups and uploads for the rest of the run once the cache
    /// server refuses a lookup, or bills nothing more: the token can't read
    /// that cache, or the cache is paused or disabled, so every later
    /// request would be refused too. True when this call stopped lookups.
    fn refuse_lookups(&self) -> bool {
        self.uploads_refused.store(true, Ordering::Relaxed);
        !self.lookups_refused.swap(true, Ordering::Relaxed)
    }

    fn lookups_refused(&self) -> bool {
        self.lookups_refused.load(Ordering::Relaxed)
    }

    /// True the first time the run reaches this kind of limit.
    fn first_warning(&self, request: LimitedRequest) -> bool {
        let warned = match request {
            LimitedRequest::Lookup => &self.lookup_limit_warned,
            LimitedRequest::Upload => &self.upload_limit_warned,
        };
        !warned.swap(true, Ordering::Relaxed)
    }

    /// True the first time the run skips this kind of request because the
    /// cache server was busy for a moment.
    fn first_busy_notice(&self, request: LimitedRequest) -> bool {
        let noted = match request {
            LimitedRequest::Lookup => &self.lookups_busy_noted,
            LimitedRequest::Upload => &self.uploads_busy_noted,
        };
        !noted.swap(true, Ordering::Relaxed)
    }
}

fn running(until: &Mutex<Option<Instant>>) -> bool {
    until
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some_and(|until| Instant::now() < until)
}

/// Moves `until` to `resume`, unless it's already later.
fn extend(until: &Mutex<Option<Instant>>, resume: Instant) {
    let mut until = until.lock().unwrap_or_else(PoisonError::into_inner);
    if until.is_none_or(|until| until < resume) {
        *until = Some(resume);
    }
}

/// A 429's message, and how long to wait before the next request of its kind.
struct LimitReached {
    message: String,
    wait: Duration,
}

#[derive(Clone)]
enum RemoteCacheAuth {
    Static(String),
    Session(Arc<lpm_auth::SessionManager>),
}

enum RemoteCacheRequestError {
    Unauthorized,
    Message(String),
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
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Option<RemoteCacheClient> {
    match resolve_client(lpm_config, session) {
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
    if client.limits.lookups_refused() {
        return None;
    }
    if client.limits.lookups_paused() {
        client.skipping_while_busy(LimitedRequest::Lookup);
        return None;
    }
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
    inherited_env: &HashMap<std::ffi::OsString, std::ffi::OsString>,
) {
    if client.read_only || client.limits.uploads_refused() {
        return;
    }
    // A lookup's pause skips uploads too, so its notice alone wouldn't say so.
    if client.limits.uploads_paused() {
        client.skipping_while_busy(LimitedRequest::Upload);
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

pub fn status_for_project(
    project_dir: &Path,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<CacheStatus, LpmError> {
    let root = LpmRoot::from_env().ok();
    let local_path = root
        .as_ref()
        .map_or_else(|| PathBuf::from("~/.lpm/cache/tasks"), LpmRoot::cache_tasks);
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .map_err(|error| LpmError::Task(format!("cache status: {error}")))?;
    if !remote_cache_requested(lpm_config.as_ref()) {
        let local_bytes = local_task_cache_size(&local_path)?;
        return Ok(CacheStatus {
            local_path,
            local_bytes,
            remote: remote_status(lpm_config.as_ref(), session),
        });
    }

    let local_worker_path = local_path.clone();
    std::thread::scope(|scope| {
        let local = scope.spawn(move || local_task_cache_size(&local_worker_path));
        let remote = remote_status(lpm_config.as_ref(), session);
        let local_bytes = local
            .join()
            .map_err(|_| LpmError::Task("cache status local sizing worker panicked".into()))??;

        Ok(CacheStatus {
            local_path,
            local_bytes,
            remote,
        })
    })
}

fn local_task_cache_size(path: &Path) -> Result<u64, LpmError> {
    match crate::commands::cache::dir_size(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(LpmError::Task(format!(
            "failed to inspect local task cache at {}: {error}",
            path.display()
        ))),
    }
}

pub fn cache_status_json(status: &CacheStatus) -> serde_json::Value {
    // As the human line shows them: usage on its side of the limit.
    let (usage, limit) = match (status.remote.usage_bytes, status.remote.limit_bytes) {
        (Some(usage), Some(limit)) => {
            let (usage, limit) = lpm_common::format_quota(usage, limit);
            (Some(usage), Some(limit))
        }
        (usage, limit) => (usage.map(lpm_common::format_usage), limit.map(format_bytes)),
    };
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
            "usage": usage,
            "limit_bytes": status.remote.limit_bytes,
            "limit": limit,
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
            let (usage_display, limit_display) = lpm_common::format_quota(usage, limit);
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
        } else if let (Some(usage), None) = (status.remote.usage_bytes, status.remote.limit_bytes) {
            // A plan whose cache is unlimited reports no limit.
            println!(
                "{}",
                crate::install_ui::terminal_line!(
                    "  {} {} / Unlimited",
                    cache_status_label("usage"),
                    lpm_common::format_usage(usage)
                )
            );
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

impl RemoteCacheAuth {
    async fn bearer(&self) -> Result<String, String> {
        match self {
            Self::Static(token) => Ok(token.clone()),
            Self::Session(session) => session
                .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
                .await
                .map_err(session_bearer_error),
        }
    }

    async fn refresh_after_rejection(&self) -> Result<Option<String>, String> {
        match self {
            Self::Static(_) => Ok(None),
            Self::Session(session) => session
                .refresh_now()
                .await
                .map(|secret| {
                    use secrecy::ExposeSecret;
                    Some(secret.expose_secret().to_string())
                })
                .map_err(|error| format!("remote cache session refresh failed: {error}")),
        }
    }
}

fn session_bearer_error(error: LpmError) -> String {
    match error {
        LpmError::AuthRequired | LpmError::SessionExpired => {
            "remote cache is enabled but no token was found; set LPM_REMOTE_CACHE_TOKEN or run lpm login"
                .to_string()
        }
        error => format!("remote cache session unavailable: {error}"),
    }
}

impl RemoteCacheRequestError {
    fn into_message(self, unauthorized_message: &str) -> String {
        match self {
            Self::Unauthorized => unauthorized_message.to_string(),
            Self::Message(message) => message,
        }
    }
}

impl RemoteCacheClient {
    async fn send_authenticated<T>(
        &self,
        unauthorized_message: &str,
        send: impl AsyncFn(String) -> Result<T, RemoteCacheRequestError>,
    ) -> Result<T, String> {
        let bearer = self.auth.bearer().await?;
        match send(bearer).await {
            Ok(value) => Ok(value),
            Err(RemoteCacheRequestError::Unauthorized) => {
                let Some(rotated) = self.auth.refresh_after_rejection().await? else {
                    return Err(unauthorized_message.to_string());
                };
                send(rotated)
                    .await
                    .map_err(|error| error.into_message(unauthorized_message))
            }
            Err(error) => Err(error.into_message(unauthorized_message)),
        }
    }

    fn restore(
        &self,
        key: &str,
        project_dir: &Path,
        output_globs: &[String],
        validate: impl FnOnce() -> Result<bool, lpm_common::LpmError>,
    ) -> Result<Option<lpm_task::cache::CacheHit>, String> {
        block_on_remote(self.restore_async(key, project_dir, output_globs, validate))
    }

    async fn restore_async(
        &self,
        key: &str,
        project_dir: &Path,
        output_globs: &[String],
        validate: impl FnOnce() -> Result<bool, lpm_common::LpmError>,
    ) -> Result<Option<lpm_task::cache::CacheHit>, String> {
        let client = lookup_client()?;
        let url = self.artifact_url(key)?;
        let mut retried = false;
        let response = loop {
            let response = self
                .send_authenticated(
                    "remote cache authorization failed; continuing without it",
                    async |bearer: String| {
                        let response = client
                            .get(url.clone())
                            .bearer_auth(bearer)
                            .header(DOWNLOAD_REDIRECT_HEADER, "1")
                            .send()
                            .await
                            .map_err(|error| {
                                RemoteCacheRequestError::Message(format!(
                                    "remote cache lookup failed: {}",
                                    lpm_http::display_error(&error)
                                ))
                            })?;
                        if response.status() == StatusCode::UNAUTHORIZED {
                            Err(RemoteCacheRequestError::Unauthorized)
                        } else {
                            Ok(response)
                        }
                    },
                )
                .await?;
            if response.status() != StatusCode::TOO_MANY_REQUESTS {
                break response;
            }
            let limit = read_limit_reached(response).await;
            // A wait this short is the server's room for requests at once, not
            // a spent limit: a hit is worth looking up again after it, unless
            // lookups were paused meanwhile.
            if !retried && limit.wait <= MAX_RETRY_WAIT {
                retried = true;
                tokio::time::sleep(limit.wait + retry_jitter(key, limit.wait)).await;
                if self.limits.lookups_refused() {
                    return Ok(None);
                }
                if self.limits.lookups_paused() {
                    self.skipping_while_busy(LimitedRequest::Lookup);
                    return Ok(None);
                }
                continue;
            }
            self.limit_reached(LimitedRequest::Lookup, limit);
            return Ok(None);
        };

        let tag = artifact_header(&response, ARTIFACT_TAG_HEADER);
        let advertised_sha = artifact_header(&response, ARTIFACT_SHA_HEADER);
        let mut response = match response.status() {
            StatusCode::OK => response,
            status if status.is_redirection() => {
                // The redirect carries what verifies the download; without it
                // storage isn't asked, as the artifact couldn't be restored.
                if advertised_sha.is_none() {
                    return Err(MISSING_CONTENT_HASH.into());
                }
                if self.signature_key.is_some() && tag.is_none() {
                    return Err(MISSING_SIGNATURE_TAG.into());
                }
                match fetch_redirected_artifact(&url, &response).await? {
                    Some(artifact) => artifact,
                    None => return Ok(None),
                }
            }
            StatusCode::NOT_FOUND => return Ok(None),
            StatusCode::FORBIDDEN | StatusCode::PAYMENT_REQUIRED => {
                let refusal = read_refusal(response, "lookup").await;
                if self.limits.refuse_lookups() {
                    install_ui::warn_untrusted(&format!(
                        "{}; skipping the remote cache for this run",
                        refusal.detail
                    ));
                }
                return Ok(None);
            }
            _ => return Err(remote_cache_http_error(response, "lookup").await),
        };

        if let Some(length) = response.content_length()
            && length > self.max_artifact_bytes
        {
            return Err(oversized_download(self.max_artifact_bytes));
        }

        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|e| format!("failed to create remote cache temp file: {e}"))?;
        let digests = copy_response_to_temp(
            &mut response,
            &mut temp,
            self.signature_key.as_deref(),
            self.max_artifact_bytes,
        )
        .await?;

        // A downloaded artifact is extracted into the project tree only after
        // the advertised content hash passes. When a signing key is configured,
        // the HMAC must pass too, so a cache host without the key can't forge
        // restoreable bytes.
        let Some(advertised_sha) = &advertised_sha else {
            return Err(MISSING_CONTENT_HASH.into());
        };
        verify_artifact_sha(advertised_sha, &digests.sha256_hex)?;

        if let Some(key) = &self.signature_key {
            let Some(tag) = tag else {
                return Err(MISSING_SIGNATURE_TAG.into());
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
        block_on_remote(self.store_async(
            key,
            project_dir,
            command,
            output_globs,
            stdout,
            stderr,
            duration_ms,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_async(
        &self,
        key: &str,
        project_dir: &Path,
        command: &str,
        output_globs: &[String],
        stdout: &str,
        stderr: &str,
        duration_ms: u64,
    ) -> Result<(), String> {
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
        self.check_upload_size(artifact_len)?;
        self.upload_artifact(key, artifact.as_file(), artifact_len, duration_ms)
            .await
    }

    fn check_upload_size(&self, artifact_len: u64) -> Result<(), String> {
        if artifact_len > self.max_artifact_bytes {
            return Err(format!(
                "remote cache artifact exceeds the {} upload limit; skipping upload",
                format_cap(self.max_artifact_bytes),
            ));
        }
        Ok(())
    }

    /// Uploads the artifact in `artifact`, going once more after a 429 with a
    /// short wait, and pausing uploads after one that asks for longer.
    async fn upload_artifact(
        &self,
        key: &str,
        artifact: &File,
        artifact_len: u64,
        duration_ms: u64,
    ) -> Result<(), String> {
        let client = http_client()?;
        let hash_file = artifact
            .try_clone()
            .map_err(|e| format!("failed to retain remote cache artifact for hashing: {e}"))?;
        let digests = hash_artifact(hash_file, self.signature_key.as_deref())?;
        let url = self.artifact_url(key)?;
        let mut retried = false;
        loop {
            let response = self
                .send_authenticated(
                    "remote cache upload was not authorized; continuing without it",
                    async |bearer: String| {
                        let mut body_file = artifact.try_clone().map_err(|error| {
                            RemoteCacheRequestError::Message(format!(
                                "failed to retain remote cache artifact for upload: {error}"
                            ))
                        })?;
                        body_file.rewind().map_err(|error| {
                            RemoteCacheRequestError::Message(format!(
                                "failed to rewind remote cache artifact for upload: {error}"
                            ))
                        })?;
                        let mut request = client
                            .put(url.clone())
                            .bearer_auth(bearer)
                            .header(CONTENT_LENGTH, artifact_len.to_string())
                            .header(ARTIFACT_DURATION_HEADER, duration_ms.to_string())
                            .header(ARTIFACT_SHA_HEADER, digests.sha256_hex.as_str())
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
                            .body(Body::wrap_stream(
                                tokio_util::io::ReaderStream::with_capacity(
                                    tokio::fs::File::from_std(body_file),
                                    UPLOAD_READ_BYTES,
                                ),
                            ));

                        if let Some(tag) = digests.hmac_tag.as_deref() {
                            request = request.header(ARTIFACT_TAG_HEADER, tag);
                        }

                        let response = request.send().await.map_err(|error| {
                            RemoteCacheRequestError::Message(format!(
                                "remote cache upload failed: {}",
                                lpm_http::display_error(&error)
                            ))
                        })?;
                        if response.status() == StatusCode::UNAUTHORIZED {
                            Err(RemoteCacheRequestError::Unauthorized)
                        } else {
                            Ok(response)
                        }
                    },
                )
                .await?;

            // A conflict is another upload storing this artifact, which serves
            // the next lookup as well as this one would.
            if response.status().is_success() || response.status() == StatusCode::CONFLICT {
                return Ok(());
            }
            let status = response.status();
            if matches!(status, StatusCode::FORBIDDEN | StatusCode::PAYMENT_REQUIRED) {
                let refusal = read_refusal(response, "upload").await;
                // A cache too full for this upload may still take a later or
                // smaller one.
                if refusal.code.as_deref() == Some(QUOTA_EXCEEDED_CODE) {
                    return Err(format!("{}; continuing without it", refusal.detail));
                }
                let (stopped, skipped) = if status == StatusCode::PAYMENT_REQUIRED {
                    (self.limits.refuse_lookups(), "the remote cache")
                } else {
                    (self.limits.refuse_uploads(), "remote cache uploads")
                };
                if stopped {
                    install_ui::warn_untrusted(&format!(
                        "{}; skipping {skipped} for this run",
                        refusal.detail
                    ));
                }
                return Ok(());
            }
            if response.status() != StatusCode::TOO_MANY_REQUESTS {
                return Err(remote_cache_http_error(response, "upload").await);
            }
            let limit = read_limit_reached(response).await;
            // A wait this short is the server's room for uploads at once, not a
            // spent limit: the upload goes again rather than being dropped,
            // unless uploads were paused meanwhile.
            if !retried && limit.wait <= MAX_RETRY_WAIT {
                retried = true;
                tokio::time::sleep(limit.wait + retry_jitter(key, limit.wait)).await;
                if self.limits.uploads_refused() {
                    return Ok(());
                }
                if self.limits.uploads_paused() {
                    self.skipping_while_busy(LimitedRequest::Upload);
                    return Ok(());
                }
                continue;
            }
            self.limit_reached(LimitedRequest::Upload, limit);
            return Ok(());
        }
    }

    /// Pauses the refused kind of request for as long as the cache server
    /// asks, and warns the first time the run reaches that limit.
    fn limit_reached(&self, request: LimitedRequest, limit: LimitReached) {
        // A pause of a few seconds is the server's room for requests at once,
        // not a spent limit: it gets its own notice, leaving the warning for a
        // longer limit later.
        if limit.wait <= MAX_RETRY_WAIT {
            self.limits.pause(request, limit.wait);
            self.skipping_while_busy(request);
            return;
        }
        self.limits.spend(request, limit.wait);
        if !self.limits.first_warning(request) {
            return;
        }
        let skipped = match request {
            LimitedRequest::Lookup if !self.read_only => "lookups and uploads",
            LimitedRequest::Lookup => "lookups",
            LimitedRequest::Upload => "uploads",
        };
        install_ui::warn_untrusted(&format!(
            "{}; skipping remote cache {skipped} for {}",
            limit.message,
            format_wait(limit.wait),
        ));
    }

    /// Notes, once a run for each kind, that requests are being skipped
    /// while the cache server is busy for a moment. A request paused by a
    /// spent limit has that limit's warning instead.
    fn skipping_while_busy(&self, request: LimitedRequest) {
        if self.limits.paused_by_a_limit(request) || !self.limits.first_busy_notice(request) {
            return;
        }
        install_ui::skipped(busy_notice(request));
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
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<Option<RemoteCacheClient>, String> {
    if !remote_cache_requested(lpm_config) {
        return Ok(None);
    }

    let config = lpm_config.and_then(|cfg| cfg.remote_cache.as_ref());
    let active_registry = session.as_ref().map(|session| session.registry_url());
    let base_url = resolve_base_url(config.and_then(|cfg| cfg.url.as_deref()), active_registry)?;
    let cache_matches_registry = cache_origin_matches_registry(&base_url, active_registry);
    let auth = match std::env::var("LPM_REMOTE_CACHE_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
    {
        Some(token) => RemoteCacheAuth::Static(token),
        // The ambient registry login token (keychain / LPM_TOKEN) is only sent
        // when the cache lives on the LPM registry origin. A cache URL from a
        // checked-in lpm.json that points elsewhere must carry its own
        // LPM_REMOTE_CACHE_TOKEN, so a hostile config can't redirect the
        // registry credential to an attacker-controlled host.
        None if cache_matches_registry => {
            let registry_origin = registry_origin_for_auth(&base_url)
                .ok_or_else(|| "invalid remote cache origin".to_string())?;
            let session = session
                .filter(|session| {
                    registry_origin_for_auth(session.registry_url())
                        .is_some_and(|origin| origin.eq_ignore_ascii_case(&registry_origin))
                })
                .unwrap_or_else(|| {
                    Arc::new(lpm_auth::SessionManager::new(registry_origin.clone(), None))
                });
            RemoteCacheAuth::Session(session)
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

    let team = std::env::var("LPM_REMOTE_CACHE_TEAM")
        .ok()
        .filter(|team| !team.trim().is_empty())
        .or_else(|| config.and_then(|cfg| cfg.team.clone()));
    let limits = RequestLimits::for_cache(&base_url, team.as_deref());
    Ok(Some(RemoteCacheClient {
        base_url,
        auth,
        team,
        signature_key,
        read_only: env_flag("LPM_REMOTE_CACHE_READ_ONLY").unwrap_or(false)
            || config.is_some_and(|cfg| cfg.read_only),
        env_policy: config.map(|cfg| cfg.env.clone()).unwrap_or_default(),
        max_artifact_bytes: if cache_matches_registry {
            REGISTRY_MAX_ARTIFACT_BYTES
        } else {
            MAX_REMOTE_ARTIFACT_BYTES
        },
        limits,
    }))
}

fn remote_status(
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> RemoteStatus {
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

    let client = match resolve_client(lpm_config, session) {
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
        block_on_remote(self.fetch_status_async())
    }

    async fn fetch_status_async(&self) -> Result<FetchedRemoteStatus, String> {
        let client = http_client()?;
        let url = self.status_url()?;
        let response = self
            .send_authenticated(
                "remote cache status returned HTTP 401",
                async |bearer: String| {
                    let response = client
                        .get(url.clone())
                        .bearer_auth(bearer)
                        .send()
                        .await
                        .map_err(|error| {
                            RemoteCacheRequestError::Message(format!(
                                "remote cache status failed: {}",
                                lpm_http::display_error(&error)
                            ))
                        })?;
                    if response.status() == StatusCode::UNAUTHORIZED {
                        Err(RemoteCacheRequestError::Unauthorized)
                    } else {
                        Ok(response)
                    }
                },
            )
            .await?;

        if !response.status().is_success() {
            return Err(remote_cache_http_error(response, "status").await);
        }

        let body = read_remote_status_body(response).await?;
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

/// Read a status or error body of at most `MAX_REMOTE_STATUS_BYTES`.
async fn read_remote_status_body(
    mut response: reqwest::Response,
) -> Result<serde_json::Value, String> {
    let limit = MAX_REMOTE_STATUS_BYTES as usize;
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > MAX_REMOTE_STATUS_BYTES) {
        return Err(status_body_too_large());
    }
    let mut bytes = Vec::with_capacity(content_length.unwrap_or(0) as usize);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read remote cache status response: {error}"))?
    {
        if bytes.len() + chunk.len() > limit {
            return Err(status_body_too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("remote cache status returned invalid JSON: {error}"))
}

fn status_body_too_large() -> String {
    format!(
        "remote cache status response exceeds the {} limit",
        format_bytes(MAX_REMOTE_STATUS_BYTES)
    )
}

/// Reads a 429's message and wait: `Retry-After`, in seconds or as a date,
/// else the body's `retryAfter` seconds, else a minute; at least a second and
/// at most a day.
async fn read_limit_reached(response: reqwest::Response) -> LimitReached {
    let header_wait = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_retry_after(value, SystemTime::now()));
    let body = read_remote_status_body(response).await.ok();
    let message = body
        .as_ref()
        .and_then(|body| body.get("error"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("remote cache limit reached")
        .to_owned();
    let wait = header_wait
        .or_else(|| {
            body.as_ref()
                .and_then(|body| body.get("retryAfter"))
                .and_then(serde_json::Value::as_f64)
                .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
        })
        .unwrap_or(DEFAULT_LIMIT_PAUSE)
        .clamp(Duration::from_secs(1), MAX_LIMIT_PAUSE);
    LimitReached { message, wait }
}

fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(now).unwrap_or(Duration::ZERO))
}

/// A wait in the largest whole unit that fits, rounded up.
fn format_wait(wait: Duration) -> String {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    let (count, unit) = if seconds < 60 {
        (seconds, "second")
    } else if seconds < 60 * 60 {
        (seconds.div_ceil(60), "minute")
    } else {
        (seconds.div_ceil(60 * 60), "hour")
    };
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

async fn remote_cache_http_error(response: reqwest::Response, operation: &str) -> String {
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        let limit = read_limit_reached(response).await;
        return format!(
            "{}; try again in {}",
            limit.message,
            format_wait(limit.wait)
        );
    }
    let refusal = read_refusal(response, operation).await;
    if operation == "status" {
        refusal.detail
    } else {
        format!("{}; continuing without it", refusal.detail)
    }
}

/// The code the cache server gives an upload it couldn't make room for:
/// a smaller or later upload may still fit.
const QUOTA_EXCEEDED_CODE: &str = "REMOTE_CACHE_QUOTA_EXCEEDED";

/// A refused remote cache request: what to tell the user, and the server's
/// code for it, if any.
struct Refusal {
    detail: String,
    code: Option<String>,
}

async fn read_refusal(response: reqwest::Response, operation: &str) -> Refusal {
    let status = response.status();
    let body = if matches!(status, StatusCode::FORBIDDEN | StatusCode::PAYMENT_REQUIRED) {
        read_remote_status_body(response).await.ok()
    } else {
        None
    };
    let code = body
        .as_ref()
        .and_then(|body| body.get("code"))
        .and_then(serde_json::Value::as_str);
    let cache_status = body
        .as_ref()
        .and_then(|body| body.get("status"))
        .and_then(serde_json::Value::as_str);
    let detail = if status == StatusCode::PAYMENT_REQUIRED && code == Some("ORG_BILLING_LAPSED") {
        "remote cache is unavailable because organization billing requires attention; restore the subscription".to_string()
    } else if status == StatusCode::FORBIDDEN {
        match cache_status {
            Some("paused") => "remote cache is paused; check the cache settings".to_string(),
            Some("disabled") => {
                "remote cache is disabled; check the plan and cache settings".to_string()
            }
            Some("over_limit") => {
                "remote cache quota was exceeded; free cache space or enable overage".to_string()
            }
            _ => "remote cache authorization failed; check the token permissions".to_string(),
        }
    } else {
        format!("remote cache {operation} returned HTTP {}", status.as_u16())
    };
    Refusal {
        detail,
        code: code.map(ToOwned::to_owned),
    }
}

/// The value of an artifact header, if it's text.
fn artifact_header(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

const MISSING_CONTENT_HASH: &str =
    "remote cache artifact is missing a content hash; treating it as a miss";
const MISSING_SIGNATURE_TAG: &str =
    "remote cache artifact is missing a signature tag; treating it as a miss";

/// Fetches an artifact a lookup was redirected to, without the token: the
/// location is a short-lived URL on the cache's download host, which the
/// redirect's own headers vouch for, and a redirect from HTTPS may not lead
/// to plain HTTP. Returns None for an artifact the host no longer serves, a
/// miss. The URL carries the download's credential, so its errors leave it
/// out.
async fn fetch_redirected_artifact(
    lookup_url: &reqwest::Url,
    redirect: &reqwest::Response,
) -> Result<Option<reqwest::Response>, String> {
    let target = redirect_target(
        lookup_url,
        redirect
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok()),
    )?;
    let response = http_client()?.get(target).send().await.map_err(|error| {
        format!(
            "remote cache download failed: {}",
            lpm_http::display_error(&error.without_url())
        )
    })?;
    // The download host's refusals aren't the cache server's: a 403 there
    // is the URL's, which may have expired, not the token's.
    match response.status() {
        StatusCode::OK => Ok(Some(response)),
        StatusCode::NOT_FOUND => Ok(None),
        status => Err(format!(
            "remote cache download returned HTTP {}; continuing without it",
            status.as_u16()
        )),
    }
}

/// Where a lookup's redirect leads: its location, resolved against the
/// lookup's URL, which may not leave HTTPS.
fn redirect_target(
    lookup_url: &reqwest::Url,
    location: Option<&str>,
) -> Result<reqwest::Url, String> {
    let location =
        location.ok_or("remote cache redirect has no location; treating it as a miss")?;
    let target = lookup_url
        .join(location)
        .map_err(|e| format!("remote cache redirect has an invalid location: {e}"))?;
    if lookup_url.scheme() == "https" && target.scheme() != "https" {
        return Err("remote cache redirect leaves HTTPS; treating it as a miss".into());
    }
    Ok(target)
}

/// The client for lookups, which leaves redirects to
/// `fetch_redirected_artifact`, so the token never follows one.
fn lookup_client() -> Result<Client, String> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REMOTE_CACHE_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to initialize remote cache HTTP client: {e}"))
}

fn http_client() -> Result<Client, String> {
    lpm_http::client_builder()
        .timeout(REMOTE_CACHE_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to initialize remote cache HTTP client: {e}"))
}

/// Run remote-cache I/O from the synchronous task-cache paths.
///
/// Inside LPM's runtime this blocks in place on the runtime's own reactor,
/// rather than using `reqwest::blocking`, whose per-client thread and runtime
/// must not be started from inside an async runtime.
fn block_on_remote<F: Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime for remote cache I/O builds")
            .block_on(future),
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

fn resolve_base_url(
    config_url: Option<&str>,
    active_registry: Option<&str>,
) -> Result<String, String> {
    let raw = std::env::var("LPM_REMOTE_CACHE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .or_else(|| config_url.map(ToOwned::to_owned))
        .or_else(|| active_registry.map(ToOwned::to_owned))
        .unwrap_or_else(lpm_common::resolve_lpm_registry_url);

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
        "http" if parsed.host().is_some_and(is_loopback_host) => Ok(with_v8),
        "http" => Err("remote cache refuses HTTP URLs unless they point at localhost".into()),
        scheme => Err(format!(
            "remote cache URL scheme '{scheme}' is not supported"
        )),
    }
}

fn cache_origin_matches_registry(base_url: &str, active_registry: Option<&str>) -> bool {
    let Some(cache_origin) = registry_origin_for_auth(base_url) else {
        return false;
    };
    let resolved_registry;
    let registry = match active_registry {
        Some(registry) => registry,
        None => {
            resolved_registry = lpm_common::resolve_lpm_registry_url();
            &resolved_registry
        }
    };
    registry_origin_for_auth(registry)
        .is_some_and(|registry_origin| cache_origin.eq_ignore_ascii_case(&registry_origin))
}

fn registry_origin_for_auth(base_url: &str) -> Option<String> {
    let origin = reqwest::Url::parse(base_url).ok()?.origin();
    let serialized = origin.ascii_serialization();
    (serialized != "null").then_some(serialized)
}

fn is_loopback_host(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain == "localhost",
        url::Host::Ipv4(address) => address == std::net::Ipv4Addr::LOCALHOST,
        url::Host::Ipv6(address) => address == std::net::Ipv6Addr::LOCALHOST,
    }
}

fn env_flag(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn busy_notice(request: LimitedRequest) -> &'static str {
    match request {
        LimitedRequest::Lookup => "remote cache is busy; skipping some lookups for a moment",
        LimitedRequest::Upload => "remote cache is busy; skipping some uploads for a moment",
    }
}

/// Seeded afresh each run, so CI jobs refused together on the same key
/// don't all go again together either.
static RETRY_JITTER_SEED: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Up to half the wait again, from the artifact's key, so requests refused
/// together don't all go again together.
fn retry_jitter(key: &str, wait: Duration) -> Duration {
    let spread = RETRY_JITTER_SEED.hash_one(key);
    wait.mul_f64((spread % 1000) as f64 / 2000.0)
}

/// An artifact size cap, a whole number of MiB, as the Registry states it.
fn format_cap(bytes: u64) -> String {
    format!("{} MiB", bytes / (1024 * 1024))
}

fn oversized_download(max_artifact_bytes: u64) -> String {
    format!(
        "remote cache artifact exceeds the {} limit; treating it as a miss",
        format_cap(max_artifact_bytes),
    )
}

async fn copy_response_to_temp(
    response: &mut reqwest::Response,
    temp: &mut tempfile::NamedTempFile,
    signature_key: Option<&str>,
    max_artifact_bytes: u64,
) -> Result<ArtifactDigests, String> {
    let mut total = 0u64;
    let mut sha = Sha256::new();
    let mut mac = signature_key.map(new_hmac).transpose()?;

    while let Some(buffer) = response.chunk().await.map_err(|error| {
        format!(
            "failed to read remote cache artifact: {}",
            error.without_url()
        )
    })? {
        let read = buffer.len();
        total = total.saturating_add(read as u64);
        if total > max_artifact_bytes {
            return Err(oversized_download(max_artifact_bytes));
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
    inherited_env: &HashMap<std::ffi::OsString, std::ffi::OsString>,
    stdout: &str,
    stderr: &str,
) -> Option<String> {
    // Inherited names and values are compared as raw bytes: they need not be
    // valid UTF-8, and a lossy copy could hide a value that appears in output.
    let entries = env_vars
        .iter()
        .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
        .chain(
            inherited_env
                .iter()
                .map(|(name, value)| (name.as_encoded_bytes(), value.as_encoded_bytes())),
        );
    for (name, value) in entries {
        if !env_name_blocks_upload(policy, name) {
            continue;
        }
        let name = String::from_utf8_lossy(name);

        if value.len() >= 8 && (output_contains(stdout, value) || output_contains(stderr, value)) {
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

/// Task output is text, so it cannot contain a value that is not valid UTF-8.
fn output_contains(output: &str, value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok_and(|value| output.contains(value))
}

fn env_name_blocks_upload(
    policy: &lpm_runner::lpm_json::RemoteCacheEnvConfig,
    name: &[u8],
) -> bool {
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

fn default_secret_pattern(name: &[u8]) -> bool {
    let upper = name.to_ascii_uppercase();
    let contains = |part: &[u8]| upper.windows(part.len()).any(|window| window == part);
    upper == b"DATABASE_URL"
        || contains(b"TOKEN")
        || contains(b"SECRET")
        || contains(b"PASSWORD")
        || contains(b"PASSWD")
        || contains(b"PRIVATE_KEY")
        || contains(b"API_KEY")
        || upper.ends_with(b"_KEY")
}

/// Case-insensitive `*` glob over the bytes of an environment name.
fn pattern_matches(name: &[u8], pattern: &str) -> bool {
    let name = name.to_ascii_uppercase();
    let pattern = pattern.as_bytes().to_ascii_uppercase();
    if pattern == b"*" {
        return true;
    }
    if !pattern.contains(&b'*') {
        return name == pattern;
    }

    let starts_with_star = pattern.starts_with(b"*");
    let ends_with_star = pattern.ends_with(b"*");
    let parts: Vec<&[u8]> = pattern
        .split(|&byte| byte == b'*')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return true;
    }

    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let haystack = &name[cursor..];
        let Some(offset) = haystack
            .windows(part.len())
            .position(|window| window == *part)
        else {
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
    fn remote_io_runs_outside_the_runtime_and_on_its_threads() {
        assert_eq!(block_on_remote(async { 7 }), 7);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let on_block_on_thread = runtime.block_on(async {
            block_on_remote(async {
                tokio::task::yield_now().await;
                8
            })
        });
        let on_worker = runtime.block_on(async {
            tokio::spawn(async { block_on_remote(async { 9 }) })
                .await
                .unwrap()
        });

        assert_eq!((on_block_on_thread, on_worker), (8, 9));
    }

    #[test]
    fn http_cache_hosts_allow_only_exact_loopback_addresses_and_localhost() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let url = reqwest::Url::parse(&format!("http://{host}:3000/v8")).unwrap();
            assert!(url.host().is_some_and(is_loopback_host), "rejected {host}");
        }
        for host in [
            "localhost.example.com",
            "example.com",
            "127.0.0.2",
            "0.0.0.0",
            "[::]",
            "[::ffff:127.0.0.1]",
        ] {
            let url = reqwest::Url::parse(&format!("http://{host}:3000/v8")).unwrap();
            assert!(!url.host().is_some_and(is_loopback_host), "accepted {host}");
        }
    }

    /// A response whose body arrives as the given chunks, without a
    /// `Content-Length`.
    async fn chunked_status_response(chunks: Vec<Vec<u8>>) -> reqwest::Response {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            while socket.read_line(&mut line).await.unwrap() > 2 {
                line.clear();
            }
            let socket = socket.get_mut();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            for chunk in chunks {
                socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });
        reqwest::Client::new()
            .get(format!("http://{address}/status"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn remote_status_body_accepts_valid_json_at_the_exact_size_limit() {
        let prefix = br#"{"padding":""#;
        let suffix = br#""}"#;
        let padding = MAX_REMOTE_STATUS_BYTES as usize - prefix.len() - suffix.len();
        let mut body = Vec::with_capacity(MAX_REMOTE_STATUS_BYTES as usize);
        body.extend_from_slice(prefix);
        body.resize(body.len() + padding, b'x');
        body.extend_from_slice(suffix);
        let chunks = body.chunks(16 * 1024).map(<[u8]>::to_vec).collect();

        let decoded = read_remote_status_body(chunked_status_response(chunks).await)
            .await
            .unwrap();

        assert_eq!(decoded["padding"].as_str().unwrap().len(), padding);
    }

    #[tokio::test]
    async fn remote_status_body_rejects_a_chunk_that_crosses_the_size_limit() {
        let chunks = vec![b"{".to_vec(), vec![b'x'; MAX_REMOTE_STATUS_BYTES as usize]];

        let error = read_remote_status_body(chunked_status_response(chunks).await)
            .await
            .unwrap_err();

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn invalid_active_registry_never_authorizes_a_remote_cache_origin() {
        assert!(!cache_origin_matches_registry(
            "https://lpm.dev/v8",
            Some("not a URL"),
        ));
    }

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

    #[cfg(unix)]
    #[test]
    fn inherited_env_that_is_not_utf8_is_checked_byte_for_byte() {
        use std::ffi::{OsStr, OsString};
        use std::os::unix::ffi::OsStrExt;

        let policy = lpm_runner::lpm_json::RemoteCacheEnvConfig::default();
        let secret_name = HashMap::from([(
            OsStr::from_bytes(b"DEPLOY_\xff_TOKEN").to_os_string(),
            OsString::from("value"),
        )]);
        assert!(
            upload_block_reason(&policy, &HashMap::new(), &secret_name, "", "").is_some(),
            "a secret-like name must block upload even when it is not UTF-8"
        );

        let leaked = HashMap::from([(
            OsString::from("SERVICE_PASSWORD"),
            OsString::from("hunter2-hunter2"),
        )]);
        let reason = upload_block_reason(
            &policy,
            &HashMap::new(),
            &leaked,
            "connected with hunter2-hunter2",
            "",
        )
        .expect("a secret value in the output must block upload");
        assert!(
            reason.contains("contains the value of SERVICE_PASSWORD"),
            "{reason}"
        );
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
    fn retry_after_reads_seconds_and_dates() {
        let now = httpdate::parse_http_date("Sun, 11 Oct 2026 12:00:00 GMT").unwrap();

        assert_eq!(
            parse_retry_after(" 42 ", now),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            parse_retry_after("Sun, 11 Oct 2026 12:01:30 GMT", now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_retry_after("Sun, 11 Oct 2026 11:59:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-5", now), None);
    }

    #[test]
    fn waits_read_in_their_largest_unit_rounded_up() {
        for (seconds, expected) in [
            (0.5, "1 second"),
            (1.0, "1 second"),
            (42.0, "42 seconds"),
            (60.0, "1 minute"),
            (61.0, "2 minutes"),
            (3_600.0, "1 hour"),
            (86_339.0, "24 hours"),
        ] {
            assert_eq!(format_wait(Duration::from_secs_f64(seconds)), expected);
        }
    }

    async fn limit_from(response: wiremock::ResponseTemplate) -> LimitReached {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(response)
            .mount(&server)
            .await;
        let response = reqwest::get(server.uri()).await.unwrap();
        read_limit_reached(response).await
    }

    #[tokio::test]
    async fn a_limit_waits_as_long_as_the_server_asks_within_a_second_and_a_day() {
        let limited = || {
            wiremock::ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": "Remote cache limit reached: 300 uploads a minute",
                "retryAfter": 30,
            }))
        };

        let from_header = limit_from(limited().insert_header("retry-after", "42")).await;
        assert_eq!(
            from_header.message,
            "Remote cache limit reached: 300 uploads a minute"
        );
        assert_eq!(from_header.wait, Duration::from_secs(42));
        assert_eq!(
            limit_from(limited()).await.wait,
            Duration::from_secs(30),
            "without the header, the body's retryAfter"
        );
        assert_eq!(
            limit_from(limited().insert_header("retry-after", "0"))
                .await
                .wait,
            Duration::from_secs(1)
        );
        assert_eq!(
            limit_from(limited().insert_header("retry-after", "604800"))
                .await
                .wait,
            MAX_LIMIT_PAUSE
        );

        let bare = limit_from(wiremock::ResponseTemplate::new(429)).await;
        assert_eq!(bare.message, "remote cache limit reached");
        assert_eq!(bare.wait, DEFAULT_LIMIT_PAUSE);
    }

    #[test]
    fn a_lookup_limit_pauses_uploads_too_but_an_upload_limit_pauses_only_uploads() {
        let lookups = RequestLimits::default();
        lookups.pause(LimitedRequest::Lookup, Duration::from_secs(60));
        assert!(lookups.lookups_paused() && lookups.uploads_paused());

        let uploads = RequestLimits::default();
        uploads.pause(LimitedRequest::Upload, Duration::from_secs(60));
        assert!(!uploads.lookups_paused() && uploads.uploads_paused());
    }

    #[test]
    fn a_pause_ends_when_its_wait_does_and_a_shorter_one_never_cuts_it() {
        let limits = RequestLimits::default();
        limits.pause(LimitedRequest::Lookup, Duration::ZERO);
        assert!(!limits.lookups_paused());

        limits.pause(LimitedRequest::Lookup, Duration::from_secs(60));
        limits.pause(LimitedRequest::Lookup, Duration::ZERO);
        assert!(limits.lookups_paused());
    }

    #[test]
    fn each_kind_of_limit_warns_once() {
        let limits = RequestLimits::default();

        assert!(limits.first_warning(LimitedRequest::Lookup));
        assert!(!limits.first_warning(LimitedRequest::Lookup));
        assert!(limits.first_warning(LimitedRequest::Upload));
        assert!(!limits.first_warning(LimitedRequest::Upload));
    }

    #[test]
    fn clients_share_limits_per_cache_server_and_team() {
        let url = "https://limits-test.example/v8";
        let shared = RequestLimits::for_cache(url, Some("team-a"));

        assert!(Arc::ptr_eq(
            &shared,
            &RequestLimits::for_cache(url, Some("team-a"))
        ));
        assert!(!Arc::ptr_eq(
            &shared,
            &RequestLimits::for_cache(url, Some("team-b"))
        ));
        assert!(!Arc::ptr_eq(&shared, &RequestLimits::for_cache(url, None)));
        assert!(!Arc::ptr_eq(
            &shared,
            &RequestLimits::for_cache("https://other.example/v8", Some("team-a"))
        ));
    }

    const MIB: u64 = 1024 * 1024;

    fn test_client(base_url: &str, max_artifact_bytes: u64) -> RemoteCacheClient {
        RemoteCacheClient {
            base_url: base_url.to_owned(),
            auth: RemoteCacheAuth::Static("remote-token".into()),
            team: None,
            signature_key: None,
            read_only: false,
            env_policy: lpm_runner::lpm_json::RemoteCacheEnvConfig::default(),
            max_artifact_bytes,
            limits: Arc::new(RequestLimits::default()),
        }
    }

    #[test]
    fn uploads_only_artifacts_within_the_cache_servers_cap() {
        let client = test_client("http://127.0.0.1:9/v8", MIB);

        assert_eq!(client.check_upload_size(MIB), Ok(()));
        assert_eq!(
            client.check_upload_size(MIB + 1),
            Err("remote cache artifact exceeds the 1 MiB upload limit; skipping upload".into())
        );
    }

    /// A cache server that streams `bytes` of every artifact in chunks, with
    /// no Content-Length, so only the streaming check can stop a large one.
    fn chunked_artifact_server(bytes: u64) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
                    head.push(byte[0]);
                }
                let chunk = vec![0u8; 64 * 1024];
                let mut sent = 0;
                let mut send = |data: &[u8]| stream.write_all(data).is_ok();
                if !send(
                    b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                ) {
                    continue;
                }
                while sent < bytes
                    && send(format!("{:x}\r\n", chunk.len()).as_bytes())
                    && send(&chunk)
                    && send(b"\r\n")
                {
                    sent += chunk.len() as u64;
                }
                send(b"0\r\n\r\n");
            }
        });
        url
    }

    #[tokio::test]
    async fn treats_a_streamed_artifact_past_the_cache_servers_cap_as_a_miss() {
        let url = chunked_artifact_server(2 * MIB);
        let client = test_client(&format!("{url}/v8"), MIB);
        let project = tempfile::tempdir().unwrap();

        let restored = client
            .restore_async(&"a".repeat(64), project.path(), &[], || Ok(true))
            .await;

        match restored {
            Err(error) => assert_eq!(
                error,
                "remote cache artifact exceeds the 1 MiB limit; treating it as a miss"
            ),
            Ok(_) => panic!("an artifact past the cap was restored"),
        }
    }

    async fn upload_to(server: &wiremock::MockServer) -> (RemoteCacheClient, Result<(), String>) {
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let mut artifact = tempfile::tempfile().unwrap();
        artifact.write_all(b"artifact").unwrap();
        let uploaded = client
            .upload_artifact(&"a".repeat(64), &artifact, 8, 10)
            .await;
        (client, uploaded)
    }

    fn upload_refused(retry_after: &str) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(429)
            .insert_header("retry-after", retry_after)
            .set_body_json(serde_json::json!({
                "error": "Remote cache limit reached: 8 uploads at once",
            }))
    }

    #[tokio::test]
    async fn an_upload_the_token_may_not_make_stops_uploads_for_the_run() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(
                wiremock::ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": "Token does not have remote cache write permissions",
                })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(client.limits.uploads_refused());
        assert!(!client.limits.lookups_refused());
        assert!(!client.limits.uploads_paused());
        let client = client.clone();
        tokio::task::spawn_blocking(move || store_with(&client))
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lookup_the_token_may_not_make_stops_the_cache_for_the_run() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": "Token does not have remote cache read permissions",
                })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let project = tempfile::tempdir().unwrap();

        let restored = client
            .restore_async(&"a".repeat(64), project.path(), &[], || Ok(true))
            .await;

        assert!(matches!(restored, Ok(None)));
        assert!(client.limits.lookups_refused() && client.limits.uploads_refused());
        let client = client.clone();
        tokio::task::spawn_blocking(move || {
            let project = tempfile::tempdir().unwrap();
            let restored = try_restore(&client, &"b".repeat(64), project.path(), &[], || Ok(true));
            assert!(restored.is_none());
            store_with(&client);
        })
        .await
        .unwrap();
        server.verify().await;
    }

    fn billing_lapsed() -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(402).set_body_json(serde_json::json!({
            "error": "Organization billing requires attention.",
            "code": "ORG_BILLING_LAPSED",
            "status": "paused",
        }))
    }

    #[tokio::test]
    async fn an_upload_the_token_may_not_make_leaves_lookups_on() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(wiremock::ResponseTemplate::new(403).set_body_json(
                serde_json::json!({ "error": "Token does not have remote cache write permissions" }),
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let (client, _) = upload_to(&server).await;
        let project = tempfile::tempdir().unwrap();

        let restored = client
            .restore_async(&"b".repeat(64), project.path(), &[], || Ok(true))
            .await;

        assert!(matches!(restored, Ok(None)));
        server.verify().await;
    }

    #[test]
    fn a_redirect_resolves_against_the_lookup_and_may_not_leave_https() {
        let lookup = reqwest::Url::parse("https://lpm.dev/v8/artifacts/abc?slug=acme").unwrap();

        assert_eq!(
            redirect_target(&lookup, Some("/storage/abc"))
                .unwrap()
                .as_str(),
            "https://lpm.dev/storage/abc"
        );
        assert_eq!(
            redirect_target(&lookup, Some("https://storage.example/abc?sig=1"))
                .unwrap()
                .as_str(),
            "https://storage.example/abc?sig=1"
        );
        assert!(
            redirect_target(&lookup, Some("http://storage.example/abc"))
                .unwrap_err()
                .contains("leaves HTTPS")
        );
        assert!(
            redirect_target(&lookup, None)
                .unwrap_err()
                .contains("no location")
        );
        let plain = reqwest::Url::parse("http://127.0.0.1:3000/v8/artifacts/abc").unwrap();
        assert!(redirect_target(&plain, Some("http://127.0.0.1:3000/storage/abc")).is_ok());
    }

    #[tokio::test]
    async fn a_lapsed_bill_on_a_lookup_stops_the_cache_for_the_run() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(billing_lapsed())
            .expect(1)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let project = tempfile::tempdir().unwrap();

        let restored = client
            .restore_async(&"a".repeat(64), project.path(), &[], || Ok(true))
            .await;

        assert!(matches!(restored, Ok(None)));
        assert!(client.limits.lookups_refused() && client.limits.uploads_refused());
        let client = client.clone();
        tokio::task::spawn_blocking(move || {
            let project = tempfile::tempdir().unwrap();
            assert!(
                try_restore(&client, &"b".repeat(64), project.path(), &[], || Ok(true)).is_none()
            );
            store_with(&client);
        })
        .await
        .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lapsed_bill_on_an_upload_stops_the_cache_for_the_run() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(billing_lapsed())
            .expect(1)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(client.limits.lookups_refused() && client.limits.uploads_refused());
        server.verify().await;
    }

    #[tokio::test]
    async fn an_upload_the_cache_has_no_room_for_leaves_uploads_on() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(
                wiremock::ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": "Remote cache quota exceeded",
                    "status": "over_limit",
                    "code": "REMOTE_CACHE_QUOTA_EXCEEDED",
                })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(
            uploaded,
            Err("remote cache quota was exceeded; free cache space or enable overage; continuing without it".to_string())
        );
        assert!(!client.limits.uploads_refused());
        server.verify().await;
    }

    #[tokio::test]
    async fn an_upload_of_an_account_over_its_limit_stops_uploads_for_the_run() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(wiremock::ResponseTemplate::new(403).set_body_json(
                serde_json::json!({ "error": "Remote cache is not enabled", "status": "over_limit" }),
            ))
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(client.limits.uploads_refused());
    }

    #[tokio::test]
    async fn an_upload_waiting_to_go_again_is_dropped_once_the_run_stops_uploads() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(upload_refused("1"))
            .expect(1)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let limits = client.limits.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            limits.refuse_uploads();
        });
        let mut artifact = tempfile::tempfile().unwrap();
        artifact.write_all(b"artifact").unwrap();

        let uploaded = client
            .upload_artifact(&"a".repeat(64), &artifact, 8, 10)
            .await;

        assert_eq!(uploaded, Ok(()));
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lookup_waiting_to_go_again_is_dropped_once_the_run_stops_lookups() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(upload_refused("1"))
            .expect(1)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let limits = client.limits.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            limits.refuse_lookups();
        });
        let project = tempfile::tempdir().unwrap();

        let restored = client
            .restore_async(&"a".repeat(64), project.path(), &[], || Ok(true))
            .await;

        assert!(matches!(restored, Ok(None)));
        server.verify().await;
    }

    #[test]
    fn says_once_that_the_run_stops_each_kind_of_request() {
        let limits = RequestLimits::default();

        assert!(limits.refuse_uploads());
        assert!(!limits.refuse_uploads());
        assert!(limits.refuse_lookups());
        assert!(!limits.refuse_lookups());
        assert!(!limits.refuse_uploads());
    }

    #[tokio::test]
    async fn an_upload_refused_for_another_reason_leaves_uploads_on() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert!(uploaded.is_err());
        assert!(!client.limits.uploads_refused());
    }

    #[tokio::test]
    async fn an_upload_refused_for_a_moment_goes_once_more_and_pauses_nothing() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(upload_refused("1"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "urls": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(!client.limits.uploads_paused());
        server.verify().await;
    }

    #[tokio::test]
    async fn an_upload_another_is_storing_is_left_to_it_quietly() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(wiremock::ResponseTemplate::new(409).set_body_json(
                serde_json::json!({ "error": "Remote cache artifact upload already in progress" }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(!client.limits.uploads_paused());
        server.verify().await;
    }

    #[tokio::test]
    async fn uploads_pause_once_a_retry_is_refused_too_or_the_wait_is_a_spent_limit() {
        for (retry_after, attempts) in [("1", 2), ("6", 1), ("60", 1)] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("PUT"))
                .respond_with(upload_refused(retry_after))
                .expect(attempts)
                .mount(&server)
                .await;

            let (client, uploaded) = upload_to(&server).await;

            assert_eq!(uploaded, Ok(()));
            assert!(client.limits.uploads_paused(), "Retry-After {retry_after}");
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn an_upload_refused_for_five_seconds_still_goes_once_more() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(upload_refused("5"))
            .expect(2)
            .mount(&server)
            .await;

        let (client, uploaded) = upload_to(&server).await;

        assert_eq!(uploaded, Ok(()));
        assert!(client.limits.uploads_paused());
        server.verify().await;
    }

    #[tokio::test]
    async fn an_upload_doesnt_go_again_once_uploads_or_lookups_were_paused_while_it_waited() {
        for paused in [LimitedRequest::Upload, LimitedRequest::Lookup] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("PUT"))
                .respond_with(upload_refused("1"))
                .expect(1)
                .mount(&server)
                .await;
            let client = test_client(&format!("{}/v8", server.uri()), MIB);
            let mut artifact = tempfile::tempfile().unwrap();
            artifact.write_all(b"artifact").unwrap();
            let limits = client.limits.clone();
            let pause = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                limits.spend(paused, Duration::from_secs(60));
            });

            let uploaded = client
                .upload_artifact(&"a".repeat(64), &artifact, 8, 10)
                .await;

            pause.await.unwrap();
            assert_eq!(uploaded, Ok(()));
            server.verify().await;
            // A minute's pause is a spent limit, whose warning covers the
            // dropped upload, so the busy notice stays unspent.
            assert!(client.limits.first_busy_notice(LimitedRequest::Upload));
        }
    }

    fn store_with(client: &RemoteCacheClient) {
        let project = tempfile::tempdir().unwrap();
        try_store(
            client,
            "abc123",
            project.path(),
            "build",
            &[],
            "",
            "",
            1,
            &HashMap::new(),
            &HashMap::new(),
        );
    }

    #[test]
    fn an_upload_skipped_while_a_lookup_waits_on_a_busy_server_gets_the_busy_notice() {
        let client = test_client("http://127.0.0.1:9/v8", MIB);
        client
            .limits
            .pause(LimitedRequest::Lookup, Duration::from_secs(3));

        store_with(&client);

        assert!(!client.limits.first_busy_notice(LimitedRequest::Upload));
    }

    #[test]
    fn an_upload_skipped_for_a_spent_lookup_limit_has_that_limit_s_warning_instead() {
        let client = test_client("http://127.0.0.1:9/v8", MIB);
        client
            .limits
            .spend(LimitedRequest::Lookup, Duration::from_secs(60));

        store_with(&client);

        assert!(client.limits.first_busy_notice(LimitedRequest::Upload));
    }

    #[test]
    fn a_read_only_client_skips_uploads_without_a_notice() {
        let mut client = test_client("http://127.0.0.1:9/v8", MIB);
        client.read_only = true;
        client
            .limits
            .pause(LimitedRequest::Upload, Duration::from_secs(3));

        store_with(&client);

        assert!(client.limits.first_busy_notice(LimitedRequest::Upload));
    }

    #[test]
    fn a_lookup_skipped_while_the_server_is_busy_gets_the_busy_notice() {
        let client = test_client("http://127.0.0.1:9/v8", MIB);
        client
            .limits
            .pause(LimitedRequest::Lookup, Duration::from_secs(3));
        let project = tempfile::tempdir().unwrap();

        let hit = try_restore(&client, "abc123", project.path(), &[], || Ok(true));

        assert!(hit.is_none());
        assert!(!client.limits.first_busy_notice(LimitedRequest::Lookup));
    }

    #[test]
    fn a_key_s_retry_jitter_holds_for_the_whole_run() {
        let wait = Duration::from_secs(2);
        for index in 0..32 {
            let key = format!("{index:064x}");
            let jitter = retry_jitter(&key, wait);
            assert_eq!(retry_jitter(&key, wait), jitter);
            assert!(jitter < wait / 2, "{jitter:?}");
        }
    }

    #[test]
    fn the_busy_notice_names_what_it_skips_in_lpm_s_own_words() {
        assert_eq!(
            busy_notice(LimitedRequest::Lookup),
            "remote cache is busy; skipping some lookups for a moment"
        );
        assert_eq!(
            busy_notice(LimitedRequest::Upload),
            "remote cache is busy; skipping some uploads for a moment"
        );
    }

    #[test]
    fn a_short_refusal_during_a_spent_limit_leaves_the_busy_notice_unspent() {
        let client = test_client("http://127.0.0.1:9/v8", MIB);
        client
            .limits
            .spend(LimitedRequest::Lookup, Duration::from_secs(60));

        client.limit_reached(
            LimitedRequest::Upload,
            LimitReached {
                message: "Remote cache limit reached: 8 uploads at once".into(),
                wait: Duration::from_secs(1),
            },
        );

        assert!(client.limits.first_busy_notice(LimitedRequest::Upload));
    }

    fn lookup_refused(retry_after: &str) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(429)
            .insert_header("retry-after", retry_after)
            .set_body_json(serde_json::json!({
                "error": "Remote cache limit reached: 32 uploads and downloads at once",
            }))
    }

    async fn look_up_at(client: &RemoteCacheClient) {
        let project = tempfile::tempdir().unwrap();
        let restored = client
            .restore_async(&"a".repeat(64), project.path(), &[], || Ok(true))
            .await;
        assert!(matches!(restored, Ok(None)));
    }

    #[tokio::test]
    async fn a_lookup_refused_for_a_moment_goes_once_more_and_pauses_nothing() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(lookup_refused("1"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let limits = client.limits.clone();
        let during = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            limits.lookups_paused() || limits.uploads_paused()
        });

        look_up_at(&client).await;

        assert!(!during.await.unwrap(), "nothing pauses while it waits");
        assert!(!client.limits.lookups_paused());
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lookup_pauses_lookups_once_its_retry_is_refused_too() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(lookup_refused("1"))
            .expect(2)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);

        look_up_at(&client).await;

        assert!(client.limits.lookups_paused());
        assert!(!client.limits.first_busy_notice(LimitedRequest::Lookup));
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lookup_doesnt_go_again_once_lookups_were_paused_while_it_waited() {
        // A spent limit's warning covers the skipped lookup; a busy server's
        // pause gets the busy notice.
        for (spent, noted) in [(true, false), (false, true)] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .respond_with(lookup_refused("1"))
                .expect(1)
                .mount(&server)
                .await;
            let client = test_client(&format!("{}/v8", server.uri()), MIB);
            let limits = client.limits.clone();
            let pause = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                if spent {
                    limits.spend(LimitedRequest::Lookup, Duration::from_secs(60));
                } else {
                    limits.pause(LimitedRequest::Lookup, Duration::from_secs(3));
                }
            });

            look_up_at(&client).await;

            pause.await.unwrap();
            server.verify().await;
            assert_eq!(
                !client.limits.first_busy_notice(LimitedRequest::Lookup),
                noted,
                "spent limit: {spent}"
            );
        }
    }

    #[tokio::test]
    async fn a_lookup_refused_for_five_seconds_still_goes_once_more() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(lookup_refused("5"))
            .expect(2)
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);

        look_up_at(&client).await;

        assert!(client.limits.lookups_paused());
        assert!(!client.limits.paused_by_a_limit(LimitedRequest::Lookup));
        server.verify().await;
    }

    #[tokio::test]
    async fn a_lookup_goes_again_after_the_wait_and_its_share_of_the_spread() {
        let wait = Duration::from_secs(1);
        let key = (0u32..)
            .map(|index| format!("{index:064x}"))
            .find(|key| retry_jitter(key, wait) >= Duration::from_millis(300))
            .unwrap();
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(lookup_refused("1"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let project = tempfile::tempdir().unwrap();

        let started = Instant::now();
        let restored = client
            .restore_async(&key, project.path(), &[], || Ok(true))
            .await;

        assert!(matches!(restored, Ok(None)));
        assert!(started.elapsed() >= wait + retry_jitter(&key, wait));
    }

    #[test]
    fn a_spent_limit_is_told_from_a_busy_server_however_little_of_it_is_left() {
        let limits = RequestLimits::default();
        limits.spend(LimitedRequest::Lookup, Duration::from_millis(5_500));
        std::thread::sleep(Duration::from_millis(600));
        assert!(limits.paused_by_a_limit(LimitedRequest::Lookup));
        assert!(limits.paused_by_a_limit(LimitedRequest::Upload));

        let busy = RequestLimits::default();
        busy.pause(LimitedRequest::Lookup, Duration::from_secs(60));
        assert!(busy.lookups_paused());
        assert!(!busy.paused_by_a_limit(LimitedRequest::Lookup));

        let uploads = RequestLimits::default();
        uploads.spend(LimitedRequest::Upload, Duration::from_secs(60));
        assert!(!uploads.paused_by_a_limit(LimitedRequest::Lookup));
    }

    #[tokio::test]
    async fn an_upload_goes_again_after_the_wait_and_its_share_of_the_spread() {
        let wait = Duration::from_secs(1);
        let key = (0u32..)
            .map(|index| format!("{index:064x}"))
            .find(|key| retry_jitter(key, wait) >= Duration::from_millis(300))
            .unwrap();
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(upload_refused("1"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "urls": [] })),
            )
            .mount(&server)
            .await;
        let client = test_client(&format!("{}/v8", server.uri()), MIB);
        let mut artifact = tempfile::tempfile().unwrap();
        artifact.write_all(b"artifact").unwrap();

        let started = Instant::now();
        let uploaded = client.upload_artifact(&key, &artifact, 8, 10).await;

        assert_eq!(uploaded, Ok(()));
        assert!(started.elapsed() >= wait + retry_jitter(&key, wait));
    }

    #[test]
    fn retries_spread_over_up_to_half_the_wait_again() {
        let wait = Duration::from_secs(1);
        let spreads: std::collections::BTreeSet<_> = (0..50)
            .map(|index| retry_jitter(&format!("{index:064x}"), wait))
            .collect();

        assert!(spreads.iter().all(|spread| *spread <= wait / 2));
        assert!(spreads.len() > 10, "{spreads:?}");
    }

    #[test]
    fn a_pause_of_up_to_five_seconds_gets_its_own_notice_and_leaves_the_warning_for_a_longer_limit()
    {
        let limit = |seconds| LimitReached {
            message: "Remote cache limit reached: 8 uploads at once".into(),
            wait: Duration::from_secs(seconds),
        };
        for request in [LimitedRequest::Upload, LimitedRequest::Lookup] {
            let client = test_client("http://127.0.0.1:9/v8", MIB);

            client.limit_reached(request, limit(5));
            assert!(client.limits.paused(request));
            assert!(!client.limits.paused_by_a_limit(request));
            assert!(!client.limits.first_busy_notice(request));
            assert!(client.limits.first_warning(request));

            let client = test_client("http://127.0.0.1:9/v8", MIB);
            client.limit_reached(request, limit(6));
            assert!(client.limits.paused_by_a_limit(request));
            assert!(!client.limits.first_warning(request));
            assert!(client.limits.first_busy_notice(request));
        }
    }

    #[test]
    fn exclude_pattern_overrides_include_pattern() {
        let policy = lpm_runner::lpm_json::RemoteCacheEnvConfig {
            include: vec!["PUBLIC_*".into()],
            exclude: vec!["*_KEY".into()],
            ..Default::default()
        };

        assert!(env_name_blocks_upload(&policy, b"PUBLIC_API_KEY"));
    }
}
