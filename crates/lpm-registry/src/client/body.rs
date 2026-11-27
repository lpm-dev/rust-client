use super::*;

/// Hard cap on the number of bytes we will buffer from a single metadata
/// response body. LPM requests the abbreviated packument format
/// (`application/vnd.npm.install-v1+json`), but npm-compatible proxies can
/// reserialize packuments above 32 MiB. 64 MiB preserves growth headroom while
/// keeping a four-request metadata lane below 256 MiB of body buffers.
pub(super) const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const _: () = assert!(MAX_METADATA_BYTES <= 64 * 1024 * 1024);
/// Exact npm version documents contain one manifest rather than package
/// history. Keep their widened concurrency lane under a tighter memory cap.
pub(super) const MAX_VERSION_METADATA_BYTES: usize = 4 * 1024 * 1024;
// Keep small responses inline; large packuments can monopolize an async worker.
pub(super) const BLOCKING_METADATA_PARSE_THRESHOLD: usize = 64 * 1024;
// Bound simultaneous multi-MB packument buffers and deserializations to keep peak RSS in check.
const LARGE_METADATA_PARSE_THRESHOLD: usize = 512 * 1024;
const METADATA_MEMORY_BUDGET_QUANTUM: usize = 64 * 1024;
const METADATA_MEMORY_BUDGET_UNITS: usize = (128 * 1024 * 1024) / METADATA_MEMORY_BUDGET_QUANTUM;
const CHUNKED_LARGE_BODY_UNITS: u32 = ((16 * 1024 * 1024) / METADATA_MEMORY_BUDGET_QUANTUM) as u32;

fn large_metadata_parse_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIMITER: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| {
        let permits =
            std::thread::available_parallelism().map_or(2, |cpus| (cpus.get() / 4).clamp(2, 4));
        Arc::new(tokio::sync::Semaphore::new(permits))
    })
}

fn metadata_body_memory_budget() -> &'static Arc<tokio::sync::Semaphore> {
    static BUDGET: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    BUDGET.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS)))
}

struct LargeMetadataMemoryGuard {
    _concurrency_permit: tokio::sync::OwnedSemaphorePermit,
    _byte_budget_permit: tokio::sync::OwnedSemaphorePermit,
}

async fn acquire_large_metadata_guard(
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
    bytes: usize,
    is_declared_total: bool,
) -> Option<LargeMetadataMemoryGuard> {
    let concurrency_permit = Arc::clone(limiter).acquire_owned().await.ok()?;
    let units = if is_declared_total {
        u32::try_from(
            bytes
                .div_ceil(METADATA_MEMORY_BUDGET_QUANTUM)
                .clamp(1, METADATA_MEMORY_BUDGET_UNITS),
        )
        .unwrap_or(METADATA_MEMORY_BUDGET_UNITS as u32)
    } else {
        CHUNKED_LARGE_BODY_UNITS.min(METADATA_MEMORY_BUDGET_UNITS as u32)
    };
    let byte_budget_permit = Arc::clone(budget).acquire_many_owned(units).await.ok()?;
    Some(LargeMetadataMemoryGuard {
        _concurrency_permit: concurrency_permit,
        _byte_budget_permit: byte_budget_permit,
    })
}

async fn read_metadata_body_with_budget(
    response: reqwest::Response,
    cap: usize,
    body: &mut Vec<u8>,
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
) -> (
    Result<(), lpm_http::ResponseBodyError>,
    Option<LargeMetadataMemoryGuard>,
) {
    let limiter = Arc::clone(limiter);
    let budget = Arc::clone(budget);
    lpm_http::read_body_capped_with_budget(
        response,
        cap,
        body,
        None::<LargeMetadataMemoryGuard>,
        move |mut guard, next_len, is_declared_total| {
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            async move {
                if guard.is_none() && next_len >= LARGE_METADATA_PARSE_THRESHOLD {
                    guard = acquire_large_metadata_guard(
                        &limiter,
                        &budget,
                        next_len,
                        is_declared_total,
                    )
                    .await;
                }
                guard
            }
        },
    )
    .await
}

async fn run_blocking_metadata_parse_with_guard<T, F>(
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
    buf_len: usize,
    preacquired_guard: Option<LargeMetadataMemoryGuard>,
    parse: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let guard = if let Some(guard) = preacquired_guard {
        Some(guard)
    } else if buf_len >= LARGE_METADATA_PARSE_THRESHOLD {
        acquire_large_metadata_guard(limiter, budget, buf_len, true).await
    } else {
        None
    };
    tokio::task::spawn_blocking(move || {
        // Keep permits alive inside the blocking worker so cancelling the outer future
        // cannot release RSS headroom while deserialization is still running.
        let _guard = guard;
        parse()
    })
    .await
}

#[cfg(test)]
async fn run_blocking_metadata_parse<T, F>(
    limiter: &Arc<tokio::sync::Semaphore>,
    buf_len: usize,
    parse: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_blocking_metadata_parse_with_guard(
        limiter,
        metadata_body_memory_budget(),
        buf_len,
        None,
        parse,
    )
    .await
}

/// Hard cap for non-metadata API responses (whoami, token check,
/// quality/skills, tunnel domain ops, publish ack, error bodies).
/// These payloads are kilobytes in practice; 10 MB gives several
/// orders of magnitude of headroom over the legitimate envelope and
/// stops a hostile / compromised mirror from OOM-ing the CLI on a
/// path that never needed metadata-sized buffers.
pub(super) const MAX_API_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with a two-stage size cap.
///
/// Stage 1 (pre-stream): refuse when the server's declared
/// `Content-Length` exceeds `cap` — no bytes are allocated for a
/// hostile-declared-length response.
///
/// Stage 2 (mid-stream): for chunked / undeclared-length responses,
/// accumulate `bytes_stream()` chunks into a bounded `Vec` and abort
/// the moment another chunk would cross `cap`. Closing the response
/// at that point drops the underlying connection.
pub(super) async fn read_capped_body(
    response: reqwest::Response,
    cap: usize,
    context: &str,
) -> Result<Vec<u8>, LpmError> {
    lpm_http::read_body_capped(response, cap)
        .await
        .map_err(|error| LpmError::Registry(format!("{context}: {error}")))
}

/// Read a metadata-shaped JSON response with the metadata cap.
///
/// Wraps [`read_capped_body`] with the metadata-tier ceiling.
///
/// Small responses parse inline; larger metadata buffers are parsed on
/// Tokio's blocking pool so packuments do not monopolize async workers.
pub(super) async fn parse_capped_metadata<T: serde::de::DeserializeOwned + Send + 'static>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, LpmError> {
    let mut buf = Vec::new();
    let (read, guard) = read_metadata_body_with_budget(
        response,
        MAX_METADATA_BYTES,
        &mut buf,
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
    )
    .await;
    read.map_err(|error| LpmError::Registry(format!("{context}: {error}")))?;
    if buf.len() < BLOCKING_METADATA_PARSE_THRESHOLD {
        return parse_metadata_buffer(&buf, context);
    }

    let buf_len = buf.len();
    let context_owned = context.to_string();
    run_blocking_metadata_parse_with_guard(
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
        buf_len,
        guard,
        move || {
            let parsed = parse_metadata_buffer(&buf, &context_owned);
            drop(buf);
            parsed
        },
    )
    .await
    .map_err(|e| LpmError::Registry(format!("{context}: JSON parse task failed: {e}")))?
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct MetadataBodyTimings {
    pub(super) body_read_ms: u128,
    pub(super) json_parse_ms: u128,
    pub(super) body_bytes: u64,
    /// The body was larger than the cap the caller read it with.
    pub(super) cap_exceeded: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ApiBodyTimings {
    pub(super) body_read_ms: u64,
    pub(super) json_parse_ms: u64,
    pub(super) body_bytes: u64,
}

pub(super) async fn parse_capped_metadata_with_timing<
    T: serde::de::DeserializeOwned + Send + 'static,
>(
    response: reqwest::Response,
    context: &str,
) -> Result<(T, MetadataBodyTimings), LpmError> {
    parse_capped_metadata_with_timing_limit(response, MAX_METADATA_BYTES, context).await
}

pub(super) async fn parse_capped_metadata_with_timing_limit<
    T: serde::de::DeserializeOwned + Send + 'static,
>(
    response: reqwest::Response,
    cap: usize,
    context: &str,
) -> Result<(T, MetadataBodyTimings), LpmError> {
    parse_capped_metadata_with_timing_using(response, cap, context, |buf| {
        serde_json::from_slice(buf)
    })
    .await
}

pub(super) async fn parse_capped_metadata_with_timing_using<T, F>(
    response: reqwest::Response,
    cap: usize,
    context: &str,
    parse: F,
) -> Result<(T, MetadataBodyTimings), LpmError>
where
    T: Send + 'static,
    F: FnOnce(&[u8]) -> Result<T, serde_json::Error> + Send + 'static,
{
    let (result, timings) = parse_capped_metadata_attempt(response, cap, context, parse).await;
    result.map(|parsed| (parsed, timings))
}

pub(super) async fn parse_capped_metadata_attempt<T, F>(
    response: reqwest::Response,
    cap: usize,
    context: &str,
    parse: F,
) -> (Result<T, LpmError>, MetadataBodyTimings)
where
    T: Send + 'static,
    F: FnOnce(&[u8]) -> Result<T, serde_json::Error> + Send + 'static,
{
    parse_capped_metadata_owned_attempt(response, cap, context, move |bytes| {
        parse(lpm_common::strip_utf8_bom_bytes(&bytes))
    })
    .await
}

#[tracing::instrument(
    target = "lpm_install_timeline",
    level = "trace",
    name = "metadata_body",
    skip_all
)]
pub(super) async fn parse_capped_metadata_owned_attempt<T, F>(
    response: reqwest::Response,
    cap: usize,
    context: &str,
    parse: F,
) -> (Result<T, LpmError>, MetadataBodyTimings)
where
    T: Send + 'static,
    F: FnOnce(Vec<u8>) -> Result<T, serde_json::Error> + Send + 'static,
{
    let body_start = std::time::Instant::now();
    let mut buf = Vec::new();
    let (read, guard) = read_metadata_body_with_budget(
        response,
        cap,
        &mut buf,
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
    )
    .await;
    tracing::event!(name: "body_end", target: "lpm_install_timeline", tracing::Level::TRACE, bytes = buf.len() as u64, success = read.is_ok());
    let mut timings = MetadataBodyTimings {
        body_read_ms: body_start.elapsed().as_millis(),
        body_bytes: buf.len() as u64,
        cap_exceeded: matches!(
            read,
            Err(lpm_http::ResponseBodyError::DeclaredTooLarge { .. }
                | lpm_http::ResponseBodyError::StreamedTooLarge { .. })
        ),
        ..MetadataBodyTimings::default()
    };
    let read = read.map_err(|error| LpmError::Registry(format!("{context}: {error}")));
    if let Err(error) = read {
        drop(buf);
        drop(guard);
        return (Err(error), timings);
    }
    if buf.len() < BLOCKING_METADATA_PARSE_THRESHOLD {
        let span = tracing::trace_span!(target: "lpm_install_timeline", "metadata_parse", blocking = false);
        let _entered = span.enter();
        tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
        let parse_start = std::time::Instant::now();
        let parsed = parse(buf).map_err(|error| {
            LpmError::Registry(format!("{context}: failed to parse JSON: {error}"))
        });
        timings.json_parse_ms = parse_start.elapsed().as_millis();
        tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, success = parsed.is_ok());
        return (parsed, timings);
    }

    let buf_len = buf.len();
    let context_owned = context.to_string();
    let span =
        tracing::trace_span!(target: "lpm_install_timeline", "metadata_parse", blocking = true);
    tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
    let worker_span = span.clone();
    let result = run_blocking_metadata_parse_with_guard(
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
        buf_len,
        guard,
        move || {
            let _entered = worker_span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let parse_start = std::time::Instant::now();
            let parsed = parse(buf).map_err(|error| {
                LpmError::Registry(format!("{context_owned}: failed to parse JSON: {error}"))
            });
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, success = parsed.is_ok());
            (parsed, parse_start.elapsed().as_millis())
        },
    )
    .await;
    tracing::event!(name: "await_resume", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, success = result.is_ok());
    match result {
        Ok((parsed, json_parse_ms)) => {
            timings.json_parse_ms = json_parse_ms;
            (parsed, timings)
        }
        Err(error) => (
            Err(LpmError::Registry(format!(
                "{context}: JSON parse task failed: {error}"
            ))),
            timings,
        ),
    }
}

fn parse_metadata_buffer<T: serde::de::DeserializeOwned>(
    buf: &[u8],
    context: &str,
) -> Result<T, LpmError> {
    serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(buf))
        .map_err(|e| LpmError::Registry(format!("{context}: failed to parse JSON: {e}")))
}

/// Read a non-metadata JSON response (whoami, token check, etc.) with
/// the smaller API-tier cap. Exposed for callers outside this module
/// (e.g., the `token` command, the `dlx` resolver) that operate on a
/// raw `reqwest::Response` returned by [`RegistryClient::post_json_raw`]
/// and would otherwise reach for `.json()` directly.
pub async fn parse_capped_api_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, LpmError> {
    let buf = read_capped_body(response, MAX_API_RESPONSE_BYTES, context).await?;
    serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&buf))
        .map_err(|e| LpmError::Registry(format!("{context}: failed to parse JSON: {e}")))
}

pub(super) async fn parse_capped_api_json_with_timing<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<(T, ApiBodyTimings), LpmError> {
    let body_start = std::time::Instant::now();
    let buf = read_capped_body(response, MAX_API_RESPONSE_BYTES, context).await?;
    let body_read_ms = elapsed_millis(body_start);

    let parse_start = std::time::Instant::now();
    let parsed = serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&buf))
        .map_err(|e| LpmError::Registry(format!("{context}: failed to parse JSON: {e}")))?;
    let json_parse_ms = elapsed_millis(parse_start);

    Ok((
        parsed,
        ApiBodyTimings {
            body_read_ms,
            json_parse_ms,
            body_bytes: buf.len() as u64,
        },
    ))
}

/// Read an error answer's body as UTF-8 text, keeping at most
/// [`MAX_ERROR_BODY_BYTES`](super::error_body::MAX_ERROR_BODY_BYTES) of it:
/// a registry's message comes first, and an oversized body, such as a
/// proxy's page, must neither be buffered whole nor erase what came before
/// the cap. A read that fails keeps what had arrived.
pub(super) async fn read_capped_error_text(mut response: reqwest::Response) -> String {
    let limit = super::error_body::MAX_ERROR_BODY_BYTES;
    let mut buf = Vec::with_capacity(
        response
            .content_length()
            .map_or(4096, |length| usize::try_from(length).unwrap_or(limit))
            .min(limit),
    );
    while buf.len() < limit {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = limit - buf.len();
                buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// The firewall or entitlement refusal an lpm.dev Worker's 403 names, with
/// every field it sends cleaned for one terminal row, as any registry text is.
pub(super) fn parse_lpm_worker_error_body(body: &str) -> Option<LpmError> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = json_string_field(&value, "error")?;
    let text = |key: &str, max_chars: usize| {
        json_string_field(&value, key)
            .map(|text| lpm_common::sanitize_server_text(text, max_chars))
            .filter(|text| !text.is_empty())
    };
    let message = || {
        text("message", 600)
            .unwrap_or_else(|| "A Pro account or active org membership is required.".to_owned())
    };

    match error {
        "blocked_by_lpm_firewall" => {
            let display_text = |key: &str, max_chars: usize| {
                value
                    .get("display")
                    .and_then(|display| json_string_field(display, key))
                    .map(|text| lpm_common::sanitize_server_text(text, max_chars))
                    .filter(|text| !text.is_empty())
            };
            let (name, version) = split_package_coordinate(
                text("package", 214).unwrap_or_else(|| "requested package".to_owned()),
            );
            Some(LpmError::NpmFirewallBlocked(Box::new(
                lpm_common::NpmFirewallBlockedErrorContext::registry(
                    lpm_common::NpmFirewallBlockedPackage {
                        name,
                        version,
                        verdict: text("verdict", 64).unwrap_or_else(|| "unknown".to_owned()),
                        reason: text("reason", 600).unwrap_or_else(|| {
                            "the registry policy refused this download".to_owned()
                        }),
                        decision_id: text("decisionId", 120),
                        match_source: text("matchSource", 120),
                        policy_group: None,
                        summary: display_text("summary", 600),
                        report_url: display_text("reportUrl", 600),
                        block_class: None,
                        bypassable: false,
                    },
                ),
            )))
        }
        "upstream_proxy_entitlement_required" => Some(LpmError::UpstreamProxyEntitlementRequired {
            message: message(),
            reason: text("reason", 600),
            entitlement_source: text("entitlementSource", 120),
        }),
        "npm_firewall_entitlement_required" => Some(LpmError::NpmFirewallEntitlementRequired {
            message: message(),
            reason: text("reason", 600),
            entitlement_source: text("entitlementSource", 120),
        }),
        _ => None,
    }
}

/// Splits `name@version`, keeping a scoped name's leading `@`.
fn split_package_coordinate(coordinate: String) -> (String, Option<String>) {
    match coordinate.rfind('@') {
        Some(at) if at > 0 && at + 1 < coordinate.len() => {
            let version = coordinate[at + 1..].to_owned();
            let mut name = coordinate;
            name.truncate(at);
            (name, Some(version))
        }
        _ => (coordinate, None),
    }
}

pub(super) fn json_string_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn elapsed_millis(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_large_metadata_parse_retains_permit_until_worker_finishes() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let limiter_for_task = Arc::clone(&limiter);
        let task = tokio::spawn(async move {
            run_blocking_metadata_parse(
                &limiter_for_task,
                LARGE_METADATA_PARSE_THRESHOLD,
                move || {
                    let _ = started_tx.send(());
                    let _ = resume_rx.recv();
                    42usize
                },
            )
            .await
        });

        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            limiter.available_permits(),
            0,
            "permit must stay held while blocking metadata parse is still executing"
        );

        resume_tx.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), limiter.acquire())
            .await
            .expect("permit must be released once blocking parse finishes")
            .unwrap();
        drop(permit);
        assert_eq!(limiter.available_permits(), 1);
    }

    #[test]
    fn firewall_refusal_keeps_a_scoped_name_and_reads_the_report_link() {
        let body = r#"{"error":"blocked_by_lpm_firewall","package":"@scope/pkg@1.2.3","verdict":"malicious","reason":"r","display":{"summary":"s","reportUrl":"https://firewall.lpm.dev/npm/@scope/pkg/v/1.2.3"}}"#;

        let Some(LpmError::NpmFirewallBlocked(blocked)) = parse_lpm_worker_error_body(body) else {
            panic!("expected a firewall block");
        };

        let package = &blocked.packages[0];
        assert_eq!(package.name, "@scope/pkg");
        assert_eq!(package.version.as_deref(), Some("1.2.3"));
        assert_eq!(package.summary.as_deref(), Some("s"));
        assert_eq!(
            package.report_url.as_deref(),
            Some("https://firewall.lpm.dev/npm/@scope/pkg/v/1.2.3")
        );
        assert_eq!(blocked.source, lpm_common::NpmFirewallBlockSource::Registry);
    }

    #[test]
    fn firewall_refusal_without_a_version_keeps_the_whole_name() {
        assert_eq!(
            split_package_coordinate("@scope/pkg".to_owned()),
            ("@scope/pkg".to_owned(), None)
        );
        assert_eq!(
            split_package_coordinate("pkg@".to_owned()),
            ("pkg@".to_owned(), None)
        );
    }

    #[tokio::test]
    async fn large_metadata_body_read_waits_for_memory_budget_before_completing() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let payload = "a".repeat(LARGE_METADATA_PARSE_THRESHOLD + 4096);
        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_string(payload.clone()))
            .mount(&server)
            .await;

        let response = reqwest::Client::new()
            .get(format!("{}/large", server.uri()))
            .send()
            .await
            .unwrap();
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let held = Arc::clone(&budget)
            .try_acquire_many_owned(METADATA_MEMORY_BUDGET_UNITS as u32)
            .unwrap();

        let limiter_for_task = Arc::clone(&limiter);
        let budget_for_task = Arc::clone(&budget);
        let mut task = tokio::spawn(async move {
            let mut body = Vec::new();
            let (read, guard) = read_metadata_body_with_budget(
                response,
                MAX_METADATA_BYTES,
                &mut body,
                &limiter_for_task,
                &budget_for_task,
            )
            .await;
            read.unwrap();
            (body.len(), guard.is_some())
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(60), &mut task)
                .await
                .is_err(),
            "large body read must wait for memory budget permits before buffering"
        );
        drop(held);
        let (len, acquired_guard) = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("body read must finish once memory budget permits are available")
            .unwrap();
        assert_eq!(len, payload.len());
        assert!(acquired_guard);
        assert_eq!(budget.available_permits(), METADATA_MEMORY_BUDGET_UNITS);
    }
}
