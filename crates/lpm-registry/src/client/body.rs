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
// Initial upfront reservation for unknown-length chunked HTTP/1.1 bodies so up to 4
// concurrent chunked packument streams overlap under the 128 MiB budget (4 * 16 MiB =
// 64 MiB). No stream may grow past 16 MiB without first acquiring the single-permit
// `chunked_overflow_limiter`, and once holding it the stream acquires its full remaining
// headroom up to `cap` in one shot. Because every stream without `overflow_permit` holds
// at most 16 MiB (or is a declared-length stream that already holds its full length and
// never blocks again), both all-chunked (`4 * 16 + 48 = 112 MiB <= 128 MiB`) and mixed
// FIFO declared-length (`3 * 16 + 64 = 112 MiB <= 128 MiB`) schedules are deadlock-free.
const CHUNKED_INITIAL_RESERVE_BYTES: usize = 16 * 1024 * 1024;

fn chunked_overflow_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static OVERFLOW: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    OVERFLOW.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
}

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

#[inline]
fn budget_units_for_bytes(bytes: usize) -> u32 {
    u32::try_from(
        bytes
            .div_ceil(METADATA_MEMORY_BUDGET_QUANTUM)
            .clamp(1, METADATA_MEMORY_BUDGET_UNITS),
    )
    .unwrap_or(METADATA_MEMORY_BUDGET_UNITS as u32)
}

struct LargeMetadataMemoryGuard {
    concurrency_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    byte_budget_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    overflow_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    reserved_units: u32,
}

impl LargeMetadataMemoryGuard {
    fn shrink_to(&mut self, actual_bytes: usize) {
        let needed = budget_units_for_bytes(actual_bytes);
        if self.reserved_units > needed
            && let Some(permit) = self.byte_budget_permit.as_mut()
            && let Some(excess) = permit.split((self.reserved_units - needed) as usize)
        {
            drop(excess);
            self.reserved_units = needed;
        }
    }
}

async fn acquire_large_metadata_guard_units(
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
    units: u32,
) -> Option<LargeMetadataMemoryGuard> {
    let concurrency_permit = Arc::clone(limiter).acquire_owned().await.ok()?;
    let units = units.clamp(1, METADATA_MEMORY_BUDGET_UNITS as u32);
    let byte_budget_permit = Arc::clone(budget).acquire_many_owned(units).await.ok()?;
    Some(LargeMetadataMemoryGuard {
        concurrency_permit: Some(concurrency_permit),
        byte_budget_permit: Some(byte_budget_permit),
        overflow_permit: None,
        reserved_units: units,
    })
}

fn try_reserve_multiplexed_bytes(
    budget: &Arc<tokio::sync::Semaphore>,
    guard: &mut Option<LargeMetadataMemoryGuard>,
    bytes: usize,
) {
    let needed = budget_units_for_bytes(bytes);
    match guard {
        Some(existing) => {
            if needed <= existing.reserved_units {
                return;
            }
            let delta = needed - existing.reserved_units;
            if let Ok(extra) = Arc::clone(budget).try_acquire_many_owned(delta) {
                if let Some(permit) = existing.byte_budget_permit.as_mut() {
                    permit.merge(extra);
                } else {
                    existing.byte_budget_permit = Some(extra);
                }
                existing.reserved_units += delta;
            }
        }
        None => {
            if let Ok(permit) = Arc::clone(budget).try_acquire_many_owned(needed) {
                *guard = Some(LargeMetadataMemoryGuard {
                    concurrency_permit: None,
                    byte_budget_permit: Some(permit),
                    overflow_permit: None,
                    reserved_units: needed,
                });
            }
        }
    }
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
    read_metadata_body_with_budget_and_overflow(
        response,
        cap,
        body,
        limiter,
        budget,
        chunked_overflow_limiter(),
    )
    .await
}

async fn read_metadata_body_with_budget_and_overflow(
    response: reqwest::Response,
    cap: usize,
    body: &mut Vec<u8>,
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
    overflow_limiter: &Arc<tokio::sync::Semaphore>,
) -> (
    Result<(), lpm_http::ResponseBodyError>,
    Option<LargeMetadataMemoryGuard>,
) {
    // Never park mid-stream on multiplexed connections (HTTP/2, HTTP/3): unread
    // DATA frames pin stream windows against the shared connection window and
    // can starve permit-holding streams until read timeout. Multiplexed streams
    // therefore reserve bytes non-blockingly during reads (bounded in practice
    // by the resolver's metadata fanout cap and `MAX_METADATA_BYTES`) and
    // acquire full concurrency + byte permits in canonical order before parsing.
    let is_multiplexed = matches!(
        response.version(),
        reqwest::Version::HTTP_2 | reqwest::Version::HTTP_3
    );
    let limiter = Arc::clone(limiter);
    let budget = Arc::clone(budget);
    let overflow_limiter = Arc::clone(overflow_limiter);
    let (result, mut guard) = lpm_http::read_body_capped_with_budget(
        response,
        cap,
        body,
        None::<LargeMetadataMemoryGuard>,
        move |mut guard, next_len, next_capacity, is_declared_total| {
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            let overflow_limiter = Arc::clone(&overflow_limiter);
            async move {
                if next_len < LARGE_METADATA_PARSE_THRESHOLD {
                    return guard;
                }
                let accounted_bytes = next_capacity.min(cap).max(next_len);
                if is_multiplexed {
                    try_reserve_multiplexed_bytes(&budget, &mut guard, accounted_bytes);
                    return guard;
                }
                if guard.is_none() {
                    // Reserve either the exact declared length or a bounded initial
                    // quantum for unknown-length chunked streams so normal packuments
                    // keep full concurrency while avoiding mid-stream deadlocks.
                    let reserve_bytes = if is_declared_total {
                        accounted_bytes
                    } else {
                        cap.min(CHUNKED_INITIAL_RESERVE_BYTES).max(accounted_bytes)
                    };
                    guard = acquire_large_metadata_guard_units(
                        &limiter,
                        &budget,
                        budget_units_for_bytes(reserve_bytes),
                    )
                    .await;
                } else if !is_declared_total {
                    let needed = budget_units_for_bytes(accounted_bytes);
                    if let Some(existing) = guard.as_mut()
                        && existing.reserved_units < needed
                    {
                        // Never grow past the initial 16 MiB slice without first
                        // acquiring `overflow_limiter`, and reserve up to `cap` in one
                        // shot so neither concurrent chunked streams nor mixed FIFO
                        // declared-length requests can enter hold-and-wait deadlock.
                        if existing.overflow_permit.is_none() {
                            existing.overflow_permit =
                                Arc::clone(&overflow_limiter).acquire_owned().await.ok();
                        }
                        let target_units = budget_units_for_bytes(cap).max(needed);
                        if target_units > existing.reserved_units {
                            let delta = target_units - existing.reserved_units;
                            if let Ok(extra) = Arc::clone(&budget).acquire_many_owned(delta).await {
                                if let Some(permit) = existing.byte_budget_permit.as_mut() {
                                    permit.merge(extra);
                                } else {
                                    existing.byte_budget_permit = Some(extra);
                                }
                                existing.reserved_units += delta;
                            }
                        }
                    }
                }
                guard
            }
        },
    )
    .await;
    if let Some(guard) = guard.as_mut() {
        // Release the overflow serialization token as soon as streaming ends so the
        // next large chunked stream can proceed while this body is parsed.
        guard.overflow_permit = None;
        if result.is_ok() {
            guard.shrink_to(body.capacity().min(cap).max(body.len()));
        }
    }
    (result, guard)
}

async fn run_blocking_metadata_parse_with_guard<T, F>(
    limiter: &Arc<tokio::sync::Semaphore>,
    budget: &Arc<tokio::sync::Semaphore>,
    buf_len: usize,
    retained_bytes: usize,
    preacquired_guard: Option<LargeMetadataMemoryGuard>,
    parse: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let guard = if buf_len >= LARGE_METADATA_PARSE_THRESHOLD {
        let accounted_bytes = retained_bytes.max(buf_len);
        let needed_units = budget_units_for_bytes(accounted_bytes);
        match preacquired_guard {
            Some(mut existing)
                if existing.concurrency_permit.is_some()
                    && existing.reserved_units >= needed_units =>
            {
                existing.shrink_to(accounted_bytes);
                Some(existing)
            }
            partial => {
                // Release partial non-blocking reservation before acquiring both
                // permits in canonical order (limiter -> budget) to prevent deadlock.
                drop(partial);
                acquire_large_metadata_guard_units(limiter, budget, needed_units).await
            }
        }
    } else {
        drop(preacquired_guard);
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
    let retained_bytes = buf.capacity().min(MAX_METADATA_BYTES).max(buf_len);
    let context_owned = context.to_string();
    run_blocking_metadata_parse_with_guard(
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
        buf_len,
        retained_bytes,
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
    let retained_bytes = buf.capacity().min(cap).max(buf_len);
    let context_owned = context.to_string();
    let span =
        tracing::trace_span!(target: "lpm_install_timeline", "metadata_parse", blocking = true);
    tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
    let worker_span = span.clone();
    let result = run_blocking_metadata_parse_with_guard(
        large_metadata_parse_limiter(),
        metadata_body_memory_budget(),
        buf_len,
        retained_bytes,
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

    #[tokio::test]
    async fn chunked_large_body_reserves_upfront_shrinks_on_eof_and_releases_on_cancel() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let chunk_body = "x".repeat(LARGE_METADATA_PARSE_THRESHOLD + 8192);
        let chunk_body_for_server = chunk_body.clone();
        let stalled_sent = Arc::new(tokio::sync::Notify::new());
        let stalled_sent_for_server = Arc::clone(&stalled_sent);
        let release_stalled = Arc::new(tokio::sync::Notify::new());
        let release_stalled_for_server = Arc::clone(&release_stalled);
        tokio::spawn(async move {
            // Request 1: complete chunked response.
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req_buf = [0u8; 1024];
            let _ = socket.read(&mut req_buf).await;
            let hex_len = format!("{:x}", chunk_body_for_server.len());
            let header = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{hex_len}\r\n"
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(chunk_body_for_server.as_bytes()).await;
            let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
            let _ = socket.shutdown().await;

            // Request 2: sends first chunk exceeding threshold, then stalls mid-stream
            // so the caller can cancel the future and verify permit release.
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut req_buf).await;
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(chunk_body_for_server.as_bytes()).await;
            let _ = socket.write_all(b"\r\n").await;
            let _ = socket.flush().await;
            stalled_sent_for_server.notify_one();
            release_stalled_for_server.notified().await;
            drop(socket);
        });

        let cap = 2 * 1024 * 1024;
        let cap_units = budget_units_for_bytes(cap);
        let actual_units = budget_units_for_bytes(chunk_body.len());
        assert!(cap_units > actual_units);

        let limiter = Arc::new(tokio::sync::Semaphore::new(2));
        let budget = Arc::new(tokio::sync::Semaphore::new(cap_units as usize));

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/chunked"))
            .send()
            .await
            .unwrap();
        let mut body = Vec::new();
        let (read, guard) =
            read_metadata_body_with_budget(response, cap, &mut body, &limiter, &budget).await;
        read.unwrap();
        assert_eq!(body.len(), chunk_body.len());
        let capacity_units = budget_units_for_bytes(body.capacity());
        assert!(
            cap_units > capacity_units && capacity_units >= actual_units,
            "backing capacity units ({capacity_units}) must sit between payload ({actual_units}) and cap ({cap_units})"
        );
        let guard = guard.expect("chunked large body must hold shrunk guard");
        // Unused headroom above the live Vec backing allocation must be returned on EOF.
        assert_eq!(
            budget.available_permits(),
            (cap_units - capacity_units) as usize
        );
        drop(guard);
        assert_eq!(budget.available_permits(), cap_units as usize);

        // Cancel a stalled chunked body mid-stream and verify both limiter and budget release.
        let response2 = reqwest::Client::new()
            .get(format!("http://{addr}/chunked-stalled"))
            .send()
            .await
            .unwrap();
        let limiter_for_task = Arc::clone(&limiter);
        let budget_for_task = Arc::clone(&budget);
        let stalled_task = tokio::spawn(async move {
            let mut body2 = Vec::new();
            let _ = read_metadata_body_with_budget(
                response2,
                cap,
                &mut body2,
                &limiter_for_task,
                &budget_for_task,
            )
            .await;
        });
        stalled_sent.notified().await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while limiter.available_permits() == 2
                || budget.available_permits() == cap_units as usize
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled chunked body must acquire permits after crossing threshold");

        stalled_task.abort();
        let _ = stalled_task.await;
        release_stalled.notify_one();
        assert_eq!(limiter.available_permits(), 2);
        assert_eq!(budget.available_permits(), cap_units as usize);
    }

    #[tokio::test]
    async fn multiplexed_http2_large_bodies_drain_without_deadlocking_on_limiter_or_budget() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        async fn write_h2_frame<W: tokio::io::AsyncWrite + Unpin>(
            w: &mut W,
            frame_type: u8,
            flags: u8,
            stream_id: u32,
            payload: &[u8],
        ) -> std::io::Result<()> {
            let len = payload.len() as u32;
            let header = [
                ((len >> 16) & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
                frame_type,
                flags,
                ((stream_id >> 24) & 0x7f) as u8,
                ((stream_id >> 16) & 0xff) as u8,
                ((stream_id >> 8) & 0xff) as u8,
                (stream_id & 0xff) as u8,
            ];
            w.write_all(&header).await?;
            w.write_all(payload).await?;
            Ok(())
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = vec![b'z'; LARGE_METADATA_PARSE_THRESHOLD + 128 * 1024];
        let payload_for_server = payload.clone();
        let clients_done = Arc::new(tokio::sync::Notify::new());
        let clients_done_for_server = Arc::clone(&clients_done);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0u8; 24];
            socket.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // Send empty server SETTINGS frame.
            write_h2_frame(&mut socket, 4, 0, 0, &[]).await.unwrap();

            let mut completed_streams = 0usize;
            let mut saw_warmup = false;
            let mut pending_streams: Vec<(u32, usize)> = Vec::new();
            let mut conn_send_window: usize = 65_535;
            let mut initial_stream_window: usize = 65_535;
            let mut stream_send_windows: HashMap<u32, usize> = HashMap::new();

            loop {
                // Flush DATA frames round-robin until every pending stream is window-blocked or done.
                loop {
                    let mut progressed = false;
                    let mut i = 0;
                    while i < pending_streams.len() && conn_send_window > 0 {
                        let (stream_id, offset) = pending_streams[i];
                        let sw = stream_send_windows.get(&stream_id).copied().unwrap_or(0);
                        let remaining = payload_for_server.len() - offset;
                        let send_len = remaining.min(16_384).min(conn_send_window).min(sw);
                        if send_len == 0 {
                            i += 1;
                            continue;
                        }
                        progressed = true;
                        let next_offset = offset + send_len;
                        let flags = if next_offset == payload_for_server.len() {
                            0x01 // END_STREAM
                        } else {
                            0x00
                        };
                        if write_h2_frame(
                            &mut socket,
                            0,
                            flags,
                            stream_id,
                            &payload_for_server[offset..next_offset],
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        conn_send_window -= send_len;
                        *stream_send_windows.get_mut(&stream_id).unwrap() -= send_len;
                        if next_offset == payload_for_server.len() {
                            pending_streams.swap_remove(i);
                            completed_streams += 1;
                        } else {
                            pending_streams[i].1 = next_offset;
                            i += 1;
                        }
                    }
                    if !progressed {
                        break;
                    }
                }
                if completed_streams == 6 {
                    // Keep the TCP socket open until all client tasks finish draining
                    // buffered DATA frames so teardown never injects a spurious RST.
                    let _ = socket.flush().await;
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        clients_done_for_server.notified(),
                    )
                    .await;
                    break;
                }

                let mut hdr = [0u8; 9];
                if socket.read_exact(&mut hdr).await.is_err() {
                    break;
                }
                let frame_len =
                    ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
                let frame_type = hdr[3];
                let flags = hdr[4];
                let stream_id = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
                let mut frame_payload = vec![0u8; frame_len];
                if socket.read_exact(&mut frame_payload).await.is_err() {
                    break;
                }
                match frame_type {
                    4 if (flags & 1) == 0 => {
                        for chunk in frame_payload.as_chunks::<6>().0 {
                            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                            let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]])
                                as usize;
                            if id == 4 {
                                initial_stream_window = val;
                            }
                        }
                        // SETTINGS (non-ACK) -> acknowledge.
                        let _ = write_h2_frame(&mut socket, 4, 1, 0, &[]).await;
                    }
                    1 => {
                        if !saw_warmup {
                            // First request warms up reqwest's shared H2 connection pool with an empty 200.
                            saw_warmup = true;
                            let _ = write_h2_frame(&mut socket, 1, 0x05, stream_id, &[0x88]).await;
                        } else {
                            // Subsequent requests multiplex large bodies over that single connection.
                            let _ = write_h2_frame(&mut socket, 1, 0x04, stream_id, &[0x88]).await;
                            stream_send_windows.insert(stream_id, initial_stream_window);
                            pending_streams.push((stream_id, 0));
                        }
                    }
                    8 if frame_payload.len() == 4 => {
                        let inc = u32::from_be_bytes([
                            frame_payload[0] & 0x7f,
                            frame_payload[1],
                            frame_payload[2],
                            frame_payload[3],
                        ]) as usize;
                        if stream_id == 0 {
                            conn_send_window += inc;
                        } else if let Some(w) = stream_send_windows.get_mut(&stream_id) {
                            *w += inc;
                        }
                    }
                    _ => {}
                }
            }
        });

        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        // Establish the single HTTP/2 connection in reqwest's pool before fanning out streams.
        let warmup = client
            .get(format!("http://{addr}/warmup"))
            .send()
            .await
            .unwrap();
        assert_eq!(warmup.version(), reqwest::Version::HTTP_2);
        let _ = warmup.bytes().await.unwrap();
        // Saturate both limiter and budget to prove multiplexed HTTP/2 reads never
        // park mid-stream and starve hyper's shared connection window.
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let _held_limiter = Arc::clone(&limiter).try_acquire_owned().unwrap();
        let _held_budget = Arc::clone(&budget)
            .try_acquire_many_owned(METADATA_MEMORY_BUDGET_UNITS as u32)
            .unwrap();

        let mut tasks = Vec::new();
        for i in 0..6 {
            let client = client.clone();
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            let expected_len = payload.len();
            tasks.push(tokio::spawn(async move {
                let response = client
                    .get(format!("http://{addr}/stream-{i}"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.version(), reqwest::Version::HTTP_2);
                let mut body = Vec::new();
                let (read, guard) = read_metadata_body_with_budget(
                    response,
                    MAX_METADATA_BYTES,
                    &mut body,
                    &limiter,
                    &budget,
                )
                .await;
                read.unwrap();
                assert_eq!(body.len(), expected_len);
                assert!(guard.is_none());
            }));
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect(
            "multiplexed HTTP/2 large bodies must drain without stalling the connection window",
        );
        clients_done.notify_one();
    }

    #[tokio::test]
    async fn chunked_http1_bodies_exceeding_initial_reserve_respect_budget_without_deadlock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Stream three 18 MiB chunked HTTP/1.1 bodies concurrently through a 128 MiB
        // budget while another consumer holds 80 MiB of the budget (leaving 48 MiB,
        // enough for 3 * 16 MiB initial reserves but NOT enough for all three to grow
        // past 16 MiB simultaneously). Once the 80 MiB holder releases, every stream
        // must finish cleanly with full budget accounting.
        let body_len = 18 * 1024 * 1024;
        let chunk_size = 512 * 1024;
        let chunk_bytes = Arc::new(vec![b'a'; chunk_size]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn({
            let chunk_bytes = Arc::clone(&chunk_bytes);
            async move {
                let mut handlers = Vec::new();
                for _ in 0..3 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let chunk_bytes = Arc::clone(&chunk_bytes);
                    handlers.push(tokio::spawn(async move {
                        let mut req = [0u8; 1024];
                        let _ = socket.read(&mut req).await;
                        socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                            )
                            .await
                            .unwrap();
                        let header = format!("{:x}\r\n", chunk_bytes.len());
                        let mut sent = 0usize;
                        while sent < body_len {
                            socket.write_all(header.as_bytes()).await.unwrap();
                            socket.write_all(&chunk_bytes).await.unwrap();
                            socket.write_all(b"\r\n").await.unwrap();
                            sent += chunk_bytes.len();
                        }
                        socket.write_all(b"0\r\n\r\n").await.unwrap();
                    }));
                }
                for h in handlers {
                    let _ = h.await;
                }
            }
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let limiter = Arc::new(tokio::sync::Semaphore::new(4));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let overflow = Arc::new(tokio::sync::Semaphore::new(1));
        // Hold 80 MiB initially so all three streams can reserve their 16 MiB slices
        // (48 MiB) and must wait cleanly on the overflow limiter + budget to grow past
        // 16 MiB, proving both budget enforcement and deadlock-freedom.
        let held_units = budget_units_for_bytes(80 * 1024 * 1024);
        let held_budget = Arc::clone(&budget)
            .acquire_many_owned(held_units)
            .await
            .unwrap();

        let mut tasks = Vec::new();
        for i in 0..3 {
            let client = client.clone();
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            let overflow = Arc::clone(&overflow);
            tasks.push(tokio::spawn(async move {
                let response = client
                    .get(format!("http://{addr}/chunked-{i}"))
                    .send()
                    .await
                    .unwrap();
                let mut body = Vec::new();
                let (read, guard) = read_metadata_body_with_budget_and_overflow(
                    response,
                    20 * 1024 * 1024,
                    &mut body,
                    &limiter,
                    &budget,
                    &overflow,
                )
                .await;
                read.unwrap();
                assert_eq!(body.len(), body_len);
                let guard = guard.expect("chunked >16 MiB body must hold a memory guard");
                assert!(
                    guard.reserved_units >= budget_units_for_bytes(body_len),
                    "guard must account for full 18 MiB body"
                );
            }));
        }

        // Release the 80 MiB blocker shortly after the streams reach their 16 MiB boundary.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(held_budget);

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("concurrent chunked HTTP/1.1 bodies >16 MiB must complete without deadlock");
        assert_eq!(
            budget.available_permits(),
            METADATA_MEMORY_BUDGET_UNITS,
            "all byte budget permits must be returned after completion"
        );
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn four_concurrent_chunked_http1_bodies_exceeding_budget_complete_without_deadlock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 4 concurrent 40 MiB chunked streams (160 MiB aggregate > 128 MiB budget) with
        // cap = MAX_METADATA_BYTES (64 MiB) and 64 KiB chunks. Without gating growth
        // past 16 MiB behind `overflow_limiter`, streams fill all 128 MiB and deadlock.
        let body_len = 40 * 1024 * 1024;
        let chunk_size = 64 * 1024;
        let chunk_bytes = Arc::new(vec![b'b'; chunk_size]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn({
            let chunk_bytes = Arc::clone(&chunk_bytes);
            async move {
                let mut handlers = Vec::new();
                for _ in 0..4 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let chunk_bytes = Arc::clone(&chunk_bytes);
                    handlers.push(tokio::spawn(async move {
                        let mut req = [0u8; 1024];
                        let _ = socket.read(&mut req).await;
                        socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                            )
                            .await
                            .unwrap();
                        let header = format!("{:x}\r\n", chunk_bytes.len());
                        let mut sent = 0usize;
                        while sent < body_len {
                            socket.write_all(header.as_bytes()).await.unwrap();
                            socket.write_all(&chunk_bytes).await.unwrap();
                            socket.write_all(b"\r\n").await.unwrap();
                            sent += chunk_bytes.len();
                        }
                        socket.write_all(b"0\r\n\r\n").await.unwrap();
                    }));
                }
                for h in handlers {
                    let _ = h.await;
                }
            }
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let limiter = Arc::new(tokio::sync::Semaphore::new(4));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let overflow = Arc::new(tokio::sync::Semaphore::new(1));

        let mut tasks = Vec::new();
        for i in 0..4 {
            let client = client.clone();
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            let overflow = Arc::clone(&overflow);
            tasks.push(tokio::spawn(async move {
                let response = client
                    .get(format!("http://{addr}/large-chunked-{i}"))
                    .send()
                    .await
                    .unwrap();
                let mut body = Vec::new();
                let (read, guard) = read_metadata_body_with_budget_and_overflow(
                    response,
                    MAX_METADATA_BYTES,
                    &mut body,
                    &limiter,
                    &budget,
                    &overflow,
                )
                .await;
                read.unwrap();
                assert_eq!(body.len(), body_len);
                assert!(
                    body.capacity() <= MAX_METADATA_BYTES,
                    "backing allocation {} must not exceed cap {MAX_METADATA_BYTES}",
                    body.capacity()
                );
                let guard = guard.expect("40 MiB chunked body must hold a memory guard");
                assert!(
                    guard.reserved_units >= budget_units_for_bytes(body.capacity()),
                    "guard must account for backing Vec capacity"
                );
            }));
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("four 40 MiB chunked streams must finish without deadlock");
        assert_eq!(budget.available_permits(), METADATA_MEMORY_BUDGET_UNITS);
        assert_eq!(limiter.available_permits(), 4);
        assert_eq!(overflow.available_permits(), 1);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn mixed_declared_and_chunked_http1_bodies_complete_without_fifo_deadlock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let chunked_len = 36 * 1024 * 1024;
        let declared_len = 48 * 1024 * 1024;
        let chunk_bytes = Arc::new(vec![b'c'; 256 * 1024]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn({
            let chunk_bytes = Arc::clone(&chunk_bytes);
            async move {
                let mut handlers = Vec::new();
                for _ in 0..5 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let chunk_bytes = Arc::clone(&chunk_bytes);
                    handlers.push(tokio::spawn(async move {
                        let mut req = [0u8; 1024];
                        let n = socket.read(&mut req).await.unwrap();
                        let req_head = String::from_utf8_lossy(&req[..n]);
                        if req_head.contains("/declared-") {
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n"
                            );
                            socket.write_all(header.as_bytes()).await.unwrap();
                            let mut sent = 0usize;
                            while sent < declared_len {
                                let step = chunk_bytes.len().min(declared_len - sent);
                                socket.write_all(&chunk_bytes[..step]).await.unwrap();
                                sent += step;
                            }
                        } else {
                            socket
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                                )
                                .await
                                .unwrap();
                            let header = format!("{:x}\r\n", chunk_bytes.len());
                            let mut sent = 0usize;
                            while sent < chunked_len {
                                socket.write_all(header.as_bytes()).await.unwrap();
                                socket.write_all(&chunk_bytes).await.unwrap();
                                socket.write_all(b"\r\n").await.unwrap();
                                sent += chunk_bytes.len();
                            }
                            socket.write_all(b"0\r\n\r\n").await.unwrap();
                        }
                    }));
                }
                for h in handlers {
                    let _ = h.await;
                }
            }
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let limiter = Arc::new(tokio::sync::Semaphore::new(4));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let overflow = Arc::new(tokio::sync::Semaphore::new(1));

        let mut tasks = Vec::new();
        for (path, expected_len) in [
            ("chunked-0", chunked_len),
            ("chunked-1", chunked_len),
            ("declared-0", declared_len),
            ("chunked-2", chunked_len),
            ("declared-1", declared_len),
        ] {
            let client = client.clone();
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            let overflow = Arc::clone(&overflow);
            tasks.push(tokio::spawn(async move {
                let response = client
                    .get(format!("http://{addr}/{path}"))
                    .send()
                    .await
                    .unwrap();
                let mut body = Vec::new();
                let (read, guard) = read_metadata_body_with_budget_and_overflow(
                    response,
                    MAX_METADATA_BYTES,
                    &mut body,
                    &limiter,
                    &budget,
                    &overflow,
                )
                .await;
                read.unwrap();
                assert_eq!(body.len(), expected_len);
                assert!(guard.is_some());
            }));
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("mixed declared-length and chunked streams must finish without FIFO deadlock");
        assert_eq!(budget.available_permits(), METADATA_MEMORY_BUDGET_UNITS);
        assert_eq!(limiter.available_permits(), 4);
        assert_eq!(overflow.available_permits(), 1);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn blocking_metadata_parse_retains_backing_capacity_budget_until_parse_completes() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(4));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let buf_len = 33 * 1024 * 1024;
        let capacity = 64 * 1024 * 1024;
        let preacquired =
            acquire_large_metadata_guard_units(&limiter, &budget, budget_units_for_bytes(capacity))
                .await
                .expect("capacity-sized guard");

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let parse_task = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            let budget = Arc::clone(&budget);
            async move {
                run_blocking_metadata_parse_with_guard(
                    &limiter,
                    &budget,
                    buf_len,
                    capacity,
                    Some(preacquired),
                    move || {
                        let _ = entered_tx.send(());
                        let _ = release_rx.recv();
                        42usize
                    },
                )
                .await
            }
        });

        entered_rx.await.unwrap();
        let expected_remaining =
            METADATA_MEMORY_BUDGET_UNITS - budget_units_for_bytes(capacity) as usize;
        assert_eq!(
            budget.available_permits(),
            expected_remaining,
            "byte budget must remain reserved for full backing capacity while parsing runs"
        );
        release_tx.send(()).unwrap();
        assert_eq!(parse_task.await.unwrap().unwrap(), 42);
        assert_eq!(budget.available_permits(), METADATA_MEMORY_BUDGET_UNITS);
        assert_eq!(limiter.available_permits(), 4);
    }

    #[tokio::test]
    async fn chunked_http1_body_below_large_threshold_does_not_acquire_large_guard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 300 KiB body doubles backing Vec capacity to 512 KiB, but actual length stays
        // below LARGE_METADATA_PARSE_THRESHOLD (512 KiB) so it must not consume large-body permits.
        let body_len = 300 * 1024;
        let chunk = vec![b'a'; 60 * 1024];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = socket.read(&mut req).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let header = format!("{:x}\r\n", chunk.len());
            for _ in 0..(body_len / chunk.len()) {
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let limiter = Arc::new(tokio::sync::Semaphore::new(2));
        let budget = Arc::new(tokio::sync::Semaphore::new(METADATA_MEMORY_BUDGET_UNITS));
        let overflow = Arc::new(tokio::sync::Semaphore::new(1));
        let response = client
            .get(format!("http://{addr}/mid-chunked"))
            .send()
            .await
            .unwrap();
        let mut body = Vec::new();
        let (read, guard) = read_metadata_body_with_budget_and_overflow(
            response,
            MAX_METADATA_BYTES,
            &mut body,
            &limiter,
            &budget,
            &overflow,
        )
        .await;
        read.unwrap();
        assert_eq!(body.len(), body_len);
        assert!(
            guard.is_none(),
            "300 KiB chunked body must not trigger the 512 KiB large-body limiter"
        );
        assert_eq!(limiter.available_permits(), 2);
        assert_eq!(budget.available_permits(), METADATA_MEMORY_BUDGET_UNITS);
        let _ = server_task.await;
    }
}
