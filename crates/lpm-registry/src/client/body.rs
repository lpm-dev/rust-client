use super::*;

/// Hard cap on the number of bytes we will buffer from a single metadata
/// response body. Real packuments — even for the largest npm packages
/// like `react` or `lodash` — top out at ~10-20 MB; LPM requests the
/// abbreviated packument format (`application/vnd.npm.install-v1+json`)
/// which trims further. 100 MB is several×-headroom over any
/// legitimate metadata response and orders of magnitude below a
/// memory-exhaustion attack from a compromised mirror or MITM.
pub(super) const MAX_METADATA_BYTES: usize = 100 * 1024 * 1024;
// Keep small responses inline; large packuments can monopolize an async worker.
const BLOCKING_METADATA_PARSE_THRESHOLD: usize = 64 * 1024;

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
    use futures::StreamExt;

    if let Some(declared) = response.content_length()
        && declared as usize > cap
    {
        return Err(LpmError::Registry(format!(
            "{context}: declared body length {declared} exceeds cap {cap}"
        )));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(std::cmp::min(64 * 1024, cap));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| LpmError::Registry(format!("{context}: body read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(LpmError::Registry(format!(
                "{context}: streamed body exceeded cap {cap}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
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
    let buf = read_capped_body(response, MAX_METADATA_BYTES, context).await?;
    if buf.len() < BLOCKING_METADATA_PARSE_THRESHOLD {
        return parse_metadata_buffer(&buf, context);
    }

    let context_owned = context.to_string();
    tokio::task::spawn_blocking(move || parse_metadata_buffer(&buf, &context_owned))
        .await
        .map_err(|e| LpmError::Registry(format!("{context}: JSON parse task failed: {e}")))?
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct MetadataBodyTimings {
    pub(super) body_read_ms: u128,
    pub(super) json_parse_ms: u128,
    pub(super) body_bytes: u64,
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
    let body_start = std::time::Instant::now();
    let buf = read_capped_body(response, MAX_METADATA_BYTES, context).await?;
    let mut timings = MetadataBodyTimings {
        body_read_ms: body_start.elapsed().as_millis(),
        body_bytes: buf.len() as u64,
        ..MetadataBodyTimings::default()
    };

    if buf.len() < BLOCKING_METADATA_PARSE_THRESHOLD {
        let parse_start = std::time::Instant::now();
        let parsed = parse_metadata_buffer(&buf, context)?;
        timings.json_parse_ms = parse_start.elapsed().as_millis();
        return Ok((parsed, timings));
    }

    let context_owned = context.to_string();
    let (parsed, json_parse_ms) = tokio::task::spawn_blocking(move || {
        let parse_start = std::time::Instant::now();
        let parsed = parse_metadata_buffer(&buf, &context_owned);
        (parsed, parse_start.elapsed().as_millis())
    })
    .await
    .map_err(|e| LpmError::Registry(format!("{context}: JSON parse task failed: {e}")))?;
    timings.json_parse_ms = json_parse_ms;
    Ok((parsed?, timings))
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

/// Read an error-body response as UTF-8 text under the API-tier cap.
///
/// Returns the empty string on cap-overflow or read errors so the
/// caller can still construct a typed error variant — the previous
/// `response.text().await.unwrap_or_default()` shape is preserved
/// but the buffer is now bounded.
pub(super) async fn read_capped_error_text(response: reqwest::Response) -> String {
    match read_capped_body(response, MAX_API_RESPONSE_BYTES, "error body").await {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

pub(super) fn parse_lpm_worker_error_body(body: &str) -> Option<LpmError> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = json_string_field(&value, "error")?;

    match error {
        "blocked_by_lpm_firewall" => {
            let package = json_string_field(&value, "package").unwrap_or("requested package");
            let verdict = json_string_field(&value, "verdict").unwrap_or("unknown");
            let reason = json_string_field(&value, "reason")
                .unwrap_or("the registry policy refused this download");
            Some(LpmError::NpmFirewallBlocked {
                package: package.to_owned(),
                verdict: verdict.to_owned(),
                reason: reason.to_owned(),
                decision_id: json_string_field(&value, "decisionId").map(str::to_owned),
                match_source: json_string_field(&value, "matchSource").map(str::to_owned),
            })
        }
        "upstream_proxy_entitlement_required" => {
            let message = json_string_field(&value, "message")
                .unwrap_or("A Pro account or active org membership is required.");
            Some(LpmError::UpstreamProxyEntitlementRequired {
                message: message.to_owned(),
                reason: json_string_field(&value, "reason").map(str::to_owned),
                entitlement_source: json_string_field(&value, "entitlementSource")
                    .map(str::to_owned),
            })
        }
        "npm_firewall_entitlement_required" => {
            let message = json_string_field(&value, "message")
                .unwrap_or("A Pro account or active org membership is required.");
            Some(LpmError::NpmFirewallEntitlementRequired {
                message: message.to_owned(),
                reason: json_string_field(&value, "reason").map(str::to_owned),
                entitlement_source: json_string_field(&value, "entitlementSource")
                    .map(str::to_owned),
            })
        }
        _ => None,
    }
}

pub(super) fn forbidden_error_from_body(body: String) -> LpmError {
    parse_lpm_worker_error_body(&body).unwrap_or(LpmError::Forbidden(body))
}

pub(super) fn json_string_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

pub(super) fn elapsed_millis(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}
