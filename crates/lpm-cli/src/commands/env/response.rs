use super::prelude::*;

/// Hard cap on platform-API response bodies (env / vault / OIDC
/// endpoints called from this module). Real payloads are kilobytes;
/// 10 MB leaves several orders of magnitude of headroom and prevents
/// a malicious / compromised platform endpoint from OOM-ing the CLI
/// on the `.json()` path.
pub(super) const MAX_PLATFORM_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with a two-stage cap. Stage 1 refuses
/// pre-stream when `Content-Length` exceeds the cap; stage 2 aborts
/// mid-stream the moment another chunk would cross it.
pub(super) async fn read_capped_platform_body(
    response: reqwest::Response,
) -> Result<Vec<u8>, LpmError> {
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_PLATFORM_RESPONSE_BYTES
    {
        return Err(LpmError::Script(format!(
            "platform response too large: declared length {declared} exceeds cap {MAX_PLATFORM_RESPONSE_BYTES}"
        )));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LpmError::Script(format!("response read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > MAX_PLATFORM_RESPONSE_BYTES {
            return Err(LpmError::Script(format!(
                "platform response too large: streamed body exceeded cap {MAX_PLATFORM_RESPONSE_BYTES}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Parse a capped platform response as JSON. Used in success-path
/// reads where the caller wants typed parse errors back.
pub(super) async fn parse_capped_platform_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, LpmError> {
    let buf = read_capped_platform_body(response).await?;
    serde_json::from_slice(&buf).map_err(|e| LpmError::Script(format!("parse error: {e}")))
}

/// Parse a capped platform response as JSON, falling back to a stub
/// `{"error": "unknown error"}` value on read / cap / parse failure.
/// Used on error-path reads where the caller only needs an `error`
/// field to display.
pub(super) async fn parse_capped_platform_json_or_unknown(
    response: reqwest::Response,
) -> serde_json::Value {
    match read_capped_platform_body(response).await {
        Ok(buf) => serde_json::from_slice::<serde_json::Value>(&buf)
            .unwrap_or_else(|_| serde_json::json!({"error": "unknown error"})),
        Err(_) => serde_json::json!({"error": "unknown error"}),
    }
}

pub(super) fn print_json_value(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON value should serialize")
    );
}

pub(super) fn success_envelope(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(mut map) => {
            map.insert("success".to_string(), serde_json::json!(true));
            if !map.contains_key("count")
                && let Some(count) = map
                    .get("platforms")
                    .or_else(|| map.get("vaults"))
                    .and_then(|items| items.as_array())
                    .map(Vec::len)
            {
                map.insert("count".to_string(), serde_json::json!(count));
            }
            serde_json::Value::Object(map)
        }
        other => serde_json::json!({
            "success": true,
            "result": other,
        }),
    }
}
