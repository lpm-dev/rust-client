use super::prelude::*;

/// Hard cap on platform-API response bodies (env / vault / OIDC
/// endpoints called from this module). Real payloads are kilobytes;
/// 10 MB leaves several orders of magnitude of headroom and prevents
/// a malicious / compromised platform endpoint from OOM-ing the CLI
/// on the `.json()` path.
pub(super) const MAX_PLATFORM_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

pub(super) struct PlatformResponseBudget {
    remaining: usize,
}

impl PlatformResponseBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining: MAX_PLATFORM_RESPONSE_BYTES,
        }
    }
}

/// Drain a response body with a two-stage cap. Stage 1 refuses
/// pre-stream when `Content-Length` exceeds the cap; stage 2 aborts
/// mid-stream the moment another chunk would cross it.
pub(super) async fn read_capped_platform_body(
    response: reqwest::Response,
) -> Result<Vec<u8>, LpmError> {
    read_capped_platform_body_with_budget(response, &mut PlatformResponseBudget::new()).await
}

pub(super) async fn read_capped_platform_body_with_budget(
    response: reqwest::Response,
    budget: &mut PlatformResponseBudget,
) -> Result<Vec<u8>, LpmError> {
    let declared = response.content_length();
    let declared_length = declared.and_then(|length| usize::try_from(length).ok());
    if declared_length.is_some_and(|declared| declared > budget.remaining) {
        let declared = declared.unwrap_or(u64::MAX);
        return Err(LpmError::Script(format!(
            "platform response too large: declared length {declared} exceeds the remaining {}-byte pagination budget",
            budget.remaining,
        )));
    }
    let initial_capacity = initial_response_capacity(declared_length, budget.remaining);
    let mut buf: Vec<u8> = Vec::with_capacity(initial_capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LpmError::Script(format!("response read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > budget.remaining {
            return Err(LpmError::Script(format!(
                "platform response too large: streamed body exceeded the remaining {}-byte pagination budget",
                budget.remaining,
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    budget.remaining -= buf.len();
    Ok(buf)
}

fn initial_response_capacity(declared_length: Option<usize>, remaining: usize) -> usize {
    declared_length.unwrap_or_else(|| remaining.min(16 * 1024))
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn response(server: &MockServer, response_path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}{response_path}", server.uri()))
            .send()
            .await
            .expect("request capped response")
    }

    #[test]
    fn known_response_length_sets_the_initial_capacity() {
        assert_eq!(initial_response_capacity(Some(131_072), 1_048_576), 131_072);
        assert_eq!(initial_response_capacity(None, 1_048_576), 16 * 1024);
        assert_eq!(initial_response_capacity(None, 7), 7);
    }

    #[tokio::test]
    async fn pagination_budget_accepts_bodies_at_the_exact_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/first"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ab"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/second"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cde"))
            .expect(1)
            .mount(&server)
            .await;
        let mut budget = PlatformResponseBudget { remaining: 5 };

        let first =
            read_capped_platform_body_with_budget(response(&server, "/first").await, &mut budget)
                .await
                .expect("first page within budget");
        let second =
            read_capped_platform_body_with_budget(response(&server, "/second").await, &mut budget)
                .await
                .expect("second page reaches exact budget");

        assert_eq!(
            (first, second, budget.remaining),
            (b"ab".to_vec(), b"cde".to_vec(), 0)
        );
    }

    #[tokio::test]
    async fn pagination_budget_rejects_a_cumulative_overflow() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/first"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ab"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/second"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cd"))
            .expect(1)
            .mount(&server)
            .await;
        let mut budget = PlatformResponseBudget { remaining: 3 };
        read_capped_platform_body_with_budget(response(&server, "/first").await, &mut budget)
            .await
            .expect("first page within budget");

        let error =
            read_capped_platform_body_with_budget(response(&server, "/second").await, &mut budget)
                .await
                .expect_err("second page must exceed the cumulative budget");

        assert!(
            error
                .to_string()
                .contains("remaining 1-byte pagination budget")
        );
    }
}
