//! Registry tools, served by the registry's hosted MCP server and forwarded
//! one request at a time.

use lpm_auth::TokenSource;
use lpm_common::LpmError;
use lpm_registry::client::AuthPosture;
use lpm_registry::{
    HostedMcpAnswer, HostedMcpRequest, MAX_HOSTED_MCP_RESPONSE_BYTES, RegistryClient,
};
use rmcp::model::{CallToolResult, ContentBlock, ErrorData, JsonObject, ListToolsResult, Tool};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The protocol revision requests to the hosted server declare. That
/// revision serves each request on its own, so no session is opened first.
const PROTOCOL_VERSION: &str = "2026-07-28";

/// Pages read for one tool listing, so a server that keeps paging can't keep
/// a listing going forever.
const MAX_LISTING_PAGES: usize = 8;

/// The most a tool listing's pages may hold together. A listing is tens of
/// kilobytes; it stays in memory for as long as it is fresh.
const MAX_LISTING_BYTES: usize = 4 * 1024 * 1024;

/// How long a listing stays fresh when the server doesn't say.
const DEFAULT_LISTING_TTL: Duration = Duration::from_secs(5 * 60);

/// The longest a listing is kept, whatever the server says.
const MAX_LISTING_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest message from the server quoted back to the agent.
const MAX_MESSAGE_CHARS: usize = 1_000;

pub(super) struct HostedRegistry {
    client: RegistryClient,
    listing: tokio::sync::Mutex<Option<Listing>>,
    next_id: AtomicU64,
}

struct Listing {
    tools: Arc<[Tool]>,
    fresh_until: Instant,
}

/// Why the hosted server didn't serve a request.
#[derive(Debug)]
pub(super) enum HostedFailure {
    /// The request went without a login, and the server wants one.
    SignIn(Option<String>),
    /// The server is limiting requests.
    Busy {
        message: Option<String>,
        retry_after_secs: Option<u64>,
    },
    /// The registry has no hosted MCP server.
    Missing,
    /// Another refusal, by HTTP status.
    Status {
        status: u16,
        message: Option<String>,
    },
    /// The server answered with an error of its own, for the client to see.
    Rpc(ErrorData),
    /// The answer wasn't a JSON-RPC response to the request.
    Protocol(String),
    /// The request couldn't be sent, or its login was refused.
    Request(LpmError),
}

impl HostedRegistry {
    pub(super) fn new(client: RegistryClient) -> Self {
        Self {
            client,
            listing: tokio::sync::Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }

    /// The registry's tools, from a listing kept for as long as the server
    /// says it stays fresh. The listing is the same for everyone, so it is
    /// read without a login, and a client listing tools at startup never
    /// opens the credential store.
    pub(super) async fn tools(&self) -> Result<Arc<[Tool]>, HostedFailure> {
        let mut listing = self.listing.lock().await;
        if let Some(listing) = listing.as_ref()
            && Instant::now() < listing.fresh_until
        {
            return Ok(Arc::clone(&listing.tools));
        }
        let (tools, ttl) = self.fetch_tools().await?;
        *listing = Some(Listing {
            tools: Arc::clone(&tools),
            fresh_until: Instant::now() + ttl,
        });
        Ok(tools)
    }

    async fn fetch_tools(&self) -> Result<(Arc<[Tool]>, Duration), HostedFailure> {
        let mut tools = Vec::new();
        let mut ttl = MAX_LISTING_TTL;
        let mut cursor = None;
        let mut budget = MAX_LISTING_BYTES;
        for _ in 0..MAX_LISTING_PAGES {
            let mut params = Map::new();
            if let Some(cursor) = cursor.take() {
                params.insert("cursor".to_owned(), Value::String(cursor));
            }
            let (result, read) = self
                .send(
                    "tools/list",
                    None,
                    params,
                    AuthPosture::AnonymousOnly,
                    budget,
                )
                .await?;
            budget = budget.saturating_sub(read);
            let page: ListToolsResult = serde_json::from_value(result)
                .map_err(|error| HostedFailure::Protocol(format!("the tool listing: {error}")))?;
            ttl = ttl.min(
                page.ttl_ms
                    .map_or(DEFAULT_LISTING_TTL, Duration::from_millis),
            );
            tools.extend(page.tools);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok((tools.into(), ttl)),
            }
        }
        Err(HostedFailure::Protocol(format!(
            "the tool listing ran past {MAX_LISTING_PAGES} pages"
        )))
    }

    /// Call one of the registry's tools, with the user's login when there
    /// is one. A server's own error, such as for arguments it refuses, is
    /// returned as that error; anything else that stops the call is a tool
    /// result that says why, which the agent can act on.
    pub(super) async fn call_tool(
        &self,
        name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut params = Map::with_capacity(3);
        params.insert("name".to_owned(), Value::String(name.to_owned()));
        if let Some(arguments) = arguments {
            params.insert("arguments".to_owned(), Value::Object(arguments));
        }
        self.read_login_off_thread().await;
        let mut outcome = self
            .send(
                "tools/call",
                Some(name),
                params.clone(),
                AuthPosture::AuthRequired,
                MAX_HOSTED_MCP_RESPONSE_BYTES,
            )
            .await
            .map(|(result, _)| result);
        // The user may have run `lpm login`, or `lpm logout`, since the
        // login this server holds was read.
        if matches!(
            outcome,
            Err(HostedFailure::SignIn(_)
                | HostedFailure::Request(LpmError::AuthRequired | LpmError::SessionExpired))
        ) && self.login_changed().await
        {
            outcome = self
                .send(
                    "tools/call",
                    Some(name),
                    params,
                    AuthPosture::AuthRequired,
                    MAX_HOSTED_MCP_RESPONSE_BYTES,
                )
                .await
                .map(|(result, _)| result);
        }
        match outcome {
            Ok(result) => Ok(forwarded_result(name, result)),
            Err(HostedFailure::Rpc(error)) => Err(error),
            Err(failure) => Ok(tool_error(&self.explain(&failure))),
        }
    }

    /// Read the stored login before a request needs it, on a blocking
    /// thread: reading the credential store can wait on a macOS Keychain
    /// prompt, which must not hold an async worker of a long-running server.
    async fn read_login_off_thread(&self) {
        let Some(session) = self.client.session().map(Arc::clone) else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || session.current_source()).await;
    }

    /// Read the stored login again, on a blocking thread, and say whether it
    /// differs from the one the failed request used.
    async fn login_changed(&self) -> bool {
        let Some(session) = self.client.session().map(Arc::clone) else {
            return false;
        };
        tokio::task::spawn_blocking(move || {
            let before = session.current_bearer_lazy().ok().flatten();
            session.reread_stored_credentials().unwrap_or(false)
                && session.current_bearer_lazy().ok().flatten() != before
        })
        .await
        .unwrap_or(false)
    }

    async fn send(
        &self,
        method: &str,
        name: Option<&str>,
        mut params: Map<String, Value>,
        posture: AuthPosture,
        max_response_bytes: usize,
    ) -> Result<(Value, usize), HostedFailure> {
        params.insert("_meta".to_owned(), request_meta());
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|error| HostedFailure::Protocol(error.to_string()))?;
        let answer = self
            .client
            .post_hosted_mcp(HostedMcpRequest {
                protocol_version: PROTOCOL_VERSION,
                method,
                name,
                body: &body,
                posture,
                max_response_bytes,
            })
            .await
            .map_err(HostedFailure::Request)?;
        Ok((read_answer(&answer, id)?, answer.body.len()))
    }

    /// What to tell the agent about a failure.
    pub(super) fn explain(&self, failure: &HostedFailure) -> String {
        let server = self.client.hosted_mcp_url();
        match failure {
            HostedFailure::SignIn(message) => format!(
                "{} Run `lpm login` in a terminal to sign in to LPM.dev, then call the tool again.",
                message
                    .as_deref()
                    .unwrap_or("This needs a signed-in LPM.dev account.")
            ),
            HostedFailure::Busy {
                message: Some(message),
                ..
            } => message.clone(),
            HostedFailure::Busy {
                message: None,
                retry_after_secs: Some(seconds),
            } => format!(
                "The registry's MCP server at {server} is limiting requests. Retry in {seconds} seconds."
            ),
            HostedFailure::Busy {
                message: None,
                retry_after_secs: None,
            } => format!(
                "The registry's MCP server at {server} is limiting requests. Retry later."
            ),
            HostedFailure::Missing => format!(
                "The registry has no MCP server at {server}, so its registry tools are unavailable."
            ),
            HostedFailure::Status { status, message } => match message {
                Some(message) => {
                    format!("The registry's MCP server at {server} answered HTTP {status}: {message}")
                }
                None => format!("The registry's MCP server at {server} answered HTTP {status}."),
            },
            HostedFailure::Rpc(error) => error.message.to_string(),
            HostedFailure::Protocol(reason) => format!(
                "The registry's MCP server at {server} sent an answer lpm couldn't read: {reason}"
            ),
            HostedFailure::Request(LpmError::AuthRequired | LpmError::SessionExpired)
                if self
                    .client
                    .session()
                    .and_then(|session| session.current_source_peek())
                    == Some(TokenSource::ExplicitFlag) =>
            {
                "LPM.dev rejected the token given with --token, which may be expired, revoked, or invalid. Replace it, or remove --token from the server's entry to use the login from `lpm login`.".to_owned()
            }
            HostedFailure::Request(LpmError::AuthRequired | LpmError::SessionExpired) => {
                "LPM.dev didn't accept your login, which may have expired or been signed out. Run `lpm login` in a terminal, then call the tool again.".to_owned()
            }
            HostedFailure::Request(LpmError::EnvTokenRejected) => {
                "LPM.dev rejected the token in LPM_TOKEN, which may be expired, revoked, or invalid. Replace it with a valid token, or unset it to use the login from `lpm login`.".to_owned()
            }
            HostedFailure::Request(LpmError::Network(reason)) => {
                format!("lpm couldn't reach the registry's MCP server at {server}: {reason}")
            }
            HostedFailure::Request(error) => error.to_string(),
        }
    }
}

/// `_meta` for a 2026-07-28 request, which carries what an `initialize`
/// handshake used to.
fn request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
            "name": "lpm",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

/// A tool result from the hosted server, as this server's own. Metadata
/// under the protocol's `io.modelcontextprotocol/` prefix describes the
/// hosted server, such as its `serverInfo`, so it stays behind.
fn forwarded_result(name: &str, result: Value) -> CallToolResult {
    let mut result: CallToolResult = match serde_json::from_value(result) {
        Ok(result) => result,
        Err(error) => {
            return tool_error(&format!(
                "The registry's MCP server answered `{name}` with a result lpm couldn't read: {error}"
            ));
        }
    };
    if let Some(meta) = result.meta.as_mut() {
        meta.retain(|key, _| !key.starts_with("io.modelcontextprotocol/"));
        if meta.is_empty() {
            result.meta = None;
        }
    }
    result
}

fn tool_error(text: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

fn read_answer(answer: &HostedMcpAnswer, id: u64) -> Result<Value, HostedFailure> {
    match answer.status {
        200..=299 => match response_to(answer, id)? {
            Ok(result) => Ok(result),
            Err(error) => Err(HostedFailure::Rpc(error)),
        },
        401 => Err(HostedFailure::SignIn(error_message(answer))),
        404 => Err(HostedFailure::Missing),
        429 => Err(HostedFailure::Busy {
            message: error_message(answer),
            retry_after_secs: answer.retry_after_secs,
        }),
        status => Err(HostedFailure::Status {
            status,
            message: error_message(answer),
        }),
    }
}

/// The response to request `id` in a JSON body or an event stream.
fn response_to(
    answer: &HostedMcpAnswer,
    id: u64,
) -> Result<Result<Value, ErrorData>, HostedFailure> {
    let event_stream = answer.content_type.as_deref().is_some_and(|content_type| {
        content_type
            .trim_start()
            .get(..17)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/event-stream"))
    });
    if event_stream {
        return event_data(&answer.body)
            .find_map(|data| response_in(data.as_bytes(), id))
            .ok_or_else(|| {
                HostedFailure::Protocol("its event stream ended without a response".to_owned())
            });
    }
    response_in(&answer.body, id).ok_or_else(|| {
        HostedFailure::Protocol("it isn't a JSON-RPC response to the request".to_owned())
    })
}

/// The result or error of the JSON-RPC response to `id` in `body`.
fn response_in(body: &[u8], id: u64) -> Option<Result<Value, ErrorData>> {
    let Value::Object(mut message) = serde_json::from_slice(body).ok()? else {
        return None;
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || message.get("id").and_then(Value::as_u64) != Some(id)
    {
        return None;
    }
    if let Some(error) = message.remove("error") {
        return Some(Err(serde_json::from_value(error).ok()?));
    }
    message.remove("result").map(Ok)
}

/// The data of each event in a `text/event-stream` body.
fn event_data(body: &[u8]) -> impl Iterator<Item = String> + '_ {
    // An event stream may end its lines with CRLF, LF, or a lone CR.
    let text = String::from_utf8_lossy(body)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut events = Vec::new();
    let mut data = String::new();
    for line in text.split('\n') {
        if line.is_empty() {
            if !data.is_empty() {
                events.push(std::mem::take(&mut data));
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if !data.is_empty() {
        events.push(data);
    }
    events.into_iter()
}

/// The message of a JSON-RPC error answer, shortened for quoting.
fn error_message(answer: &HostedMcpAnswer) -> Option<String> {
    let message: Value = serde_json::from_slice(&answer.body).ok()?;
    let text = message.get("error")?.get("message")?.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    let mut shortened: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
    if shortened.len() < text.len() {
        shortened.push('…');
    }
    Some(shortened)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, content_type: &str, body: &str) -> HostedMcpAnswer {
        HostedMcpAnswer {
            status,
            content_type: Some(content_type.to_owned()),
            retry_after_secs: None,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn read_answer_returns_the_result_for_its_own_request_id() {
        let ok = answer(
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}"#,
        );
        assert_eq!(read_answer(&ok, 7).unwrap(), json!({"tools": []}));
        assert!(matches!(
            read_answer(&ok, 8),
            Err(HostedFailure::Protocol(_))
        ));
    }

    #[test]
    fn read_answer_finds_the_response_in_an_event_stream() {
        let stream = answer(
            200,
            "text/event-stream; charset=utf-8",
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nid: 2\ndata: {\"jsonrpc\":\"2.0\",\n\
             data: \"id\":3,\"result\":{\"content\":[]}}\n\n",
        );

        assert_eq!(read_answer(&stream, 3).unwrap(), json!({"content": []}));
    }

    #[test]
    fn read_answer_reads_an_event_stream_with_lone_carriage_returns() {
        let stream = answer(
            200,
            "text/event-stream",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\rdata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"content\":[]}}\r\r",
        );

        assert_eq!(read_answer(&stream, 5).unwrap(), json!({"content": []}));
    }

    #[test]
    fn read_answer_keeps_a_server_error_for_the_client() {
        let refused = answer(
            200,
            "application/json",
            r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Unknown tool: lpm_nope"}}"#,
        );

        let Err(HostedFailure::Rpc(error)) = read_answer(&refused, 4) else {
            panic!("a server error must reach the client as that error");
        };
        assert_eq!(error.code.0, -32602);
        assert_eq!(error.message, "Unknown tool: lpm_nope");
    }

    #[test]
    fn read_answer_reads_why_the_server_wants_a_login_or_is_busy() {
        let sign_in = answer(
            401,
            "application/json",
            r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"Reading an account needs you to sign in."}}"#,
        );
        assert!(matches!(
            read_answer(&sign_in, 5),
            Err(HostedFailure::SignIn(Some(message))) if message == "Reading an account needs you to sign in."
        ));

        let mut busy = answer(
            429,
            "application/json",
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Too many MCP requests. Retry in 9 seconds."}}"#,
        );
        busy.retry_after_secs = Some(9);
        assert!(matches!(
            read_answer(&busy, 6),
            Err(HostedFailure::Busy { message: Some(message), retry_after_secs: Some(9) })
                if message == "Too many MCP requests. Retry in 9 seconds."
        ));

        assert!(matches!(
            read_answer(&answer(404, "text/html", "<h1>Not found</h1>"), 7),
            Err(HostedFailure::Missing)
        ));
    }

    #[test]
    fn forwarded_result_drops_the_hosted_servers_protocol_metadata() {
        let result = forwarded_result(
            "lpm_docs",
            json!({
                "content": [{ "type": "text", "text": "docs" }],
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": { "name": "lpm-registry" },
                    "dev.lpm/trace": "abc",
                },
            }),
        );
        let meta = result.meta.expect("other metadata is kept");
        assert!(meta.get("io.modelcontextprotocol/serverInfo").is_none());
        assert_eq!(meta.get("dev.lpm/trace"), Some(&json!("abc")));

        let bare = forwarded_result(
            "lpm_docs",
            json!({
                "content": [],
                "_meta": { "io.modelcontextprotocol/serverInfo": { "name": "lpm-registry" } },
            }),
        );
        assert!(bare.meta.is_none());
    }

    #[test]
    fn forwarded_result_that_cant_be_read_is_a_tool_error() {
        let result = forwarded_result("lpm_docs", json!({ "resultType": "task" }));

        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn a_tool_listing_larger_than_its_budget_across_pages_is_refused() {
        use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let padding = "x".repeat(1_500_000);
        Mock::given(method("POST"))
            .respond_with(move |request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let page = body["params"]["cursor"]
                    .as_str()
                    .map_or(1, |cursor| cursor.parse::<u32>().unwrap());
                let mut result = json!({
                    "tools": [{
                        "name": format!("lpm_page_{page}"),
                        "description": padding,
                        "inputSchema": { "type": "object" },
                    }],
                });
                if page < 4 {
                    result["nextCursor"] = json!((page + 1).to_string());
                }
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "jsonrpc": "2.0", "id": body["id"], "result": result }))
            })
            .mount(&server)
            .await;
        let hosted = HostedRegistry::new(RegistryClient::new().with_base_url(server.uri()));

        let listing = hosted.tools().await;

        assert!(
            listing.is_err(),
            "four 1.5 MB pages must exceed the listing budget"
        );
    }

    #[test]
    fn a_refused_explicit_token_is_named_instead_of_lpm_login() {
        let session = Arc::new(lpm_auth::SessionManager::new(
            "https://registry.example",
            Some("flag-token".to_owned()),
        ));
        let hosted = HostedRegistry::new(
            RegistryClient::new()
                .with_base_url("https://registry.example")
                .with_session(session),
        );

        for error in [LpmError::AuthRequired, LpmError::SessionExpired] {
            let text = hosted.explain(&HostedFailure::Request(error));
            assert!(text.contains("--token"), "{text}");
            assert!(!text.contains("lpm login`, then"), "{text}");
        }
    }

    #[test]
    fn error_message_shortens_a_long_server_message() {
        let long = "x".repeat(MAX_MESSAGE_CHARS + 50);
        let refused = answer(
            500,
            "application/json",
            &json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":long}}).to_string(),
        );

        let message = error_message(&refused).unwrap();

        assert_eq!(message.chars().count(), MAX_MESSAGE_CHARS + 1);
        assert!(message.ends_with('…'));
    }
}
