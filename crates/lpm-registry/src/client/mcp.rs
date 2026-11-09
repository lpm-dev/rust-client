use super::body::read_capped_body;
use super::*;
use base64::Engine as _;
use reqwest::header::{ACCEPT, CONTENT_TYPE};

/// The largest tool result read from the hosted MCP server. Results are
/// bounded there; reading package source is the largest, at a few megabytes.
pub const MAX_HOSTED_MCP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// How long one request to the hosted MCP server may take.
const HOSTED_MCP_TIMEOUT: Duration = Duration::from_secs(60);

/// A `Mcp-Name` value that can't travel as a bare header value is sent as
/// `=?base64?<value>?=`, as MCP's standard request headers specify.
const BASE64_HEADER_PREFIX: &str = "=?base64?";
const BASE64_HEADER_SUFFIX: &str = "?=";

/// One JSON-RPC request for the registry's hosted MCP server.
#[derive(Debug, Clone, Copy)]
pub struct HostedMcpRequest<'a> {
    /// The protocol revision the request's `_meta` declares, sent as
    /// `MCP-Protocol-Version`.
    pub protocol_version: &'a str,
    /// The JSON-RPC method, sent as `Mcp-Method`.
    pub method: &'a str,
    /// The tool a `tools/call` names, sent as `Mcp-Name`.
    pub name: Option<&'a str>,
    /// The serialized JSON-RPC request.
    pub body: &'a [u8],
    /// [`AuthPosture::AnonymousOnly`] for requests whose answer is the same
    /// for everyone, such as listing tools, so they never read stored
    /// credentials. [`AuthPosture::AuthRequired`] sends the session's bearer
    /// when there is one, and goes anonymous otherwise.
    pub posture: AuthPosture,
    /// The most of the answer to read, such as
    /// [`MAX_HOSTED_MCP_RESPONSE_BYTES`]; a longer answer is an error.
    pub max_response_bytes: usize,
}

/// What the hosted MCP server answered, with its status kept: an anonymous
/// request's 401 and a 429 carry a JSON-RPC error that says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedMcpAnswer {
    pub status: u16,
    pub content_type: Option<String>,
    pub retry_after_secs: Option<u64>,
    pub body: Vec<u8>,
}

impl RegistryClient {
    /// The registry's hosted MCP server, `<registry>/mcp`.
    pub fn hosted_mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url.trim_end_matches('/'))
    }

    /// Send one JSON-RPC request to the registry's hosted MCP server.
    ///
    /// A 401 to a request that carried a bearer refreshes a refresh-backed
    /// session once and retries; when that can't help, the error is
    /// [`LpmError::AuthRequired`], [`LpmError::SessionExpired`], or
    /// [`LpmError::EnvTokenRejected`]. Every other answer, including an
    /// anonymous request's 401, is returned for the caller to read.
    pub async fn post_hosted_mcp(
        &self,
        request: HostedMcpRequest<'_>,
    ) -> Result<HostedMcpAnswer, LpmError> {
        let url = self.hosted_mcp_url();
        let name = request.name.map(mcp_header_value);
        self.execute_with_recovery(request.posture, || async {
            let bearer = self.current_bearer(request.posture)?;
            let mut builder = self
                .http
                .for_url(&url)
                .await?
                .post(&url)
                .timeout(HOSTED_MCP_TIMEOUT)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json, text/event-stream")
                .header("MCP-Protocol-Version", request.protocol_version)
                .header("Mcp-Method", request.method)
                .body(request.body.to_vec());
            if let Some(name) = &name {
                builder = builder.header("Mcp-Name", name.as_ref());
            }
            if let Some(bearer) = &bearer {
                builder = builder.bearer_auth(bearer);
            }
            let response = self.send_once_preserving_status(builder).await?;
            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && bearer.is_some() {
                return Err(LpmError::AuthRequired);
            }
            let header = |name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            let content_type = header(CONTENT_TYPE);
            let retry_after_secs = header(reqwest::header::RETRY_AFTER).and_then(|value| {
                super::error_body::retry_after_secs(&value, std::time::SystemTime::now())
            });
            let body = read_capped_body(
                response,
                request.max_response_bytes,
                "the hosted MCP server's answer",
            )
            .await?;
            Ok(HostedMcpAnswer {
                status: status.as_u16(),
                content_type,
                retry_after_secs,
                body,
            })
        })
        .await
    }
}

/// `value` as an MCP standard request header value: as it is when it is
/// printable ASCII without surrounding whitespace, else Base64-wrapped.
fn mcp_header_value(value: &str) -> std::borrow::Cow<'_, str> {
    let bytes = value.as_bytes();
    let needs_wrapping = matches!(bytes.first(), Some(b' ' | b'\t'))
        || matches!(bytes.last(), Some(b' ' | b'\t'))
        || bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        || (value.starts_with(BASE64_HEADER_PREFIX) && value.ends_with(BASE64_HEADER_SUFFIX));
    if !needs_wrapping {
        return std::borrow::Cow::Borrowed(value);
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    std::borrow::Cow::Owned(format!(
        "{BASE64_HEADER_PREFIX}{encoded}{BASE64_HEADER_SUFFIX}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_header_value_keeps_printable_ascii_and_wraps_the_rest() {
        assert_eq!(mcp_header_value("lpm_search"), "lpm_search");
        assert_eq!(mcp_header_value("ünïcode"), "=?base64?w7xuw69jb2Rl?=");
        assert_eq!(mcp_header_value(" padded"), "=?base64?IHBhZGRlZA==?=");
        assert_eq!(
            mcp_header_value("line\nbreak"),
            "=?base64?bGluZQpicmVhaw==?="
        );
        assert_eq!(
            mcp_header_value("=?base64?looks-wrapped?="),
            "=?base64?PT9iYXNlNjQ/bG9va3Mtd3JhcHBlZD89?="
        );
    }
}
