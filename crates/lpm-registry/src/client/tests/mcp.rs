use super::*;
use wiremock::matchers::{body_string_contains, header, headers, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LISTING: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
const CALL: &[u8] =
    br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lpm_account"}}"#;

fn listing(posture: AuthPosture) -> HostedMcpRequest<'static> {
    HostedMcpRequest {
        protocol_version: "2026-07-28",
        method: "tools/list",
        name: None,
        body: LISTING,
        posture,
    }
}

fn call(posture: AuthPosture) -> HostedMcpRequest<'static> {
    HostedMcpRequest {
        protocol_version: "2026-07-28",
        method: "tools/call",
        name: Some("lpm_account"),
        body: CALL,
        posture,
    }
}

async fn stored_session_client(server: &MockServer, access: &str) -> RegistryClient {
    lpm_auth::store_refresh_backed_session(
        &server.uri(),
        access,
        "valid-refresh",
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    let session = std::sync::Arc::new(lpm_auth::SessionManager::new(server.uri(), None));
    RegistryClient::new()
        .with_base_url(server.uri())
        .with_session(session)
}

#[tokio::test]
async fn hosted_mcp_request_sends_the_standard_mcp_headers_and_keeps_the_answer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("content-type", "application/json"))
        .and(headers(
            "accept",
            vec!["application/json", "text/event-stream"],
        ))
        .and(header("mcp-protocol-version", "2026-07-28"))
        .and(header("mcp-method", "tools/call"))
        .and(header("mcp-name", "lpm_account"))
        .and(body_string_contains("\"lpm_account\""))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#,
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = RegistryClient::new().with_base_url(format!("{}/", server.uri()));

    let answer = client
        .post_hosted_mcp(call(AuthPosture::AuthRequired))
        .await
        .unwrap();

    assert_eq!(answer.status, 200);
    assert_eq!(answer.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        answer.body,
        br#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#
    );
}

#[tokio::test]
async fn hosted_mcp_listing_never_sends_a_stored_session() {
    let _lock = auth_env_lock().await;
    let home = tempfile::tempdir().unwrap();
    let _env = ScopedAuthEnv::file_backed(home.path());
    let server = MockServer::start().await;
    let saw_authorization = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(AuthorizationRecorder {
            saw_authorization: saw_authorization.clone(),
            body: br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#.to_vec(),
        })
        .mount(&server)
        .await;
    let client = stored_session_client(&server, "stored-access").await;

    let answer = client
        .post_hosted_mcp(listing(AuthPosture::AnonymousOnly))
        .await
        .unwrap();

    assert_eq!(answer.status, 200);
    assert!(
        !saw_authorization.load(std::sync::atomic::Ordering::SeqCst),
        "a public listing must not carry the session's bearer"
    );
}

#[tokio::test]
async fn hosted_mcp_call_refreshes_a_rejected_session_once_and_retries() {
    let _lock = auth_env_lock().await;
    let home = tempfile::tempdir().unwrap();
    let _env = ScopedAuthEnv::file_backed(home.path());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer stale-access"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "Bearer error=\"invalid_token\""),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "rotated-access",
            "refreshToken": "rotated-refresh",
            "expiresAt": "2099-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","id":2,"result":{"content":[]}}"#,
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = stored_session_client(&server, "stale-access").await;

    let answer = client
        .post_hosted_mcp(call(AuthPosture::AuthRequired))
        .await
        .unwrap();

    assert_eq!(answer.status, 200);
}

#[tokio::test]
async fn hosted_mcp_call_without_a_login_returns_the_servers_call_to_sign_in() {
    let _lock = auth_env_lock().await;
    let home = tempfile::tempdir().unwrap();
    let _env = ScopedAuthEnv::file_backed(home.path());
    let server = MockServer::start().await;
    let refusal = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Reading an account needs you to sign in."}}"#;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "Bearer scope=\"read\"")
                .insert_header("retry-after", "17")
                .set_body_raw(refusal, "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let session = std::sync::Arc::new(lpm_auth::SessionManager::new(server.uri(), None));
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_session(session);

    let answer = client
        .post_hosted_mcp(call(AuthPosture::AuthRequired))
        .await
        .unwrap();

    assert_eq!(answer.status, 401);
    assert_eq!(answer.retry_after_secs, Some(17));
    assert_eq!(answer.body, refusal.as_bytes());
}

#[tokio::test]
async fn hosted_mcp_answer_over_the_size_limit_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
            b' ';
            MAX_HOSTED_MCP_RESPONSE_BYTES
                + 1
        ]))
        .mount(&server)
        .await;
    let client = RegistryClient::new().with_base_url(server.uri());

    let error = client
        .post_hosted_mcp(listing(AuthPosture::AnonymousOnly))
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("hosted MCP server"),
        "unexpected error: {error}"
    );
}
