use super::SyncError;
use super::http::{read_capped_error_text, read_capped_json, sync_http_client};

/// HTTP header the server expects the CLI step-up proof JWT in. Mirrors
/// `CLI_STEP_UP_HEADER_NAME` exported from the dashboard's
/// `lib/auth/cli-step-up.js`. Defined here as a constant so the upload
/// site and any future caller route the proof through the same name.
pub const CLI_STEP_UP_HEADER_NAME: &str = "X-LPM-Step-Up-Proof";

/// Step-up policy resolved by the server for the calling user. The CLI
/// asks for the credential named in `method` (or refuses outright when
/// `unavailable`), and may offer the others in `methods`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliStepUpPolicy {
    /// `"approval"`, `"password"`, `"totp"`, or `"unavailable"`. The CLI
    /// MUST refuse any flow when `unavailable` because the prompt would ask
    /// for a credential the user cannot satisfy.
    pub method: String,
    /// Every method the account can use, `method` first. Older servers
    /// don't send it.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Present only when `method == "unavailable"`. Currently the only
    /// observed value is `"set_password_required"`.
    pub reason: Option<String>,
    /// TTL the server applies to a freshly-minted proof. Surfaced so the
    /// CLI can render an honest "expires in N seconds" hint.
    pub ttl_seconds: Option<u32>,
    /// Header name the server expects the minted proof in. Echoed so a
    /// future server-side rename gets picked up without coordinating
    /// constants.
    pub header: Option<String>,
}

/// Credential the CLI supplies on mint: password-only for users with no
/// MFA, password+TOTP for MFA-enrolled users (the server expects password-
/// backed reauthentication for a code typed here), or the one-time token of
/// a browser approval.
pub enum CliStepUpCredential<'a> {
    Password { password: &'a str },
    Totp { password: &'a str, code: &'a str },
    Approval { token: &'a str },
}

/// Where the user approves a step-up in the browser, and where the CLI
/// waits for the token, from `request_cli_step_up_approval`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliStepUpApproval {
    pub auth_url: String,
    pub done_url: String,
}

/// Ask the server for a browser approval of `scope`. The user approves it
/// with their passkey or authenticator; the token `done_url` then gives the
/// CLI mints the proof through `CliStepUpCredential::Approval`.
pub async fn request_cli_step_up_approval(
    registry_url: &str,
    auth_token: &str,
    scope: &str,
) -> Result<CliStepUpApproval, SyncError> {
    let client = sync_http_client()?;
    let url = format!("{registry_url}/api/auth/cli-step-up");

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&serde_json::json!({ "scope": scope, "method": "approval" }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    if status != reqwest::StatusCode::ACCEPTED {
        let body = read_capped_error_text(response).await;
        return Err(SyncError::http(
            status,
            format!("step-up approval: {status}: {body}"),
        ));
    }
    Ok(read_capped_json::<CliStepUpApproval>(response).await?)
}

/// Discover the step-up method the server expects for the calling
/// user — does not consume any credential, no rate-limit cost beyond
/// the per-IP shield. Used by the CLI to decide what to prompt for
/// before asking the user to type a password / TOTP.
pub async fn discover_cli_step_up_policy(
    registry_url: &str,
    auth_token: &str,
) -> Result<CliStepUpPolicy, SyncError> {
    let client = sync_http_client()?;
    let url = format!("{registry_url}/api/auth/cli-step-up");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(SyncError::http(
            status,
            format!("step-up policy: {status}: {body}"),
        ));
    }

    Ok(read_capped_json::<CliStepUpPolicy>(response).await?)
}

/// Successful mint response from `POST /api/auth/cli-step-up`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintCliStepUpResponse {
    ok: Option<bool>,
    proof: Option<String>,
}

/// Mint a CLI step-up proof against the server.
///
/// On success, returns the JWT the caller carries in the
/// `X-LPM-Step-Up-Proof` header for the subsequent sensitive write
/// (public-key set/rotate, force-push, etc).
///
/// On failure, the returned error includes the server's response body
/// so the CLI can surface the structured envelope (`code:
/// wrong_credential`, `code: rate_limited`, etc) to the user.
pub async fn mint_cli_step_up_proof(
    registry_url: &str,
    auth_token: &str,
    scope: &str,
    credential: &CliStepUpCredential<'_>,
) -> Result<String, SyncError> {
    let client = sync_http_client()?;
    let url = format!("{registry_url}/api/auth/cli-step-up");

    let body = match credential {
        CliStepUpCredential::Password { password } => serde_json::json!({
            "scope": scope,
            "method": "password",
            "password": password,
        }),
        CliStepUpCredential::Totp { password, code } => serde_json::json!({
            "scope": scope,
            "method": "totp",
            "password": password,
            "totpCode": code,
        }),
        CliStepUpCredential::Approval { token } => serde_json::json!({
            "scope": scope,
            "method": "approval",
            "approvalToken": token,
        }),
    };

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        let message = format!("step-up mint: {status}: {body}");
        let rejects_submitted_credential = status == reqwest::StatusCode::UNAUTHORIZED
            && serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|value| {
                    value.get("code").and_then(serde_json::Value::as_str)
                        == Some("wrong_credential")
                });
        return Err(if rejects_submitted_credential {
            SyncError::credential_rejected(status, message)
        } else {
            SyncError::http(status, message)
        });
    }

    let parsed = read_capped_json::<MintCliStepUpResponse>(response).await?;
    if parsed.ok != Some(true) {
        return Err(SyncError::from(
            "step-up mint: server returned ok=false on 2xx response (unexpected)",
        ));
    }
    parsed
        .proof
        .ok_or_else(|| SyncError::from("step-up mint: server response missing proof"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[tokio::test]
    async fn discover_cli_step_up_policy_parses_password_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "password",
                "ttlSeconds": 300,
                "header": "X-LPM-Step-Up-Proof",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let policy = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect("happy path");
        assert_eq!(policy.method, "password");
        assert!(policy.reason.is_none());
        assert_eq!(policy.ttl_seconds, Some(300));
        assert_eq!(policy.header.as_deref(), Some("X-LPM-Step-Up-Proof"));
    }

    #[tokio::test]
    async fn discover_cli_step_up_policy_parses_unavailable_with_reason() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "unavailable",
                "reason": "set_password_required",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let policy = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect("happy path");
        assert_eq!(policy.method, "unavailable");
        assert_eq!(policy.reason.as_deref(), Some("set_password_required"));
    }

    #[tokio::test]
    async fn discover_cli_step_up_policy_errors_on_non_2xx() {
        // A 401 here can't be silently collapsed — the CLI would
        // proceed to prompt for a credential the server can't accept.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired token"))
            .expect(1)
            .mount(&server)
            .await;

        let err = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect_err("401 must propagate");
        assert!(err.to_string().contains("401"), "got: {err}");
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_password_sends_expected_body() {
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let captured = Arc::new(StdMutex::new(Vec::<String>::new()));
        let server = MockServer::start().await;

        #[derive(Clone)]
        struct CaptureBody(Arc<StdMutex<Vec<String>>>);
        impl Respond for CaptureBody {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                self.0
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request.body).to_string());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "proof": "test-jwt",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(CaptureBody(Arc::clone(&captured)))
            .expect(1)
            .mount(&server)
            .await;

        let proof = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:set:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &CliStepUpCredential::Password {
                password: "hunter2",
            },
        )
        .await
        .expect("happy path");
        assert_eq!(proof, "test-jwt");

        let body = captured.lock().unwrap()[0].clone();
        assert!(body.contains("\"method\":\"password\""));
        assert!(body.contains("\"scope\":\"vault:public-key:set:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
        assert!(body.contains("\"password\":\"hunter2\""));
        assert!(
            !body.contains("totpCode"),
            "password-only request must not include totpCode field: {body}"
        );
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_totp_sends_both_password_and_code() {
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let captured = Arc::new(StdMutex::new(Vec::<String>::new()));
        let server = MockServer::start().await;

        #[derive(Clone)]
        struct CaptureBody(Arc<StdMutex<Vec<String>>>);
        impl Respond for CaptureBody {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                self.0
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request.body).to_string());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "proof": "totp-jwt",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(CaptureBody(Arc::clone(&captured)))
            .expect(1)
            .mount(&server)
            .await;

        let proof = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:rotate:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &CliStepUpCredential::Totp {
                password: "hunter2",
                code: "123456",
            },
        )
        .await
        .expect("happy path");
        assert_eq!(proof, "totp-jwt");

        let body = captured.lock().unwrap()[0].clone();
        assert!(body.contains("\"method\":\"totp\""));
        assert!(body.contains("\"scope\":\"vault:public-key:rotate:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
        assert!(body.contains("\"password\":\"hunter2\""));
        assert!(body.contains("\"totpCode\":\"123456\""));
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_propagates_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "ok": false,
                "code": "wrong_credential",
                "error": "Incorrect password.",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let err = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:set:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &CliStepUpCredential::Password { password: "wrong" },
        )
        .await
        .expect_err("401 must propagate");
        assert!(err.to_string().contains("401"), "got: {err}");
        assert!(
            err.to_string().contains("wrong_credential")
                || err.to_string().contains("Incorrect password"),
            "error envelope should be preserved so CLI can render it: {err}"
        );
    }

    const SCOPE: &str =
        "vault:public-key:set:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn discover_cli_step_up_policy_reads_every_method_the_account_can_use() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "approval",
                "methods": ["approval", "totp"],
                "ttlSeconds": 300,
                "header": "X-LPM-Step-Up-Proof",
            })))
            .mount(&server)
            .await;

        let policy = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect("policy");

        assert_eq!(policy.method, "approval");
        assert_eq!(policy.methods, vec!["approval", "totp"]);
    }

    #[tokio::test]
    async fn request_cli_step_up_approval_reads_where_to_approve_and_wait() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .and(body_partial_json(serde_json::json!({
                "scope": SCOPE,
                "method": "approval",
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "ok": false,
                "code": "approval_required",
                "authUrl": "https://lpm.dev/cli/approve/approval-1",
                "doneUrl": "https://lpm.dev/api/auth/cli-approvals/approval-1/secret",
                "expiresAt": 1_900_000_000_000_u64,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let approval = request_cli_step_up_approval(&server.uri(), "token", SCOPE)
            .await
            .expect("approval");

        assert_eq!(approval.auth_url, "https://lpm.dev/cli/approve/approval-1");
        assert_eq!(
            approval.done_url,
            "https://lpm.dev/api/auth/cli-approvals/approval-1/secret"
        );
    }

    #[tokio::test]
    async fn request_cli_step_up_approval_refuses_a_server_that_minted_nothing_to_wait_for() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "ok": false,
                "code": "method_not_available",
            })))
            .mount(&server)
            .await;

        let error = request_cli_step_up_approval(&server.uri(), "token", SCOPE)
            .await
            .expect_err("refusal");

        assert!(error.to_string().contains("method_not_available"));
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_sends_the_approval_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .and(body_partial_json(serde_json::json!({
                "scope": SCOPE,
                "method": "approval",
                "approvalToken": "approval-token",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "proof": "approved-jwt",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let proof = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            SCOPE,
            &CliStepUpCredential::Approval {
                token: "approval-token",
            },
        )
        .await
        .expect("proof");

        assert_eq!(proof, "approved-jwt");
    }
}
