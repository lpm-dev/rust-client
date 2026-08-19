use super::SyncError;
use super::http::{read_capped_error_text, sync_http_client_builder};

/// HTTP header the server expects the CLI step-up proof JWT in. Mirrors
/// `CLI_STEP_UP_HEADER_NAME` exported from the dashboard's
/// `lib/auth/cli-step-up.js`. Defined here as a constant so the upload
/// site and any future caller route the proof through the same name.
pub const CLI_STEP_UP_HEADER_NAME: &str = "X-LPM-Step-Up-Proof";

/// Step-up policy resolved by the server for the calling user. The CLI
/// prompts for the credential named in `method` (or refuses outright
/// when `unavailable`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliStepUpPolicy {
    /// `"password"`, `"totp"`, or `"unavailable"`. The CLI MUST refuse
    /// any flow when `unavailable` because the prompt would ask for a
    /// credential the user cannot satisfy.
    pub method: String,
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

/// Credential the CLI supplies on mint. Two shapes — password-only for
/// users with no MFA, and password+TOTP for MFA-enrolled users. The CLI
/// cannot drive TOTP alone because the server expects password-backed
/// reauthentication for this proof.
pub enum CliStepUpCredential<'a> {
    Password { password: &'a str },
    Totp { password: &'a str, code: &'a str },
}

/// Discover the step-up method the server expects for the calling
/// user — does not consume any credential, no rate-limit cost beyond
/// the per-IP shield. Used by the CLI to decide what to prompt for
/// before asking the user to type a password / TOTP.
pub async fn discover_cli_step_up_policy(
    registry_url: &str,
    auth_token: &str,
) -> Result<CliStepUpPolicy, SyncError> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
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

    Ok(response
        .json::<CliStepUpPolicy>()
        .await
        .map_err(|e| format!("parse error: {e}"))?)
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
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
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
        return Err(SyncError::http(
            status,
            format!("step-up mint: {status}: {body}"),
        ));
    }

    let parsed = response
        .json::<MintCliStepUpResponse>()
        .await
        .map_err(|e| format!("parse error: {e}"))?;
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
    use wiremock::matchers::{method, path};
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
            "vault:public-key:set",
            &CliStepUpCredential::Password {
                password: "hunter2",
            },
        )
        .await
        .expect("happy path");
        assert_eq!(proof, "test-jwt");

        let body = captured.lock().unwrap()[0].clone();
        assert!(body.contains("\"method\":\"password\""));
        assert!(body.contains("\"scope\":\"vault:public-key:set\""));
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
            "vault:public-key:rotate",
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
        assert!(body.contains("\"scope\":\"vault:public-key:rotate\""));
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
            "vault:public-key:set",
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
}
