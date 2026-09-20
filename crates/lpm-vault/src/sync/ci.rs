use std::collections::HashMap;

use super::SyncError;
use super::http::{read_capped_error_text, read_capped_json, sync_http_client, url_path_segment};

/// Response from the CI pull endpoint (server-side decrypted secrets).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CiPullResponse {
    pub env: Option<String>,
    pub vars: Option<HashMap<String, String>>,
    pub error: Option<String>,
}

/// Pull vault secrets via CI escrow (OIDC flow).
/// The server decrypts using the escrowed wrapping key — no local keychain needed.
pub async fn ci_pull(
    registry_url: &str,
    oidc_token: &str,
    vault_id: &str,
    env: Option<&str>,
) -> Result<(HashMap<String, String>, String), String> {
    let client = sync_http_client().map_err(|error| error.to_string())?;
    let mut url = format!(
        "{registry_url}/api/vaults/{}/ci-pull",
        url_path_segment(vault_id)
    );
    if let Some(e) = env {
        // Env names are alphanumeric/dashes — safe for query strings without encoding
        url = format!("{url}?env={}", url_path_segment(e));
    }

    let response = client
        .get(&url)
        .bearer_auth(oidc_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    let result: CiPullResponse = read_capped_json(response).await?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    let env_name = result.env.unwrap_or_else(|| "default".to_string());
    let vars = result
        .vars
        .ok_or_else(|| "server returned no vars".to_string())?;

    Ok((vars, env_name))
}

/// Enable a complete personal CI policy with only its authenticated project key.
pub async fn enable_personal_ci(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    expected_principal_id: &str,
    policy: &serde_json::Value,
) -> Result<serde_json::Value, SyncError> {
    let pulled = super::personal::pull_raw_bound_to_principal(
        registry_url,
        auth_token,
        vault_id,
        Some(expected_principal_id),
    )
    .await?;
    let envelope = pulled
        .key_envelope
        .ok_or("push this personal env project with the current CLI before enabling CI access")?;
    let project = crate::crypto::personal::open_project_key(
        &envelope,
        registry_url,
        expected_principal_id,
        vault_id,
    )?;
    let project_key_hex = elliptic_curve::zeroize::Zeroizing::new(hex::encode(project.key));
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Activation<'a> {
        vault_id: &'a str,
        expected_principal_id: &'a str,
        expected_version: i32,
        #[serde(flatten)]
        keys: &'a crate::crypto::personal::PersonalKeyEnvelope,
        project_key_hex: &'a str,
        allow_server_decryption: bool,
        policy: &'a serde_json::Value,
    }
    let body = Activation {
        vault_id,
        expected_principal_id,
        expected_version: pulled.version,
        keys: &envelope,
        project_key_hex: &project_key_hex,
        allow_server_decryption: true,
        policy,
    };
    let response = sync_http_client()?
        .post(format!("{registry_url}/api/vault/oidc/escrow"))
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;
    let status = response.status();
    let result: serde_json::Value = read_capped_json(response).await?;
    if !status.is_success() {
        return Err(SyncError::http(
            status,
            result["error"]
                .as_str()
                .unwrap_or("personal CI activation failed")
                .to_owned(),
        ));
    }
    Ok(result)
}

/// An authenticated organization content key prepared for explicit CI decryption.
/// Key material stays private and is cleared when this value is dropped.
pub struct OrganizationCiEscrow {
    pub(super) registry_url: String,
    pub(super) org_slug: String,
    pub(super) vault_id: String,
    pub(super) principal_id: String,
    pub(super) caller_user_id: String,
    pub(super) version: i32,
    pub(super) content_key_version: i32,
    pub(super) content_key_hex: elliptic_curve::zeroize::Zeroizing<String>,
}

impl OrganizationCiEscrow {
    /// Upload the key to the same registry and immutable organization that supplied it.
    pub async fn upload(&self, auth_token: &str) -> Result<(), SyncError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Upload<'a> {
            vault_id: &'a str,
            org: &'a str,
            expected_principal_id: &'a str,
            expected_caller_user_id: &'a str,
            expected_version: i32,
            content_key_version: i32,
            content_key_hex: &'a str,
            allow_server_decryption: bool,
        }
        let body = Upload {
            vault_id: &self.vault_id,
            org: &self.org_slug,
            expected_principal_id: &self.principal_id,
            expected_caller_user_id: &self.caller_user_id,
            expected_version: self.version,
            content_key_version: self.content_key_version,
            content_key_hex: self.content_key_hex.as_str(),
            allow_server_decryption: true,
        };
        send_org_escrow_request(&self.registry_url, auth_token, reqwest::Method::POST, &body).await
    }
}

/// Disable organization CI decryption and revoke issued project credentials.
pub async fn disable_org_ci_escrow(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    expected_principal_id: &str,
) -> Result<(), SyncError> {
    let body = serde_json::json!({ "vaultId": vault_id, "org": org_slug, "expectedPrincipalId": expected_principal_id });
    send_org_escrow_request(registry_url, auth_token, reqwest::Method::DELETE, &body).await
}

async fn send_org_escrow_request<T: serde::Serialize + ?Sized>(
    registry_url: &str,
    auth_token: &str,
    method: reqwest::Method,
    body: &T,
) -> Result<(), SyncError> {
    let response = sync_http_client()?
        .request(method, format!("{registry_url}/api/vault/oidc/escrow"))
        .bearer_auth(auth_token)
        .json(body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let text = read_capped_error_text(response).await;
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|body| body["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("organization CI request failed: {status}"));
    Err(SyncError::http(status, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[cfg(debug_assertions)]
    async fn personal_ci_fixture(
        server: &MockServer,
        legacy: bool,
    ) -> Option<crate::crypto::personal::PersonalProjectKey> {
        use crate::crypto::{self, personal};
        use crate::sync::test_support::{TestSyncScope, signed_sync_ok_response};
        let principal = "personal-test-principal";
        let vault = "project-ci";
        let (project, blob, wrapped) = if legacy {
            let (blob, wrapped) =
                crypto::encrypt_vault_for_sync(r#"{"API_KEY":"fixture"}"#, principal, vault, 7)
                    .unwrap();
            (None, blob, wrapped)
        } else {
            let project = personal::create_project_key(&personal::PersonalKeyContext {
                registry_origin: &server.uri(),
                principal_id: principal,
                vault_id: vault,
                project_key_version: 1,
            })
            .unwrap();
            let (blob, wrapped) = personal::encrypt_personal_payload(
                &project,
                principal,
                vault,
                7,
                r#"{"API_KEY":"fixture"}"#,
            )
            .unwrap();
            (Some(project), blob, wrapped)
        };
        let mut body = serde_json::json!({ "encryptedBlob": blob, "wrappedKey": wrapped, "version": 7, "cryptoVersion": 3 });
        if let Some(project) = &project {
            body.as_object_mut().unwrap().extend(
                serde_json::to_value(&project.envelope)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        }
        Mock::given(method("GET"))
            .and(path("/api/vaults/project-ci/sync"))
            .respond_with(signed_sync_ok_response(
                body,
                "auth-token",
                vault,
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(server)
            .await;
        project
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[expect(
        clippy::await_holding_lock,
        reason = "the shared process-environment lock isolates current-thread tests"
    )]
    async fn personal_ci_activation_sends_only_the_project_key_and_captured_policy() {
        use crate::sync::test_support::{IsolatedVaultKeyEnv, env_lock_guard};
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let project = personal_ci_fixture(&server, false).await.unwrap();
        let policy = serde_json::json!({"vaultId":"project-ci", "provider":"github", "subject":"repo:owner/repo", "repositoryId":"123", "allowedBranches":["main"], "allowedEnvironments":["production"], "allowedWorkflows":[".github/workflows/ci.yml"], "allowedEvents":["push"], "allowForks":false});
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"policyId":"policy-id"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = enable_personal_ci(
            &server.uri(),
            "auth-token",
            "project-ci",
            "personal-test-principal",
            &policy,
        )
        .await
        .unwrap();
        assert_eq!(result["policyId"], "policy-id");
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        let mut expected = serde_json::to_value(&project.envelope).unwrap();
        expected.as_object_mut().unwrap().extend(serde_json::json!({
            "vaultId":"project-ci", "expectedPrincipalId":"personal-test-principal", "expectedVersion":7,
            "projectKeyHex":hex::encode(project.key), "allowServerDecryption":true, "policy":policy,
        }).as_object().unwrap().clone());
        assert_eq!(body, expected);
        let root = crate::crypto::personal::personal_root_key(
            &server.uri(),
            "personal-test-principal",
            false,
        )
        .unwrap();
        assert_ne!(project.key, root);
        assert!(crate::crypto::read_legacy_wrapping_key().unwrap().is_none());
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[expect(
        clippy::await_holding_lock,
        reason = "the shared process-environment lock isolates current-thread tests"
    )]
    async fn personal_ci_activation_refuses_legacy_envelopes_without_uploading_a_key() {
        use crate::sync::test_support::{IsolatedVaultKeyEnv, env_lock_guard};
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        personal_ci_fixture(&server, true).await;
        let error = enable_personal_ci(
            &server.uri(),
            "auth-token",
            "project-ci",
            "personal-test-principal",
            &serde_json::json!({}),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("push this personal env project"),
            "{error}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[expect(
        clippy::await_holding_lock,
        reason = "the shared process-environment lock isolates current-thread tests"
    )]
    async fn personal_ci_activation_refuses_a_changed_principal_before_upload() {
        use crate::sync::test_support::{IsolatedVaultKeyEnv, env_lock_guard};
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        personal_ci_fixture(&server, false).await;
        let error = enable_personal_ci(
            &server.uri(),
            "auth-token",
            "project-ci",
            "other-principal",
            &serde_json::json!({}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("different account"), "{error}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[expect(
        clippy::await_holding_lock,
        reason = "the shared process-environment lock isolates current-thread tests"
    )]
    async fn personal_ci_activation_propagates_a_concurrent_revision_conflict() {
        use crate::sync::test_support::{IsolatedVaultKeyEnv, env_lock_guard};
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        personal_ci_fixture(&server, false).await;
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"error":"project changed; pull and retry"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = enable_personal_ci(
            &server.uri(),
            "auth-token",
            "project-ci",
            "personal-test-principal",
            &serde_json::json!({}),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("project changed; pull and retry"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn ci_pull_rejects_an_oversized_declared_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let declared_length = crate::sync::http::MAX_VAULT_RESPONSE_BYTES + 1;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {declared_length}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });

        let error = ci_pull(&format!("http://{addr}"), "oidc-token", "vault-123", None)
            .await
            .expect_err("an oversized CI response must be rejected");

        assert!(
            error.contains("response too large"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn ci_pull_returns_vars_and_requested_env() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .and(query_param("env", "preview"))
            .and(header("authorization", "Bearer oidc-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "env": "preview",
                "vars": {
                    "API_KEY": "secret-value",
                    "NODE_ENV": "preview"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (vars, env_name) = ci_pull(&server.uri(), "oidc-token", "vault-123", Some("preview"))
            .await
            .expect("ci pull should succeed");

        assert_eq!(env_name, "preview");
        assert_eq!(
            vars.get("API_KEY").map(String::as_str),
            Some("secret-value")
        );
        assert_eq!(vars.get("NODE_ENV").map(String::as_str), Some("preview"));
    }

    #[tokio::test]
    async fn ci_pull_defaults_env_when_server_omits_it() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vars": {
                    "API_KEY": "secret-value"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (vars, env_name) = ci_pull(&server.uri(), "oidc-token", "vault-123", None)
            .await
            .expect("ci pull should default env name");

        assert_eq!(env_name, "default");
        assert_eq!(
            vars.get("API_KEY").map(String::as_str),
            Some("secret-value")
        );
    }

    #[tokio::test]
    async fn ci_pull_returns_server_error_message_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "oidc subject not allowed"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = ci_pull(&server.uri(), "oidc-token", "vault-123", None).await;

        assert!(matches!(result, Err(message) if message == "oidc subject not allowed"));
    }

    #[tokio::test]
    async fn ci_pull_errors_when_server_returns_no_vars() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "env": "production"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = ci_pull(&server.uri(), "oidc-token", "vault-123", None).await;

        assert!(matches!(result, Err(message) if message == "server returned no vars"));
    }
}
