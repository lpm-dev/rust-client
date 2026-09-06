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

/// Upload the wrapping key to the server for CI escrow.
/// Called during `lpm env oidc allow` to enable server-side decryption.
pub async fn upload_escrow_key(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    wrapping_key_hex: &str,
    expected_principal_id: &str,
) -> Result<(), SyncError> {
    let client = sync_http_client()?;
    let url = format!("{registry_url}/api/vault/oidc/escrow");

    let body = serde_json::json!({
        "vaultId": vault_id,
        "wrappingKeyHex": wrapping_key_hex,
        "expectedPrincipalId": expected_principal_id,
    });

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let status = response.status();
        let body = read_capped_error_text(response).await;
        // Try to extract error message from JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(err) = json["error"].as_str()
        {
            return Err(SyncError::http(status, err.to_string()));
        }
        return Err(SyncError::http(
            status,
            format!("escrow upload failed: {body}"),
        ));
    }

    Ok(())
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
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn escrow_upload_carries_the_captured_personal_principal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .and(body_json(serde_json::json!({
                "vaultId": "vault-123",
                "wrappingKeyHex": "aa",
                "expectedPrincipalId": "account-1",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        upload_escrow_key(&server.uri(), "session", "vault-123", "aa", "account-1")
            .await
            .expect("escrow upload should preserve the captured principal");
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
