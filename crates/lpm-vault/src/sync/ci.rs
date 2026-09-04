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
) -> Result<(), SyncError> {
    let client = sync_http_client()?;
    let url = format!("{registry_url}/api/vault/oidc/escrow");

    let body = serde_json::json!({
        "vaultId": vault_id,
        "wrappingKeyHex": wrapping_key_hex,
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
