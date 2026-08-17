use super::SyncError;
use super::http::{read_capped_error_text, sync_http_client_builder, url_path_segment};

/// Response from GET /api/vault/pair/:code (pending session).
///
/// `protocol_version` is optional so a new CLI can identify and complete a
/// session created by a protocol-v1 server during a rolling upgrade.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSession {
    pub status: String,
    pub protocol_version: Option<u8>,
    pub browser_public_key: Option<String>,
    pub device_label: Option<String>,
    pub created_at: Option<String>,
    pub created_from_ip: Option<String>,
}

/// Fetch a pending pairing session to get the browser's P-256 public key.
pub async fn get_pairing_session(
    registry_url: &str,
    auth_token: &str,
    code: &str,
) -> Result<PairingSession, SyncError> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/{}", url_path_segment(code));

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let status = response.status();
        let body = read_capped_error_text(response).await;
        return Err(SyncError::http(status, format!("pairing error: {body}")));
    }

    Ok(response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?)
}

/// Stage the protocol-v2 CLI public key before displaying the ECDH-derived SAS.
pub async fn stage_pairing(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    ephemeral_public_key: &str,
) -> Result<(), SyncError> {
    post_pairing(
        registry_url,
        auth_token,
        code,
        serde_json::json!({
            "action": "stage",
            "ephemeralPublicKey": ephemeral_public_key,
        }),
        "staging",
    )
    .await
}

/// Approve a protocol-v2 pairing session after user SAS confirmation.
pub async fn approve_pairing(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    encrypted_wrapping_key: &str,
    ephemeral_public_key: &str,
) -> Result<(), SyncError> {
    post_pairing(
        registry_url,
        auth_token,
        code,
        serde_json::json!({
            "action": "approve",
            "encryptedWrappingKey": encrypted_wrapping_key,
            "ephemeralPublicKey": ephemeral_public_key,
        }),
        "approval",
    )
    .await
}

/// Complete a session created by a protocol-v1 server.
pub async fn approve_pairing_legacy(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    encrypted_wrapping_key: &str,
    ephemeral_public_key: &str,
) -> Result<(), SyncError> {
    post_pairing(
        registry_url,
        auth_token,
        code,
        serde_json::json!({
            "encryptedWrappingKey": encrypted_wrapping_key,
            "ephemeralPublicKey": ephemeral_public_key,
        }),
        "approval",
    )
    .await
}

async fn post_pairing(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    body: serde_json::Value,
    operation: &str,
) -> Result<(), SyncError> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/{}", url_path_segment(code));

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
        return Err(SyncError::http(
            status,
            format!("{operation} failed: {body}"),
        ));
    }

    Ok(())
}

/// Revoke all browser pairings for the authenticated user.
pub async fn unpair_all(registry_url: &str, auth_token: &str) -> Result<(), SyncError> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/revoke-all");

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .header("content-type", "application/json")
        .body("{}")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let status = response.status();
        let body = read_capped_error_text(response).await;
        return Err(SyncError::http(status, format!("unpair failed: {body}")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_pairing_session_returns_pending_session_with_browser_key() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "pending",
                "protocolVersion": 2,
                "browserPublicKey": "browser-key"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = get_pairing_session(&server.uri(), "auth-token", "ABC123")
            .await
            .expect("pairing session should parse");

        assert_eq!(result.status, "pending");
        assert_eq!(result.protocol_version, Some(2));
        assert_eq!(result.browser_public_key.as_deref(), Some("browser-key"));
    }

    #[tokio::test]
    async fn get_pairing_session_returns_body_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vault/pair/EXPIRED"))
            .respond_with(ResponseTemplate::new(410).set_body_string("pairing expired"))
            .expect(1)
            .mount(&server)
            .await;

        let result = get_pairing_session(&server.uri(), "auth-token", "EXPIRED").await;

        assert!(
            matches!(result, Err(message) if message.to_string() == "pairing error: pairing expired")
        );
    }

    #[tokio::test]
    async fn approve_pairing_posts_wrapped_key_payload() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
            .and(body_string_contains("\"action\":\"approve\""))
            .and(body_string_contains(
                "\"encryptedWrappingKey\":\"wrapped-key\"",
            ))
            .and(body_string_contains(
                "\"ephemeralPublicKey\":\"ephemeral-key\"",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        approve_pairing(
            &server.uri(),
            "auth-token",
            "ABC123",
            "wrapped-key",
            "ephemeral-key",
        )
        .await
        .expect("approve pairing should succeed");
    }

    #[tokio::test]
    async fn stage_pairing_posts_only_the_cli_public_key() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
            .and(body_string_contains("\"action\":\"stage\""))
            .and(body_string_contains(
                "\"ephemeralPublicKey\":\"ephemeral-key\"",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "confirming"
            })))
            .expect(1)
            .mount(&server)
            .await;

        stage_pairing(&server.uri(), "auth-token", "ABC123", "ephemeral-key")
            .await
            .expect("stage pairing should succeed");
    }

    #[tokio::test]
    async fn unpair_all_returns_body_on_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/revoke-all"))
            .and(header("authorization", "Bearer auth-token"))
            .and(body_string_contains("{}"))
            .respond_with(ResponseTemplate::new(500).set_body_string("vault revoke failed"))
            .expect(1)
            .mount(&server)
            .await;

        let result = unpair_all(&server.uri(), "auth-token").await;

        assert!(
            matches!(result, Err(message) if message.to_string() == "unpair failed: vault revoke failed")
        );
    }
}
