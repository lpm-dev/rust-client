use super::http::{read_capped_error_text, sync_http_client_builder, url_path_segment};

/// Response from GET /api/vault/pair/:code (pending session).
///
/// The CLI derives the browser-key fingerprint and the short authentication
/// string locally from `browser_public_key` and the user-typed pairing code —
/// trusting the server for those derived values would let a malicious server
/// silently approve any pair, defeating the visual confirmation. Only the
/// genuinely server-side facts (`device_label`, `created_at`,
/// `created_from_ip`) are wire-supplied, and all three are optional so a
/// newer CLI built against an older server still parses the response and
/// simply omits the missing fields from the confirmation prompt.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSession {
    pub status: String,
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
) -> Result<PairingSession, String> {
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
        let body = read_capped_error_text(response).await;
        return Err(format!("pairing error: {body}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Approve a pairing session by sending the ECDH-wrapped wrapping key.
pub async fn approve_pairing(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    encrypted_wrapping_key: &str,
    ephemeral_public_key: &str,
) -> Result<(), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/{}", url_path_segment(code));

    let body = serde_json::json!({
        "encryptedWrappingKey": encrypted_wrapping_key,
        "ephemeralPublicKey": ephemeral_public_key,
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
        let body = read_capped_error_text(response).await;
        return Err(format!("approval failed: {body}"));
    }

    Ok(())
}

/// Revoke all browser pairings for the authenticated user.
pub async fn unpair_all(registry_url: &str, auth_token: &str) -> Result<(), String> {
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
        let body = read_capped_error_text(response).await;
        return Err(format!("unpair failed: {body}"));
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
                "browserPublicKey": "browser-key"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = get_pairing_session(&server.uri(), "auth-token", "ABC123")
            .await
            .expect("pairing session should parse");

        assert_eq!(result.status, "pending");
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

        assert!(matches!(result, Err(message) if message == "pairing error: pairing expired"));
    }

    #[tokio::test]
    async fn approve_pairing_posts_wrapped_key_payload() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
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

        assert!(matches!(result, Err(message) if message == "unpair failed: vault revoke failed"));
    }
}
