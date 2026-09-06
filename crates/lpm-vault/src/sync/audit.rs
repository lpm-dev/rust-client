use super::SyncError;
use super::http::{read_capped_json, sync_http_client, sync_request_timeout, url_path_segment};

/// Response from audit log endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResponse {
    pub entries: Option<Vec<AuditEntry>>,
    pub next_cursor: Option<String>,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

/// Get the vault audit log.
pub async fn get_audit_log(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    cursor: Option<&str>,
) -> Result<AuditResponse, SyncError> {
    let client = sync_http_client()?;
    let mut url = format!(
        "{registry_url}/api/vaults/{}/audit",
        url_path_segment(vault_id)
    );
    if let Some(c) = cursor {
        url = format!("{url}?cursor={}", url_path_segment(c));
    }

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    let result: AuditResponse = read_capped_json(response).await?;

    if !status.is_success() {
        let message = result
            .error
            .unwrap_or_else(|| format!("server error: {status}"));
        return Err(SyncError::http(status, message));
    }

    Ok(result)
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    #[cfg(debug_assertions)]
    use super::*;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::env_lock_guard;
    #[cfg(debug_assertions)]
    use wiremock::matchers::{header, method, path};
    #[cfg(debug_assertions)]
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn audit_request_times_out_when_server_stalls() {
        let _guard = env_lock_guard();
        let server = MockServer::start().await;
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");

        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/audit"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(2)))
            .expect(1)
            .mount(&server)
            .await;

        let started_at = std::time::Instant::now();
        let result = get_audit_log(&server.uri(), "auth-token", "vault-123", None).await;
        let elapsed = started_at.elapsed();

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "audit request should time out, took {elapsed:?}"
        );
        assert!(result.is_err(), "a stalled audit request must fail");
    }
}
