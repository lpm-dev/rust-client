use super::SyncError;
use super::http::{sync_http_client_builder, url_path_segment};

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
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
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
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    let result: AuditResponse = response
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        let message = result
            .error
            .unwrap_or_else(|| format!("server error: {status}"));
        return Err(SyncError::http(status, message));
    }

    Ok(result)
}
