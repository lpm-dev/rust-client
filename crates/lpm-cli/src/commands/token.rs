use crate::commands::registry_change::{OtpCode, RegistryChange, send_with_second_factor};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::{RegistryClient, SecondFactorProof};
use secrecy::{ExposeSecret, SecretString};

const COMMAND: &str = "lpm token-rotate";

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRotationResponse {
    token: String,
    expires_at: Option<String>,
}

impl TokenRotationResponse {
    fn parse(body: serde_json::Value) -> Result<Self, LpmError> {
        if body.get("expiresAt").is_none() {
            return Err(LpmError::Registry(
                "invalid token rotation response: missing expiresAt".into(),
            ));
        }
        let response: Self = serde_json::from_value(body).map_err(|error| {
            LpmError::Registry(format!("invalid token rotation response: {error}"))
        })?;
        if response.token.trim().is_empty()
            || response
                .expires_at
                .as_deref()
                .is_some_and(|expiry| chrono::DateTime::parse_from_rfc3339(expiry).is_err())
        {
            return Err(LpmError::Registry(
                "invalid token rotation response: expected a non-empty token and an RFC 3339 or null expiry"
                    .to_string(),
            ));
        }
        Ok(response)
    }
}

/// Rotate the current token (create new, revoke old).
pub async fn run_rotate(
    client: &RegistryClient,
    registry_url: &str,
    otp: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    let rejected_access_token = locally_managed_bearer(client)?;
    let otp = otp.map(|code| OtpCode::parse(code, COMMAND)).transpose()?;

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Rotating {} token",
            install_ui::yellow("lpm.dev")
        ));
    }

    let url = format!("{}/api/registry/-/token/rotate", registry_url);

    let change = RegistryChange {
        command: COMMAND,
        approval: "rotate this token",
    };
    let sent = send_with_second_factor(
        &change,
        registry_url,
        otp.as_ref(),
        json_output,
        async |proof| rotate_once(client, &url, proof).await,
    )
    .await;
    let (body, submitted_bearer) = match sent {
        Err(LpmError::AuthRequired) => {
            clear_rejected_local_session_if_current(registry_url, &rejected_access_token)?;
            return Err(LpmError::AuthRequired);
        }
        Err(LpmError::SessionExpired) => {
            let rejected_legacy =
                clear_rejected_local_session_if_current(registry_url, &rejected_access_token)?;
            return Err(if rejected_legacy {
                LpmError::AuthRequired
            } else {
                LpmError::SessionExpired
            });
        }
        result => result?,
    };
    let rotated = TokenRotationResponse::parse(body)?;

    let storage_status = lpm_auth::store_rotated_access_token_if_current(
        registry_url,
        submitted_bearer.expose_secret(),
        &rotated.token,
        rotated.expires_at.as_deref(),
    )
    .await?;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "rotated": true,
            "expires_at": rotated.expires_at,
            "storage_backend": storage_status.backend_json_value(),
            "storage_degraded": storage_status.degraded,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done("Old token invalidated");
        install_ui::done("New token stored");
        if let Some(label) = storage_status.human_label() {
            install_ui::detail_untrusted(&format!("secure storage backend: {label}"));
        }
        if storage_status.degraded {
            install_ui::warn(
                "Encrypted file fallback is active; unlock or repair the OS keychain, then run `lpm logout` and `lpm login` to store a new session in the keychain.",
            );
        }
        install_ui::done("Done · session token rotated successfully");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("Expires:"),
            install_ui::dim(rotated.expires_at.as_deref().unwrap_or("never"))
        ));
        eprintln!();
    }

    Ok(())
}

fn locally_managed_bearer(client: &RegistryClient) -> Result<String, LpmError> {
    let session = client.session().ok_or(LpmError::AuthRequired)?;
    let source = session.current_source()?.ok_or(LpmError::AuthRequired)?;
    if source.is_locally_managed() {
        return session.current_bearer_lazy()?.ok_or(LpmError::AuthRequired);
    }

    Err(LpmError::UnsupportedAuthSource {
        command: COMMAND,
        auth_source: source.label(),
    })
}

fn clear_rejected_local_session_if_current(
    registry_url: &str,
    rejected_access_token: &str,
) -> Result<bool, LpmError> {
    crate::auth::clear_rejected_legacy_session_if_current(registry_url, rejected_access_token)
        .map_err(|error| {
            LpmError::CredentialStorage(format!("failed to clear rejected token: {error}"))
        })
}

async fn rotate_once(
    client: &RegistryClient,
    url: &str,
    proof: Option<SecondFactorProof<'_>>,
) -> Result<(serde_json::Value, SecretString), LpmError> {
    client
        .post_json_with_second_factor_and_bearer(
            url,
            &serde_json::json!({}),
            proof,
            COMMAND,
            "token rotation",
        )
        .await
}
