use crate::install_ui;
use crate::prompt::PromptResultExt as _;
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

struct OtpCode(SecretString);

impl OtpCode {
    fn parse(value: String) -> Result<Self, LpmError> {
        if is_valid_otp(&value) {
            Ok(Self(SecretString::from(value)))
        } else {
            Err(LpmError::OtpInvalid { command: COMMAND })
        }
    }

    fn expose(&self) -> &str {
        self.0.expose_secret()
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
    let otp = otp.map(OtpCode::parse).transpose()?;

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Rotating {} token",
            install_ui::yellow("lpm.dev")
        ));
    }

    let url = format!("{}/api/registry/-/token/rotate", registry_url);

    let interactive = crate::commands::web_auth::terminal_is_interactive();
    let first = rotate_once(
        client,
        &url,
        otp.as_ref()
            .map(|code| SecondFactorProof::Code(code.expose())),
    )
    .await;
    let (body, submitted_bearer) = match first {
        Err(LpmError::BrowserApprovalRequired {
            action,
            auth_url,
            done_url,
            accepts_code,
            has_passkey,
        }) => {
            if otp.is_some() && !accepts_code {
                // The registry takes no code from an account without an
                // authenticator app.
                return Err(LpmError::Registry(
                    "--otp needs an authenticator app, and this account has none — it confirms in the browser with its passkey; run without --otp".into(),
                ));
            }
            if accepts_code && !has_passkey {
                // Without a passkey to prefer, the code is asked for in the
                // terminal, as it was before browser approvals.
                if json_output || !interactive {
                    return Err(LpmError::OtpRequired { command: COMMAND });
                }
                let prompted_otp = prompt_otp()?;
                rotate_once(
                    client,
                    &url,
                    Some(SecondFactorProof::Code(prompted_otp.expose())),
                )
                .await?
            } else if json_output {
                return Err(LpmError::BrowserApprovalRequired {
                    action,
                    auth_url,
                    done_url,
                    accepts_code,
                    has_passkey,
                });
            } else {
                let approval = crate::commands::web_auth::complete_lpm_browser_approval(
                    &auth_url,
                    &done_url,
                    registry_url,
                    "rotate this token",
                )
                .await?;
                rotate_once(client, &url, Some(SecondFactorProof::Approval(&approval))).await?
            }
        }
        // A registry that doesn't offer browser approvals asks for the code.
        Err(LpmError::OtpRequired { .. }) if otp.is_none() && !json_output && interactive => {
            let prompted_otp = prompt_otp()?;
            rotate_once(
                client,
                &url,
                Some(SecondFactorProof::Code(prompted_otp.expose())),
            )
            .await?
        }
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

fn prompt_otp() -> Result<OtpCode, LpmError> {
    let value = cliclack::password("Authenticator code (6 digits)")
        .mask('*')
        .validate(|input: &String| {
            if is_valid_otp(input) {
                Ok(())
            } else {
                Err("Enter a 6-digit code")
            }
        })
        .interact()
        .map_prompt_err(|error| LpmError::Registry(format!("OTP prompt failed: {error}")))?;
    OtpCode::parse(value)
}

fn is_valid_otp(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_code_accepts_exactly_six_ascii_digits() {
        assert!(OtpCode::parse("012345".to_owned()).is_ok());
    }

    #[test]
    fn otp_code_rejects_non_digits_without_preserving_the_input_in_the_error() {
        let input = "12secret";
        let error = match OtpCode::parse(input.to_owned()) {
            Ok(_) => panic!("non-digit OTP unexpectedly passed validation"),
            Err(error) => error,
        };

        assert_eq!(error.error_code(), "otp_invalid");
        assert!(!error.to_string().contains(input));
    }

    #[test]
    fn otp_code_rejects_non_six_digit_lengths() {
        for input in ["", "12345", "1234567"] {
            assert!(OtpCode::parse(input.to_owned()).is_err(), "input: {input}");
        }
    }
}
