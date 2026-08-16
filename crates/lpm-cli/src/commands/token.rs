use crate::install_ui;
use lpm_auth::TokenSource;
use lpm_common::LpmError;
use lpm_registry::{RegistryClient, parse_capped_api_json};
use secrecy::{ExposeSecret, SecretString};

const COMMAND: &str = "lpm token-rotate";

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
    let auth_source = require_locally_managed_auth(client)?;
    let otp = otp.map(OtpCode::parse).transpose()?;

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Rotating {} token",
            install_ui::yellow("lpm.dev")
        ));
    }

    let url = format!("{}/api/registry/-/token/rotate", registry_url);

    let body = match rotate_once(client, &url, otp.as_ref()).await {
        Err(LpmError::OtpRequired { .. })
            if otp.is_none()
                && !json_output
                && crate::commands::web_auth::terminal_is_interactive() =>
        {
            let prompted_otp = prompt_otp()?;
            rotate_once(client, &url, Some(&prompted_otp)).await?
        }
        Err(LpmError::AuthRequired) => {
            clear_rejected_legacy_token(registry_url, auth_source)?;
            return Err(LpmError::AuthRequired);
        }
        result => result?,
    };

    if let Some(new_token) = body.get("token").and_then(|t| t.as_str()) {
        // Store the new token
        let storage_backend = crate::auth::set_token_with_backend(registry_url, new_token)
            .map_err(|e| LpmError::Registry(format!("failed to store new token: {e}")))?;
        let storage_status = crate::auth::AuthStorageStatus::from_backend(storage_backend);

        // Store token expiry metadata.
        if let Some(expires) = body.get("expiresAt").and_then(|e| e.as_str()) {
            let date_part = expires.split('T').next().unwrap_or(expires);
            crate::auth::set_token_expiry(registry_url, date_part);
        }

        if json_output {
            let json = serde_json::json!({
                "success": true,
                "rotated": true,
                "expires_at": body.get("expiresAt"),
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
                    "Encrypted file fallback is active; unlock or repair the OS keychain and rotate again to use keychain storage.",
                );
            }
            install_ui::done("Done · session token rotated successfully");
            if let Some(expires) = body.get("expiresAt").and_then(|e| e.as_str()) {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("Expires:"),
                    install_ui::dim(expires)
                ));
            }
            eprintln!();
        }
    } else {
        let error = body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(LpmError::Registry(format!(
            "token rotation failed: {error}"
        )));
    }

    Ok(())
}

fn require_locally_managed_auth(client: &RegistryClient) -> Result<TokenSource, LpmError> {
    let source = client
        .session()
        .and_then(|session| session.current_source())
        .ok_or(LpmError::AuthRequired)?;
    if source.is_locally_managed() {
        return Ok(source);
    }

    Err(LpmError::UnsupportedAuthSource {
        command: COMMAND,
        auth_source: source.label(),
    })
}

fn clear_rejected_legacy_token(
    registry_url: &str,
    auth_source: TokenSource,
) -> Result<(), LpmError> {
    if auth_source != TokenSource::StoredLegacy {
        return Ok(());
    }

    crate::auth::clear_login_state(registry_url)
        .map_err(|error| LpmError::Registry(format!("failed to clear rejected token: {error}")))
}

async fn rotate_once(
    client: &RegistryClient,
    url: &str,
    otp: Option<&OtpCode>,
) -> Result<serde_json::Value, LpmError> {
    let response = client
        .post_json_raw_with_otp(url, &serde_json::json!({}), otp.map(OtpCode::expose))
        .await?;
    let status = response.status();
    let body =
        parse_capped_api_json::<serde_json::Value>(response, "token rotation response").await;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        if let Ok(body) = &body {
            match body.get("code").and_then(serde_json::Value::as_str) {
                Some("OTP_REQUIRED") => return Err(LpmError::OtpRequired { command: COMMAND }),
                Some("OTP_INVALID") => return Err(LpmError::OtpInvalid { command: COMMAND }),
                _ => {}
            }
        }
        return Err(LpmError::AuthRequired);
    }
    let body = body?;
    if !status.is_success() {
        let error = body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown error");
        return Err(LpmError::Registry(format!(
            "token rotation failed: {error}"
        )));
    }
    Ok(body)
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
        .map_err(|error| LpmError::Registry(format!("OTP prompt failed: {error}")))?;
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
