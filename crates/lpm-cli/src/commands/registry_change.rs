//! The second factor an lpm.dev change asks for, other than a publish's:
//! unpublishing, deprecating, undeprecating and rotating a token. The
//! registry refuses the change saying what it needs, and the change is sent
//! again with it.

use crate::prompt::PromptResultExt as _;
use lpm_common::LpmError;
use lpm_registry::SecondFactorProof;
use secrecy::{ExposeSecret, SecretString};

/// A six-digit authenticator code, checked before any request is sent.
pub(crate) struct OtpCode(SecretString);

impl OtpCode {
    /// Checks a code `command` was given; the error doesn't repeat it.
    pub(crate) fn parse(value: String, command: &'static str) -> Result<Self, LpmError> {
        if is_valid_otp(&value) {
            Ok(Self(SecretString::from(value)))
        } else {
            Err(LpmError::OtpInvalid { command })
        }
    }

    fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

/// A change, as the CLI names it while confirming it.
pub(crate) struct RegistryChange<'a> {
    /// The command making it, as errors name it, such as `lpm unpublish`.
    pub(crate) command: &'static str,
    /// What the browser approval is for, completing "Approve in your
    /// browser to …", such as `unpublish @lpm.dev/acme.kit@1.2.3`.
    pub(crate) approval: &'a str,
}

/// Sends a change, and sends it again with the second factor the registry
/// asks for: `otp` from the start; otherwise, for an account with a passkey,
/// the token of a browser approval, or for one with only an authenticator
/// app, a code asked for in the terminal.
///
/// `--json` neither prompts nor waits for an approval. Without a terminal, a
/// code can't be asked for, but the approval URL is printed and waited for,
/// so a change from CI can be approved by whoever reads its log.
pub(crate) async fn send_with_second_factor<T>(
    change: &RegistryChange<'_>,
    registry_url: &str,
    otp: Option<&OtpCode>,
    json_output: bool,
    mut send: impl AsyncFnMut(Option<SecondFactorProof<'_>>) -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    let interactive = crate::commands::web_auth::terminal_is_interactive();
    let first = send(otp.map(|code| SecondFactorProof::Code(code.expose()))).await;
    match first {
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
                    return Err(LpmError::OtpRequired {
                        command: change.command,
                    });
                }
                let code = prompt_otp(change.command)?;
                return send(Some(SecondFactorProof::Code(code.expose()))).await;
            }
            if json_output {
                return Err(LpmError::BrowserApprovalRequired {
                    action,
                    auth_url,
                    done_url,
                    accepts_code,
                    has_passkey,
                });
            }
            let approval = crate::commands::web_auth::complete_lpm_browser_approval(
                &auth_url,
                &done_url,
                registry_url,
                change.approval,
            )
            .await?;
            send(Some(SecondFactorProof::Approval(&approval))).await
        }
        // A registry that doesn't offer browser approvals asks for the code.
        Err(LpmError::OtpRequired { .. }) if otp.is_none() && !json_output && interactive => {
            let code = prompt_otp(change.command)?;
            send(Some(SecondFactorProof::Code(code.expose()))).await
        }
        result => result,
    }
}

fn prompt_otp(command: &'static str) -> Result<OtpCode, LpmError> {
    crate::install_ui::settle_spinner();
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
    OtpCode::parse(value, command)
}

fn is_valid_otp(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND: &str = "lpm unpublish";

    #[test]
    fn otp_code_accepts_exactly_six_ascii_digits() {
        assert!(OtpCode::parse("012345".to_owned(), COMMAND).is_ok());
    }

    #[test]
    fn otp_code_rejects_non_digits_without_preserving_the_input_in_the_error() {
        let input = "12secret";
        let error = match OtpCode::parse(input.to_owned(), COMMAND) {
            Ok(_) => panic!("non-digit OTP unexpectedly passed validation"),
            Err(error) => error,
        };

        assert_eq!(error.error_code(), "otp_invalid");
        assert!(!error.to_string().contains(input));
        assert!(error.to_string().contains(COMMAND));
    }

    #[test]
    fn otp_code_rejects_non_six_digit_lengths() {
        for input in ["", "12345", "1234567", "１２３４５６"] {
            assert!(
                OtpCode::parse(input.to_owned(), COMMAND).is_err(),
                "input: {input}"
            );
        }
    }
}
