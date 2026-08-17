//! CLI wrapper around the dashboard's `/api/auth/cli-step-up` endpoint
//! (Workstream 2 reauth primitive).
//!
//! Wraps the lpm-vault network clients with cliclack prompts and a
//! strict non-interactive refusal. Every sensitive CLI write that the
//! WS3 + WS4 server gates require a step-up proof for routes through
//! this helper:
//!
//!   - `lpm env rotate-sharing-key` → `vault:public-key:rotate`
//!   - `lpm env share` / `lpm env pull --org` first-time registration
//!     → `vault:public-key:set`
//!   - (future) force-push gates → `vault:force-push:*`
//!
//! Always refuses non-interactive callers: a CI environment piping
//! stdin should never silently advance through a password prompt and
//! then succeed; the failure must be loud so the operator wires a
//! different credential flow (long-lived token, OIDC, etc.) instead.

use lpm_vault::sync::{CliStepUpCredential, discover_cli_step_up_policy, mint_cli_step_up_proof};
use std::io::IsTerminal;

use lpm_common::LpmError;

use crate::output;

/// Acquire a step-up proof for `scope`, prompting the user
/// interactively for the credential the server's policy requires.
///
/// Returns the proof JWT on success. The caller carries it in the
/// `X-LPM-Step-Up-Proof` header on the subsequent sensitive write
/// (e.g. `lpm_vault::sync::upload_public_key(..., Some(&proof))`).
pub async fn request_cli_step_up_proof(
    client: &lpm_registry::RegistryClient,
    scope: &str,
) -> Result<String, LpmError> {
    // Refuse non-interactive callers up-front. Prompting for a password
    // without a TTY would either block on stdin forever or silently
    // accept whatever's piped in — both are worse than a clear refusal.
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(format!(
            "step-up reauth is required for `{scope}` but stdin is not a TTY. \
             Run this command from an interactive terminal."
        )));
    }

    let policy = crate::commands::env::auth::execute_sync_with_bearer(
        client,
        lpm_auth::AuthRequirement::TokenRequired,
        |registry_url, auth_token| async move {
            discover_cli_step_up_policy(&registry_url, &auth_token).await
        },
    )
    .await?;

    match policy.method.as_str() {
        "password" => {
            output::info(
                "Confirm your password to authorize this action. This proof is bound to your \
                 current CLI session and expires in 5 minutes.",
            );
            let password: String = cliclack::password("Password")
                .interact()
                .map_err(|e| LpmError::Script(format!("password prompt failed: {e}")))?;

            crate::commands::env::auth::execute_sync_with_bearer(
                client,
                lpm_auth::AuthRequirement::TokenRequired,
                |registry_url, auth_token| {
                    let password = password.clone();
                    async move {
                        mint_cli_step_up_proof(
                            &registry_url,
                            &auth_token,
                            scope,
                            &CliStepUpCredential::Password {
                                password: &password,
                            },
                        )
                        .await
                    }
                },
            )
            .await
        }
        "totp" => {
            // Two-factor proof — the server requires password AND a
            // fresh TOTP code because the CLI bearer is not a Supabase
            // session and `mfa.verify` can only be reached by signing
            // in transiently with the password first. See WS2 server
            // route docstring for the full rationale.
            output::info(
                "Confirm your password and a fresh authenticator code to authorize this \
                 action. This proof is bound to your current CLI session and expires in 5 \
                 minutes.",
            );
            let password: String = cliclack::password("Password")
                .interact()
                .map_err(|e| LpmError::Script(format!("password prompt failed: {e}")))?;
            let code: String = cliclack::input("Authenticator code (6 digits)")
                .validate(|input: &String| {
                    if input.chars().all(|c| c.is_ascii_digit()) && input.len() == 6 {
                        Ok(())
                    } else {
                        Err("must be exactly 6 digits")
                    }
                })
                .interact()
                .map_err(|e| LpmError::Script(format!("totp prompt failed: {e}")))?;

            crate::commands::env::auth::execute_sync_with_bearer(
                client,
                lpm_auth::AuthRequirement::TokenRequired,
                |registry_url, auth_token| {
                    let password = password.clone();
                    let code = code.clone();
                    async move {
                        mint_cli_step_up_proof(
                            &registry_url,
                            &auth_token,
                            scope,
                            &CliStepUpCredential::Totp {
                                password: &password,
                                code: &code,
                            },
                        )
                        .await
                    }
                },
            )
            .await
        }
        "unavailable" => {
            let reason = policy.reason.as_deref().unwrap_or("unknown");
            Err(LpmError::Script(format!(
                "step-up reauth is unavailable for this account: {reason}. \
                 Set an account password or enroll an authenticator in the dashboard \
                 (Settings → Security) and retry."
            )))
        }
        other => Err(LpmError::Script(format!(
            "server returned unknown step-up method `{other}` — your CLI may be too old; \
             try upgrading with `lpm upgrade`"
        ))),
    }
}
