use super::prelude::*;

/// Resolve an LPM session bearer for env vault sync sites.
///
/// `lpm env` subcommands build their own reqwest client (long timeouts,
/// custom routing) so they don't get `RegistryClient::execute_with_recovery`
/// for free. This helper builds a local `SessionManager` (cheap,
/// local-only — no network) and asks it for a usable bearer.
///
/// `bearer_string_for` handles the refresh-only-state path internally:
/// if the cached access token is missing but a refresh token is on disk,
/// the silent refresh runs here. Subsequent calls within the same process
/// see the persisted rotated token, so constructing per-call instead of
/// threading a shared session is behaviorally equivalent for env's
/// single-shot usage pattern.
pub(super) async fn resolve_lpm_bearer(
    registry_url: &str,
    json_output: bool,
) -> Result<String, LpmError> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
    session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .map_err(|error| match error {
            LpmError::AuthRequired | LpmError::SessionExpired => {
                LpmError::Script("not logged in. Run `lpm login` first".into())
            }
            other => other,
        })
}

/// Vault-pairing variant that requires a real interactive login (not
/// `LPM_TOKEN`/`--token`/CI/legacy tokens). `SessionRequired` posture
/// maps directly to "source is `StoredSession`".
///
/// Distinguishes two failure modes so the user gets actionable text:
/// - **No session at all** (post-logout, never-logged-in): "not
///   logged in. Run `lpm login` first" — same message as
///   `resolve_lpm_bearer`.
/// - **Has a non-session token** (`LPM_TOKEN` / `--token` / CI /
///   legacy stored): the upgrade-to-session message.
pub(super) async fn resolve_session_bearer(
    registry_url: &str,
    json_output: bool,
) -> Result<String, LpmError> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
    let has_any_source = session.current_source()?.is_some();
    session
        .bearer_string_for(lpm_auth::AuthRequirement::SessionRequired)
        .await
        .map_err(|error| match error {
            LpmError::AuthRequired | LpmError::SessionExpired => {
                if has_any_source {
                    LpmError::Script(
                        "your current login uses a legacy token that doesn't support vault pairing.\n  \
                         Run `lpm logout` then `lpm login` to upgrade to a session-based login."
                            .into(),
                    )
                } else {
                    LpmError::Script("not logged in. Run `lpm login` first".into())
                }
            }
            other => other,
        })
}

/// Get the LPM auth token and registry URL for API calls.
pub(super) async fn get_platform_auth(json_output: bool) -> Result<(String, String), LpmError> {
    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;
    Ok((registry_url, auth_token))
}
