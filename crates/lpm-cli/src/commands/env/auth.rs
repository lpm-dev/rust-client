use super::prelude::*;
use lpm_auth::{AuthRequirement, RefreshPolicy};
use lpm_registry::RegistryClient;

async fn resolve_bearer(
    client: &RegistryClient,
    requirement: AuthRequirement,
) -> Result<String, LpmError> {
    let session = client.session().ok_or(LpmError::AuthRequired)?;
    session.bearer_string_for(requirement).await
}

fn login_required(error: LpmError) -> LpmError {
    match error {
        LpmError::AuthRequired | LpmError::SessionExpired => {
            LpmError::Script("not logged in. Run `lpm login` first".into())
        }
        other => other,
    }
}

/// Resolve the current LPM bearer for a direct env API client.
pub(super) async fn resolve_lpm_bearer(client: &RegistryClient) -> Result<String, LpmError> {
    resolve_bearer(client, AuthRequirement::TokenRequired)
        .await
        .map_err(login_required)
}

async fn resolve_required_bearer(
    client: &RegistryClient,
    requirement: AuthRequirement,
) -> Result<String, LpmError> {
    match requirement {
        AuthRequirement::TokenRequired => resolve_lpm_bearer(client).await,
        AuthRequirement::SessionRequired => resolve_session_bearer(client).await,
        AuthRequirement::AnonymousAllowed => resolve_bearer(client, requirement).await,
    }
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
pub(super) async fn resolve_session_bearer(client: &RegistryClient) -> Result<String, LpmError> {
    let Some(session) = client.session() else {
        return Err(login_required(LpmError::AuthRequired));
    };
    match resolve_bearer(client, AuthRequirement::SessionRequired).await {
        Ok(bearer) => Ok(bearer),
        Err(error @ (LpmError::AuthRequired | LpmError::SessionExpired)) => {
            let has_non_session_source = session
                .current_source()?
                .is_some_and(|source| !source.is_session_backed());
            if has_non_session_source {
                Err(LpmError::Script(
                    "your current login uses a legacy token that doesn't support vault pairing.\n  \
                     Run `lpm logout` then `lpm login` to upgrade to a session-based login."
                        .into(),
                ))
            } else {
                Err(login_required(error))
            }
        }
        Err(other) => Err(other),
    }
}

fn sync_error(error: lpm_vault::sync::SyncError) -> LpmError {
    if error.is_unauthorized() {
        login_required(LpmError::AuthRequired)
    } else {
        LpmError::Script(error.to_string())
    }
}

pub(crate) async fn execute_sync_with_bearer<T, F, Fut>(
    client: &RegistryClient,
    requirement: AuthRequirement,
    operation: F,
) -> Result<T, LpmError>
where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<T, lpm_vault::sync::SyncError>>,
{
    let session = client
        .session()
        .ok_or_else(|| login_required(LpmError::AuthRequired))?;
    let registry_url = client.base_url().to_owned();
    let bearer = resolve_required_bearer(client, requirement).await?;

    match operation(registry_url.clone(), bearer).await {
        Err(error) if error.is_unauthorized() => {
            let can_refresh = session
                .current_source()?
                .is_some_and(|source| source.refresh_policy() == RefreshPolicy::IfRefreshable);
            if !can_refresh {
                return Err(sync_error(error));
            }

            session.refresh_now().await.map_err(login_required)?;
            let bearer = resolve_required_bearer(client, requirement).await?;
            operation(registry_url, bearer).await.map_err(sync_error)
        }
        result => result.map_err(sync_error),
    }
}

pub(crate) async fn execute_lpm_with_bearer<T, F, Fut>(
    client: &RegistryClient,
    requirement: AuthRequirement,
    operation: F,
) -> Result<T, LpmError>
where
    F: Fn(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<T, LpmError>>,
{
    let session = client
        .session()
        .ok_or_else(|| login_required(LpmError::AuthRequired))?;
    let registry_url = client.base_url().to_owned();
    let bearer = resolve_required_bearer(client, requirement).await?;

    match operation(registry_url.clone(), bearer).await {
        Err(error @ LpmError::AuthRequired) => {
            let can_refresh = session
                .current_source()?
                .is_some_and(|source| source.refresh_policy() == RefreshPolicy::IfRefreshable);
            if !can_refresh {
                return Err(login_required(error));
            }

            session.refresh_now().await.map_err(login_required)?;
            let bearer = resolve_required_bearer(client, requirement).await?;
            operation(registry_url, bearer)
                .await
                .map_err(login_required)
        }
        result => result.map_err(login_required),
    }
}
