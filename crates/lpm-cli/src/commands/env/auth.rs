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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn wrong_step_up_credential_is_not_retried_as_a_stale_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "rotated-access",
                "refreshToken": "rotated-refresh",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid credentials",
                "code": "wrong_credential",
            })))
            .mount(&server)
            .await;

        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
            ("LPM_TOKEN", None),
        ]);
        lpm_auth::store_refresh_backed_session(
            &server.uri(),
            "valid-access",
            "valid-refresh",
            "2099-01-01T00:00:00Z",
        )
        .await
        .expect("store refresh-backed session");
        let session = Arc::new(lpm_auth::SessionManager::new(server.uri(), None));
        let client = RegistryClient::new()
            .with_base_url(server.uri())
            .with_session(session);
        let calls = Arc::new(AtomicUsize::new(0));

        let result = execute_sync_with_bearer(&client, AuthRequirement::TokenRequired, {
            let calls = Arc::clone(&calls);
            move |registry_url, auth_token| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    lpm_vault::sync::mint_cli_step_up_proof(
                        &registry_url,
                        &auth_token,
                        "vault:public-key:set",
                        &lpm_vault::sync::CliStepUpCredential::Password {
                            password: "wrong-password",
                        },
                    )
                    .await
                }
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            result
                .expect_err("wrong credential must remain an error")
                .to_string()
                .contains("wrong_credential")
        );
    }
}
