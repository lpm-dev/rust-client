use std::sync::Arc;

use lpm_auth::{AuthRequirement, RefreshPolicy};
use lpm_registry::RegistryClient;
use lpm_tunnel::client::{TunnelTokenFuture, TunnelTokenProvider};

pub(crate) fn refresh_backed_provider(
    client: &RegistryClient,
    relay_url: &str,
) -> Result<Option<TunnelTokenProvider>, lpm_common::LpmError> {
    let Some(session) = client.session().map(Arc::clone) else {
        return Ok(None);
    };
    if session
        .current_source()?
        .is_none_or(|source| source.refresh_policy() != RefreshPolicy::IfRefreshable)
    {
        return Ok(None);
    }
    let requirement = if lpm_tunnel::client::relay_url_is_loopback(relay_url) {
        AuthRequirement::TokenRequired
    } else {
        AuthRequirement::SessionRequired
    };
    let current_session = Arc::clone(&session);

    Ok(Some(TunnelTokenProvider::new(
        move || {
            let session = Arc::clone(&current_session);
            Box::pin(async move { session.bearer_string_for(requirement).await })
                as TunnelTokenFuture
        },
        move || {
            let session = Arc::clone(&session);
            Box::pin(async move {
                session.refresh_now().await?;
                session.bearer_string_for(requirement).await
            }) as TunnelTokenFuture
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_token_does_not_create_a_refresh_provider() {
        let home = tempfile::tempdir().unwrap();
        let _environment = crate::test_env::ScopedEnv::set([
            ("HOME", home.path().as_os_str().to_owned()),
            ("LPM_TOKEN", "explicit-token".into()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
        ]);
        let session = Arc::new(lpm_auth::SessionManager::new("http://127.0.0.1:4873", None));
        let client = RegistryClient::new().with_session(session);

        assert!(
            refresh_backed_provider(&client, "ws://127.0.0.1:8787/connect")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn stored_refresh_session_creates_a_dynamic_provider() {
        let home = tempfile::tempdir().unwrap();
        let _environment = crate::test_env::ScopedEnv::set([
            ("HOME", home.path().as_os_str().to_owned()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
            ("LPM_TEST_FAST_SCRYPT", "1".into()),
        ]);
        let registry = "http://127.0.0.1:4873";
        lpm_auth::store_refresh_backed_session(
            registry,
            "stored-access-token",
            "stored-refresh-token",
            "2099-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let session = Arc::new(lpm_auth::SessionManager::new(registry, None));
        let client = RegistryClient::new().with_session(session);

        assert!(
            refresh_backed_provider(&client, "ws://127.0.0.1:8787/connect")
                .unwrap()
                .is_some()
        );
    }
}
