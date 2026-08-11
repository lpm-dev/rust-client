use super::types::{LpmPublicationStatus, PublicationWaitResult};
use crate::oidc::OidcToken;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::future::Future;
use std::time::Duration;

pub(super) const DEFAULT_PUBLICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(1_200);
const PUBLICATION_POLL_INTERVAL: Duration = Duration::from_secs(3);

fn publication_poll_limit(timeout: Duration) -> usize {
    timeout
        .as_secs()
        .div_ceil(PUBLICATION_POLL_INTERVAL.as_secs())
        .saturating_add(1)
        .max(1) as usize
}

pub(super) async fn wait_for_lpm_publication(
    client: &RegistryClient,
    name: &str,
    version: &str,
    timeout: Duration,
) -> PublicationWaitResult {
    let max_polls = publication_poll_limit(timeout);
    let polling = poll_publication_snapshots(
        || async {
            client
                .get_publication_status(name, version)
                .await
                .map(|response| {
                    (
                        LpmPublicationStatus::from_registry_value(&response.status),
                        response.current_latest_version,
                    )
                })
        },
        max_polls,
        PUBLICATION_POLL_INTERVAL,
    );

    match tokio::time::timeout(timeout, polling).await {
        Ok(result) => result,
        Err(_) => PublicationWaitResult::timed_out(None),
    }
}

pub(super) async fn wait_for_lpm_publication_with_oidc(
    client: &RegistryClient,
    name: &str,
    version: &str,
    timeout: Duration,
    oidc_token: Option<&OidcToken>,
) -> PublicationWaitResult {
    let status_token = match oidc_token
        .map(|token| token.publication_status_token_for_wait(timeout))
        .transpose()
    {
        Ok(token) => token.flatten(),
        Err(error) => return PublicationWaitResult::request_failed(&error),
    };
    let status_client;
    let wait_client = if let Some(token) = status_token {
        status_client = client
            .clone_with_config()
            .with_token_override(token.to_string());
        &status_client
    } else {
        client
    };

    wait_for_lpm_publication(wait_client, name, version, timeout).await
}

#[cfg(test)]
pub(super) async fn poll_publication_status<F, Fut>(
    mut fetch_status: F,
    max_polls: usize,
    poll_interval: Duration,
) -> PublicationWaitResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<LpmPublicationStatus, LpmError>>,
{
    poll_publication_snapshots(
        || {
            let status = fetch_status();
            async move { status.await.map(|status| (status, None)) }
        },
        max_polls,
        poll_interval,
    )
    .await
}

async fn poll_publication_snapshots<F, Fut>(
    mut fetch_status: F,
    max_polls: usize,
    poll_interval: Duration,
) -> PublicationWaitResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(LpmPublicationStatus, Option<String>), LpmError>>,
{
    let mut last_status = None;
    let mut current_latest_version = None;
    for poll_index in 0..max_polls {
        let (status, latest_version) = match fetch_status().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return PublicationWaitResult::request_failed(&error)
                    .with_current_latest_version(current_latest_version);
            }
        };
        last_status = Some(status.clone());
        current_latest_version = latest_version;
        match status {
            LpmPublicationStatus::Active => {
                return PublicationWaitResult::active()
                    .with_current_latest_version(current_latest_version);
            }
            LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing => {}
            terminal => {
                return PublicationWaitResult::terminal(terminal)
                    .with_current_latest_version(current_latest_version);
            }
        }

        if poll_index + 1 < max_polls && !poll_interval.is_zero() {
            tokio::time::sleep(poll_interval).await;
        }
    }

    PublicationWaitResult::timed_out(last_status)
        .with_current_latest_version(current_latest_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::OidcPublicationStatusToken;

    #[test]
    fn poll_limit_leaves_the_outer_timeout_in_control() {
        assert_eq!(publication_poll_limit(Duration::from_secs(10)), 5);
        assert_eq!(publication_poll_limit(Duration::from_secs(600)), 201);
    }

    #[test]
    fn default_wait_exceeds_the_registry_source_change_cooldown() {
        assert!(DEFAULT_PUBLICATION_WAIT_TIMEOUT > Duration::from_secs(15 * 60));
    }

    #[tokio::test]
    async fn expired_oidc_wait_credential_preserves_successful_upload_state() {
        let oidc_token = OidcToken {
            token: "publish-token".into(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
            publication_status: Some(OidcPublicationStatusToken {
                token: "status-token".into(),
                expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
            }),
        };
        let client = RegistryClient::new().with_base_url("http://127.0.0.1:1");

        let result = wait_for_lpm_publication_with_oidc(
            &client,
            "@lpm.dev/owner.package",
            "1.0.0",
            Duration::from_secs(60),
            Some(&oidc_token),
        )
        .await;

        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("Do not publish this version again"))
        );
    }
}
