use super::types::{LpmPublicationStatus, PublicationSnapshot, PublicationWaitResult};
use crate::oidc::OidcToken;
use lpm_common::LpmError;
use lpm_registry::{PublicationHold, RegistryClient};
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

pub(super) const DEFAULT_PUBLICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(1_200);
const PUBLICATION_POLL_INTERVAL: Duration = Duration::from_secs(3);

pub(super) async fn wait_for_lpm_publication(
    client: &RegistryClient,
    name: &str,
    version: &str,
    timeout: Duration,
    on_hold: impl FnMut(&PublicationHold),
) -> PublicationWaitResult {
    poll_publication_snapshots(
        || async {
            client
                .get_publication_status(name, version)
                .await
                .map(PublicationSnapshot::from)
        },
        Instant::now() + timeout,
        PUBLICATION_POLL_INTERVAL,
        on_hold,
    )
    .await
}

pub(super) async fn wait_for_lpm_publication_with_oidc(
    client: &RegistryClient,
    name: &str,
    version: &str,
    timeout: Duration,
    oidc_token: Option<&OidcToken>,
    on_hold: impl FnMut(&PublicationHold),
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

    wait_for_lpm_publication(wait_client, name, version, timeout, on_hold).await
}

/// Polls until the version is active, reaches a state further polls can't
/// change, or `deadline` passes, a poll in flight included. Each hold is
/// reported once as it appears or changes; one only a new version gets past
/// ends the wait. A wait that runs out reports what the last poll saw.
pub(super) async fn poll_publication_snapshots<F, Fut>(
    mut fetch_snapshot: F,
    deadline: Instant,
    poll_interval: Duration,
    mut on_hold: impl FnMut(&PublicationHold),
) -> PublicationWaitResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<PublicationSnapshot, LpmError>>,
{
    let mut last: Option<PublicationSnapshot> = None;
    loop {
        let snapshot = match tokio::time::timeout_at(deadline, fetch_snapshot()).await {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(error)) => {
                return PublicationWaitResult::request_failed(&error).with_current_latest_version(
                    last.and_then(|last| last.current_latest_version),
                );
            }
            Err(_) => break,
        };
        if snapshot.status == LpmPublicationStatus::Active {
            return PublicationWaitResult::active()
                .with_current_latest_version(snapshot.current_latest_version);
        }
        if !matches!(
            snapshot.status,
            LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing
        ) {
            return PublicationWaitResult::terminal(snapshot.status)
                .with_current_latest_version(snapshot.current_latest_version);
        }
        if let Some(hold) = &snapshot.hold {
            if hold.is_final {
                return PublicationWaitResult::held(snapshot.status, hold.clone())
                    .with_current_latest_version(snapshot.current_latest_version);
            }
            if last.as_ref().and_then(|last| last.hold.as_ref()) != Some(hold) {
                on_hold(hold);
            }
        }
        last = Some(snapshot);

        let next_poll = Instant::now() + poll_interval;
        if next_poll >= deadline {
            break;
        }
        tokio::time::sleep_until(next_poll).await;
    }

    match last {
        Some(last) => PublicationWaitResult::timed_out(Some(last.status), last.hold)
            .with_current_latest_version(last.current_latest_version),
        None => PublicationWaitResult::timed_out(None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::OidcPublicationStatusToken;

    use lpm_registry::PublicationHold;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const POLL: Duration = Duration::from_secs(3);

    fn snapshot(
        status: LpmPublicationStatus,
        hold: Option<PublicationHold>,
    ) -> PublicationSnapshot {
        PublicationSnapshot {
            status,
            current_latest_version: Some("1.1.0".into()),
            hold,
        }
    }

    fn hold(reason: &str, message: &str, is_final: bool) -> PublicationHold {
        PublicationHold {
            reason: Some(reason.into()),
            message: Some(message.into()),
            is_final,
        }
    }

    /// Answers each poll from `snapshots` in order, then the last one again,
    /// counting the polls.
    fn scripted(
        snapshots: Vec<PublicationSnapshot>,
    ) -> (
        impl FnMut() -> std::future::Ready<Result<PublicationSnapshot, LpmError>>,
        Arc<Mutex<usize>>,
    ) {
        let polls = Arc::new(Mutex::new(0));
        let queue = Arc::new(Mutex::new(VecDeque::from(snapshots)));
        let counter = Arc::clone(&polls);
        let fetch = move || {
            *counter.lock().unwrap() += 1;
            let mut queue = queue.lock().unwrap();
            let next = if queue.len() > 1 {
                queue.pop_front().unwrap()
            } else {
                queue.front().cloned().expect("a scripted snapshot")
            };
            std::future::ready(Ok(next))
        };
        (fetch, polls)
    }

    async fn wait_for(
        fetch: impl FnMut() -> std::future::Ready<Result<PublicationSnapshot, LpmError>>,
        timeout: Duration,
        reported: &mut Vec<PublicationHold>,
    ) -> PublicationWaitResult {
        poll_publication_snapshots(fetch, Instant::now() + timeout, POLL, |hold| {
            reported.push(hold.clone());
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn completes_after_pending_and_processing_states() {
        let (fetch, polls) = scripted(vec![
            snapshot(LpmPublicationStatus::PendingReview, None),
            snapshot(LpmPublicationStatus::Processing, None),
            snapshot(LpmPublicationStatus::Active, None),
        ]);

        let result = wait_for(fetch, Duration::from_secs(60), &mut Vec::new()).await;

        assert_eq!(
            result,
            PublicationWaitResult::active().with_current_latest_version(Some("1.1.0".into()))
        );
        assert_eq!(*polls.lock().unwrap(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_once_for_states_further_polls_cant_change() {
        for status in [
            LpmPublicationStatus::ManualReview,
            LpmPublicationStatus::Rejected,
            LpmPublicationStatus::Quarantined,
            LpmPublicationStatus::Other("future".into()),
        ] {
            let (fetch, polls) = scripted(vec![snapshot(status.clone(), None)]);

            let result = wait_for(fetch, Duration::from_secs(60), &mut Vec::new()).await;

            assert!(!result.success, "{status:?} must end the wait");
            assert_eq!(result.status, Some(status));
            assert_eq!(*polls.lock().unwrap(), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn polls_until_the_deadline_and_reports_the_last_state() {
        let started = Instant::now();
        let (fetch, polls) = scripted(vec![snapshot(LpmPublicationStatus::PendingReview, None)]);

        let result = wait_for(fetch, Duration::from_secs(10), &mut Vec::new()).await;

        assert_eq!(*polls.lock().unwrap(), 4, "polls at 0, 3, 6 and 9 seconds");
        assert!(started.elapsed() <= Duration::from_secs(10));
        assert_eq!(result.status, Some(LpmPublicationStatus::PendingReview));
        assert_eq!(result.current_latest_version.as_deref(), Some("1.1.0"));
        assert_eq!(
            result.error.as_deref(),
            Some(
                "Upload succeeded, but waiting for LPM.dev Registry publication timed out. Do not publish this version again."
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_a_hold_only_a_new_version_gets_past() {
        let final_hold = hold(
            "publication_intent_changed",
            "It was published for a distribution this package doesn't have. Publish a new version.",
            true,
        );
        let (fetch, polls) = scripted(vec![snapshot(
            LpmPublicationStatus::Processing,
            Some(final_hold.clone()),
        )]);
        let mut reported = Vec::new();

        let result = wait_for(fetch, Duration::from_secs(60), &mut reported).await;

        assert_eq!(*polls.lock().unwrap(), 1);
        assert!(!result.success);
        assert_eq!(result.status, Some(LpmPublicationStatus::Processing));
        assert_eq!(result.hold, Some(final_hold));
        assert_eq!(
            result.error.as_deref(),
            Some(
                "Upload succeeded, but this version won't become available. It was published for a distribution this package doesn't have. Publish a new version. Do not publish this version again."
            )
        );
        assert!(reported.is_empty(), "the result reports a final hold");
    }

    #[tokio::test(start_paused = true)]
    async fn reports_each_hold_once_as_it_changes_and_times_out_with_the_last() {
        let archived = hold("package_archived", "The package is archived.", false);
        let cooldown = hold(
            "release_cooldown",
            "It becomes available when its release cooldown ends.",
            false,
        );
        let (fetch, _) = scripted(vec![
            snapshot(LpmPublicationStatus::Processing, Some(archived.clone())),
            snapshot(LpmPublicationStatus::Processing, Some(archived.clone())),
            snapshot(LpmPublicationStatus::Processing, Some(cooldown.clone())),
        ]);
        let mut reported = Vec::new();

        let result = wait_for(fetch, Duration::from_secs(30), &mut reported).await;

        assert_eq!(reported, vec![archived, cooldown.clone()]);
        assert_eq!(result.hold, Some(cooldown));
        assert_eq!(
            result.error.as_deref(),
            Some(
                "Upload succeeded, but waiting for LPM.dev Registry publication timed out. The version isn't available yet. It becomes available when its release cooldown ends. Do not publish this version again."
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_poll_still_in_flight_at_the_deadline_keeps_what_the_last_one_saw() {
        let archived = hold("package_archived", "The package is archived.", false);
        let mut answered = false;
        let fetch = || {
            let first = !std::mem::replace(&mut answered, true);
            let archived = archived.clone();
            async move {
                if first {
                    Ok(snapshot(LpmPublicationStatus::Processing, Some(archived)))
                } else {
                    std::future::pending().await
                }
            }
        };

        let result = poll_publication_snapshots(
            fetch,
            Instant::now() + Duration::from_secs(10),
            POLL,
            |_| {},
        )
        .await;

        assert_eq!(result.status, Some(LpmPublicationStatus::Processing));
        assert_eq!(result.hold, Some(archived));
        assert_eq!(result.current_latest_version.as_deref(), Some("1.1.0"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_less_hold_still_explains_itself() {
        let (fetch, _) = scripted(vec![snapshot(
            LpmPublicationStatus::Processing,
            Some(PublicationHold {
                reason: None,
                message: Some("  ".into()),
                is_final: true,
            }),
        )]);

        let result = wait_for(fetch, Duration::from_secs(60), &mut Vec::new()).await;

        assert!(result.error.as_deref().is_some_and(|error| {
            error.contains("won't become available. LPM.dev Registry is holding it.")
        }));
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
            |_| {},
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
