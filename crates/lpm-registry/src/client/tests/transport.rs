use super::*;

#[test]
fn backoff_delay_exponential() {
    assert_eq!(backoff_delay(0), Duration::from_secs(1));
    assert_eq!(backoff_delay(1), Duration::from_secs(2));
    assert_eq!(backoff_delay(2), Duration::from_secs(4));
}

#[test]
fn backoff_delay_capped() {
    assert_eq!(backoff_delay(5), RETRY_MAX_DELAY);
    assert_eq!(backoff_delay(10), RETRY_MAX_DELAY);
}

#[test]
fn auth_posture_attaches_bearer_only_for_auth_or_session() {
    assert!(!AuthPosture::AnonymousOnly.attaches_bearer());
    assert!(!AuthPosture::AnonymousPreferred.attaches_bearer());
    assert!(AuthPosture::AuthRequired.attaches_bearer());
    assert!(AuthPosture::SessionRequired.attaches_bearer());
}

#[test]
fn auth_posture_allows_recovery_only_for_auth_or_session() {
    assert!(!AuthPosture::AnonymousOnly.allows_recovery());
    assert!(!AuthPosture::AnonymousPreferred.allows_recovery());
    assert!(AuthPosture::AuthRequired.allows_recovery());
    assert!(AuthPosture::SessionRequired.allows_recovery());
}

#[test]
fn current_bearer_returns_none_for_anonymous_postures_even_with_token() {
    let client = RegistryClient::new().with_token("real-token");
    assert!(
        client.current_bearer(AuthPosture::AnonymousOnly).is_none(),
        "AnonymousOnly must never attach a bearer"
    );
    assert!(
        client
            .current_bearer(AuthPosture::AnonymousPreferred)
            .is_none(),
        "AnonymousPreferred must never attach a bearer"
    );
}

#[test]
fn current_bearer_returns_token_for_auth_required_when_set() {
    let client = RegistryClient::new().with_token("real-token");
    assert_eq!(
        client.current_bearer(AuthPosture::AuthRequired),
        Some("real-token".to_string())
    );
    assert_eq!(
        client.current_bearer(AuthPosture::SessionRequired),
        Some("real-token".to_string())
    );
}

#[test]
fn current_bearer_filters_empty_token() {
    // Empty bearer must never be sent — `current_bearer` returns
    // None even if `with_token("")` was called.
    let client = RegistryClient::new().with_token("");
    assert!(client.current_bearer(AuthPosture::AuthRequired).is_none());
}

#[test]
fn has_bearer_for_posture_honors_auth_posture_and_direct_token() {
    let client = RegistryClient::new().with_token("real-token");

    assert!(!client.has_bearer_for_posture(AuthPosture::AnonymousOnly));
    assert!(!client.has_bearer_for_posture(AuthPosture::AnonymousPreferred));
    assert!(client.has_bearer_for_posture(AuthPosture::AuthRequired));
    assert!(client.has_bearer_for_posture(AuthPosture::SessionRequired));
}

#[test]
fn has_bearer_for_posture_filters_empty_direct_token() {
    let client = RegistryClient::new().with_token("");

    assert!(!client.has_bearer_for_posture(AuthPosture::AuthRequired));
}

#[test]
fn has_bearer_for_posture_detects_attached_session_token() {
    let session = std::sync::Arc::new(lpm_auth::SessionManager::new(
        "https://example.invalid",
        Some("session-token".to_string()),
    ));
    let client = RegistryClient::new().with_session(session);

    assert!(client.has_bearer_for_posture(AuthPosture::AuthRequired));
}

#[tokio::test]
async fn execute_with_recovery_propagates_success_unchanged() {
    let client = RegistryClient::new();
    let count = std::sync::atomic::AtomicU32::new(0);
    let result = client
        .execute_with_recovery(AuthPosture::AuthRequired, || async {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, LpmError>(42u32)
        })
        .await;
    assert_eq!(result.unwrap(), 42);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn execute_with_recovery_does_not_retry_anonymous_postures() {
    let client = RegistryClient::new();
    let count = std::sync::atomic::AtomicU32::new(0);
    let result = client
        .execute_with_recovery(AuthPosture::AnonymousPreferred, || async {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err::<u32, _>(LpmError::AuthRequired)
        })
        .await;
    assert!(matches!(result, Err(LpmError::AuthRequired)));
    // Anonymous postures never retry — exactly one attempt.
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn execute_with_recovery_does_not_retry_when_no_session() {
    let client = RegistryClient::new().with_token("static-token");
    let count = std::sync::atomic::AtomicU32::new(0);
    let result = client
        .execute_with_recovery(AuthPosture::AuthRequired, || async {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err::<u32, _>(LpmError::AuthRequired)
        })
        .await;
    assert!(matches!(result, Err(LpmError::AuthRequired)));
    // No session attached → no refresh is even attempted.
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_bearer_never_appears_on_the_wire() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "u_test",
            "username": "test",
            "scope": "user",
            "scopes": ["registry:read"],
        })))
        .mount(&server)
        .await;

    // The pathological case: a caller threaded `unwrap_or_default()`
    // on a missing token and seeded the client with `""`.
    // `current_bearer` must filter this so `bearer_auth("")` is
    // never called.
    let client = RegistryClient::new()
        .with_base_url(server.uri())
        .with_token("");

    let _ = client.whoami().await; // outcome not the point — header is

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "exactly one request expected");
    let auth_header = received[0].headers.get("authorization");
    assert!(
        auth_header.is_none(),
        "with_token(\"\") must NOT produce an Authorization header on the wire — \
             pre-fix, this site sent literal `Authorization: Bearer ` (empty value), \
             which the server logs as a malformed-auth attempt. Got: {auth_header:?}"
    );
}
