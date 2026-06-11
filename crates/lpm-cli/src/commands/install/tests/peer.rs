use super::*;

#[test]
fn v2_linking_can_prepare_before_fetch_allows_current_lockfile_peer_context() {
    assert!(v2_linking_can_prepare_before_fetch(
        true, false, true, true, true
    ));
}

#[test]
fn v2_linking_can_prepare_before_fetch_rejects_legacy_lockfile_peer_context() {
    assert!(!v2_linking_can_prepare_before_fetch(
        true, false, true, true, false
    ));
}
