//! Earlier LPM releases stored credentials through keyring 3. These tests use
//! the real platform store to check that this crate reads, replaces and
//! deletes the items keyring 3 wrote, and that keyring 3 reads the items this
//! crate writes. CI runs them on Linux, macOS and Windows.

use std::time::{SystemTime, UNIX_EPOCH};

const USER: &str = "compatibility";

/// A service name no real credential uses, whose items are deleted when the
/// test ends however it ends.
struct TestService(String);

impl TestService {
    fn new(case: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(format!(
            "lpm-keyring-test-{case}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn keyring3(&self) -> keyring3::Entry {
        keyring3::Entry::new(&self.0, USER).unwrap()
    }

    fn lpm(&self) -> lpm_keyring::Entry {
        lpm_keyring::entry(&self.0, USER).unwrap()
    }
}

impl Drop for TestService {
    fn drop(&mut self) {
        let _ = self.keyring3().delete_credential();
        let _ = self.lpm().delete_credential();
    }
}

#[test]
#[ignore = "uses the real credential store; CI runs it on each platform"]
fn an_item_keyring_3_wrote_is_read_replaced_and_deleted() {
    let service = TestService::new("written-by-keyring-3");
    service
        .keyring3()
        .set_password("written by keyring 3")
        .unwrap();

    assert_eq!(
        service.lpm().get_password().unwrap(),
        "written by keyring 3"
    );

    service.lpm().set_password("replaced").unwrap();
    assert_eq!(service.keyring3().get_password().unwrap(), "replaced");

    service.lpm().delete_credential().unwrap();
    assert!(matches!(
        service.keyring3().get_password(),
        Err(keyring3::Error::NoEntry)
    ));
}

#[test]
#[ignore = "uses the real credential store; CI runs it on each platform"]
fn keyring_3_reads_and_deletes_an_item_this_crate_wrote() {
    let service = TestService::new("written-by-lpm-keyring");
    service
        .lpm()
        .set_password("written by lpm-keyring")
        .unwrap();

    assert_eq!(
        service.keyring3().get_password().unwrap(),
        "written by lpm-keyring"
    );

    service.keyring3().delete_credential().unwrap();
    assert!(matches!(
        service.lpm().get_password(),
        Err(lpm_keyring::Error::NoEntry)
    ));
}

#[test]
#[ignore = "uses the real credential store; CI runs it on each platform"]
fn a_missing_item_is_no_entry() {
    let service = TestService::new("missing");

    assert!(matches!(
        service.lpm().get_password(),
        Err(lpm_keyring::Error::NoEntry)
    ));
    assert!(matches!(
        service.lpm().delete_credential(),
        Err(lpm_keyring::Error::NoEntry)
    ));
}
