use super::test_support::{RoleSet, TestKey, repository_files, repository_files_listing, resigned};
use super::*;
use lpm_common::Timestamp as Time;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;

const REAL_ROOT_13: &[u8] = include_bytes!("../../../tests/fixtures/sigstore_tuf/13.root.json");
const REAL_ROOT_14: &[u8] = include_bytes!("../../../tests/fixtures/sigstore_tuf/14.root.json");
const REAL_ROOT_15: &[u8] = include_bytes!("../../../tests/fixtures/sigstore_tuf/15.root.json");
const REAL_ROOT_16: &[u8] = include_bytes!("../../../tests/fixtures/sigstore_tuf/16.root.json");
const REAL_TIMESTAMP: &[u8] = include_bytes!("../../../tests/fixtures/sigstore_tuf/timestamp.json");
const REAL_SNAPSHOT_166: &[u8] =
    include_bytes!("../../../tests/fixtures/sigstore_tuf/166.snapshot.json");
const REAL_TARGETS_14: &[u8] =
    include_bytes!("../../../tests/fixtures/sigstore_tuf/14.targets.json");
const EMBEDDED_TUF_ROOT: &[u8] = include_bytes!("../../../assets/sigstore_tuf_root.json");
const EMBEDDED_TRUSTED_ROOT: &[u8] = include_bytes!("../../../assets/sigstore_trusted_root.json");

fn at(text: &str) -> SystemTime {
    Time::parse_rfc3339(text).unwrap().into()
}

/// A time at which the real timestamp fixture, valid for a week, is current.
fn while_real_metadata_is_current() -> SystemTime {
    at("2026-11-26T00:00:00Z")
}

/// An in-memory repository that records which paths were requested.
#[derive(Default)]
struct Repository {
    files: BTreeMap<String, Vec<u8>>,
    requested: Mutex<Vec<String>>,
}

impl Repository {
    fn with(mut self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.to_string(), bytes.into());
        self
    }

    fn requested(&self) -> Vec<String> {
        self.requested.lock().unwrap().clone()
    }
}

impl Fetcher for Repository {
    async fn fetch(&self, path: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
        self.requested.lock().unwrap().push(path.to_string());
        match self.files.get(path) {
            Some(bytes) if bytes.len() as u64 > max_bytes => {
                Err(format!("{path} is over {max_bytes} bytes"))
            }
            Some(bytes) => Ok(Some(bytes.clone())),
            None => Ok(None),
        }
    }
}

fn trusted_root_path(bytes: &[u8]) -> String {
    format!(
        "targets/{}.trusted_root.json",
        hex::encode(Sha256::digest(bytes))
    )
}

/// Sigstore's real repository as it stood when the fixtures were captured,
/// seen by a client whose newest root is version 13.
fn real_repository() -> Repository {
    Repository::default()
        .with("14.root.json", REAL_ROOT_14)
        .with("15.root.json", REAL_ROOT_15)
        .with("16.root.json", REAL_ROOT_16)
        .with("timestamp.json", REAL_TIMESTAMP)
        .with("166.snapshot.json", REAL_SNAPSHOT_166)
        .with("14.targets.json", REAL_TARGETS_14)
        .with(
            &trusted_root_path(EMBEDDED_TRUSTED_ROOT),
            EMBEDDED_TRUSTED_ROOT,
        )
}

fn refreshed(
    embedded_root: &[u8],
    stored: Option<&TrustedMetadata>,
    repository: &Repository,
    now: SystemTime,
) -> Result<TrustedMetadata, TufError> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(refresh(embedded_root, stored, repository, now))
}

#[test]
fn real_sigstore_metadata_refreshes_through_three_root_rotations() {
    let repository = real_repository();

    let metadata = refreshed(
        REAL_ROOT_13,
        None,
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap();

    assert_eq!(metadata.roots.len(), 3);
    assert_eq!(metadata.trusted_root.as_bytes(), EMBEDDED_TRUSTED_ROOT);
    assert_eq!(
        repository.requested(),
        [
            "14.root.json",
            "15.root.json",
            "16.root.json",
            "17.root.json",
            "timestamp.json",
            "166.snapshot.json",
            "14.targets.json",
            &trusted_root_path(EMBEDDED_TRUSTED_ROOT),
        ]
    );
    let verified = metadata.verified_trusted_root(REAL_ROOT_13).unwrap();
    assert_eq!(verified.bytes, EMBEDDED_TRUSTED_ROOT);
    assert_eq!(verified.targets_version, 14);
}

#[test]
fn the_embedded_tuf_root_signs_the_embedded_trust_root() {
    assert_eq!(EMBEDDED_TUF_ROOT, REAL_ROOT_16);
    let stored = TrustedMetadata {
        roots: Vec::new(),
        timestamp: String::from_utf8(REAL_TIMESTAMP.to_vec()).unwrap(),
        snapshot: String::from_utf8(REAL_SNAPSHOT_166.to_vec()).unwrap(),
        targets: String::from_utf8(REAL_TARGETS_14.to_vec()).unwrap(),
        trusted_root: String::from_utf8(EMBEDDED_TRUSTED_ROOT.to_vec()).unwrap(),
    };

    let verified = stored.verified_trusted_root(EMBEDDED_TUF_ROOT).unwrap();

    assert_eq!(verified.bytes, EMBEDDED_TRUSTED_ROOT);
    assert_eq!(
        verified.targets_version,
        crate::sigstore_verify::trust_store::EMBEDDED_TRUSTED_ROOT_TARGETS_VERSION
    );
}

#[test]
fn stored_roots_are_not_fetched_again() {
    let repository = real_repository();
    let first = refreshed(
        REAL_ROOT_13,
        None,
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap();
    let repository = real_repository();

    let second = refreshed(
        REAL_ROOT_13,
        Some(&first),
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap();

    assert_eq!(second, first);
    assert_eq!(repository.requested()[0], "17.root.json");
}

#[test]
fn a_root_its_predecessor_did_not_sign_is_refused() {
    let mut tampered: Value = serde_json::from_slice(REAL_ROOT_15).unwrap();
    tampered["signed"]["expires"] = json!("2099-01-01T00:00:00Z");
    let repository = real_repository().with("15.root.json", serde_json::to_vec(&tampered).unwrap());

    let error = refreshed(
        REAL_ROOT_13,
        None,
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap_err();

    assert!(
        matches!(
            error,
            TufError::Threshold {
                role: "root",
                valid: 0,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_root_served_under_the_next_version_must_carry_that_version() {
    let repository = real_repository().with("17.root.json", REAL_ROOT_16);

    let error = refreshed(
        REAL_ROOT_13,
        None,
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap_err();

    assert_eq!(
        error,
        TufError::Version {
            role: "root",
            expected: 17,
            actual: 16
        }
    );
}

#[test]
fn expired_timestamp_metadata_is_refused() {
    let error = refreshed(
        REAL_ROOT_13,
        None,
        &real_repository(),
        at("2026-12-03T00:00:00Z"),
    )
    .unwrap_err();

    assert!(
        matches!(
            error,
            TufError::Expired {
                role: "timestamp",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn an_expired_final_root_is_refused_even_when_everything_else_verifies() {
    let error = refreshed(
        REAL_ROOT_13,
        None,
        &real_repository(),
        at("2027-05-01T00:00:00Z"),
    )
    .unwrap_err();

    assert!(
        matches!(error, TufError::Expired { role: "root", .. }),
        "{error}"
    );
}

#[test]
fn a_trust_root_that_differs_from_the_signed_hash_is_refused() {
    let mut altered = EMBEDDED_TRUSTED_ROOT.to_vec();
    let last = altered.len() - 2;
    altered[last] = b' ';
    let repository = real_repository().with(&trusted_root_path(EMBEDDED_TRUSTED_ROOT), altered);

    let error = refreshed(
        REAL_ROOT_13,
        None,
        &repository,
        while_real_metadata_is_current(),
    )
    .unwrap_err();

    assert!(
        matches!(&error, TufError::Mismatch { name, .. } if name == TRUSTED_ROOT_TARGET),
        "{error}"
    );
}

#[test]
fn stored_metadata_with_an_altered_trust_root_does_not_verify() {
    let mut stored = refreshed(
        REAL_ROOT_13,
        None,
        &real_repository(),
        while_real_metadata_is_current(),
    )
    .unwrap();
    stored.trusted_root = stored
        .trusted_root
        .replace("https://rekor.sigstore.dev", "https://rekor.example.com");

    let error = stored.verified_trusted_root(REAL_ROOT_13).unwrap_err();

    assert!(matches!(error, TufError::Mismatch { .. }), "{error}");
}

// ── Synthetic repositories ─────────────────────────────────────

const SYNTHETIC_TRUSTED_ROOT: &[u8] = br#"{"mediaType":"synthetic"}"#;

fn synthetic_repository(
    roles: &RoleSet,
    timestamp_version: u64,
    snapshot_version: u64,
    targets_version: u64,
) -> Repository {
    Repository {
        files: repository_files(
            roles,
            timestamp_version,
            snapshot_version,
            targets_version,
            SYNTHETIC_TRUSTED_ROOT,
        ),
        requested: Mutex::default(),
    }
}

fn now() -> SystemTime {
    at("2030-01-01T00:00:00Z")
}

#[test]
fn a_repository_without_consistent_snapshots_is_read_by_plain_names() {
    let roles = RoleSet {
        consistent_snapshot: false,
        ..RoleSet::new()
    };
    let repository = synthetic_repository(&roles, 1, 1, 1);

    let metadata = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap();

    assert_eq!(metadata.trusted_root.as_bytes(), SYNTHETIC_TRUSTED_ROOT);
    assert!(
        repository
            .requested()
            .contains(&"targets/trusted_root.json".to_string())
    );
}

#[test]
fn ed25519_keys_sign_metadata() {
    let roles = RoleSet {
        root: vec![TestKey::ed25519(9)],
        timestamp: TestKey::ed25519(10),
        snapshot: TestKey::ed25519(11),
        targets: TestKey::ed25519(12),
        ..RoleSet::new()
    };

    let metadata = refreshed(
        &roles.signed_root(1),
        None,
        &synthetic_repository(&roles, 1, 1, 1),
        now(),
    )
    .unwrap();

    assert_eq!(metadata.trusted_root.as_bytes(), SYNTHETIC_TRUSTED_ROOT);
}

#[test]
fn an_older_timestamp_than_the_stored_one_is_refused() {
    let roles = RoleSet::new();
    let embedded = roles.signed_root(1);
    let stored = refreshed(
        &embedded,
        None,
        &synthetic_repository(&roles, 5, 5, 5),
        now(),
    )
    .unwrap();

    let error = refreshed(
        &embedded,
        Some(&stored),
        &synthetic_repository(&roles, 4, 5, 5),
        now(),
    )
    .unwrap_err();

    assert_eq!(
        error,
        TufError::Rollback {
            role: "timestamp",
            trusted: 5,
            offered: 4
        }
    );
}

#[test]
fn an_older_targets_version_than_the_stored_snapshot_records_is_refused() {
    let roles = RoleSet::new();
    let embedded = roles.signed_root(1);
    let stored = refreshed(
        &embedded,
        None,
        &synthetic_repository(&roles, 5, 5, 5),
        now(),
    )
    .unwrap();

    let error = refreshed(
        &embedded,
        Some(&stored),
        &synthetic_repository(&roles, 6, 6, 4),
        now(),
    )
    .unwrap_err();

    assert_eq!(
        error,
        TufError::Rollback {
            role: "targets",
            trusted: 5,
            offered: 4
        }
    );
}

#[test]
fn a_root_that_replaces_the_timestamp_key_lets_its_versions_restart() {
    let roles = RoleSet::new();
    let embedded = roles.signed_root(1);
    let stored = refreshed(
        &embedded,
        None,
        &synthetic_repository(&roles, 5, 5, 5),
        now(),
    )
    .unwrap();
    let rotated = RoleSet {
        timestamp: TestKey::p256(20),
        snapshot: TestKey::p256(21),
        ..roles
    };
    let repository =
        synthetic_repository(&rotated, 1, 1, 6).with("2.root.json", rotated.signed_root(2));

    let metadata = refreshed(&embedded, Some(&stored), &repository, now()).unwrap();

    assert_eq!(metadata.roots.len(), 1);
}

#[test]
fn a_root_rotation_needs_the_previous_root_keys() {
    let roles = RoleSet::new();
    let takeover = RoleSet {
        root: vec![TestKey::p256(30)],
        ..roles.clone()
    };
    let repository =
        synthetic_repository(&roles, 1, 1, 1).with("2.root.json", takeover.signed_root(2));

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 0,
            threshold: 1
        }
    );
}

#[test]
fn a_key_listed_twice_counts_once_toward_the_threshold() {
    let key = TestKey::p256(1);
    let roles = RoleSet {
        root: vec![key.clone(), key.clone()],
        root_threshold: 2,
        ..RoleSet::new()
    };
    let embedded = roles.signed_root(1);
    let next = roles.root(2, &[&key, &key]);
    let repository = synthetic_repository(&roles, 1, 1, 1).with("2.root.json", next);

    let error = refreshed(&embedded, None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 1,
            threshold: 2
        }
    );
}

#[test]
fn targets_signed_by_another_key_are_refused() {
    let roles = RoleSet::new();
    let impostor = RoleSet {
        targets: TestKey::p256(40),
        ..roles.clone()
    };
    let honest = synthetic_repository(&roles, 1, 1, 1);
    let forged = synthetic_repository(&impostor, 1, 1, 1);
    let repository = honest.with("1.targets.json", forged.files["1.targets.json"].clone());

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "targets",
            valid: 0,
            threshold: 1
        }
    );
}

#[test]
fn stored_roots_must_still_chain_from_the_embedded_root() {
    let roles = RoleSet::new();
    let takeover = RoleSet {
        root: vec![TestKey::p256(50)],
        ..roles.clone()
    };
    let stored = TrustedMetadata {
        roots: vec![String::from_utf8(takeover.signed_root(2)).unwrap()],
        ..refreshed(
            &takeover.signed_root(1),
            None,
            &synthetic_repository(&takeover, 1, 1, 1),
            now(),
        )
        .unwrap()
    };

    let error = stored
        .verified_trusted_root(&roles.signed_root(1))
        .unwrap_err();

    assert!(
        matches!(error, TufError::Threshold { role: "root", .. }),
        "{error}"
    );
}

#[test]
fn a_missing_trust_root_target_is_reported() {
    let roles = RoleSet::new();
    let mut repository = synthetic_repository(&roles, 1, 1, 1);
    repository
        .files
        .retain(|path, _| !path.starts_with("targets/"));

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert!(matches!(error, TufError::Missing(_)), "{error}");
}

#[test]
fn one_key_under_two_ids_and_encodings_counts_once_toward_the_threshold() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public = hex::encode(key.verifying_key().as_bytes());
    let root_with = |version: u64| {
        json!({
            "_type": "root",
            "spec_version": "1.0",
            "version": version,
            "expires": "2099-01-01T00:00:00Z",
            "consistent_snapshot": true,
            "keys": {
                "lower": {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": public}},
                "upper": {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": public.to_uppercase()}},
            },
            "roles": {
                "root": {"keyids": ["lower", "upper"], "threshold": 2},
                "timestamp": {"keyids": ["lower"], "threshold": 1},
                "snapshot": {"keyids": ["lower"], "threshold": 1},
                "targets": {"keyids": ["lower"], "threshold": 1},
            },
        })
    };
    let signed_by_both_ids = |signed: Value| {
        use ed25519_dalek::Signer;
        let mut message = Vec::new();
        canonical::encode(&signed, &mut message).unwrap();
        let sig = hex::encode(key.sign(&message).to_bytes());
        serde_json::to_vec(&json!({
            "signed": signed,
            "signatures": [{"keyid": "lower", "sig": sig}, {"keyid": "upper", "sig": sig}],
        }))
        .unwrap()
    };
    let repository = Repository::default().with("2.root.json", signed_by_both_ids(root_with(2)));

    let error = refreshed(&signed_by_both_ids(root_with(1)), None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 1,
            threshold: 2
        }
    );
}

#[test]
fn a_cache_written_before_the_built_in_root_was_updated_still_verifies() {
    let roles = RoleSet::new();
    let repository =
        synthetic_repository(&roles, 1, 1, 1).with("2.root.json", roles.signed_root(2));
    let stored = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap();
    assert_eq!(stored.roots.len(), 1);

    let verified = stored.verified_trusted_root(&roles.signed_root(2)).unwrap();

    assert_eq!(verified.bytes, SYNTHETIC_TRUSTED_ROOT);
}

#[test]
fn a_delegated_role_sigstore_drops_does_not_block_refreshes() {
    let roles = RoleSet::new();
    let embedded = roles.signed_root(1);
    let with_delegation = Repository {
        files: repository_files_listing(
            &roles,
            1,
            1,
            1,
            SYNTHETIC_TRUSTED_ROOT,
            &["registry.npmjs.org"],
        ),
        requested: Mutex::default(),
    };
    let stored = refreshed(&embedded, None, &with_delegation, now()).unwrap();

    refreshed(
        &embedded,
        Some(&stored),
        &synthetic_repository(&roles, 2, 2, 2),
        now(),
    )
    .expect("only targets.json is held to its stored version");
}

#[test]
fn a_root_listing_a_key_this_client_cannot_read_still_verifies() {
    let roles = RoleSet::new();
    let root_signers: Vec<&TestKey> = roles.root.iter().collect();
    let next = resigned(&roles.signed_root(2), &root_signers, |signed| {
        signed["keys"]["future"] = json!({"keytype": "post-quantum", "keyval": {"x": [1, 2]}});
    });
    let repository = synthetic_repository(&roles, 1, 1, 1).with("2.root.json", next);

    let metadata = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap();

    assert_eq!(metadata.roots.len(), 1);
}

#[test]
fn a_root_whose_own_keys_did_not_sign_it_is_refused() {
    let roles = RoleSet::new();
    let successor = RoleSet {
        root: vec![TestKey::p256(60)],
        ..roles.clone()
    };
    let old_keys: Vec<&TestKey> = roles.root.iter().collect();
    let repository =
        synthetic_repository(&roles, 1, 1, 1).with("2.root.json", successor.root(2, &old_keys));

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 0,
            threshold: 1
        }
    );
}

#[test]
fn a_threshold_of_two_is_met_by_two_distinct_keys_only() {
    let roles = RoleSet {
        root: vec![TestKey::p256(70), TestKey::ed25519(71)],
        root_threshold: 2,
        ..RoleSet::new()
    };
    let both: Vec<&TestKey> = roles.root.iter().collect();
    let one = [&roles.root[0]];
    let accepted = synthetic_repository(&roles, 1, 1, 1).with("2.root.json", roles.root(2, &both));
    let refused = synthetic_repository(&roles, 1, 1, 1).with("2.root.json", roles.root(2, &one));

    refreshed(&roles.root(1, &both), None, &accepted, now()).unwrap();
    let error = refreshed(&roles.root(1, &both), None, &refused, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 1,
            threshold: 2
        }
    );
}

#[test]
fn a_key_of_an_unsupported_type_never_counts() {
    let roles = RoleSet::new();
    let root_signers: Vec<&TestKey> = roles.root.iter().collect();
    let keyid = roles.root[0].keyid();
    let next = resigned(&roles.signed_root(2), &root_signers, |signed| {
        signed["keys"][&keyid]["keytype"] = json!("rsa");
        signed["keys"][&keyid]["scheme"] = json!("rsassa-pss-sha256");
    });
    let repository = synthetic_repository(&roles, 1, 1, 1).with("2.root.json", next);

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert_eq!(
        error,
        TufError::Threshold {
            role: "root",
            valid: 0,
            threshold: 1
        }
    );
}

#[test]
fn metadata_of_version_zero_or_another_specification_is_refused() {
    let roles = RoleSet::new();
    let root_signers: Vec<&TestKey> = roles.root.iter().collect();
    for (field, value) in [("version", json!(0)), ("spec_version", json!("2.0"))] {
        let embedded = resigned(&roles.signed_root(1), &root_signers, |signed| {
            signed[field] = value.clone();
        });

        let error = refreshed(
            &embedded,
            None,
            &synthetic_repository(&roles, 1, 1, 1),
            now(),
        )
        .unwrap_err();

        assert!(
            matches!(error, TufError::Malformed { role: "root", .. }),
            "{field}: {error}"
        );
    }
}

#[test]
fn a_snapshot_that_differs_from_its_recorded_hash_is_refused() {
    let roles = RoleSet::new();
    let mut repository = synthetic_repository(&roles, 1, 1, 1);
    let snapshot = repository.files.get_mut("1.snapshot.json").unwrap();
    let space = snapshot.iter().position(|&byte| byte == b' ').unwrap();
    snapshot[space] = b'\t';

    let error = refreshed(&roles.signed_root(1), None, &repository, now()).unwrap_err();

    assert!(
        matches!(&error, TufError::Mismatch { name, .. } if name == "snapshot.json"),
        "{error}"
    );
}

#[test]
fn a_cache_a_newer_binary_wrote_still_verifies_for_an_older_one() {
    let roles = RoleSet::new();
    let older_built_in = roles.signed_root(1);
    let newer_built_in = roles.signed_root(2);
    let repository = synthetic_repository(&roles, 1, 1, 1)
        .with("2.root.json", roles.signed_root(2))
        .with("3.root.json", roles.signed_root(3));
    let written_by_older = refreshed(&older_built_in, None, &repository, now()).unwrap();

    let written_by_newer =
        refreshed(&newer_built_in, Some(&written_by_older), &repository, now()).unwrap();

    let verified = written_by_newer
        .verified_trusted_root(&older_built_in)
        .unwrap();
    assert_eq!(verified.bytes, SYNTHETIC_TRUSTED_ROOT);
}
