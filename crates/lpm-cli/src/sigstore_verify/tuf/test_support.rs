//! Synthetic TUF repositories signed with test keys.

use super::canonical;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A signing key for a synthetic repository.
#[derive(Clone)]
pub(crate) enum TestKey {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl TestKey {
    pub(crate) fn p256(seed: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    pub(crate) fn ed25519(seed: u8) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    fn metadata(&self) -> Value {
        match self {
            Self::P256(key) => json!({
                "keytype": "ecdsa",
                "scheme": "ecdsa-sha2-nistp256",
                "keyval": {"public": key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()},
            }),
            Self::Ed25519(key) => json!({
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyval": {"public": hex::encode(key.verifying_key().as_bytes())},
            }),
        }
    }

    fn keyid(&self) -> String {
        hex::encode(Sha256::digest(self.metadata().to_string()))
    }

    fn sign(&self, message: &[u8]) -> String {
        match self {
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    key.sign_prehash(&Sha256::digest(message)).unwrap();
                hex::encode(signature.to_der().as_bytes())
            }
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer;
                hex::encode(key.sign(message).to_bytes())
            }
        }
    }
}

pub(crate) fn envelope(signed: Value, signers: &[&TestKey]) -> Vec<u8> {
    let mut canonical_bytes = Vec::new();
    canonical::encode(&signed, &mut canonical_bytes).unwrap();
    let signatures: Vec<Value> = signers
        .iter()
        .map(|key| json!({"keyid": key.keyid(), "sig": key.sign(&canonical_bytes)}))
        .collect();
    serde_json::to_vec_pretty(&json!({"signed": signed, "signatures": signatures})).unwrap()
}

/// The keys of each top-level role in a synthetic root.
#[derive(Clone)]
pub(crate) struct RoleSet {
    pub(crate) root: Vec<TestKey>,
    pub(crate) root_threshold: u32,
    pub(crate) timestamp: TestKey,
    pub(crate) snapshot: TestKey,
    pub(crate) targets: TestKey,
    pub(crate) consistent_snapshot: bool,
}

impl RoleSet {
    pub(crate) fn new() -> Self {
        Self {
            root: vec![TestKey::p256(1)],
            root_threshold: 1,
            timestamp: TestKey::p256(2),
            snapshot: TestKey::p256(3),
            targets: TestKey::p256(4),
            consistent_snapshot: true,
        }
    }

    pub(crate) fn root(&self, version: u64, signers: &[&TestKey]) -> Vec<u8> {
        let mut keys = serde_json::Map::new();
        let all = self
            .root
            .iter()
            .chain([&self.timestamp, &self.snapshot, &self.targets]);
        for key in all {
            keys.insert(key.keyid(), key.metadata());
        }
        let role = |keys: &[&TestKey], threshold: u32| json!({"keyids": keys.iter().map(|key| key.keyid()).collect::<Vec<_>>(), "threshold": threshold});
        let root_keys: Vec<&TestKey> = self.root.iter().collect();
        envelope(
            json!({
                "_type": "root",
                "spec_version": "1.0",
                "version": version,
                "expires": "2099-01-01T00:00:00Z",
                "consistent_snapshot": self.consistent_snapshot,
                "keys": keys,
                "roles": {
                    "root": role(&root_keys, self.root_threshold),
                    "timestamp": role(&[&self.timestamp], 1),
                    "snapshot": role(&[&self.snapshot], 1),
                    "targets": role(&[&self.targets], 1),
                },
            }),
            signers,
        )
    }

    pub(crate) fn signed_root(&self, version: u64) -> Vec<u8> {
        let signers: Vec<&TestKey> = self.root.iter().collect();
        self.root(version, &signers)
    }
}

/// The files of a synthetic repository whose timestamp, snapshot and
/// targets carry the given versions, and whose `trusted_root.json` is
/// `trusted_root`.
pub(crate) fn repository_files(
    roles: &RoleSet,
    timestamp_version: u64,
    snapshot_version: u64,
    targets_version: u64,
    trusted_root: &[u8],
) -> BTreeMap<String, Vec<u8>> {
    let target_hash = hex::encode(Sha256::digest(trusted_root));
    let targets = envelope(
        json!({
            "_type": "targets",
            "spec_version": "1.0",
            "version": targets_version,
            "expires": "2099-01-01T00:00:00Z",
            "targets": {
                "trusted_root.json": {"length": trusted_root.len(), "hashes": {"sha256": target_hash}},
            },
        }),
        &[&roles.targets],
    );
    let snapshot = envelope(
        json!({
            "_type": "snapshot",
            "spec_version": "1.0",
            "version": snapshot_version,
            "expires": "2099-01-01T00:00:00Z",
            "meta": {"targets.json": {"version": targets_version}},
        }),
        &[&roles.snapshot],
    );
    let timestamp = envelope(
        json!({
            "_type": "timestamp",
            "spec_version": "1.0",
            "version": timestamp_version,
            "expires": "2099-01-01T00:00:00Z",
            "meta": {"snapshot.json": {
                "version": snapshot_version,
                "length": snapshot.len(),
                "hashes": {"sha256": hex::encode(Sha256::digest(&snapshot))},
            }},
        }),
        &[&roles.timestamp],
    );
    let (snapshot_path, targets_path, target_path) = if roles.consistent_snapshot {
        (
            format!("{snapshot_version}.snapshot.json"),
            format!("{targets_version}.targets.json"),
            format!("targets/{target_hash}.trusted_root.json"),
        )
    } else {
        (
            "snapshot.json".into(),
            "targets.json".into(),
            "targets/trusted_root.json".into(),
        )
    };
    BTreeMap::from([
        ("timestamp.json".to_string(), timestamp),
        (snapshot_path, snapshot),
        (targets_path, targets),
        (target_path, trusted_root.to_vec()),
    ])
}
